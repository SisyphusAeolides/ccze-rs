//! Distributed Vector Gossip Protocol
//!
//! Swarm intelligence for fleet immunity using UDP mesh to share
//! threat signatures and state vectors between ccze-rs instances.

use bincode::{deserialize, serialize};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Gossip message types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GossipMessageType {
    /// Heartbeat message (node is alive)
    Heartbeat = 0x01,
    /// State vector sharing
    StateVector = 0x02,
    /// Threat signature alert
    ThreatAlert = 0x03,
    /// Node join announcement
    NodeJoin = 0x04,
    /// Node leave announcement
    NodeLeave = 0x05,
    /// Request for state vectors
    StateRequest = 0x06,
    /// Response with state vectors
    StateResponse = 0x07,
    /// Acknowledgment
    Acknowledgment = 0x08,
}

/// Threat severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatSeverity {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl From<f64> for ThreatSeverity {
    fn from(severity: f64) -> Self {
        if severity >= 0.9 {
            ThreatSeverity::Critical
        } else if severity >= 0.7 {
            ThreatSeverity::High
        } else if severity >= 0.4 {
            ThreatSeverity::Medium
        } else {
            ThreatSeverity::Low
        }
    }
}

/// Node information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipNode {
    pub node_id: String,
    pub address: SocketAddr,
    pub last_seen: u64,
    pub state_hash: String,
    pub version: String,
    pub capabilities: Vec<String>,
}

impl GossipNode {
    pub fn new(node_id: String, address: SocketAddr, version: &str) -> Self {
        Self {
            node_id,
            address,
            last_seen: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            state_hash: String::new(),
            version: version.to_string(),
            capabilities: vec!["xdp".to_string(), "cgroup".to_string(), "zram".to_string()],
        }
    }

    pub fn is_alive(&self, timeout_seconds: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        now - self.last_seen <= timeout_seconds
    }
}

/// State vector for compressed log data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateVector {
    pub vector_id: String,
    pub data: Vec<f64>,
    pub timestamp: u64,
    pub source_node: String,
    pub severity: f64,
    pub entropy: f64,
}

impl StateVector {
    pub fn new(data: Vec<f64>, source_node: &str, severity: f64, entropy: f64) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            vector_id: format!("vec_{}_{}", source_node, timestamp),
            data,
            timestamp,
            source_node: source_node.to_string(),
            severity,
            entropy,
        }
    }

    pub fn get_hash(&self) -> String {
        // Simple hash based on data content
        let mut hash = 0u64;
        for &value in &self.data {
            hash = hash.wrapping_mul(value.to_bits());
        }
        hash ^= self.timestamp;
        hash ^= self.severity.to_bits();
        hash ^= self.entropy.to_bits();

        format!("{:016x}", hash)
    }
}

/// Threat signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatSignature {
    pub signature_id: String,
    pub threat_type: String,
    pub severity: ThreatSeverity,
    pub signature_data: Vec<u8>,
    pub affected_nodes: Vec<String>,
    pub timestamp: u64,
    pub expiration: u64,
}

impl ThreatSignature {
    pub fn new(threat_type: &str, severity: ThreatSeverity, signature_data: Vec<u8>) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            signature_id: format!("threat_{}_{}", threat_type, timestamp),
            threat_type: threat_type.to_string(),
            severity,
            signature_data,
            affected_nodes: Vec::new(),
            timestamp,
            expiration: timestamp + 3600, // 1 hour expiration
        }
    }

    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        now > self.expiration
    }
}

/// Gossip message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipMessage {
    pub message_type: GossipMessageType,
    pub node_id: String,
    pub timestamp: u64,
    pub sequence_number: u64,
    pub payload: Vec<u8>,
}

impl GossipMessage {
    pub fn new(message_type: GossipMessageType, node_id: &str) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            message_type,
            node_id: node_id.to_string(),
            timestamp,
            sequence_number: 0, // Will be set by sender
            payload: Vec::new(),
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(serialize(self)?)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(deserialize(data)?)
    }
}

/// Gossip protocol configuration
#[derive(Debug, Clone)]
pub struct GossipConfig {
    pub node_id: String,
    pub bind_address: SocketAddr,
    pub broadcast_address: SocketAddr,
    pub multicast_address: Option<SocketAddr>,
    pub port: u16,
    pub heartbeat_interval: u64, // Seconds
    pub gossip_interval: u64,    // Seconds
    pub timeout: u64,            // Seconds
    pub max_peers: usize,
    pub ttl: u8, // Time to live for messages
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            node_id: "ccze_node_1".to_string(),
            bind_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 54321),
            broadcast_address: SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
                54321,
            ),
            multicast_address: Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(239, 255, 255, 250)),
                54321,
            )),
            port: 54321,
            heartbeat_interval: 30,
            gossip_interval: 60,
            timeout: 120,
            max_peers: 100,
            ttl: 3,
        }
    }
}

/// Gossip protocol manager
pub struct GossipManager {
    config: GossipConfig,
    socket: Option<UdpSocket>,
    nodes: Arc<Mutex<HashMap<String, GossipNode>>>,
    state_vectors: Arc<Mutex<HashMap<String, StateVector>>>,
    threat_signatures: Arc<Mutex<HashMap<String, ThreatSignature>>>,
    sequence_number: Arc<Mutex<u64>>,
    running: Arc<AtomicBool>,
    message_receiver: Option<thread::JoinHandle<()>>,
}

impl GossipManager {
    pub fn new(config: GossipConfig) -> Self {
        Self {
            config,
            socket: None,
            nodes: Arc::new(Mutex::new(HashMap::new())),
            state_vectors: Arc::new(Mutex::new(HashMap::new())),
            threat_signatures: Arc::new(Mutex::new(HashMap::new())),
            sequence_number: Arc::new(Mutex::new(0)),
            running: Arc::new(AtomicBool::new(false)),
            message_receiver: None,
        }
    }

    /// Clone the socket if possible
    fn clone_socket(&self) -> Option<UdpSocket> {
        self.socket.as_ref().and_then(|s| {
            // Try to create a new socket with the same settings
            UdpSocket::bind(s.local_addr().unwrap()).ok()
        })
    }

    /// Initialize the gossip protocol
    pub fn initialize(&mut self) -> Result<(), String> {
        // Create UDP socket
        let socket = UdpSocket::bind(self.config.bind_address)
            .map_err(|e| format!("Failed to bind socket: {}", e))?;

        // Set socket options for broadcast
        socket
            .set_broadcast(true)
            .map_err(|e| format!("Failed to set broadcast: {}", e))?;

        // Set TTL for multicast
        if let Some(multicast_addr) = self.config.multicast_address {
            socket
                .set_ttl(self.config.ttl as u32)
                .map_err(|e| format!("Failed to set TTL: {}", e))?;

            // Join multicast group (if available on this platform)
            #[cfg(unix)]
            if let IpAddr::V4(addr) = multicast_addr.ip() {
                let any_addr = Ipv4Addr::new(0, 0, 0, 0);
                socket
                    .join_multicast_v4(&addr, &any_addr)
                    .map_err(|e| format!("Failed to join multicast group: {}", e))?;
            }
        }

        self.socket = Some(socket);

        // Add self to nodes
        let self_node = GossipNode::new(
            self.config.node_id.clone(),
            self.config.bind_address,
            "ccze-rs",
        );

        let mut nodes = self.nodes.lock().unwrap();
        nodes.insert(self.config.node_id.clone(), self_node);

        Ok(())
    }

    /// Start the gossip protocol
    pub fn start(&mut self) -> Result<(), String> {
        if !self.running.load(Ordering::SeqCst) {
            self.running.store(true, Ordering::SeqCst);

            // Start message receiver thread
            let socket = self.clone_socket().ok_or("Socket not initialized")?;
            let nodes = self.nodes.clone();
            let state_vectors = self.state_vectors.clone();
            let threat_signatures = self.threat_signatures.clone();
            let config = self.config.clone();
            let running = self.running.clone();

            let receiver = thread::spawn(move || {
                Self::receive_messages(
                    socket,
                    nodes,
                    state_vectors,
                    threat_signatures,
                    config,
                    running,
                )
            });

            self.message_receiver = Some(receiver);

            // Start heartbeat and gossip
            self.start_heartbeat();
            self.start_gossip();
        }

        Ok(())
    }

    /// Stop the gossip protocol
    pub fn stop(&mut self) -> Result<(), String> {
        if self.running.load(Ordering::SeqCst) {
            self.running.store(false, Ordering::SeqCst);

            // Stop receiver thread
            if let Some(handle) = self.message_receiver.take() {
                // The thread will exit when running is false
                let _ = handle.join();
            }
        }

        Ok(())
    }

    /// Receive gossip messages
    fn receive_messages(
        socket: UdpSocket,
        nodes: Arc<Mutex<HashMap<String, GossipNode>>>,
        state_vectors: Arc<Mutex<HashMap<String, StateVector>>>,
        threat_signatures: Arc<Mutex<HashMap<String, ThreatSignature>>>,
        config: GossipConfig,
        running: Arc<AtomicBool>,
    ) {
        let mut buffer = [0u8; 65536]; // 64KB buffer

        while running.load(Ordering::SeqCst) {
            match socket.recv_from(&mut buffer) {
                Ok((size, sender_addr)) => {
                    // Deserialize message
                    if let Ok(message) = GossipMessage::deserialize(&buffer[..size]) {
                        Self::handle_message(
                            message,
                            sender_addr,
                            &nodes,
                            &state_vectors,
                            &threat_signatures,
                            &config,
                        );
                    }
                }
                Err(e) => {
                    // Log error but continue
                    eprintln!("Gossip receive error: {}", e);
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }

    /// Handle incoming gossip message
    fn handle_message(
        message: GossipMessage,
        sender_addr: SocketAddr,
        nodes: &Arc<Mutex<HashMap<String, GossipNode>>>,
        state_vectors: &Arc<Mutex<HashMap<String, StateVector>>>,
        threat_signatures: &Arc<Mutex<HashMap<String, ThreatSignature>>>,
        _config: &GossipConfig,
    ) {
        // Update node last seen time
        let mut nodes_lock = nodes.lock().unwrap();
        if let Some(node) = nodes_lock.get_mut(&message.node_id) {
            node.last_seen = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
        } else {
            // Add new node
            let new_node = GossipNode::new(message.node_id.clone(), sender_addr, "unknown");
            nodes_lock.insert(message.node_id.clone(), new_node);
        }

        // Handle message based on type
        match message.message_type {
            GossipMessageType::Heartbeat => {
                // Node is alive, already updated last_seen
            }
            GossipMessageType::StateVector => {
                if let Ok(state_vector) = deserialize::<StateVector>(&message.payload) {
                    let mut vectors = state_vectors.lock().unwrap();
                    vectors.insert(state_vector.vector_id.clone(), state_vector);
                }
            }
            GossipMessageType::ThreatAlert => {
                if let Ok(signature) = deserialize::<ThreatSignature>(&message.payload) {
                    let mut signatures = threat_signatures.lock().unwrap();
                    signatures.insert(signature.signature_id.clone(), signature);
                }
            }
            GossipMessageType::NodeJoin => {
                if let Ok(node) = deserialize::<GossipNode>(&message.payload) {
                    let mut nodes_lock = nodes.lock().unwrap();
                    nodes_lock.insert(node.node_id.clone(), node);
                }
            }
            GossipMessageType::NodeLeave => {
                let mut nodes_lock = nodes.lock().unwrap();
                nodes_lock.remove(&message.node_id);
            }
            GossipMessageType::StateRequest => {
                // Send state vectors in response
            }
            GossipMessageType::StateResponse => {
                if let Ok(vectors) = deserialize::<Vec<StateVector>>(&message.payload) {
                    let mut state_vectors_lock = state_vectors.lock().unwrap();
                    for vector in vectors {
                        state_vectors_lock.insert(vector.vector_id.clone(), vector);
                    }
                }
            }
            GossipMessageType::Acknowledgment => {
                // ACK received, can be ignored for now
            }
        }
    }

    /// Start heartbeat thread
    fn start_heartbeat(&self) {
        let config = self.config.clone();
        let socket = self.clone_socket();
        let running = self.running.clone();
        let sequence_number = self.sequence_number.clone();

        if let Some(socket) = socket {
            thread::spawn(move || {
                while running.load(Ordering::SeqCst) {
                    // Create heartbeat message
                    let mut message =
                        GossipMessage::new(GossipMessageType::Heartbeat, &config.node_id);

                    {
                        let mut seq = sequence_number.lock().unwrap();
                        message.sequence_number = *seq;
                        *seq += 1;
                    }

                    // Send to broadcast address
                    if let Ok(data) = message.serialize() {
                        let _ = socket.send_to(&data, config.broadcast_address);
                    }

                    thread::sleep(Duration::from_secs(config.heartbeat_interval));
                }
            });
        }
    }

    /// Start gossip thread
    fn start_gossip(&self) {
        let config = self.config.clone();
        let socket = self.clone_socket();
        let running = self.running.clone();
        let nodes = self.nodes.clone();
        let state_vectors = self.state_vectors.clone();
        let threat_signatures = self.threat_signatures.clone();
        let sequence_number = self.sequence_number.clone();

        if let Some(socket) = socket {
            thread::spawn(move || {
                while running.load(Ordering::SeqCst) {
                    // Get random nodes to gossip with
                    let nodes_lock = nodes.lock().unwrap();
                    let _peer_count = nodes_lock.len().min(config.max_peers);

                    // For now, broadcast to all known nodes
                    Self::broadcast_state_vectors(
                        &socket,
                        &config,
                        &nodes_lock,
                        &state_vectors,
                        &sequence_number,
                    );

                    Self::broadcast_threat_signatures(
                        &socket,
                        &config,
                        &nodes_lock,
                        &threat_signatures,
                        &sequence_number,
                    );

                    thread::sleep(Duration::from_secs(config.gossip_interval));
                }
            });
        }
    }

    /// Broadcast state vectors to all known nodes
    fn broadcast_state_vectors(
        socket: &UdpSocket,
        config: &GossipConfig,
        nodes: &HashMap<String, GossipNode>,
        state_vectors: &Arc<Mutex<HashMap<String, StateVector>>>,
        sequence_number: &Arc<Mutex<u64>>,
    ) {
        let vectors_lock = state_vectors.lock().unwrap();

        // Send a few random state vectors
        let vectors: Vec<StateVector> = vectors_lock.values().cloned().collect();

        for vector in vectors.iter().take(5) {
            // Send up to 5 vectors
            let mut message = GossipMessage::new(GossipMessageType::StateVector, &config.node_id);

            {
                let mut seq = sequence_number.lock().unwrap();
                message.sequence_number = *seq;
                *seq += 1;
            }

            message.payload = serialize(vector).unwrap_or_default();

            if let Ok(data) = message.serialize() {
                // Broadcast to all nodes
                for node in nodes.values() {
                    if node.address != config.bind_address {
                        let _ = socket.send_to(&data, node.address);
                    }
                }

                // Also send to broadcast address
                let _ = socket.send_to(&data, config.broadcast_address);
            }
        }
    }

    /// Broadcast threat signatures to all known nodes
    fn broadcast_threat_signatures(
        socket: &UdpSocket,
        config: &GossipConfig,
        nodes: &HashMap<String, GossipNode>,
        threat_signatures: &Arc<Mutex<HashMap<String, ThreatSignature>>>,
        sequence_number: &Arc<Mutex<u64>>,
    ) {
        let signatures_lock = threat_signatures.lock().unwrap();

        // Send all active threat signatures
        for signature in signatures_lock.values() {
            if !signature.is_expired() {
                let mut message =
                    GossipMessage::new(GossipMessageType::ThreatAlert, &config.node_id);

                {
                    let mut seq = sequence_number.lock().unwrap();
                    message.sequence_number = *seq;
                    *seq += 1;
                }

                message.payload = serialize(signature).unwrap_or_default();

                if let Ok(data) = message.serialize() {
                    // Broadcast to all nodes
                    for node in nodes.values() {
                        if node.address != config.bind_address {
                            let _ = socket.send_to(&data, node.address);
                        }
                    }

                    // Also send to broadcast address
                    let _ = socket.send_to(&data, config.broadcast_address);
                }
            }
        }
    }

    /// Share a state vector with the network
    pub fn share_state_vector(&self, vector: StateVector) -> Result<(), String> {
        let mut vectors = self.state_vectors.lock().unwrap();
        vectors.insert(vector.vector_id.clone(), vector.clone());

        // Immediately broadcast this vector
        if let Some(socket) = &self.socket {
            let mut message =
                GossipMessage::new(GossipMessageType::StateVector, &self.config.node_id);

            {
                let mut seq = self.sequence_number.lock().unwrap();
                message.sequence_number = *seq;
                *seq += 1;
            }

            message.payload = serialize(&vector).unwrap_or_default();

            if let Ok(data) = message.serialize() {
                socket
                    .send_to(&data, self.config.broadcast_address)
                    .map_err(|e| format!("Failed to broadcast state vector: {}", e))?;
            }
        }

        Ok(())
    }

    /// Share a threat signature with the network
    pub fn share_threat_signature(&self, signature: ThreatSignature) -> Result<(), String> {
        let mut signatures = self.threat_signatures.lock().unwrap();
        signatures.insert(signature.signature_id.clone(), signature.clone());

        // Immediately broadcast this signature
        if let Some(socket) = &self.socket {
            let mut message =
                GossipMessage::new(GossipMessageType::ThreatAlert, &self.config.node_id);

            {
                let mut seq = self.sequence_number.lock().unwrap();
                message.sequence_number = *seq;
                *seq += 1;
            }

            message.payload = serialize(&signature).unwrap_or_default();

            if let Ok(data) = message.serialize() {
                socket
                    .send_to(&data, self.config.broadcast_address)
                    .map_err(|e| format!("Failed to broadcast threat signature: {}", e))?;
            }
        }

        Ok(())
    }

    /// Get known nodes
    pub fn get_nodes(&self) -> Vec<GossipNode> {
        let nodes = self.nodes.lock().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        nodes
            .values()
            .filter(|n| n.is_alive(now - self.config.timeout))
            .cloned()
            .collect()
    }

    /// Get known state vectors
    pub fn get_state_vectors(&self) -> Vec<StateVector> {
        let vectors = self.state_vectors.lock().unwrap();
        vectors.values().cloned().collect()
    }

    /// Get known threat signatures
    pub fn get_threat_signatures(&self) -> Vec<ThreatSignature> {
        let signatures = self.threat_signatures.lock().unwrap();
        let _now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        signatures
            .values()
            .filter(|s| !s.is_expired())
            .cloned()
            .collect()
    }

    /// Get threat signatures from a specific threat type
    pub fn get_threat_signatures_by_type(&self, threat_type: &str) -> Vec<ThreatSignature> {
        let signatures = self.threat_signatures.lock().unwrap();
        let _now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        signatures
            .values()
            .filter(|s| !s.is_expired() && s.threat_type == threat_type)
            .cloned()
            .collect()
    }

    /// Get statistics about the gossip network
    pub fn get_stats(&self) -> GossipStats {
        let nodes = self.nodes.lock().unwrap();
        let vectors = self.state_vectors.lock().unwrap();
        let signatures = self.threat_signatures.lock().unwrap();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let active_nodes = nodes
            .values()
            .filter(|n| n.is_alive(now - self.config.timeout))
            .count();

        let critical_signatures = signatures
            .values()
            .filter(|s| s.severity == ThreatSeverity::Critical && !s.is_expired())
            .count();

        GossipStats {
            node_id: self.config.node_id.clone(),
            total_nodes: nodes.len(),
            active_nodes,
            total_state_vectors: vectors.len(),
            total_threat_signatures: signatures.len(),
            critical_threat_signatures: critical_signatures,
            running: self.running.load(Ordering::SeqCst),
        }
    }
}

impl Drop for GossipManager {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// Gossip network statistics
#[derive(Debug, Clone)]
pub struct GossipStats {
    pub node_id: String,
    pub total_nodes: usize,
    pub active_nodes: usize,
    pub total_state_vectors: usize,
    pub total_threat_signatures: usize,
    pub critical_threat_signatures: usize,
    pub running: bool,
}

// Add serde dependency for serialization
// This would be in Cargo.toml: serde = { version = "1.0", features = ["derive"] }
// bincode = "1.3"

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gossip_node_creation() {
        let node = GossipNode::new(
            "node1".to_string(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 54321),
            "1.0.0",
        );

        assert_eq!(node.node_id, "node1");
        assert_eq!(node.version, "1.0.0");
        assert!(node.is_alive(60)); // Within timeout
    }

    #[test]
    fn test_state_vector_creation() {
        let vector = StateVector::new(vec![0.1, 0.2, 0.3, 0.4], "node1", 0.5, 0.8);

        assert_eq!(vector.source_node, "node1");
        assert_eq!(vector.severity, 0.5);
        assert_eq!(vector.entropy, 0.8);
        assert_eq!(vector.data.len(), 4);
    }

    #[test]
    fn test_threat_signature_creation() {
        let signature = ThreatSignature::new(
            "xdp_attack",
            ThreatSeverity::High,
            vec![0x01, 0x02, 0x03, 0x04],
        );

        assert_eq!(signature.threat_type, "xdp_attack");
        assert_eq!(signature.severity, ThreatSeverity::High);
        assert!(!signature.is_expired());
    }

    #[test]
    fn test_gossip_message_creation() {
        let message = GossipMessage::new(GossipMessageType::Heartbeat, "node1");

        assert_eq!(message.message_type, GossipMessageType::Heartbeat);
        assert_eq!(message.node_id, "node1");
    }

    #[test]
    fn test_gossip_config_default() {
        let config = GossipConfig::default();

        assert_eq!(config.node_id, "ccze_node_1");
        assert_eq!(config.port, 54321);
        assert_eq!(config.heartbeat_interval, 30);
        assert_eq!(config.gossip_interval, 60);
    }

    #[test]
    fn test_threat_severity_from_f64() {
        assert_eq!(ThreatSeverity::from(0.95), ThreatSeverity::Critical);
        assert_eq!(ThreatSeverity::from(0.75), ThreatSeverity::High);
        assert_eq!(ThreatSeverity::from(0.5), ThreatSeverity::Medium);
        assert_eq!(ThreatSeverity::from(0.2), ThreatSeverity::Low);
    }

    #[test]
    fn test_gossip_stats() {
        let stats = GossipStats {
            node_id: "test_node".to_string(),
            total_nodes: 10,
            active_nodes: 8,
            total_state_vectors: 100,
            total_threat_signatures: 5,
            critical_threat_signatures: 2,
            running: true,
        };

        assert_eq!(stats.node_id, "test_node");
        assert_eq!(stats.active_nodes, 8);
        assert_eq!(stats.critical_threat_signatures, 2);
    }
}
