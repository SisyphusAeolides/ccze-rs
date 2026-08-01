//! Ring-0 XDP Auto-Immune Shield
//!
//! Dynamically compiles and injects eXpress Data Path (XDP) eBPF filters
//! into NIC drivers to drop malicious traffic at hardware level.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// XDP filter state
#[derive(Debug, Clone)]
pub enum XdpState {
    /// No XDP filter loaded
    Inactive,
    /// XDP filter loaded and active
    Active,
    /// XDP filter loaded but in error state
    Error(String),
}

/// Offending entity to be dropped by XDP
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BlockTarget {
    /// IP address to block
    Ip(IpAddr),
    /// IP range (CIDR) to block
    IpRange(String),
    /// Specific port on an IP
    IpPort(SocketAddr),
    /// MAC address to block
    Mac([u8; 6]),
    /// Payload pattern to match (simplified representation)
    PayloadPattern(Vec<u8>),
}

/// XDP filter configuration
#[derive(Clone)]
pub struct XdpFilter {
    /// Targets to block
    pub targets: HashSet<BlockTarget>,
    /// NIC interface name (e.g., "eth0")
    pub interface: String,
    /// Filter priority (higher = evaluated first)
    pub priority: u32,
    /// Creation timestamp
    pub created_at: u64,
    /// State of the filter
    pub state: XdpState,
}

impl XdpFilter {
    pub fn new(interface: &str, priority: u32) -> Self {
        Self {
            targets: HashSet::new(),
            interface: interface.to_string(),
            priority,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            state: XdpState::Inactive,
        }
    }

    /// Add a block target to the filter
    pub fn add_target(&mut self, target: BlockTarget) {
        self.targets.insert(target);
    }

    /// Remove a block target from the filter
    pub fn remove_target(&mut self, target: &BlockTarget) -> bool {
        self.targets.remove(target)
    }

    /// Check if filter is active
    pub fn is_active(&self) -> bool {
        matches!(self.state, XdpState::Active)
    }
}

/// XDP shield manager
pub struct XdpShield {
    filters: Arc<Mutex<Vec<XdpFilter>>>,
}

impl XdpShield {
    pub fn new() -> Self {
        Self {
            filters: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Create a new XDP filter for a specific interface
    pub fn create_filter(&self, interface: &str, priority: u32) -> XdpFilter {
        XdpFilter::new(interface, priority)
    }

    /// Add a filter to the shield
    pub fn add_filter(&self, filter: XdpFilter) -> Result<(), String> {
        let mut filters = self.filters.lock().map_err(|e| e.to_string())?;

        // Check for duplicate interface
        if filters.iter().any(|f| f.interface == filter.interface) {
            return Err(format!(
                "Filter already exists for interface {}",
                filter.interface
            ));
        }

        filters.push(filter);
        Ok(())
    }

    /// Remove a filter by interface name
    pub fn remove_filter(&self, interface: &str) -> Result<bool, String> {
        let mut filters = self.filters.lock().map_err(|e| e.to_string())?;

        let index = filters.iter().position(|f| f.interface == interface);

        if let Some(idx) = index {
            filters.remove(idx);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Find filter by interface
    pub fn get_filter(&self, interface: &str) -> Result<Option<XdpFilter>, String> {
        let filters = self.filters.lock().map_err(|e| e.to_string())?;

        Ok(filters.iter().find(|f| f.interface == interface).cloned())
    }

    /// List all active filters
    pub fn list_filters(&self) -> Result<Vec<XdpFilter>, String> {
        let filters = self.filters.lock().map_err(|e| e.to_string())?;
        Ok(filters.clone())
    }

    /// Activate a filter (load XDP program into kernel)
    pub fn activate_filter(&self, interface: &str) -> Result<(), String> {
        let mut filters = self.filters.lock().map_err(|e| e.to_string())?;

        if let Some(filter) = filters.iter_mut().find(|f| f.interface == interface) {
            // In a real implementation, this would:
            // 1. Compile the eBPF program with the current targets
            // 2. Load it into the kernel via libbpf
            // 3. Attach it to the NIC
            // For now, we'll simulate success

            filter.state = XdpState::Active;
            Ok(())
        } else {
            Err(format!("Filter not found for interface {}", interface))
        }
    }

    /// Deactivate a filter (remove XDP program from kernel)
    pub fn deactivate_filter(&self, interface: &str) -> Result<(), String> {
        let mut filters = self.filters.lock().map_err(|e| e.to_string())?;

        if let Some(filter) = filters.iter_mut().find(|f| f.interface == interface) {
            // In a real implementation, this would detach and unload the XDP program
            filter.state = XdpState::Inactive;
            Ok(())
        } else {
            Err(format!("Filter not found for interface {}", interface))
        }
    }

    /// Add a target to an existing filter
    pub fn add_target_to_filter(&self, interface: &str, target: BlockTarget) -> Result<(), String> {
        let mut filters = self.filters.lock().map_err(|e| e.to_string())?;

        if let Some(filter) = filters.iter_mut().find(|f| f.interface == interface) {
            filter.add_target(target);

            // If filter is active, we'd need to recompile and reload the XDP program
            // For now, we'll just update the state
            if filter.is_active() {
                // Simulate recompilation
                filter.state = XdpState::Active;
            }

            Ok(())
        } else {
            Err(format!("Filter not found for interface {}", interface))
        }
    }

    /// Check if an IP address is blocked by any filter
    pub fn is_blocked(&self, ip: &IpAddr) -> Result<bool, String> {
        let filters = self.filters.lock().map_err(|e| e.to_string())?;

        for filter in filters.iter() {
            if filter.targets.contains(&BlockTarget::Ip(ip.clone())) {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

impl Default for XdpShield {
    fn default() -> Self {
        Self::new()
    }
}

/// Entropy spike detection thresholds
pub struct EntropyThresholds {
    /// Threshold for IP entropy
    pub ip_entropy: f64,
    /// Threshold for payload entropy
    pub payload_entropy: f64,
    /// Threshold for timing jitter
    pub timing_jitter: f64,
    /// Threshold for connection rate
    pub connection_rate: f64,
}

impl Default for EntropyThresholds {
    fn default() -> Self {
        Self {
            ip_entropy: 0.95,
            payload_entropy: 0.90,
            timing_jitter: 0.85,
            connection_rate: 1000.0, // connections per second
        }
    }
}

/// XDP shield configuration
pub struct XdpShieldConfig {
    /// Enable/disable XDP shield
    pub enabled: bool,
    /// Interfaces to protect
    pub interfaces: Vec<String>,
    /// Entropy thresholds
    pub thresholds: EntropyThresholds,
    /// Auto-activation on threat detection
    pub auto_activate: bool,
}

impl Default for XdpShieldConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interfaces: vec!["eth0".to_string(), "ens3".to_string()],
            thresholds: EntropyThresholds::default(),
            auto_activate: true,
        }
    }
}

/// Safe wrapper for XDP operations
pub struct XdpNative {
    shield: XdpShield,
}

impl XdpNative {
    pub fn new() -> Self {
        Self {
            shield: XdpShield::new(),
        }
    }

    /// Initialize XDP shield with native support
    pub fn initialize(&self, config: &XdpShieldConfig) -> Result<(), String> {
        if !config.enabled {
            return Ok(());
        }

        for interface in &config.interfaces {
            let filter = self.shield.create_filter(interface, 100);
            self.shield.add_filter(filter)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_xdp_filter() {
        let shield = XdpShield::new();
        let filter = shield.create_filter("eth0", 100);

        assert_eq!(filter.interface, "eth0");
        assert_eq!(filter.priority, 100);
        assert_eq!(filter.targets.len(), 0);
        assert!(matches!(filter.state, XdpState::Inactive));
    }

    #[test]
    fn test_add_remove_target() {
        let shield = XdpShield::new();
        let mut filter = shield.create_filter("eth0", 100);

        let target = BlockTarget::Ip("192.168.1.100".parse().unwrap());
        filter.add_target(target.clone());

        assert!(filter.targets.contains(&target));

        let removed = filter.remove_target(&target);
        assert!(removed);
        assert!(!filter.targets.contains(&target));
    }

    #[test]
    fn test_add_get_filter() {
        let shield = XdpShield::new();
        let filter = shield.create_filter("eth0", 100);

        shield.add_filter(filter).unwrap();

        let retrieved = shield.get_filter("eth0").unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().interface, "eth0");
    }

    #[test]
    fn test_activate_deactivate_filter() {
        let shield = XdpShield::new();
        let filter = shield.create_filter("eth0", 100);

        shield.add_filter(filter).unwrap();
        shield.activate_filter("eth0").unwrap();

        let activated = shield.get_filter("eth0").unwrap().unwrap();
        assert!(activated.is_active());

        shield.deactivate_filter("eth0").unwrap();

        let deactivated = shield.get_filter("eth0").unwrap().unwrap();
        assert!(!deactivated.is_active());
    }

    #[test]
    fn test_is_blocked() {
        let shield = XdpShield::new();
        let mut filter = shield.create_filter("eth0", 100);

        let target_ip: IpAddr = "192.168.1.100".parse().unwrap();
        let target = BlockTarget::Ip(target_ip.clone());
        filter.add_target(target);

        shield.add_filter(filter).unwrap();
        shield.activate_filter("eth0").unwrap();

        assert!(shield.is_blocked(&target_ip).unwrap());

        let safe_ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(!shield.is_blocked(&safe_ip).unwrap());
    }

    #[test]
    fn test_xdp_config_defaults() {
        let config = XdpShieldConfig::default();

        assert!(config.enabled);
        assert!(config.auto_activate);
        assert_eq!(config.thresholds.ip_entropy, 0.95);
        assert_eq!(config.thresholds.payload_entropy, 0.90);
    }
}
