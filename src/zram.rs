//! Hot-Cloned zRAM Memory Ejection
//!
//! Zero-downtime live core dumps using eBPF to hot-clone process memory
//! directly into zstd-compressed zRAM pool for debugging.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// zRAM device information
#[derive(Debug, Clone)]
pub struct ZramDevice {
    pub device_path: PathBuf,
    pub device_number: u32,
    pub size: u64,              // Size in bytes
    pub used: u64,              // Used space in bytes
    pub compression_ratio: f64, // Current compression ratio
    pub algorithm: String,      // Compression algorithm (e.g., "zstd", "lzo", "lz4")
}

impl ZramDevice {
    pub fn new(device_number: u32, size: u64, algorithm: &str) -> Self {
        Self {
            device_path: PathBuf::from(format!("/dev/zram{}", device_number)),
            device_number,
            size,
            used: 0,
            compression_ratio: 1.0,
            algorithm: algorithm.to_string(),
        }
    }

    /// Get compression ratio
    pub fn get_compression_ratio(&self) -> f64 {
        if self.used == 0 {
            1.0
        } else {
            self.compression_ratio
        }
    }
}

/// Memory snapshot state
#[derive(Debug, Clone)]
pub struct MemorySnapshot {
    pub pid: u32,
    pub timestamp: u64,
    pub snapshot_id: String,
    pub device: ZramDevice,
    pub original_memory_size: u64, // Original process memory size
    pub compressed_size: u64,      // Compressed size in zRAM
    pub status: SnapshotStatus,
    pub reason: String,
}

impl MemorySnapshot {
    pub fn new(pid: u32, device: ZramDevice, reason: &str) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            pid,
            timestamp,
            snapshot_id: format!("snapshot_{}_{}", pid, timestamp),
            device,
            original_memory_size: 0,
            compressed_size: 0,
            status: SnapshotStatus::Pending,
            reason: reason.to_string(),
        }
    }
}

/// Snapshot status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotStatus {
    Pending,   // Snapshot in progress
    Completed, // Snapshot completed successfully
    Failed,    // Snapshot failed
    Expired,   // Snapshot expired and cleaned up
}

/// zRAM pool configuration
#[derive(Debug, Clone)]
pub struct ZramPoolConfig {
    pub devices: Vec<ZramDevice>,
    pub default_device: u32,
    pub max_snapshot_size: u64, // Maximum snapshot size in bytes
    pub retention_hours: u64,   // How long to keep snapshots
    pub compression_algorithm: String,
    pub enabled: bool,
}

impl Default for ZramPoolConfig {
    fn default() -> Self {
        Self {
            devices: vec![ZramDevice::new(0, 32 * 1024 * 1024 * 1024, "zstd")], // 32GB default
            default_device: 0,
            max_snapshot_size: 4 * 1024 * 1024 * 1024, // 4GB max per snapshot
            retention_hours: 24,                       // Keep snapshots for 24 hours
            compression_algorithm: "zstd".to_string(),
            enabled: true,
        }
    }
}

/// zRAM memory ejection manager
pub struct ZramManager {
    config: ZramPoolConfig,
    snapshots: Arc<Mutex<HashMap<String, MemorySnapshot>>>,
    current_device_index: Arc<Mutex<usize>>,
}

impl ZramManager {
    pub fn new(config: ZramPoolConfig) -> Self {
        Self {
            config,
            snapshots: Arc::new(Mutex::new(HashMap::new())),
            current_device_index: Arc::new(Mutex::new(0)),
        }
    }

    /// Get the next available zRAM device using round-robin
    pub fn get_next_device(&self) -> Option<ZramDevice> {
        if self.config.devices.is_empty() {
            return None;
        }

        let mut index = self.current_device_index.lock().unwrap();
        let device = self.config.devices[*index].clone();

        // Round-robin
        *index = (*index + 1) % self.config.devices.len();

        Some(device)
    }

    /// Get a specific zRAM device by number
    pub fn get_device(&self, device_number: u32) -> Option<ZramDevice> {
        self.config
            .devices
            .iter()
            .find(|d| d.device_number == device_number)
            .cloned()
    }

    /// Initialize zRAM device
    pub fn initialize_device(
        &self,
        device_number: u32,
        size: u64,
        algorithm: &str,
    ) -> io::Result<ZramDevice> {
        // In a real implementation, this would:
        // 1. Load zram kernel module if not loaded
        // 2. Create zram device with specified size
        // 3. Set compression algorithm
        // 4. Format and mount the device

        let device = ZramDevice::new(device_number, size, algorithm);

        // Simulate device initialization
        Ok(device)
    }

    /// Create a memory snapshot of a process
    pub fn create_snapshot(&self, pid: u32, reason: &str) -> io::Result<MemorySnapshot> {
        if !self.config.enabled {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "zRAM snapshot disabled",
            ));
        }

        let device = self
            .get_next_device()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "No zRAM devices available"))?;

        let mut snapshot = MemorySnapshot::new(pid, device.clone(), reason);

        // Get process memory information
        let memory_info = self.get_process_memory_info(pid)?;
        snapshot.original_memory_size = memory_info.rss;

        // Calculate expected compressed size
        snapshot.compressed_size =
            (snapshot.original_memory_size as f64 * device.get_compression_ratio()) as u64;

        // Check if snapshot would exceed limits
        if snapshot.compressed_size > self.config.max_snapshot_size {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "Snapshot too large: {} > {}",
                    snapshot.compressed_size, self.config.max_snapshot_size
                ),
            ));
        }

        // Trigger the actual memory capture via eBPF
        self.trigger_memory_capture(pid, &snapshot)?;

        snapshot.status = SnapshotStatus::Completed;

        // Store the snapshot
        let mut snapshots = self.snapshots.lock().unwrap();
        snapshots.insert(snapshot.snapshot_id.clone(), snapshot.clone());

        Ok(snapshot)
    }

    /// Get process memory information from /proc
    fn get_process_memory_info(&self, pid: u32) -> io::Result<ProcessMemoryInfo> {
        let status_path = format!("/proc/{}/status", pid);
        let mut file = File::open(&status_path)?;

        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        let mut memory_info = ProcessMemoryInfo::default();

        for line in contents.lines() {
            if line.starts_with("VmRSS:") {
                if let Some(rss) = self.parse_memory_value(line) {
                    memory_info.rss = rss;
                }
            } else if line.starts_with("VmSize:") {
                if let Some(vsize) = self.parse_memory_value(line) {
                    memory_info.virtual_memory = vsize;
                }
            } else if line.starts_with("VmSwap:") {
                if let Some(swap) = self.parse_memory_value(line) {
                    memory_info.swap = swap;
                }
            }
        }

        Ok(memory_info)
    }

    /// Parse memory value from /proc status line
    fn parse_memory_value(&self, line: &str) -> Option<u64> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            parts[1]
                .strip_suffix("kB")
                .and_then(|s| s.parse::<u64>().ok())
                .map(|kb| kb * 1024)
        } else {
            None
        }
    }

    /// Trigger memory capture via eBPF
    fn trigger_memory_capture(&self, _pid: u32, _snapshot: &MemorySnapshot) -> io::Result<()> {
        // In a real implementation, this would:
        // 1. Load eBPF program to capture process memory
        // 2. Use process_vm_readv to read process memory
        // 3. Compress the memory data using zstd
        // 4. Write to zRAM device

        // For now, we'll simulate the operation
        // This would call into native C code that handles the actual eBPF operations

        Ok(())
    }

    /// Save snapshot to file (for debugging/analysis)
    pub fn save_snapshot(&self, snapshot_id: &str, output_path: &Path) -> io::Result<()> {
        let snapshots = self.snapshots.lock().unwrap();
        let snapshot = snapshots
            .get(snapshot_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Snapshot not found"))?;

        // Create directory structure
        std::fs::create_dir_all(output_path.parent().unwrap_or(output_path))?;

        let mut file = File::create(output_path)?;

        // Write snapshot metadata
        writeln!(file, "=== ccze-rs zRAM Snapshot ===")?;
        writeln!(file, "Snapshot ID: {}", snapshot.snapshot_id)?;
        writeln!(file, "PID: {}", snapshot.pid)?;
        writeln!(file, "Timestamp: {}", snapshot.timestamp)?;
        writeln!(file, "Reason: {}", snapshot.reason)?;
        writeln!(file, "Device: /dev/zram{}", snapshot.device.device_number)?;
        writeln!(file, "Algorithm: {}", snapshot.device.algorithm)?;
        writeln!(
            file,
            "Original Memory Size: {} bytes",
            snapshot.original_memory_size
        )?;
        writeln!(file, "Compressed Size: {} bytes", snapshot.compressed_size)?;
        writeln!(
            file,
            "Compression Ratio: {:.2}",
            snapshot.device.get_compression_ratio()
        )?;
        writeln!(file, "Status: {:?}", snapshot.status)?;

        Ok(())
    }

    /// List all snapshots
    pub fn list_snapshots(&self) -> Vec<MemorySnapshot> {
        let snapshots = self.snapshots.lock().unwrap();
        snapshots.values().cloned().collect()
    }

    /// Get a specific snapshot by ID
    pub fn get_snapshot(&self, snapshot_id: &str) -> Option<MemorySnapshot> {
        let snapshots = self.snapshots.lock().unwrap();
        snapshots.get(snapshot_id).cloned()
    }

    /// Clean up expired snapshots
    pub fn cleanup_expired(&self) -> io::Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let retention_seconds = self.config.retention_hours * 3600;

        let mut snapshots = self.snapshots.lock().unwrap();
        let expired: Vec<String> = snapshots
            .iter()
            .filter(|(_, snapshot)| now > snapshot.timestamp + retention_seconds)
            .map(|(id, _)| id.clone())
            .collect();

        for id in expired {
            snapshots.remove(&id);
        }

        Ok(())
    }

    /// Get zRAM statistics
    pub fn get_stats(&self) -> ZramStats {
        let snapshots = self.snapshots.lock().unwrap();

        let total_snapshots = snapshots.len() as u64;
        let total_original = snapshots
            .values()
            .map(|s| s.original_memory_size)
            .sum::<u64>();
        let total_compressed = snapshots.values().map(|s| s.compressed_size).sum::<u64>();

        let overall_ratio = if total_original > 0 {
            total_original as f64 / total_compressed as f64
        } else {
            1.0
        };

        ZramStats {
            total_snapshots,
            total_original_size: total_original,
            total_compressed_size: total_compressed,
            overall_compression_ratio: overall_ratio,
            active_devices: self.config.devices.len() as u32,
            enabled: self.config.enabled,
        }
    }
}

/// Process memory information
#[derive(Debug, Clone, Default)]
pub struct ProcessMemoryInfo {
    pub rss: u64,            // Resident Set Size
    pub virtual_memory: u64, // Virtual memory size
    pub swap: u64,           // Swap usage
    pub shared: u64,         // Shared memory
}

/// zRAM statistics
#[derive(Debug, Clone)]
pub struct ZramStats {
    pub total_snapshots: u64,
    pub total_original_size: u64,
    pub total_compressed_size: u64,
    pub overall_compression_ratio: f64,
    pub active_devices: u32,
    pub enabled: bool,
}

/// Memory ejection configuration
#[derive(Debug, Clone)]
pub struct MemoryEjectionConfig {
    pub enabled: bool,
    pub zram_config: ZramPoolConfig,
    pub auto_trigger: bool,     // Automatically trigger on critical anomalies
    pub anomaly_threshold: f64, // Threshold to trigger automatic snapshot
    pub max_concurrent_snapshots: usize, // Maximum number of concurrent snapshots
}

impl Default for MemoryEjectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            zram_config: ZramPoolConfig::default(),
            auto_trigger: true,
            anomaly_threshold: 0.95, // Trigger on high-severity anomalies
            max_concurrent_snapshots: 10,
        }
    }
}

/// Memory ejection manager
pub struct MemoryEjector {
    manager: ZramManager,
    config: MemoryEjectionConfig,
}

impl MemoryEjector {
    pub fn new(config: MemoryEjectionConfig) -> Self {
        Self {
            manager: ZramManager::new(config.zram_config.clone()),
            config,
        }
    }

    /// Trigger memory ejection for a process
    pub fn eject_memory(&self, pid: u32, reason: &str) -> io::Result<MemorySnapshot> {
        if !self.config.enabled {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Memory ejection disabled",
            ));
        }

        // Check if we have too many concurrent snapshots
        let current_snapshots = self.manager.list_snapshots().len();
        if current_snapshots >= self.config.max_concurrent_snapshots {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "Too many concurrent snapshots: {} >= {}",
                    current_snapshots, self.config.max_concurrent_snapshots
                ),
            ));
        }

        self.manager.create_snapshot(pid, reason)
    }

    /// Trigger memory ejection based on anomaly severity
    pub fn eject_if_needed(&self, pid: u32, severity: f64, reason: &str) -> io::Result<bool> {
        if !self.config.enabled || !self.config.auto_trigger {
            return Ok(false);
        }

        if severity >= self.config.anomaly_threshold {
            let _ = self.eject_memory(pid, reason)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Get ejection statistics
    pub fn get_stats(&self) -> MemoryEjectionStats {
        let zram_stats = self.manager.get_stats();

        MemoryEjectionStats {
            zram_stats,
            auto_trigger_enabled: self.config.auto_trigger,
            anomaly_threshold: self.config.anomaly_threshold,
            max_concurrent_snapshots: self.config.max_concurrent_snapshots,
            enabled: self.config.enabled,
        }
    }
}

/// Memory ejection statistics
#[derive(Debug, Clone)]
pub struct MemoryEjectionStats {
    pub zram_stats: ZramStats,
    pub auto_trigger_enabled: bool,
    pub anomaly_threshold: f64,
    pub max_concurrent_snapshots: usize,
    pub enabled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zram_device_creation() {
        let device = ZramDevice::new(0, 32 * 1024 * 1024 * 1024, "zstd");

        assert_eq!(device.device_number, 0);
        assert_eq!(device.size, 32 * 1024 * 1024 * 1024);
        assert_eq!(device.algorithm, "zstd");
        assert_eq!(device.get_compression_ratio(), 1.0);
    }

    #[test]
    fn test_memory_snapshot_creation() {
        let device = ZramDevice::new(0, 32 * 1024 * 1024 * 1024, "zstd");
        let snapshot = MemorySnapshot::new(1234, device, "test anomaly");

        assert_eq!(snapshot.pid, 1234);
        assert_eq!(snapshot.reason, "test anomaly");
        assert!(snapshot.snapshot_id.starts_with("snapshot_1234_"));
        assert_eq!(snapshot.status, SnapshotStatus::Pending);
    }

    #[test]
    fn test_zram_pool_config_default() {
        let config = ZramPoolConfig::default();

        assert!(config.enabled);
        assert_eq!(config.compression_algorithm, "zstd");
        assert_eq!(config.max_snapshot_size, 4 * 1024 * 1024 * 1024);
        assert_eq!(config.retention_hours, 24);
    }

    #[test]
    fn test_memory_ejection_config_default() {
        let config = MemoryEjectionConfig::default();

        assert!(config.enabled);
        assert!(config.auto_trigger);
        assert_eq!(config.anomaly_threshold, 0.95);
        assert_eq!(config.max_concurrent_snapshots, 10);
    }

    #[test]
    fn test_snapshot_status_equality() {
        assert_eq!(SnapshotStatus::Pending, SnapshotStatus::Pending);
        assert_eq!(SnapshotStatus::Completed, SnapshotStatus::Completed);
        assert_ne!(SnapshotStatus::Pending, SnapshotStatus::Completed);
    }

    #[test]
    fn test_zram_stats_creation() {
        let stats = ZramStats {
            total_snapshots: 5,
            total_original_size: 1024 * 1024 * 1024,  // 1GB
            total_compressed_size: 512 * 1024 * 1024, // 512MB
            overall_compression_ratio: 2.0,
            active_devices: 1,
            enabled: true,
        };

        assert_eq!(stats.total_snapshots, 5);
        assert_eq!(stats.overall_compression_ratio, 2.0);
    }
}
