//! Pre-Cognitive cgroup v2 Clamping
//!
//! Predicts process crashes by analyzing log output derivatives (rate of change)
//! and clamps CPU/memory limits to prevent system damage.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Cgroup v2 controller types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupController {
    Cpu,
    Memory,
    CpuMemory, // Combined
}

impl std::fmt::Display for CgroupController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CgroupController::Cpu => write!(f, "cpu"),
            CgroupController::Memory => write!(f, "memory"),
            CgroupController::CpuMemory => write!(f, "cpu,memory"),
        }
    }
}

/// Process resource limits
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    pub cpu_max: Option<f64>,     // Percentage (0.0-100.0) or None for unlimited
    pub memory_max: Option<u64>,  // Bytes or None for unlimited
    pub cpu_weight: Option<u16>,  // Weight (1-10000) or None for default
    pub memory_swap: Option<u64>, // Swap limit or None for unlimited
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            cpu_max: None,
            memory_max: None,
            cpu_weight: None,
            memory_swap: None,
        }
    }
}

/// Process resource usage
#[derive(Debug, Clone)]
pub struct ResourceUsage {
    pub cpu_usage: f64,    // Percentage (0.0-100.0)
    pub memory_usage: u64, // Bytes
    pub memory_rss: u64,   // Resident Set Size
    pub timestamp: u64,    // Timestamp in seconds
}

/// Process clamping state
#[derive(Debug, Clone)]
pub struct ClampState {
    pub pid: u32,
    pub controller: CgroupController,
    pub limits: ResourceLimits,
    pub is_clamped: bool,
    pub clamp_level: f64, // 0.0 (no clamp) to 1.0 (fully clamped)
    pub reason: String,
    pub clamped_at: u64,
}

impl ClampState {
    pub fn new(pid: u32, controller: CgroupController) -> Self {
        Self {
            pid,
            controller,
            limits: ResourceLimits::default(),
            is_clamped: false,
            clamp_level: 0.0,
            reason: String::new(),
            clamped_at: 0,
        }
    }

    pub fn clamp(&mut self, limits: ResourceLimits, reason: &str, clamp_level: f64) {
        self.limits = limits;
        self.is_clamped = true;
        self.clamp_level = clamp_level.clamp(0.0, 1.0);
        self.reason = reason.to_string();
        self.clamped_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
    }

    pub fn unclamp(&mut self) {
        self.limits = ResourceLimits::default();
        self.is_clamped = false;
        self.clamp_level = 0.0;
        self.reason.clear();
    }
}

/// Cgroup v2 manager
pub struct CgroupManager {
    cgroup_root: PathBuf,
    clamps: Arc<Mutex<HashMap<u32, ClampState>>>,
    usage_history: Arc<Mutex<HashMap<u32, Vec<ResourceUsage>>>>,
}

impl CgroupManager {
    pub fn new(cgroup_root: impl AsRef<Path>) -> Self {
        Self {
            cgroup_root: cgroup_root.as_ref().to_path_buf(),
            clamps: Arc::new(Mutex::new(HashMap::new())),
            usage_history: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Get cgroup path for a PID
    pub fn get_cgroup_path(&self, pid: u32, controller: CgroupController) -> PathBuf {
        self.cgroup_root
            .join(format!("ccze_clamp_{}_{}", pid, controller))
    }

    /// Initialize cgroup for a PID
    pub fn initialize_cgroup(&self, pid: u32, controller: CgroupController) -> io::Result<()> {
        let cgroup_path = self.get_cgroup_path(pid, controller);

        // Create cgroup directory
        if !cgroup_path.exists() {
            std::fs::create_dir_all(&cgroup_path)?;
        }

        // Write cgroup.type
        self.write_cgroup_file(&cgroup_path, "cgroup.type", "domain")?;

        // Enable controllers
        self.write_cgroup_file(&cgroup_path, "cgroup.controllers", &controller.to_string())?;

        // Add PID to cgroup
        self.write_cgroup_file(&cgroup_path, "cgroup.procs", &pid.to_string())?;

        Ok(())
    }

    /// Write to a cgroup file
    fn write_cgroup_file(
        &self,
        cgroup_path: &Path,
        filename: &str,
        content: &str,
    ) -> io::Result<()> {
        let file_path = cgroup_path.join(filename);
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(file_path)?;
        file.write_all(content.as_bytes())?;
        Ok(())
    }

    /// Read from a cgroup file
    fn read_cgroup_file(&self, cgroup_path: &Path, filename: &str) -> io::Result<String> {
        let file_path = cgroup_path.join(filename);
        let mut file = File::open(file_path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        Ok(contents.trim().to_string())
    }

    /// Set CPU limit for a cgroup
    pub fn set_cpu_limit(&self, pid: u32, max_percent: f64) -> io::Result<()> {
        let cgroup_path = self.get_cgroup_path(pid, CgroupController::Cpu);

        if max_percent <= 0.0 {
            // No limit
            self.write_cgroup_file(&cgroup_path, "cpu.max", "max 100000")?;
        } else {
            // Convert percentage to cgroup format (cpu.max uses quota.period)
            let quota = (max_percent * 1000.0) as u64; // 100000 = 100%
            self.write_cgroup_file(&cgroup_path, "cpu.max", &format!("{} 100000", quota))?;
        }

        Ok(())
    }

    /// Set memory limit for a cgroup
    pub fn set_memory_limit(&self, pid: u32, max_bytes: u64) -> io::Result<()> {
        let cgroup_path = self.get_cgroup_path(pid, CgroupController::Memory);

        if max_bytes == 0 {
            // No limit
            self.write_cgroup_file(&cgroup_path, "memory.max", "max")?;
        } else {
            self.write_cgroup_file(&cgroup_path, "memory.max", &max_bytes.to_string())?;
        }

        Ok(())
    }

    /// Get current CPU usage for a PID
    pub fn get_cpu_usage(&self, pid: u32) -> io::Result<f64> {
        let cgroup_path = self.get_cgroup_path(pid, CgroupController::Cpu);

        // Read cpu.stat
        let _stat_content = self.read_cgroup_file(&cgroup_path, "cpu.stat")?;

        // Parse usage from stat file (simplified)
        // In real implementation, this would parse the actual format
        Ok(0.0) // Placeholder
    }

    /// Get current memory usage for a PID
    pub fn get_memory_usage(&self, pid: u32) -> io::Result<u64> {
        let cgroup_path = self.get_cgroup_path(pid, CgroupController::Memory);

        // Read memory.current
        let current_content = self.read_cgroup_file(&cgroup_path, "memory.current")?;
        current_content.parse::<u64>().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "Failed to parse memory.current")
        })
    }

    /// Record resource usage for a PID
    pub fn record_usage(&self, pid: u32, usage: ResourceUsage) {
        let mut history = self.usage_history.lock().unwrap();

        let entries = history.entry(pid).or_insert_with(Vec::new);
        entries.push(usage);

        // Keep only recent history (last 100 entries)
        if entries.len() > 100 {
            entries.remove(0);
        }
    }

    /// Get usage history for a PID
    pub fn get_usage_history(&self, pid: u32) -> Vec<ResourceUsage> {
        let history = self.usage_history.lock().unwrap();
        history.get(&pid).cloned().unwrap_or_default()
    }

    /// Calculate derivative (rate of change) for memory usage
    pub fn calculate_memory_derivative(&self, pid: u32) -> f64 {
        let history = self.get_usage_history(pid);

        if history.len() < 2 {
            return 0.0;
        }

        // Get last two entries
        let last = &history[history.len() - 1];
        let prev = &history[history.len() - 2];

        let time_diff = last.timestamp as f64 - prev.timestamp as f64;
        if time_diff <= 0.0 {
            return 0.0;
        }

        let memory_diff = last.memory_usage as f64 - prev.memory_usage as f64;
        memory_diff / time_diff
    }

    /// Calculate derivative for CPU usage
    pub fn calculate_cpu_derivative(&self, pid: u32) -> f64 {
        let history = self.get_usage_history(pid);

        if history.len() < 2 {
            return 0.0;
        }

        // Get last two entries
        let last = &history[history.len() - 1];
        let prev = &history[history.len() - 2];

        let time_diff = last.timestamp as f64 - prev.timestamp as f64;
        if time_diff <= 0.0 {
            return 0.0;
        }

        let cpu_diff = last.cpu_usage - prev.cpu_usage;
        cpu_diff / time_diff
    }

    /// Check if process is showing signs of runaway behavior
    pub fn is_runaway(&self, pid: u32, memory_threshold: f64, cpu_threshold: f64) -> bool {
        let memory_derivative = self.calculate_memory_derivative(pid);
        let cpu_derivative = self.calculate_cpu_derivative(pid);

        // Positive derivatives indicate increasing usage
        memory_derivative > memory_threshold || cpu_derivative > cpu_threshold
    }

    /// Clamp a process based on its behavior
    pub fn clamp_process(&self, pid: u32, reason: &str) -> io::Result<()> {
        let mut clamps = self.clamps.lock().unwrap();

        // Check if already clamped
        if let Some(state) = clamps.get_mut(&pid) {
            if state.is_clamped {
                return Ok(()); // Already clamped
            }
        }

        // Create clamp state
        let clamp_level = 0.01; // 1% limit
        let limits = ResourceLimits {
            cpu_max: Some(clamp_level * 100.0),
            memory_max: Some(1024 * 1024), // 1MB limit
            cpu_weight: None,
            memory_swap: None,
        };

        let mut state = ClampState::new(pid, CgroupController::CpuMemory);
        state.clamp(limits, reason, clamp_level);

        // Apply the limits
        self.set_cpu_limit(pid, clamp_level * 100.0)?;
        self.set_memory_limit(pid, 1024 * 1024)?;

        clamps.insert(pid, state);

        Ok(())
    }

    /// Unclamp a process
    pub fn unclamp_process(&self, pid: u32) -> io::Result<()> {
        let mut clamps = self.clamps.lock().unwrap();

        if let Some(state) = clamps.get_mut(&pid) {
            if state.is_clamped {
                // Remove limits
                self.set_cpu_limit(pid, 100.0)?; // Full CPU
                self.set_memory_limit(pid, 0)?; // No memory limit

                state.unclamp();
            }
        }

        Ok(())
    }

    /// Get current clamp state for a PID
    pub fn get_clamp_state(&self, pid: u32) -> Option<ClampState> {
        let clamps = self.clamps.lock().unwrap();
        clamps.get(&pid).cloned()
    }

    /// List all clamped processes
    pub fn list_clamped(&self) -> Vec<ClampState> {
        let clamps = self.clamps.lock().unwrap();
        clamps.values().cloned().collect()
    }

    /// Check if a PID is clamped
    pub fn is_clamped(&self, pid: u32) -> bool {
        let clamps = self.clamps.lock().unwrap();
        clamps.get(&pid).map(|s| s.is_clamped).unwrap_or(false)
    }
}

/// Cgroup clamping configuration
#[derive(Debug, Clone)]
pub struct CgroupConfig {
    pub enabled: bool,
    pub cgroup_root: PathBuf,
    pub memory_threshold: f64, // Derivative threshold for memory
    pub cpu_threshold: f64,    // Derivative threshold for CPU
    pub clamp_level: f64,      // Default clamp level (0.0-1.0)
    pub clamp_memory: u64,     // Memory limit when clamping (bytes)
    pub clamp_cpu: f64,        // CPU limit when clamping (percentage)
    pub max_history: usize,    // Maximum usage history to keep
}

impl Default for CgroupConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cgroup_root: PathBuf::from("/sys/fs/cgroup"),
            memory_threshold: 100.0,   // 100 MB/sec increase
            cpu_threshold: 50.0,       // 50% CPU increase per second
            clamp_level: 0.01,         // 1% resource limit
            clamp_memory: 1024 * 1024, // 1MB memory limit
            clamp_cpu: 1.0,            // 1% CPU limit
            max_history: 100,
        }
    }
}

/// Predictive clamping manager
pub struct PredictiveClamp {
    manager: CgroupManager,
    config: CgroupConfig,
}

impl PredictiveClamp {
    pub fn new(config: CgroupConfig) -> Self {
        Self {
            manager: CgroupManager::new(&config.cgroup_root),
            config,
        }
    }

    /// Monitor a process and clamp if necessary
    pub fn monitor_process(&self, pid: u32, usage: ResourceUsage) -> io::Result<bool> {
        if !self.config.enabled {
            return Ok(false);
        }

        // Record usage
        self.manager.record_usage(pid, usage);

        // Check if process is showing runaway behavior
        if self
            .manager
            .is_runaway(pid, self.config.memory_threshold, self.config.cpu_threshold)
        {
            let reason = format!(
                "Runaway detected: memory_derivative > {} or cpu_derivative > {}",
                self.config.memory_threshold, self.config.cpu_threshold
            );

            self.manager.clamp_process(pid, &reason)?;
            return Ok(true);
        }

        Ok(false)
    }

    /// Force clamp a process
    pub fn clamp(&self, pid: u32, reason: &str) -> io::Result<bool> {
        if !self.config.enabled {
            return Ok(false);
        }

        self.manager.clamp_process(pid, reason)?;
        Ok(true)
    }

    /// Release a clamped process
    pub fn release(&self, pid: u32) -> io::Result<bool> {
        self.manager.unclamp_process(pid)?;
        Ok(true)
    }

    /// Get clamping statistics
    pub fn get_stats(&self) -> HashMap<u32, ClampState> {
        let clamps = self.manager.clamps.lock().unwrap();
        clamps.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tempfile::tempdir;

    #[test]
    fn test_resource_limits_default() {
        let limits = ResourceLimits::default();

        assert!(limits.cpu_max.is_none());
        assert!(limits.memory_max.is_none());
        assert!(limits.cpu_weight.is_none());
        assert!(limits.memory_swap.is_none());
    }

    #[test]
    fn test_clamp_state_operations() {
        let mut state = ClampState::new(1234, CgroupController::Cpu);

        assert!(!state.is_clamped);
        assert_eq!(state.clamp_level, 0.0);

        let limits = ResourceLimits {
            cpu_max: Some(50.0),
            memory_max: Some(1024 * 1024),
            ..Default::default()
        };

        state.clamp(limits.clone(), "test", 0.5);

        assert!(state.is_clamped);
        assert_eq!(state.clamp_level, 0.5);
        assert_eq!(state.reason, "test");
        assert_eq!(state.limits.cpu_max, Some(50.0));
        assert_eq!(state.limits.memory_max, Some(1024 * 1024));

        state.unclamp();

        assert!(!state.is_clamped);
        assert_eq!(state.clamp_level, 0.0);
        assert!(state.reason.is_empty());
    }

    #[test]
    fn test_cgroup_config_default() {
        let config = CgroupConfig::default();

        assert!(config.enabled);
        assert_eq!(config.memory_threshold, 100.0);
        assert_eq!(config.cpu_threshold, 50.0);
        assert_eq!(config.clamp_level, 0.01);
    }

    #[test]
    fn test_usage_history() {
        let temp_dir = tempdir().unwrap();
        let manager = CgroupManager::new(temp_dir.path());

        let usage1 = ResourceUsage {
            cpu_usage: 10.0,
            memory_usage: 1024 * 1024,
            memory_rss: 512 * 1024,
            timestamp: 1000,
        };

        let usage2 = ResourceUsage {
            cpu_usage: 20.0,
            memory_usage: 2048 * 1024,
            memory_rss: 1024 * 1024,
            timestamp: 1001,
        };

        manager.record_usage(1234, usage1);
        manager.record_usage(1234, usage2);

        let history = manager.get_usage_history(1234);
        assert_eq!(history.len(), 2);
    }

    #[test]
    fn test_memory_derivative() {
        let temp_dir = tempdir().unwrap();
        let manager = CgroupManager::new(temp_dir.path());

        // Record two usage entries 1 second apart
        let usage1 = ResourceUsage {
            cpu_usage: 0.0,
            memory_usage: 1000,
            memory_rss: 500,
            timestamp: 1000,
        };

        let usage2 = ResourceUsage {
            cpu_usage: 0.0,
            memory_usage: 2000, // Increased by 1000 bytes
            memory_rss: 1000,
            timestamp: 1001, // 1 second later
        };

        manager.record_usage(1234, usage1);
        manager.record_usage(1234, usage2);

        let derivative = manager.calculate_memory_derivative(1234);
        assert!((derivative - 1000.0).abs() < 0.001);
    }

    #[test]
    fn test_runaway_detection() {
        let temp_dir = tempdir().unwrap();
        let manager = CgroupManager::new(temp_dir.path());

        // Record normal usage
        for i in 0..10 {
            let usage = ResourceUsage {
                cpu_usage: 10.0,
                memory_usage: 1000 * (i as u64 + 1),
                memory_rss: 500 * (i as u64 + 1),
                timestamp: 1000 + i,
            };
            manager.record_usage(1234, usage);
        }

        // Add a spike in memory usage
        let spike_usage = ResourceUsage {
            cpu_usage: 10.0,
            memory_usage: 1000000, // Big spike
            memory_rss: 500000,
            timestamp: 1010,
        };
        manager.record_usage(1234, spike_usage);

        let is_runaway = manager.is_runaway(1234, 100.0, 50.0);
        assert!(is_runaway);
    }
}
