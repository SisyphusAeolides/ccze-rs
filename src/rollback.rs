//! Transactional Boot Rollback Triggers
//!
//! Connects system diagnostics to immutable package management to provide
//! automatic rollback on critical system failures detected through log analysis.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::Command;
use std::process::Output;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Rollback trigger types
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RollbackTriggerType {
    /// Critical binary entropy spike detected
    BinaryEntropySpike,
    /// System service crash
    ServiceCrash,
    /// Kernel panic detected
    KernelPanic,
    /// Boot failure detected
    BootFailure,
    /// Package corruption detected
    PackageCorruption,
    /// Critical security vulnerability detected
    SecurityVulnerability,
    /// Configuration corruption detected
    ConfigCorruption,
}

impl std::fmt::Display for RollbackTriggerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RollbackTriggerType::BinaryEntropySpike => write!(f, "binary_entropy_spike"),
            RollbackTriggerType::ServiceCrash => write!(f, "service_crash"),
            RollbackTriggerType::KernelPanic => write!(f, "kernel_panic"),
            RollbackTriggerType::BootFailure => write!(f, "boot_failure"),
            RollbackTriggerType::PackageCorruption => write!(f, "package_corruption"),
            RollbackTriggerType::SecurityVulnerability => write!(f, "security_vulnerability"),
            RollbackTriggerType::ConfigCorruption => write!(f, "config_corruption"),
        }
    }
}

/// Rollback state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollbackState {
    /// System is in normal state
    Normal,
    /// Rollback has been triggered but not yet executed
    Triggered,
    /// Rollback is in progress
    InProgress,
    /// Rollback has been completed
    Completed,
    /// Rollback failed
    Failed,
}

/// Rollback trigger record
#[derive(Debug, Clone)]
pub struct RollbackTrigger {
    pub trigger_type: RollbackTriggerType,
    pub severity: f64,
    pub timestamp: u64,
    pub affected_packages: Vec<String>,
    pub affected_services: Vec<String>,
    pub description: String,
    pub state: RollbackState,
    pub rollback_target: String,
}

impl RollbackTrigger {
    pub fn new(trigger_type: RollbackTriggerType, severity: f64, description: &str) -> Self {
        Self {
            trigger_type,
            severity,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            affected_packages: Vec::new(),
            affected_services: Vec::new(),
            description: description.to_string(),
            state: RollbackState::Triggered,
            rollback_target: String::new(),
        }
    }
}

/// Transactional update state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateState {
    /// No update in progress
    Idle,
    /// Update is being downloaded
    Downloading,
    /// Update is being installed
    Installing,
    /// Update is ready to be activated
    Ready,
    /// Update has been activated
    Activated,
    /// Rollback has been triggered
    Rollback,
}

/// Package manager types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageManager {
    /// RPM-based systems (Fedora, RHEL, etc.)
    Rpm,
    /// DEB-based systems (Debian, Ubuntu, etc.)
    Deb,
    /// Arch Linux
    Pacman,
    /// openSUSE
    Zypper,
    /// NixOS
    Nix,
    /// Flatpak
    Flatpak,
    /// Snap
    Snap,
    /// Docker containers
    Docker,
    /// Transactional Update (openSUSE)
    TransactionalUpdate,
}

impl std::fmt::Display for PackageManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PackageManager::Rpm => write!(f, "rpm"),
            PackageManager::Deb => write!(f, "deb"),
            PackageManager::Pacman => write!(f, "pacman"),
            PackageManager::Zypper => write!(f, "zypper"),
            PackageManager::Nix => write!(f, "nix"),
            PackageManager::Flatpak => write!(f, "flatpak"),
            PackageManager::Snap => write!(f, "snap"),
            PackageManager::Docker => write!(f, "docker"),
            PackageManager::TransactionalUpdate => write!(f, "transactional-update"),
        }
    }
}

/// Package manager configuration
#[derive(Debug, Clone)]
pub struct PackageManagerConfig {
    pub package_manager: PackageManager,
    pub rollback_command: String,
    pub status_command: String,
    pub update_command: String,
    pub recovery_command: String,
}

impl Default for PackageManagerConfig {
    fn default() -> Self {
        Self {
            package_manager: PackageManager::Rpm,
            rollback_command: "transactional-update rollback".to_string(),
            status_command: "transactional-update status".to_string(),
            update_command: "transactional-update dup".to_string(),
            recovery_command: "systemctl reboot --boot-loader-entry=recovery".to_string(),
        }
    }
}

/// System entropy thresholds
#[derive(Debug, Clone)]
pub struct SystemEntropyThresholds {
    pub binary_entropy: f64,  // Threshold for binary entropy spike
    pub service_entropy: f64, // Threshold for service log entropy
    pub boot_entropy: f64,    // Threshold for boot process entropy
    pub config_entropy: f64,  // Threshold for config file entropy
}

impl Default for SystemEntropyThresholds {
    fn default() -> Self {
        Self {
            binary_entropy: 0.95,
            service_entropy: 0.90,
            boot_entropy: 0.85,
            config_entropy: 0.80,
        }
    }
}

/// Rollback configuration
#[derive(Debug, Clone)]
pub struct RollbackConfig {
    pub enabled: bool,
    pub package_manager: PackageManagerConfig,
    pub thresholds: SystemEntropyThresholds,
    pub auto_rollback: bool,
    pub max_rollback_attempts: u32,
    pub recovery_timeout: u64, // Seconds to wait before forcing recovery
}

impl Default for RollbackConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            package_manager: PackageManagerConfig::default(),
            thresholds: SystemEntropyThresholds::default(),
            auto_rollback: true,
            max_rollback_attempts: 3,
            recovery_timeout: 300, // 5 minutes
        }
    }
}

/// Transactional rollback manager
pub struct RollbackManager {
    config: RollbackConfig,
    triggers: Arc<Mutex<Vec<RollbackTrigger>>>,
    current_state: Arc<Mutex<UpdateState>>,
    rollback_attempts: Arc<Mutex<u32>>,
}

impl RollbackManager {
    pub fn new(config: RollbackConfig) -> Self {
        Self {
            config,
            triggers: Arc::new(Mutex::new(Vec::new())),
            current_state: Arc::new(Mutex::new(UpdateState::Idle)),
            rollback_attempts: Arc::new(Mutex::new(0)),
        }
    }

    /// Detect system state and check if rollback is needed
    pub fn detect_and_trigger(&self, trigger: RollbackTrigger) -> Result<bool, String> {
        if !self.config.enabled {
            return Ok(false);
        }

        // Check if we should auto-trigger rollback
        if self.config.auto_rollback
            && trigger.severity >= self.get_threshold_for_trigger(&trigger.trigger_type)
        {
            return self.trigger_rollback(trigger);
        }

        Ok(false)
    }

    /// Get the appropriate threshold for a trigger type
    fn get_threshold_for_trigger(&self, trigger_type: &RollbackTriggerType) -> f64 {
        match trigger_type {
            RollbackTriggerType::BinaryEntropySpike => self.config.thresholds.binary_entropy,
            RollbackTriggerType::ServiceCrash => self.config.thresholds.service_entropy,
            RollbackTriggerType::KernelPanic => 1.0, // Always trigger for kernel panic
            RollbackTriggerType::BootFailure => 1.0, // Always trigger for boot failure
            RollbackTriggerType::PackageCorruption => 1.0, // Always trigger for corruption
            RollbackTriggerType::SecurityVulnerability => 0.95,
            RollbackTriggerType::ConfigCorruption => self.config.thresholds.config_entropy,
        }
    }

    /// Trigger a rollback
    pub fn trigger_rollback(&self, trigger: RollbackTrigger) -> Result<bool, String> {
        let mut state = self.current_state.lock().map_err(|e| e.to_string())?;
        let mut attempts = self.rollback_attempts.lock().map_err(|e| e.to_string())?;

        // Check if we've exceeded max attempts
        if *attempts >= self.config.max_rollback_attempts {
            return Err("Maximum rollback attempts exceeded".to_string());
        }

        // Record the trigger
        self.record_trigger(trigger.clone())?;

        // Execute the rollback command
        let result = self.execute_rollback(&trigger)?;

        if result {
            *state = UpdateState::Rollback;
            *attempts += 1;
            Ok(true)
        } else {
            Err("Rollback execution failed".to_string())
        }
    }

    /// Record a rollback trigger
    pub fn record_trigger(&self, trigger: RollbackTrigger) -> Result<(), String> {
        let mut triggers = self.triggers.lock().map_err(|e| e.to_string())?;
        triggers.push(trigger);
        Ok(())
    }

    /// Execute the actual rollback
    fn execute_rollback(&self, trigger: &RollbackTrigger) -> Result<bool, String> {
        // Execute the rollback command based on the package manager
        let output = run_configured(&self.config.package_manager.rollback_command)
            .map_err(|e| format!("Failed to execute rollback: {e}"))?;

        if output.status.success() {
            // Log the rollback
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open("/var/log/ccze-rollback.log")
                .ok();

            if let Some(mut file) = file {
                let _ = writeln!(
                    file,
                    "{}: Rolled back due to: {}",
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                    trigger.description
                );
            }

            Ok(true)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("Rollback failed: {}", stderr))
        }
    }

    /// Check current system state
    pub fn check_system_state(&self) -> Result<UpdateState, String> {
        let state = self.current_state.lock().map_err(|e| e.to_string())?;
        Ok(state.clone())
    }

    /// Get the current generation (for immutable systems)
    pub fn get_current_generation(&self) -> Result<String, String> {
        // Read from transactional-update or similar
        let output = run_configured(&self.config.package_manager.status_command)
            .map_err(|e| format!("Failed to check status: {e}"))?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            Ok(stdout.to_string())
        } else {
            Err("Failed to get current generation".to_string())
        }
    }

    /// Force system recovery
    pub fn force_recovery(&self) -> Result<bool, String> {
        // Execute the recovery command
        let output = run_configured(&self.config.package_manager.recovery_command)
            .map_err(|e| format!("Failed to execute recovery: {e}"))?;

        Ok(output.status.success())
    }

    /// List all rollback triggers
    pub fn list_triggers(&self) -> Result<Vec<RollbackTrigger>, String> {
        let triggers = self.triggers.lock().map_err(|e| e.to_string())?;
        Ok(triggers.clone())
    }

    /// Clear rollback triggers
    pub fn clear_triggers(&self) -> Result<(), String> {
        let mut triggers = self.triggers.lock().map_err(|e| e.to_string())?;
        triggers.clear();
        Ok(())
    }

    /// Get rollback statistics
    pub fn get_stats(&self) -> RollbackStats {
        let triggers = self.triggers.lock().unwrap();
        let state = self.current_state.lock().unwrap();
        let attempts = self.rollback_attempts.lock().unwrap();

        let total_triggers = triggers.len() as u64;
        let critical_triggers = triggers.iter().filter(|t| t.severity >= 0.9).count() as u64;

        RollbackStats {
            total_triggers,
            critical_triggers,
            current_state: state.clone(),
            rollback_attempts: *attempts,
            enabled: self.config.enabled,
            auto_rollback: self.config.auto_rollback,
        }
    }
}

fn run_configured(command: &str) -> Result<Output, String> {
    let mut words = command.split_whitespace();
    let program = words
        .next()
        .ok_or_else(|| "configured command is empty".to_string())?;
    Command::new(program)
        .args(words)
        .output()
        .map_err(|error| error.to_string())
}

/// Rollback statistics
#[derive(Debug, Clone)]
pub struct RollbackStats {
    pub total_triggers: u64,
    pub critical_triggers: u64,
    pub current_state: UpdateState,
    pub rollback_attempts: u32,
    pub enabled: bool,
    pub auto_rollback: bool,
}

/// Binary entropy checker
pub struct BinaryEntropyChecker {
    known_good_hashes: HashMap<String, String>,
    baseline_entropy: f64,
}

impl BinaryEntropyChecker {
    pub fn new(baseline_entropy: f64) -> Self {
        Self {
            known_good_hashes: HashMap::new(),
            baseline_entropy,
        }
    }

    /// Load known good hashes from file
    pub fn load_known_good_hashes(&mut self, path: &Path) -> io::Result<()> {
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        for line in contents.lines() {
            let parts: Vec<&str> = line.split(':').map(|s| s.trim()).collect();
            if parts.len() == 2 {
                self.known_good_hashes
                    .insert(parts[0].to_string(), parts[1].to_string());
            }
        }

        Ok(())
    }

    /// Check binary entropy against baseline
    pub fn check_binary_entropy(&self, _binary_path: &Path, current_entropy: f64) -> bool {
        let deviation = (current_entropy - self.baseline_entropy).abs();
        deviation > (1.0 - self.baseline_entropy) // Threshold calculation
    }

    /// Check if binary hash matches known good hash
    pub fn is_known_good(&self, binary_path: &str, hash: &str) -> bool {
        self.known_good_hashes.get(binary_path) == Some(&hash.to_string())
    }
}

/// System health monitor
pub struct SystemHealthMonitor {
    rollback_manager: RollbackManager,
    entropy_checker: BinaryEntropyChecker,
}

impl SystemHealthMonitor {
    pub fn new(config: RollbackConfig) -> Self {
        Self {
            rollback_manager: RollbackManager::new(config),
            entropy_checker: BinaryEntropyChecker::new(0.85),
        }
    }

    /// Monitor system health and trigger rollback if needed
    pub fn monitor(&self, binary_path: &str, hash: &str, entropy: f64) -> Result<bool, String> {
        // Check if binary is known good
        if self.entropy_checker.is_known_good(binary_path, hash) {
            return Ok(false);
        }

        // Check if entropy is too high
        if self
            .entropy_checker
            .check_binary_entropy(Path::new(binary_path), entropy)
        {
            let trigger = RollbackTrigger::new(
                RollbackTriggerType::BinaryEntropySpike,
                entropy,
                &format!("High entropy detected in {}: {}", binary_path, entropy),
            );

            return self.rollback_manager.detect_and_trigger(trigger);
        }

        Ok(false)
    }

    /// Monitor service health
    pub fn monitor_service(&self, service_name: &str, entropy: f64) -> Result<bool, String> {
        if entropy > 0.9 {
            let trigger = RollbackTrigger::new(
                RollbackTriggerType::ServiceCrash,
                entropy,
                &format!(
                    "High log entropy detected in service {}: {}",
                    service_name, entropy
                ),
            );

            return self.rollback_manager.detect_and_trigger(trigger);
        }

        Ok(false)
    }

    /// Force rollback
    pub fn force_rollback(&self, reason: &str) -> Result<bool, String> {
        let trigger = RollbackTrigger::new(RollbackTriggerType::ConfigCorruption, 1.0, reason);

        self.rollback_manager.trigger_rollback(trigger)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rollback_trigger_creation() {
        let trigger = RollbackTrigger::new(
            RollbackTriggerType::BinaryEntropySpike,
            0.95,
            "Test entropy spike",
        );

        assert_eq!(
            trigger.trigger_type,
            RollbackTriggerType::BinaryEntropySpike
        );
        assert_eq!(trigger.severity, 0.95);
        assert_eq!(trigger.description, "Test entropy spike");
        assert_eq!(trigger.state, RollbackState::Triggered);
    }

    #[test]
    fn test_rollback_trigger_display() {
        assert_eq!(
            format!("{}", RollbackTriggerType::BinaryEntropySpike),
            "binary_entropy_spike"
        );
        assert_eq!(
            format!("{}", RollbackTriggerType::ServiceCrash),
            "service_crash"
        );
    }

    #[test]
    fn test_update_state_equality() {
        assert_eq!(UpdateState::Idle, UpdateState::Idle);
        assert_eq!(UpdateState::Rollback, UpdateState::Rollback);
        assert_ne!(UpdateState::Idle, UpdateState::Rollback);
    }

    #[test]
    fn test_package_manager_display() {
        assert_eq!(format!("{}", PackageManager::Rpm), "rpm");
        assert_eq!(format!("{}", PackageManager::Deb), "deb");
    }

    #[test]
    fn test_rollback_config_default() {
        let config = RollbackConfig::default();

        assert!(config.enabled);
        assert!(config.auto_rollback);
        assert_eq!(config.max_rollback_attempts, 3);
        assert_eq!(config.recovery_timeout, 300);
    }

    #[test]
    fn test_system_entropy_thresholds_default() {
        let thresholds = SystemEntropyThresholds::default();

        assert_eq!(thresholds.binary_entropy, 0.95);
        assert_eq!(thresholds.service_entropy, 0.90);
        assert_eq!(thresholds.boot_entropy, 0.85);
        assert_eq!(thresholds.config_entropy, 0.80);
    }

    #[test]
    fn test_rollback_stats() {
        let stats = RollbackStats {
            total_triggers: 5,
            critical_triggers: 2,
            current_state: UpdateState::Idle,
            rollback_attempts: 1,
            enabled: true,
            auto_rollback: true,
        };

        assert_eq!(stats.total_triggers, 5);
        assert_eq!(stats.critical_triggers, 2);
        assert_eq!(stats.rollback_attempts, 1);
    }
}
