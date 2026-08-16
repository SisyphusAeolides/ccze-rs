//! DKMS (Dynamic Kernel Module Support) Manager
//!
//! Provides functionality to manage kernel modules required by ccze-rs,
//! including XDP, zRAM, and custom eBPF modules.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Kernel module status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleStatus {
    /// Module is not loaded or available
    NotAvailable,
    /// Module is loaded and active
    Loaded,
    /// Module is available but not currently loaded
    Available,
    /// Module failed to load
    Failed,
    /// Module is blacklisted
    Blacklisted,
}

/// Kernel module information
#[derive(Debug, Clone)]
pub struct KernelModule {
    pub name: String,
    pub description: String,
    pub version: String,
    pub parameters: Vec<(String, String)>,
    pub dependencies: Vec<String>,
    pub status: ModuleStatus,
    pub last_checked: u64,
}

impl KernelModule {
    pub fn new(name: &str, description: &str) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            version: String::new(),
            parameters: Vec::new(),
            dependencies: Vec::new(),
            status: ModuleStatus::NotAvailable,
            last_checked: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        }
    }

    /// Check if module is currently loaded
    pub fn is_loaded(&self) -> bool {
        matches!(self.status, ModuleStatus::Loaded)
    }

    /// Check if module is available (loaded or can be loaded)
    pub fn is_available(&self) -> bool {
        matches!(self.status, ModuleStatus::Loaded | ModuleStatus::Available)
    }
}

/// DKMS configuration
#[derive(Debug, Clone)]
pub struct DkmsConfig {
    pub enabled: bool,
    pub auto_load: bool,
    pub modules: Vec<ModuleDefinition>,
    pub module_dir: PathBuf,
    pub dkms_command: String,
    pub modprobe_command: String,
    pub rmmod_command: String,
    pub lsmod_command: String,
}

impl Default for DkmsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_load: true,
            modules: vec![
                ModuleDefinition::new("xdp", "XDP (eXpress Data Path) support"),
                ModuleDefinition::new("zram", "Compressed RAM disk support"),
                ModuleDefinition::new("bpf", "eBPF support"),
            ],
            module_dir: PathBuf::from("/lib/modules"),
            dkms_command: "dkms".to_string(),
            modprobe_command: "modprobe".to_string(),
            rmmod_command: "rmmod".to_string(),
            lsmod_command: "lsmod".to_string(),
        }
    }
}

/// Module definition for DKMS
#[derive(Debug, Clone)]
pub struct ModuleDefinition {
    pub name: String,
    pub description: String,
    pub version: String,
    pub dkms_name: Option<String>,
    pub parameters: Vec<String>,
    pub dependencies: Vec<String>,
    pub required: bool,
}

impl ModuleDefinition {
    pub fn new(name: &str, description: &str) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            version: String::new(),
            dkms_name: None,
            parameters: Vec::new(),
            dependencies: Vec::new(),
            required: true,
        }
    }

    /// Create XDP module definition
    pub fn xdp() -> Self {
        let mut module = Self::new("xdp", "XDP (eXpress Data Path) support");
        module.version = "1.0".to_string();
        module.dependencies = vec!["bpf".to_string()];
        module.required = true;
        module
    }

    /// Create zRAM module definition
    pub fn zram() -> Self {
        let mut module = Self::new("zram", "Compressed RAM disk support");
        module.version = "1.0".to_string();
        module.parameters = vec!["num_devices=32".to_string()];
        module.required = true;
        module
    }

    /// Create eBPF module definition
    pub fn bpf() -> Self {
        let mut module = Self::new("bpf", "eBPF support");
        module.version = "1.0".to_string();
        module.required = true;
        module
    }
}

/// DKMS manager
pub struct DkmsManager {
    config: DkmsConfig,
    modules: Arc<Mutex<HashMap<String, KernelModule>>>,
}

impl DkmsManager {
    pub fn new(config: DkmsConfig) -> Self {
        Self {
            config,
            modules: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Initialize DKMS manager and check all required modules
    pub fn initialize(&self) -> Result<(), String> {
        if !self.config.enabled {
            return Ok(());
        }

        // Check if DKMS is available
        if self.is_dkms_available()? {
            // For each module definition, check its status
            for module_def in &self.config.modules {
                let module = self.check_module(&module_def.name)?;
                let mut modules = self.modules.lock().unwrap();
                modules.insert(module_def.name.clone(), module);
            }
        } else {
            // DKMS not available, try modprobe
            for module_def in &self.config.modules {
                let module = self.check_module_with_modprobe(&module_def.name)?;
                let mut modules = self.modules.lock().unwrap();
                modules.insert(module_def.name.clone(), module);
            }
        }

        Ok(())
    }

    /// Check if DKMS is available on the system
    pub fn is_dkms_available(&self) -> Result<bool, String> {
        let output = Command::new(&self.config.dkms_command)
            .arg("--version")
            .output()
            .map_err(|e| format!("Failed to check DKMS: {}", e))?;

        Ok(output.status.success())
    }

    /// Check if a kernel module is loaded
    pub fn is_module_loaded(&self, module_name: &str) -> Result<bool, String> {
        let output = Command::new(&self.config.lsmod_command)
            .output()
            .map_err(|e| format!("Failed to check module {}: {}", module_name, e))?;
        if !output.status.success() {
            return Ok(false);
        }
        Ok(String::from_utf8_lossy(&output.stdout)
            .lines()
            .skip(1)
            .filter_map(|line| line.split_whitespace().next())
            .any(|loaded| loaded == module_name))
    }

    /// Check if a kernel module is available (can be loaded)
    pub fn is_module_available(&self, module_name: &str) -> Result<bool, String> {
        let output = Command::new("modinfo")
            .arg(module_name)
            .output()
            .map_err(|e| format!("Failed to check module {} availability: {}", module_name, e))?;

        Ok(output.status.success())
    }

    /// Check module status
    pub fn check_module(&self, module_name: &str) -> Result<KernelModule, String> {
        let mut module = KernelModule::new(module_name, "");

        // Check if module is loaded
        if self.is_module_loaded(module_name)? {
            module.status = ModuleStatus::Loaded;
            return Ok(module);
        }

        // Check if module is available
        if self.is_module_available(module_name)? {
            module.status = ModuleStatus::Available;
            return Ok(module);
        }

        // Check if module is blacklisted
        if self.is_module_blacklisted(module_name)? {
            module.status = ModuleStatus::Blacklisted;
            return Ok(module);
        }

        module.status = ModuleStatus::NotAvailable;
        Ok(module)
    }

    /// Check module using modprobe
    pub fn check_module_with_modprobe(&self, module_name: &str) -> Result<KernelModule, String> {
        let mut module = KernelModule::new(module_name, "");

        // Try to load the module
        let output = Command::new(&self.config.modprobe_command)
            .args(["--dry-run", module_name])
            .output();

        match output {
            Ok(output) if output.status.success() => {
                // Module can be loaded
                if self.is_module_loaded(module_name)? {
                    module.status = ModuleStatus::Loaded;
                } else {
                    module.status = ModuleStatus::Available;
                }
            }
            _ => {
                // Check if module exists
                let info_output = Command::new("modinfo")
                    .arg(module_name)
                    .output()
                    .map_err(|_| ());

                if info_output.is_ok_and(|output| output.status.success()) {
                    module.status = ModuleStatus::Available;
                } else {
                    module.status = ModuleStatus::NotAvailable;
                }
            }
        }

        Ok(module)
    }

    /// Check if a module is blacklisted
    pub fn is_module_blacklisted(&self, module_name: &str) -> Result<bool, String> {
        // Check /etc/modprobe.d/ for blacklist entries
        let modprobe_dir = Path::new("/etc/modprobe.d");

        if modprobe_dir.exists() {
            for entry in fs::read_dir(modprobe_dir)
                .map_err(|e| format!("Failed to read modprobe.d: {}", e))?
            {
                let entry = entry.map_err(|e| format!("Failed to read dir entry: {}", e))?;
                let path = entry.path();

                if let Ok(contents) = fs::read_to_string(&path) {
                    if contents.contains(&format!("blacklist {}", module_name))
                        || contents.contains(&format!("install {} /bin/true", module_name))
                        || contents.contains(&format!("install {} /bin/false", module_name))
                    {
                        return Ok(true);
                    }
                }
            }
        }

        // Check /etc/modprobe.conf
        let modprobe_conf = Path::new("/etc/modprobe.conf");
        if modprobe_conf.exists() {
            if let Ok(contents) = fs::read_to_string(modprobe_conf) {
                if contents.contains(&format!("blacklist {}", module_name)) {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Load a kernel module
    pub fn load_module(&self, module_name: &str) -> Result<bool, String> {
        if !self.config.enabled {
            return Ok(false);
        }

        // Check if already loaded
        if self.is_module_loaded(module_name)? {
            return Ok(true);
        }

        // Try modprobe first
        let output = Command::new(&self.config.modprobe_command)
            .arg(module_name)
            .output()
            .map_err(|e| format!("Failed to load module {}: {}", module_name, e))?;

        if output.status.success() {
            // Verify it loaded
            return Ok(self.is_module_loaded(module_name)?);
        }

        // Try DKMS if available
        if self.is_dkms_available()? {
            let output = Command::new(&self.config.dkms_command)
                .args(["install", "-m", module_name, "-v", "auto"])
                .output();

            if let Ok(output) = output {
                if output.status.success() {
                    return Ok(self.is_module_loaded(module_name)?);
                }
            }
        }

        Ok(false)
    }

    /// Load a module with parameters
    pub fn load_module_with_params(
        &self,
        module_name: &str,
        params: &[&str],
    ) -> Result<bool, String> {
        if !self.config.enabled {
            return Ok(false);
        }

        // Check if already loaded
        if self.is_module_loaded(module_name)? {
            return Ok(true);
        }

        let output = Command::new(&self.config.modprobe_command)
            .arg(module_name)
            .args(params)
            .output()
            .map_err(|e| format!("Failed to load module {}: {}", module_name, e))?;

        if output.status.success() {
            return Ok(self.is_module_loaded(module_name)?);
        }

        Ok(false)
    }

    /// Unload a kernel module
    pub fn unload_module(&self, module_name: &str) -> Result<bool, String> {
        if !self.config.enabled {
            return Ok(false);
        }

        // Check if loaded
        if !self.is_module_loaded(module_name)? {
            return Ok(true); // Already unloaded
        }

        let output = Command::new(&self.config.rmmod_command)
            .arg(module_name)
            .output()
            .map_err(|e| format!("Failed to unload module {}: {}", module_name, e))?;

        Ok(output.status.success())
    }

    /// Reload a kernel module
    pub fn reload_module(&self, module_name: &str) -> Result<bool, String> {
        self.unload_module(module_name)?;
        self.load_module(module_name)
    }

    /// Get module information
    pub fn get_module_info(&self, module_name: &str) -> Result<Option<KernelModule>, String> {
        let modules = self.modules.lock().unwrap();
        Ok(modules.get(module_name).cloned())
    }

    /// List all managed modules and their status
    pub fn list_modules(&self) -> Vec<KernelModule> {
        let modules = self.modules.lock().unwrap();
        modules.values().cloned().collect()
    }

    /// Ensure all required modules are loaded
    pub fn ensure_required_modules(&self) -> Result<Vec<String>, String> {
        let mut failed_modules = Vec::new();

        for module_def in &self.config.modules {
            if module_def.required {
                let loaded = self.load_module(&module_def.name)?;
                if !loaded {
                    failed_modules.push(module_def.name.clone());
                }
            }
        }

        if failed_modules.is_empty() {
            Ok(failed_modules)
        } else {
            Err(format!(
                "Failed to load required modules: {:?}",
                failed_modules
            ))
        }
    }

    /// Get DKMS status for all modules
    pub fn get_status(&self) -> DkmsStatus {
        let modules = self.modules.lock().unwrap();

        let total = modules.len();
        let loaded = modules.values().filter(|m| m.is_loaded()).count();
        let available = modules.values().filter(|m| m.is_available()).count();
        let failed = modules
            .values()
            .filter(|m| matches!(m.status, ModuleStatus::Failed))
            .count();

        DkmsStatus {
            enabled: self.config.enabled,
            dkms_available: self.is_dkms_available().unwrap_or(false),
            total_modules: total,
            loaded_modules: loaded,
            available_modules: available,
            failed_modules: failed,
        }
    }

    /// Install DKMS module from source
    pub fn install_dkms_module(
        &self,
        source_dir: &Path,
        module_name: &str,
    ) -> Result<bool, String> {
        if !self.config.enabled {
            return Ok(false);
        }

        if !self.is_dkms_available()? {
            return Err("DKMS not available on this system".to_string());
        }

        let output = Command::new(&self.config.dkms_command)
            .args(["install", "-m", module_name, "-v", "1.0", "-s"])
            .arg(source_dir)
            .output()
            .map_err(|e| format!("Failed to install DKMS module: {}", e))?;

        Ok(output.status.success())
    }

    /// Remove DKMS module
    pub fn remove_dkms_module(&self, module_name: &str, version: &str) -> Result<bool, String> {
        if !self.config.enabled {
            return Ok(false);
        }

        if !self.is_dkms_available()? {
            return Err("DKMS not available on this system".to_string());
        }

        let output = Command::new(&self.config.dkms_command)
            .args(["remove", "-m", module_name, "-v", version, "--all"])
            .output()
            .map_err(|e| format!("Failed to remove DKMS module: {}", e))?;

        Ok(output.status.success())
    }

    /// Build DKMS module
    pub fn build_dkms_module(&self, module_name: &str, version: &str) -> Result<bool, String> {
        if !self.config.enabled {
            return Ok(false);
        }

        if !self.is_dkms_available()? {
            return Err("DKMS not available on this system".to_string());
        }

        let output = Command::new(&self.config.dkms_command)
            .args(["build", "-m", module_name, "-v", version])
            .output()
            .map_err(|e| format!("Failed to build DKMS module: {}", e))?;

        Ok(output.status.success())
    }

    /// Check if a specific kernel version has the required module built-in
    pub fn has_builtin_module(&self, module_name: &str) -> Result<bool, String> {
        let output = Command::new("uname")
            .arg("-r")
            .output()
            .map_err(|e| format!("Failed to get kernel version: {}", e))?;

        if !output.status.success() {
            return Err("Failed to get kernel version".to_string());
        }

        let kernel_version = String::from_utf8_lossy(&output.stdout).trim().to_string();

        // Check /boot/config-* for the module
        let config_path = Path::new("/boot").join(format!("config-{}", kernel_version));

        if config_path.exists() {
            if let Ok(config) = fs::read_to_string(&config_path) {
                return Ok(
                    config.contains(&format!("CONFIG_{}=y", module_name.to_uppercase()))
                        || config.contains(&format!("CONFIG_{}=m", module_name.to_uppercase())),
                );
            }
        }

        // Fallback: check if module can be loaded
        Ok(self.is_module_available(module_name)?)
    }
}

/// DKMS status
#[derive(Debug, Clone)]
pub struct DkmsStatus {
    pub enabled: bool,
    pub dkms_available: bool,
    pub total_modules: usize,
    pub loaded_modules: usize,
    pub available_modules: usize,
    pub failed_modules: usize,
}

/// XDP-specific DKMS manager
pub struct XdpDkmsManager {
    dkms: DkmsManager,
    xdp_modules: Vec<String>,
}

impl XdpDkmsManager {
    pub fn new(dkms: DkmsManager) -> Self {
        Self {
            dkms,
            xdp_modules: vec![
                "xdp_diag".to_string(),
                "xdp_socket".to_string(),
                "bpf".to_string(),
            ],
        }
    }

    /// Ensure XDP-related modules are loaded
    pub fn ensure_xdp_modules(&self) -> Result<Vec<String>, String> {
        let mut failed = Vec::new();

        for module in &self.xdp_modules {
            if !self.dkms.load_module(module)? {
                failed.push(module.clone());
            }
        }

        if failed.is_empty() {
            Ok(failed)
        } else {
            Err(format!("Failed to load XDP modules: {:?}", failed))
        }
    }

    /// Check if XDP is ready
    pub fn is_xdp_ready(&self) -> Result<bool, String> {
        for module in &self.xdp_modules {
            if !self.dkms.is_module_loaded(module)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Load XDP with specific parameters
    pub fn load_xdp_with_params(&self, params: &[&str]) -> Result<bool, String> {
        self.dkms.load_module_with_params("xdp", params)
    }
}

/// zRAM-specific DKMS manager
pub struct ZramDkmsManager {
    dkms: DkmsManager,
}

impl ZramDkmsManager {
    pub fn new(dkms: DkmsManager) -> Self {
        Self { dkms }
    }

    /// Ensure zRAM module is loaded
    pub fn ensure_zram(&self) -> Result<bool, String> {
        self.dkms.load_module("zram")
    }

    /// Load zRAM with specific parameters
    pub fn load_zram_with_params(&self, num_devices: u32) -> Result<bool, String> {
        self.dkms
            .load_module_with_params("zram", &[&format!("num_devices={}", num_devices)])
    }

    /// Create zRAM devices
    pub fn create_zram_devices(&self, count: u32) -> Result<bool, String> {
        if !self.ensure_zram()? {
            return Ok(false);
        }

        // Create zram devices via sysfs
        let base_path = Path::new("/sys/class/zram-control");

        if !base_path.exists() {
            return Err("zram-control not available".to_string());
        }

        // Create the requested number of devices
        for i in 0..count {
            let device_path = Path::new("/sys/class/zram-control").join(format!("hot_add"));
            if let Ok(mut file) = OpenOptions::new().write(true).open(&device_path) {
                if let Err(e) = writeln!(file, "{}", i) {
                    return Err(format!("Failed to create zram device {}: {}", i, e));
                }
            } else {
                return Err(format!("Failed to open zram-control for device {}", i));
            }
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_status() {
        assert!(ModuleStatus::Loaded != ModuleStatus::NotAvailable);
        assert!(ModuleStatus::Available != ModuleStatus::Blacklisted);
    }

    #[test]
    fn test_kernel_module_creation() {
        let module = KernelModule::new("test_module", "Test module");

        assert_eq!(module.name, "test_module");
        assert_eq!(module.description, "Test module");
        assert!(!module.is_loaded());
        assert!(!module.is_available());
    }

    #[test]
    fn test_module_definition_creation() {
        let module = ModuleDefinition::new("xdp", "XDP support");

        assert_eq!(module.name, "xdp");
        assert_eq!(module.description, "XDP support");
        assert!(module.required);
    }

    #[test]
    fn test_module_definition_xdp() {
        let module = ModuleDefinition::xdp();

        assert_eq!(module.name, "xdp");
        assert_eq!(module.description, "XDP (eXpress Data Path) support");
        assert!(module.dependencies.contains(&"bpf".to_string()));
    }

    #[test]
    fn test_module_definition_zram() {
        let module = ModuleDefinition::zram();

        assert_eq!(module.name, "zram");
        assert_eq!(module.description, "Compressed RAM disk support");
        assert!(!module.parameters.is_empty());
    }

    #[test]
    fn test_dkms_config_default() {
        let config = DkmsConfig::default();

        assert!(config.enabled);
        assert!(config.auto_load);
        assert!(!config.modules.is_empty());
        assert_eq!(config.modprobe_command, "modprobe");
    }

    #[test]
    fn test_dkms_status() {
        let status = DkmsStatus {
            enabled: true,
            dkms_available: true,
            total_modules: 3,
            loaded_modules: 2,
            available_modules: 3,
            failed_modules: 0,
        };

        assert!(status.enabled);
        assert!(status.dkms_available);
        assert_eq!(status.loaded_modules, 2);
    }

    #[test]
    fn test_xdp_dkms_manager() {
        let config = DkmsConfig::default();
        let dkms = DkmsManager::new(config);
        let xdp_dkms = XdpDkmsManager::new(dkms);

        assert_eq!(xdp_dkms.xdp_modules.len(), 3);
        assert!(xdp_dkms.xdp_modules.contains(&"xdp_diag".to_string()));
    }

    #[test]
    fn test_zram_dkms_manager() {
        let config = DkmsConfig::default();
        let dkms = DkmsManager::new(config);
        let zram_dkms = ZramDkmsManager::new(dkms);

        // Test that it can be created
        assert!(zram_dkms.dkms.config.enabled);
    }
}
