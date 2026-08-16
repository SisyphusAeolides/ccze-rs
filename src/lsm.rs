//! Linux Security Module (LSM) Framework
//!
//! Provides policy evaluation and observation helpers for Linux Security
//! Module state. Kernel enforcement requires a separately provisioned module.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::raw::c_char;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::dkms::{DkmsConfig, DkmsManager, ModuleDefinition};

/// LSM hook types that can be intercepted
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LsmHookType {
    /// File operation hooks
    FileOpen,
    FileRead,
    FileWrite,
    FileExecute,
    FilePermission,

    /// Process operation hooks
    ProcessExec,
    ProcessFork,
    ProcessExit,
    ProcessSetuid,
    ProcessSetgid,

    /// Network operation hooks
    SocketCreate,
    SocketBind,
    SocketConnect,
    SocketListen,
    SocketAccept,

    /// Memory operation hooks
    Mmap,
    Brk,

    /// System call hooks
    SyscallEntry,
    SyscallExit,

    /// Capability hooks
    Capable,
    Capget,
    Capset,

    /// IPC hooks
    MsgQueue,
    Semaphore,
    SharedMemory,

    /// Device hooks
    DeviceAccess,
}

impl std::fmt::Display for LsmHookType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LsmHookType::FileOpen => write!(f, "file_open"),
            LsmHookType::FileRead => write!(f, "file_read"),
            LsmHookType::FileWrite => write!(f, "file_write"),
            LsmHookType::FileExecute => write!(f, "file_execute"),
            LsmHookType::FilePermission => write!(f, "file_permission"),
            LsmHookType::ProcessExec => write!(f, "process_exec"),
            LsmHookType::ProcessFork => write!(f, "process_fork"),
            LsmHookType::ProcessExit => write!(f, "process_exit"),
            LsmHookType::ProcessSetuid => write!(f, "process_setuid"),
            LsmHookType::ProcessSetgid => write!(f, "process_setgid"),
            LsmHookType::SocketCreate => write!(f, "socket_create"),
            LsmHookType::SocketBind => write!(f, "socket_bind"),
            LsmHookType::SocketConnect => write!(f, "socket_connect"),
            LsmHookType::SocketListen => write!(f, "socket_listen"),
            LsmHookType::SocketAccept => write!(f, "socket_accept"),
            LsmHookType::Mmap => write!(f, "mmap"),
            LsmHookType::Brk => write!(f, "brk"),
            LsmHookType::SyscallEntry => write!(f, "syscall_entry"),
            LsmHookType::SyscallExit => write!(f, "syscall_exit"),
            LsmHookType::Capable => write!(f, "capable"),
            LsmHookType::Capget => write!(f, "capget"),
            LsmHookType::Capset => write!(f, "capset"),
            LsmHookType::MsgQueue => write!(f, "msg_queue"),
            LsmHookType::Semaphore => write!(f, "semaphore"),
            LsmHookType::SharedMemory => write!(f, "shared_memory"),
            LsmHookType::DeviceAccess => write!(f, "device_access"),
        }
    }
}

/// LSM hook action types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LsmAction {
    /// Allow the operation
    Allow,
    /// Deny the operation
    Deny,
    /// Audit the operation (allow but log)
    Audit,
    /// Silent deny (no logging)
    SilentDeny,
}

/// LSM hook decision
#[derive(Debug, Clone)]
pub struct LsmDecision {
    pub hook_type: LsmHookType,
    pub action: LsmAction,
    pub reason: String,
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub context: HashMap<String, String>,
}

impl LsmDecision {
    pub fn new(hook_type: LsmHookType, action: LsmAction, reason: &str) -> Self {
        Self {
            hook_type,
            action,
            reason: reason.to_string(),
            pid: 0,
            uid: 0,
            gid: 0,
            context: HashMap::new(),
        }
    }

    pub fn with_context(mut self, key: &str, value: &str) -> Self {
        self.context.insert(key.to_string(), value.to_string());
        self
    }
}

/// LSM rule for matching and deciding
#[derive(Debug, Clone)]
pub struct LsmRule {
    pub name: String,
    pub hook_type: LsmHookType,
    pub conditions: Vec<LsmCondition>,
    pub action: LsmAction,
    pub priority: u32,
    pub description: String,
}

impl LsmRule {
    pub fn new(name: &str, hook_type: LsmHookType, action: LsmAction) -> Self {
        Self {
            name: name.to_string(),
            hook_type,
            conditions: Vec::new(),
            action,
            priority: 100,
            description: String::new(),
        }
    }

    pub fn with_condition(mut self, condition: LsmCondition) -> Self {
        self.conditions.push(condition);
        self
    }

    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }

    pub fn with_description(mut self, description: &str) -> Self {
        self.description = description.to_string();
        self
    }

    /// Check if this rule matches the given context
    pub fn matches(&self, context: &HashMap<String, String>) -> bool {
        for condition in &self.conditions {
            if !condition.evaluate(context) {
                return false;
            }
        }
        true
    }
}

/// LSM condition types
#[derive(Debug, Clone)]
pub enum LsmCondition {
    /// String equality
    StringEquals { key: String, value: String },
    /// String contains
    StringContains { key: String, value: String },
    /// String prefix
    StringPrefix { key: String, value: String },
    /// String suffix
    StringSuffix { key: String, value: String },
    /// Numeric equality
    NumericEquals { key: String, value: u64 },
    /// Numeric greater than
    NumericGreaterThan { key: String, value: u64 },
    /// Numeric less than
    NumericLessThan { key: String, value: u64 },
    /// Numeric in range
    NumericInRange { key: String, min: u64, max: u64 },
    /// Boolean condition
    Boolean { key: String, value: bool },
    /// Regex match
    Regex { key: String, pattern: String },
    /// IP address in CIDR range
    IpInCidr { key: String, cidr: String },
}

impl LsmCondition {
    pub fn evaluate(&self, context: &HashMap<String, String>) -> bool {
        match self {
            LsmCondition::StringEquals { key, value } => context.get(key) == Some(value),
            LsmCondition::StringContains { key, value } => {
                context.get(key).map(|v| v.contains(value)).unwrap_or(false)
            }
            LsmCondition::StringPrefix { key, value } => context
                .get(key)
                .map(|v| v.starts_with(value))
                .unwrap_or(false),
            LsmCondition::StringSuffix { key, value } => context
                .get(key)
                .map(|v| v.ends_with(value))
                .unwrap_or(false),
            LsmCondition::NumericEquals { key, value } => {
                context.get(key).and_then(|v| v.parse::<u64>().ok()) == Some(*value)
            }
            LsmCondition::NumericGreaterThan { key, value } => context
                .get(key)
                .and_then(|v| v.parse::<u64>().ok())
                .map(|v| v > *value)
                .unwrap_or(false),
            LsmCondition::NumericLessThan { key, value } => context
                .get(key)
                .and_then(|v| v.parse::<u64>().ok())
                .map(|v| v < *value)
                .unwrap_or(false),
            LsmCondition::NumericInRange { key, min, max } => context
                .get(key)
                .and_then(|v| v.parse::<u64>().ok())
                .map(|v| v >= *min && v <= *max)
                .unwrap_or(false),
            LsmCondition::Boolean { key, value } => {
                context
                    .get(key)
                    .map(|v| match v.to_lowercase().as_str() {
                        "true" | "1" | "yes" => true,
                        "false" | "0" | "no" => false,
                        _ => false,
                    })
                    .unwrap_or(false)
                    == *value
            }
            LsmCondition::Regex { key, pattern } => {
                context
                    .get(key)
                    .map(|v| v.contains(pattern.as_str()))
                    .unwrap_or(false)
                // Note: In production, this would use the regex crate
            }
            LsmCondition::IpInCidr { key, cidr } => {
                // Simplified IP range check
                context
                    .get(key)
                    .map(|v| self.ip_in_cidr_simple(v, cidr))
                    .unwrap_or(false)
            }
        }
    }

    /// Simple IP in CIDR check (would use proper IP networking in production)
    fn ip_in_cidr_simple(&self, ip: &str, cidr: &str) -> bool {
        if cidr == "0.0.0.0/0" || cidr == "::/0" {
            return true; // Match all
        }

        // Simple equality check for now
        ip == cidr
    }
}

/// LSM configuration
#[derive(Debug, Clone)]
pub struct LsmConfig {
    pub enabled: bool,
    pub module_name: String,
    pub lsm_name: String,
    pub hook_priority: u32,
    pub auto_load: bool,
    pub rules_file: PathBuf,
    pub log_file: PathBuf,
    pub audit_log: bool,
}

impl Default for LsmConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            module_name: "ccze_lsm".to_string(),
            lsm_name: "ccze".to_string(),
            hook_priority: 100,
            auto_load: false,
            rules_file: PathBuf::from("/etc/ccze/lsm_rules.conf"),
            log_file: PathBuf::from("/var/log/ccze_lsm.log"),
            audit_log: true,
        }
    }
}

/// LSM manager
pub struct LsmManager {
    config: LsmConfig,
    rules: Arc<Mutex<Vec<LsmRule>>>,
    decisions: Arc<Mutex<Vec<LsmDecision>>>,
    lkm_manager: Option<LkmManager>,
}

impl LsmManager {
    pub fn new(config: LsmConfig) -> Self {
        Self {
            config: config.clone(),
            rules: Arc::new(Mutex::new(Vec::new())),
            decisions: Arc::new(Mutex::new(Vec::new())),
            lkm_manager: if config.enabled {
                Some(LkmManager::new(&config))
            } else {
                None
            },
        }
    }

    /// Initialize the LSM framework
    pub fn initialize(&self) -> Result<(), String> {
        if !self.config.enabled {
            return Ok(());
        }

        // Load rules from configuration file
        self.load_rules()?;

        Ok(())
    }

    /// Load rules from configuration file
    pub fn load_rules(&self) -> Result<(), String> {
        if !self.config.rules_file.exists() {
            return Ok(()); // No rules file, use defaults
        }

        let contents = fs::read_to_string(&self.config.rules_file)
            .map_err(|e| format!("Failed to read rules file: {}", e))?;

        let mut rules = self.parse_rules(&contents)?;

        // Add default rules if none exist
        if rules.is_empty() {
            rules = self.default_rules();
        }

        let mut rules_lock = self.rules.lock().unwrap();
        *rules_lock = rules;

        Ok(())
    }

    /// Parse rules from configuration
    fn parse_rules(&self, contents: &str) -> Result<Vec<LsmRule>, String> {
        let mut rules = Vec::new();

        // Simple parser for now - would be more sophisticated in production
        // Format: rule_name: hook_type [condition...] -> action
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Split on '->'
            let parts: Vec<&str> = line.split("->").collect();
            if parts.len() != 2 {
                continue;
            }

            let conditions_part = parts[0].trim();
            let action_part = parts[1].trim();

            // Parse action
            let action = match action_part.to_lowercase().as_str() {
                "allow" => LsmAction::Allow,
                "deny" => LsmAction::Deny,
                "audit" => LsmAction::Audit,
                "silent_deny" => LsmAction::SilentDeny,
                _ => LsmAction::Deny,
            };

            // Parse rule name and conditions
            let condition_parts: Vec<&str> = conditions_part.split_whitespace().collect();
            if condition_parts.len() < 2 {
                continue;
            }

            let rule_name = condition_parts[0].to_string();
            let hook_type_str = condition_parts[1];

            // Parse hook type
            let hook_type = match hook_type_str {
                "file_open" => LsmHookType::FileOpen,
                "file_read" => LsmHookType::FileRead,
                "file_write" => LsmHookType::FileWrite,
                "file_execute" => LsmHookType::FileExecute,
                "process_exec" => LsmHookType::ProcessExec,
                "process_fork" => LsmHookType::ProcessFork,
                "socket_create" => LsmHookType::SocketCreate,
                "socket_bind" => LsmHookType::SocketBind,
                "capable" => LsmHookType::Capable,
                "syscall_entry" => LsmHookType::SyscallEntry,
                _ => LsmHookType::FileOpen, // Default
            };

            let mut rule = LsmRule::new(&rule_name, hook_type, action);

            // Parse conditions (if any)
            for i in 2..condition_parts.len() {
                let condition_str = condition_parts[i];
                // Simple condition parsing for now
                if let Some((key, value)) = self.parse_condition(condition_str) {
                    rule = rule.with_condition(LsmCondition::StringEquals { key, value });
                }
            }

            rules.push(rule);
        }

        Ok(rules)
    }

    /// Parse a simple condition string
    fn parse_condition(&self, condition: &str) -> Option<(String, String)> {
        let parts: Vec<&str> = condition.split('=').collect();
        if parts.len() == 2 {
            Some((parts[0].to_string(), parts[1].to_string()))
        } else {
            None
        }
    }

    /// Get default LSM rules
    fn default_rules(&self) -> Vec<LsmRule> {
        vec![
            // Deny process execution from /tmp
            LsmRule::new("deny_exec_tmp", LsmHookType::ProcessExec, LsmAction::Deny)
                .with_condition(LsmCondition::StringPrefix {
                    key: "path".to_string(),
                    value: "/tmp/".to_string(),
                })
                .with_priority(200)
                .with_description("Deny execution from /tmp"),
            // Audit all setuid calls
            LsmRule::new("audit_setuid", LsmHookType::ProcessSetuid, LsmAction::Audit)
                .with_priority(150)
                .with_description("Audit setuid calls"),
            // Deny capability CAP_SYS_ADMIN for non-root
            LsmRule::new("deny_sys_admin", LsmHookType::Capable, LsmAction::Deny)
                .with_condition(LsmCondition::NumericEquals {
                    key: "cap".to_string(),
                    value: 21, // CAP_SYS_ADMIN
                })
                .with_condition(LsmCondition::NumericGreaterThan {
                    key: "uid".to_string(),
                    value: 0, // Not root
                })
                .with_priority(300)
                .with_description("Deny CAP_SYS_ADMIN for non-root users"),
            // Allow all by default (lowest priority)
            LsmRule::new("default_allow", LsmHookType::SyscallEntry, LsmAction::Allow)
                .with_priority(10)
                .with_description("Default allow rule"),
        ]
    }

    /// Add a rule
    pub fn add_rule(&self, rule: LsmRule) -> Result<(), String> {
        let mut rules = self.rules.lock().unwrap();
        rules.push(rule);
        Ok(())
    }

    /// Remove a rule by name
    pub fn remove_rule(&self, name: &str) -> Result<bool, String> {
        let mut rules = self.rules.lock().unwrap();
        let index = rules.iter().position(|r| r.name == name);

        if let Some(idx) = index {
            rules.remove(idx);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Evaluate a hook call and return a decision
    pub fn evaluate_hook(
        &self,
        hook_type: LsmHookType,
        context: &HashMap<String, String>,
    ) -> LsmDecision {
        let rules = self.rules.lock().unwrap();

        // Find matching rules sorted by priority (highest first)
        let mut matching_rules: Vec<&LsmRule> = rules
            .iter()
            .filter(|r| r.hook_type == hook_type && r.matches(context))
            .collect();

        matching_rules.sort_by(|a, b| b.priority.cmp(&a.priority));

        // Use the highest priority matching rule
        if let Some(rule) = matching_rules.first() {
            let mut decision = LsmDecision::new(hook_type, rule.action, &rule.description);

            // Copy relevant context
            for (key, value) in context {
                decision = decision.with_context(key, value);
            }

            // Extract pid, uid, gid from context
            if let Some(pid_str) = context.get("pid") {
                if let Ok(pid) = pid_str.parse::<u32>() {
                    decision.pid = pid;
                }
            }
            if let Some(uid_str) = context.get("uid") {
                if let Ok(uid) = uid_str.parse::<u32>() {
                    decision.uid = uid;
                }
            }
            if let Some(gid_str) = context.get("gid") {
                if let Ok(gid) = gid_str.parse::<u32>() {
                    decision.gid = gid;
                }
            }

            // Record the decision
            let mut decisions = self.decisions.lock().unwrap();
            decisions.push(decision.clone());

            // Log the decision
            self.log_decision(&decision);

            return decision;
        }

        // Default decision
        let mut decision = LsmDecision::new(hook_type, LsmAction::Allow, "No matching rule");
        for (key, value) in context {
            decision = decision.with_context(key, value);
        }

        decision
    }

    /// Log a decision
    fn log_decision(&self, decision: &LsmDecision) {
        if !self.config.audit_log {
            return;
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let action_str = match decision.action {
            LsmAction::Allow => "ALLOW",
            LsmAction::Deny => "DENY",
            LsmAction::Audit => "AUDIT",
            LsmAction::SilentDeny => "SILENT_DENY",
        };

        let log_entry = format!(
            "[{}] {} {} pid={} uid={} gid={} reason=\"{}\"\n",
            timestamp,
            action_str,
            decision.hook_type,
            decision.pid,
            decision.uid,
            decision.gid,
            decision.reason
        );

        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.config.log_file)
        {
            let _ = file.write_all(log_entry.as_bytes());
        }
    }

    /// List all rules
    pub fn list_rules(&self) -> Vec<LsmRule> {
        let rules = self.rules.lock().unwrap();
        rules.clone()
    }

    /// List recent decisions
    pub fn list_decisions(&self, limit: usize) -> Vec<LsmDecision> {
        let decisions = self.decisions.lock().unwrap();
        decisions.iter().rev().take(limit).cloned().collect()
    }

    /// Clear all decisions
    pub fn clear_decisions(&self) -> Result<(), String> {
        let mut decisions = self.decisions.lock().unwrap();
        decisions.clear();
        Ok(())
    }

    /// Get LKM manager (if available)
    pub fn get_lkm_manager(&self) -> Option<&LkmManager> {
        self.lkm_manager.as_ref()
    }

    /// Get statistics
    pub fn get_stats(&self) -> LsmStats {
        let rules = self.rules.lock().unwrap();
        let decisions = self.decisions.lock().unwrap();

        let total_rules = rules.len();
        let total_decisions = decisions.len();
        let denied = decisions
            .iter()
            .filter(|d| matches!(d.action, LsmAction::Deny | LsmAction::SilentDeny))
            .count();
        let allowed = decisions
            .iter()
            .filter(|d| matches!(d.action, LsmAction::Allow))
            .count();
        let audited = decisions
            .iter()
            .filter(|d| matches!(d.action, LsmAction::Audit))
            .count();

        LsmStats {
            enabled: self.config.enabled,
            lsm_name: self.config.lsm_name.clone(),
            module_name: self.config.module_name.clone(),
            total_rules,
            total_decisions,
            denied,
            allowed,
            audited,
        }
    }
}

/// LSM statistics
#[derive(Debug, Clone)]
pub struct LsmStats {
    pub enabled: bool,
    pub lsm_name: String,
    pub module_name: String,
    pub total_rules: usize,
    pub total_decisions: usize,
    pub denied: usize,
    pub allowed: usize,
    pub audited: usize,
}

/// LKM (Loadable Kernel Module) manager
pub struct LkmManager {
    config: LsmConfig,
    dkms_manager: DkmsManager,
    module_loaded: Arc<Mutex<bool>>,
}

impl LkmManager {
    pub fn new(config: &LsmConfig) -> Self {
        Self {
            config: config.clone(),
            dkms_manager: DkmsManager::new(DkmsConfig {
                enabled: true,
                auto_load: true,
                modules: vec![ModuleDefinition::new(
                    &config.module_name,
                    "ccze LSM module",
                )],
                ..Default::default()
            }),
            module_loaded: Arc::new(Mutex::new(false)),
        }
    }

    /// Build the LKM
    pub fn build(&self) -> Result<bool, String> {
        // Build using make in the LKM source directory
        let lkm_dir = Path::new("native/lkm");

        if !lkm_dir.exists() {
            return Err("LKM source directory not found".to_string());
        }

        let output = Command::new("make")
            .current_dir(lkm_dir)
            .output()
            .map_err(|e| format!("Failed to build LKM: {}", e))?;

        Ok(output.status.success())
    }

    /// Install the LKM
    pub fn install(&self) -> Result<bool, String> {
        // Install using make install
        let lkm_dir = Path::new("native/lkm");

        if !lkm_dir.exists() {
            return Err("LKM source directory not found".to_string());
        }

        let output = Command::new("make")
            .arg("install")
            .current_dir(lkm_dir)
            .output()
            .map_err(|e| format!("Failed to install LKM: {}", e))?;

        Ok(output.status.success())
    }

    /// Remove the LKM
    pub fn remove(&self) -> Result<bool, String> {
        // Remove using make uninstall
        let lkm_dir = Path::new("native/lkm");

        if !lkm_dir.exists() {
            return Err("LKM source directory not found".to_string());
        }

        let output = Command::new("make")
            .arg("uninstall")
            .current_dir(lkm_dir)
            .output()
            .map_err(|e| format!("Failed to remove LKM: {}", e))?;

        Ok(output.status.success())
    }

    /// Register the LSM with the kernel
    pub fn register_lsm(&self) -> Result<bool, String> {
        // The active list is observational. Registration must happen from
        // kernel initialization code, never by writing to securityfs.
        let lsm_path = Path::new("/sys/kernel/security/lsm");
        if lsm_path.exists() {
            // Check if our LSM is registered
            if let Ok(contents) = fs::read_to_string(lsm_path) {
                if contents.contains(&self.config.lsm_name) {
                    let mut loaded = self.module_loaded.lock().unwrap();
                    *loaded = true;
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Load the LKM
    pub fn load(&self) -> Result<bool, String> {
        // Try DKMS first
        if self.dkms_manager.load_module(&self.config.module_name)? {
            let mut loaded = self.module_loaded.lock().unwrap();
            *loaded = true;
            return Ok(true);
        }

        // Try modprobe
        let output = Command::new("modprobe")
            .arg(&self.config.module_name)
            .output()
            .map_err(|e| format!("Failed to load LKM: {}", e))?;

        if output.status.success() {
            let mut loaded = self.module_loaded.lock().unwrap();
            *loaded = true;
            return Ok(true);
        }

        // Try insmod
        let lkm_path = Path::new("native/lkm").join(format!("{}.ko", self.config.module_name));
        if lkm_path.exists() {
            let output = Command::new("insmod").arg(lkm_path).output();

            if let Ok(output) = output {
                if output.status.success() {
                    let mut loaded = self.module_loaded.lock().unwrap();
                    *loaded = true;
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Unload the LKM
    pub fn unload(&self) -> Result<bool, String> {
        let output = Command::new("rmmod")
            .arg(&self.config.module_name)
            .output()
            .map_err(|e| format!("Failed to unload LKM: {}", e))?;

        if output.status.success() {
            let mut loaded = self.module_loaded.lock().unwrap();
            *loaded = false;
            return Ok(true);
        }

        Ok(false)
    }

    /// Check if the LKM is loaded
    pub fn is_loaded(&self) -> Result<bool, String> {
        let loaded = self.module_loaded.lock().unwrap();
        Ok(*loaded
            || self
                .dkms_manager
                .is_module_loaded(&self.config.module_name)?)
    }

    /// Get LKM version
    pub fn get_version(&self) -> Result<String, String> {
        let output = Command::new("modinfo")
            .arg(&self.config.module_name)
            .output()
            .map_err(|e| format!("Failed to get LKM version: {}", e))?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.starts_with("version:") {
                    return Ok(line.split(':').nth(1).unwrap_or("").trim().to_string());
                }
            }
        }

        Ok("unknown".to_string())
    }

    /// Check if LSM framework is available in kernel
    pub fn is_lsm_available(&self) -> Result<bool, String> {
        let release = fs::read_to_string("/proc/sys/kernel/osrelease")
            .unwrap_or_default()
            .trim()
            .to_string();
        if !release.is_empty() {
            let config = Path::new("/boot").join(format!("config-{release}"));
            if fs::read_to_string(config)
                .is_ok_and(|contents| contents.lines().any(|line| line.starts_with("CONFIG_LSM=")))
            {
                return Ok(true);
            }
        }

        // Fallback: check if we can register LSMs
        let lsm_path = Path::new("/sys/kernel/security/lsm");
        Ok(lsm_path.exists())
    }

    /// Check if kernel supports LSM using native FFI
    pub fn check_support_native(&self) -> Result<bool, String> {
        let result = unsafe { ccze_lsm_check_support() };
        Ok(result > 0)
    }
}

/// Capability manager for LSM
pub struct CapabilityManager {
    _lsm_manager: LsmManager,
}

impl CapabilityManager {
    pub fn new(lsm_manager: LsmManager) -> Self {
        Self {
            _lsm_manager: lsm_manager,
        }
    }

    /// Check if a process has a specific capability
    pub fn has_capability(&self, pid: u32, capability: u32) -> Result<bool, String> {
        // Check via /proc/[pid]/status
        let status_path = Path::new("/proc").join(pid.to_string()).join("status");

        if let Ok(contents) = fs::read_to_string(&status_path) {
            // Look for CapEff, CapPrm, CapBnd lines
            for line in contents.lines() {
                if line.starts_with("CapEff:") || line.starts_with("CapPrm:") {
                    let caps_str = line.split(':').nth(1).unwrap_or("");
                    return Ok(self.check_capability_bit(caps_str, capability));
                }
            }
        }

        Ok(false)
    }

    /// Check if a capability bit is set in a capability string
    fn check_capability_bit(&self, caps_str: &str, capability: u32) -> bool {
        if capability >= 40 {
            return false; // Invalid capability
        }

        // Parse capability string (hex format)
        let cap_hex = caps_str.trim();
        if let Ok(cap_value) = u64::from_str_radix(cap_hex, 16) {
            let mask = 1u64 << capability;
            return (cap_value & mask) != 0;
        }

        false
    }

    /// Check capability using capsh
    pub fn check_capability_capsh(&self, pid: u32, capability: u32) -> Result<bool, String> {
        let output = Command::new("capsh")
            .arg("--decode")
            .arg(&format!("--pid={}", pid))
            .output()
            .map_err(|e| format!("Failed to check capability with capsh: {}", e))?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let cap_name = self.capability_to_name(capability);
            return Ok(stdout.contains(&cap_name));
        }

        Ok(false)
    }

    /// Convert capability number to name
    fn capability_to_name(&self, capability: u32) -> String {
        match capability {
            0 => "CAP_CHOWN".to_string(),
            1 => "CAP_DAC_OVERRIDE".to_string(),
            2 => "CAP_DAC_READ_SEARCH".to_string(),
            3 => "CAP_FOWNER".to_string(),
            4 => "CAP_FSETID".to_string(),
            5 => "CAP_KILL".to_string(),
            6 => "CAP_SETGID".to_string(),
            7 => "CAP_SETUID".to_string(),
            8 => "CAP_SETPCAP".to_string(),
            9 => "CAP_LINUX_IMMUTABLE".to_string(),
            10 => "CAP_NET_BIND_SERVICE".to_string(),
            11 => "CAP_NET_BROADCAST".to_string(),
            12 => "CAP_NET_ADMIN".to_string(),
            13 => "CAP_NET_RAW".to_string(),
            14 => "CAP_IPC_LOCK".to_string(),
            15 => "CAP_IPC_OWNER".to_string(),
            16 => "CAP_SYS_MODULE".to_string(),
            17 => "CAP_SYS_RAWIO".to_string(),
            18 => "CAP_SYS_CHROOT".to_string(),
            19 => "CAP_SYS_PTRACE".to_string(),
            20 => "CAP_SYS_PACCT".to_string(),
            21 => "CAP_SYS_ADMIN".to_string(),
            22 => "CAP_SYS_BOOT".to_string(),
            23 => "CAP_SYS_NICE".to_string(),
            24 => "CAP_SYS_RESOURCE".to_string(),
            25 => "CAP_SYS_TIME".to_string(),
            26 => "CAP_SYS_TTY_CONFIG".to_string(),
            27 => "CAP_MKNOD".to_string(),
            28 => "CAP_LEASE".to_string(),
            29 => "CAP_AUDIT_WRITE".to_string(),
            30 => "CAP_AUDIT_CONTROL".to_string(),
            31 => "CAP_SETFCAP".to_string(),
            32 => "CAP_MAC_OVERRIDE".to_string(),
            33 => "CAP_MAC_ADMIN".to_string(),
            34 => "CAP_SYSLOG".to_string(),
            35 => "CAP_WAKE_ALARM".to_string(),
            36 => "CAP_BLOCK_SUSPEND".to_string(),
            37 => "CAP_AUDIT_READ".to_string(),
            _ => format!("CAP_{}", capability),
        }
    }

    /// Get all capabilities for a process
    pub fn get_capabilities(&self, pid: u32) -> Result<Vec<String>, String> {
        let mut capabilities = Vec::new();

        for cap in 0..40 {
            if self.has_capability(pid, cap)? {
                capabilities.push(self.capability_to_name(cap));
            }
        }

        Ok(capabilities)
    }

    /// Drop capabilities for a process (would require appropriate privileges)
    pub fn drop_capability(&self, _pid: u32, _capability: u32) -> Result<bool, String> {
        // This would require CAP_SETPCAP capability
        // For now, return error as this is a privileged operation
        Err("Dropping capabilities requires CAP_SETPCAP privilege".to_string())
    }

    /// Get capability bounding set for a process using capsh
    pub fn get_bounding_set_capsh(&self, pid: u32) -> Result<Vec<String>, String> {
        let output = Command::new("capsh")
            .arg("--decode")
            .arg(&format!("--pid={}", pid))
            .output()
            .map_err(|e| format!("Failed to get bounding set with capsh: {}", e))?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut capabilities = Vec::new();

            for line in stdout.lines() {
                if line.contains("Bounding set") {
                    // Parse bounding set from line like "Bounding set =cap_chown,cap_dac_override,..."
                    if let Some(eq_pos) = line.find('=') {
                        let caps_str = &line[eq_pos + 1..];
                        for cap in caps_str.split(',') {
                            if !cap.is_empty() {
                                capabilities.push(cap.to_string());
                            }
                        }
                    }
                    break;
                }
            }

            return Ok(capabilities);
        }

        Ok(Vec::new())
    }

    /// Get all capability information for a process using capsh
    pub fn get_full_capabilities_capsh(
        &self,
        pid: u32,
    ) -> Result<HashMap<String, Vec<String>>, String> {
        let output = Command::new("capsh")
            .arg("--decode")
            .arg(&format!("--pid={}", pid))
            .output()
            .map_err(|e| format!("Failed to get capabilities with capsh: {}", e))?;

        if !output.status.success() {
            return Ok(HashMap::new());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut result = HashMap::new();
        let mut current_section = String::new();
        let mut current_caps = Vec::new();

        for line in stdout.lines() {
            let trimmed = line.trim();

            if trimmed.is_empty() {
                continue;
            }

            // Check for section headers
            if trimmed.starts_with("Current:")
                || trimmed.starts_with("Bounding set:")
                || trimmed.starts_with("Ambient set:")
                || trimmed.starts_with("Securebits:")
            {
                // Save previous section
                if !current_section.is_empty() {
                    result.insert(current_section.clone(), current_caps.clone());
                    current_caps.clear();
                }

                current_section = trimmed.to_string();

                // Parse capabilities from the line
                if let Some(eq_pos) = trimmed.find('=') {
                    let caps_str = &trimmed[eq_pos + 1..];
                    for cap in caps_str.split(',') {
                        if !cap.is_empty() {
                            current_caps.push(cap.to_string());
                        }
                    }
                }
            } else if !current_section.is_empty() {
                // Continue parsing capabilities
                for cap in trimmed.split_whitespace() {
                    if !cap.is_empty() && cap.starts_with("cap_") {
                        current_caps.push(cap.to_string());
                    }
                }
            }
        }

        // Save last section
        if !current_section.is_empty() {
            result.insert(current_section, current_caps);
        }

        Ok(result)
    }

    /// Check if current process has CAP_SETPCAP (needed to modify capabilities)
    pub fn has_setpcap(&self) -> Result<bool, String> {
        let current_pid = std::process::id();
        self.has_capability(current_pid, 8) // CAP_SETPCAP = 8
    }

    /// Check if current process has CAP_SYS_ADMIN
    pub fn has_sys_admin(&self) -> Result<bool, String> {
        let current_pid = std::process::id();
        self.has_capability(current_pid, 21) // CAP_SYS_ADMIN = 21
    }

    /// Print capabilities for a process using capsh (human-readable)
    pub fn print_capabilities_capsh(&self, pid: u32) -> Result<String, String> {
        let output = Command::new("capsh")
            .arg("--decode")
            .arg(&format!("--pid={}", pid))
            .output()
            .map_err(|e| format!("Failed to print capabilities with capsh: {}", e))?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            Ok(String::from_utf8_lossy(&output.stderr).to_string())
        }
    }

    /// Get capabilities using native FFI
    pub fn get_capabilities_native(&self, pid: u32) -> Result<Vec<String>, String> {
        // Create a buffer for the C function
        let buffer_size = 4096;
        let mut buffer = vec![0u8; buffer_size];

        let result = unsafe {
            ccze_lsm_get_capabilities(pid as i32, buffer.as_mut_ptr() as *mut c_char, buffer_size)
        };

        if result >= 0 {
            // Convert buffer to string and parse
            let caps_str = String::from_utf8_lossy(&buffer[..result as usize]).to_string();
            let capabilities: Vec<String> = caps_str
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            Ok(capabilities)
        } else {
            Ok(Vec::new())
        }
    }

    /// Check capability using native FFI
    pub fn has_capability_native(&self, pid: u32, capability: u32) -> Result<bool, String> {
        let result = unsafe { ccze_lsm_has_capability(pid as i32, capability as i32) };
        Ok(result > 0)
    }

    /// Drop capability using native FFI
    pub fn drop_capability_native(&self, pid: u32, capability: u32) -> Result<bool, String> {
        let result = unsafe { ccze_lsm_drop_capability(pid as i32, capability as i32) };
        Ok(result == 0)
    }
}

// External FFI functions for LSM operations
extern "C" {
    /// Check if a process has a capability
    fn ccze_lsm_has_capability(pid: i32, capability: i32) -> i32;

    /// Get all capabilities for a process
    fn ccze_lsm_get_capabilities(pid: i32, buffer: *mut c_char, buffer_size: usize) -> i32;

    /// Drop capability for a process
    fn ccze_lsm_drop_capability(pid: i32, capability: i32) -> i32;

    /// Check if kernel supports LSM
    fn ccze_lsm_check_support() -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lsm_hook_type_display() {
        assert_eq!(format!("{}", LsmHookType::FileOpen), "file_open");
        assert_eq!(format!("{}", LsmHookType::ProcessExec), "process_exec");
        assert_eq!(format!("{}", LsmHookType::Capable), "capable");
    }

    #[test]
    fn test_lsm_action_equality() {
        assert_eq!(LsmAction::Allow, LsmAction::Allow);
        assert_eq!(LsmAction::Deny, LsmAction::Deny);
        assert_ne!(LsmAction::Allow, LsmAction::Deny);
    }

    #[test]
    fn test_lsm_decision_creation() {
        let decision = LsmDecision::new(LsmHookType::FileOpen, LsmAction::Deny, "test");

        assert_eq!(decision.hook_type, LsmHookType::FileOpen);
        assert_eq!(decision.action, LsmAction::Deny);
        assert_eq!(decision.reason, "test");
    }

    #[test]
    fn test_lsm_rule_creation() {
        let rule = LsmRule::new("test_rule", LsmHookType::FileOpen, LsmAction::Deny);

        assert_eq!(rule.name, "test_rule");
        assert_eq!(rule.hook_type, LsmHookType::FileOpen);
        assert_eq!(rule.action, LsmAction::Deny);
    }

    #[test]
    fn test_lsm_config_default() {
        let config = LsmConfig::default();

        assert!(config.enabled);
        assert!(!config.auto_load);
        assert_eq!(config.lsm_name, "ccze");
        assert_eq!(config.module_name, "ccze_lsm");
    }

    #[test]
    fn test_lsm_stats() {
        let stats = LsmStats {
            enabled: true,
            lsm_name: "test".to_string(),
            module_name: "test_lsm".to_string(),
            total_rules: 5,
            total_decisions: 10,
            denied: 2,
            allowed: 7,
            audited: 1,
        };

        assert!(stats.enabled);
        assert_eq!(stats.total_rules, 5);
        assert_eq!(stats.denied, 2);
    }

    #[test]
    fn test_capability_to_name() {
        let cap_manager = CapabilityManager::new(LsmManager::new(LsmConfig::default()));

        assert_eq!(cap_manager.capability_to_name(0), "CAP_CHOWN");
        assert_eq!(cap_manager.capability_to_name(21), "CAP_SYS_ADMIN");
        assert_eq!(cap_manager.capability_to_name(39), "CAP_39");
    }

    #[test]
    fn test_lsm_condition_string_equals() {
        let condition = LsmCondition::StringEquals {
            key: "path".to_string(),
            value: "/tmp/test".to_string(),
        };

        let mut context = HashMap::new();
        context.insert("path".to_string(), "/tmp/test".to_string());

        assert!(condition.evaluate(&context));

        context.insert("path".to_string(), "/tmp/other".to_string());
        assert!(!condition.evaluate(&context));
    }

    #[test]
    fn test_lsm_condition_numeric_greater_than() {
        let condition = LsmCondition::NumericGreaterThan {
            key: "uid".to_string(),
            value: 0,
        };

        let mut context = HashMap::new();
        context.insert("uid".to_string(), "1000".to_string());

        assert!(condition.evaluate(&context));

        context.insert("uid".to_string(), "0".to_string());
        assert!(!condition.evaluate(&context));
    }

    #[test]
    fn test_capability_manager_basic() {
        let lsm_manager = LsmManager::new(LsmConfig::default());
        let cap_manager = CapabilityManager::new(lsm_manager);

        // Test capability name conversion
        assert_eq!(cap_manager.capability_to_name(0), "CAP_CHOWN");
        assert_eq!(cap_manager.capability_to_name(21), "CAP_SYS_ADMIN");
        assert_eq!(cap_manager.capability_to_name(39), "CAP_39");
    }

    #[test]
    fn test_lkm_manager_config() {
        let config = LsmConfig::default();
        let lkm_manager = LkmManager::new(&config);

        assert_eq!(lkm_manager.config.module_name, "ccze_lsm");
        assert_eq!(lkm_manager.config.lsm_name, "ccze");
    }

    #[test]
    fn test_lsm_stats_with_manager() {
        let config = LsmConfig::default();
        let lsm_manager = LsmManager::new(config);
        let stats = lsm_manager.get_stats();

        assert!(stats.enabled);
        assert_eq!(stats.lsm_name, "ccze");
        assert_eq!(stats.module_name, "ccze_lsm");
    }
}
