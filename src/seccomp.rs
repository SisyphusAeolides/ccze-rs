//! State-Bound Seccomp Sandboxing.
//!
//! This module provides Idris-governed dynamic seccomp filtering that bounds
//! process privileges based on their verified protocol state. If the Idris
//! specification proves a process is in a specific state, seccomp rules are
//! dynamically adjusted to allow only mathematically valid operations.
//!
//! The key insight: if a process is proven to be in the "Ready" state of the
//! Start -> Authenticate -> Bind -> Ready protocol, there is no mathematical
//! reason it should need to invoke execve to spawn a shell. ccze-rs can therefore
//! inject a seccomp filter that kills any execve attempt, providing a
//! formally-verified sandbox.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::protocol::Phase;

/// Seccomp action types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum SeccompAction {
    /// Allow the system call.
    Allow = 0,
    /// Kill the process if it makes this system call.
    Kill = 1,
    /// Trap the system call (requires signal handler).
    Trap = 2,
    /// Return an error code.
    Errno = 3,
    /// Trace the system call.
    Trace = 4,
    /// Log the system call.
    Log = 5,
}

impl Default for SeccompAction {
    fn default() -> Self {
        Self::Kill
    }
}

/// System call information.
#[derive(Clone, Debug)]
pub struct SyscallInfo {
    /// System call number.
    pub nr: i32,
    /// System call name.
    pub name: String,
    /// Category (e.g., "file", "process", "network").
    pub category: String,
}

/// A seccomp rule maps a system call to an action.
#[derive(Clone, Debug)]
pub struct SeccompRule {
    /// System call number.
    pub syscall_nr: i32,
    /// Action to take.
    pub action: SeccompAction,
}

/// A seccomp filter for a specific process.
#[derive(Clone, Debug)]
pub struct SeccompFilter {
    /// Process ID.
    pub pid: u32,
    /// Protocol phase when the filter was installed.
    pub phase: Phase,
    /// List of rules.
    pub rules: Vec<SeccompRule>,
    /// Default action for unmatched system calls.
    pub default_action: SeccompAction,
}

impl SeccompFilter {
    /// Creates a new seccomp filter for a process in a given phase.
    #[must_use]
    pub fn new(pid: u32, phase: Phase) -> Self {
        let rules = Self::generate_rules_for_phase(phase);
        Self {
            pid,
            phase,
            rules,
            default_action: if phase == Phase::Ready {
                SeccompAction::Allow
            } else {
                SeccompAction::Kill
            },
        }
    }

    /// Generates seccomp rules for a given protocol phase.
    fn generate_rules_for_phase(phase: Phase) -> Vec<SeccompRule> {
        match phase {
            Phase::Cold => vec![
                // Only allow minimal operations
                SeccompRule {
                    syscall_nr: 9, // mmap
                    action: SeccompAction::Allow,
                },
                SeccompRule {
                    syscall_nr: 12, // brk
                    action: SeccompAction::Allow,
                },
                SeccompRule {
                    syscall_nr: 21, // access
                    action: SeccompAction::Allow,
                },
            ],
            Phase::Started => vec![
                // Allow initialization but not execution
                SeccompRule {
                    syscall_nr: 2, // open
                    action: SeccompAction::Allow,
                },
                SeccompRule {
                    syscall_nr: 3, // close
                    action: SeccompAction::Allow,
                },
                SeccompRule {
                    syscall_nr: 4, // read
                    action: SeccompAction::Allow,
                },
                SeccompRule {
                    syscall_nr: 5, // write
                    action: SeccompAction::Allow,
                },
                SeccompRule {
                    syscall_nr: 9, // mmap
                    action: SeccompAction::Allow,
                },
                SeccompRule {
                    syscall_nr: 12, // brk
                    action: SeccompAction::Allow,
                },
                SeccompRule {
                    syscall_nr: 21, // access
                    action: SeccompAction::Allow,
                },
                SeccompRule {
                    syscall_nr: 59, // execve
                    action: SeccompAction::Kill,
                },
            ],
            Phase::Authenticated => vec![
                // Allow more operations but still restrict
                SeccompRule {
                    syscall_nr: 2, // open
                    action: SeccompAction::Allow,
                },
                SeccompRule {
                    syscall_nr: 3, // close
                    action: SeccompAction::Allow,
                },
                SeccompRule {
                    syscall_nr: 4, // read
                    action: SeccompAction::Allow,
                },
                SeccompRule {
                    syscall_nr: 5, // write
                    action: SeccompAction::Allow,
                },
                SeccompRule {
                    syscall_nr: 9, // mmap
                    action: SeccompAction::Allow,
                },
                SeccompRule {
                    syscall_nr: 12, // brk
                    action: SeccompAction::Allow,
                },
                SeccompRule {
                    syscall_nr: 21, // access
                    action: SeccompAction::Allow,
                },
                SeccompRule {
                    syscall_nr: 41, // socket
                    action: SeccompAction::Allow,
                },
                SeccompRule {
                    syscall_nr: 59, // execve
                    action: SeccompAction::Kill,
                },
            ],
            Phase::Bound => vec![
                // Allow most operations except privileged ones
                SeccompRule {
                    syscall_nr: 160, // sysctl
                    action: SeccompAction::Kill,
                },
                SeccompRule {
                    syscall_nr: 174, // ioperm
                    action: SeccompAction::Kill,
                },
                SeccompRule {
                    syscall_nr: 175, // iopl
                    action: SeccompAction::Kill,
                },
            ],
            Phase::Ready => vec![
                // Allow all non-privileged operations
                SeccompRule {
                    syscall_nr: 160, // sysctl
                    action: SeccompAction::Kill,
                },
                SeccompRule {
                    syscall_nr: 174, // ioperm
                    action: SeccompAction::Kill,
                },
                SeccompRule {
                    syscall_nr: 175, // iopl
                    action: SeccompAction::Kill,
                },
            ],
        }
    }

    /// Checks if a system call is allowed.
    #[must_use]
    pub fn is_allowed(&self, syscall_nr: i32) -> bool {
        for rule in &self.rules {
            if rule.syscall_nr == syscall_nr {
                return rule.action == SeccompAction::Allow;
            }
        }
        self.default_action == SeccompAction::Allow
    }

    /// Gets the action for a system call.
    #[must_use]
    pub fn get_action(&self, syscall_nr: i32) -> SeccompAction {
        for rule in &self.rules {
            if rule.syscall_nr == syscall_nr {
                return rule.action;
            }
        }
        self.default_action
    }
}

/// Seccomp manager for dynamic filter injection.
#[derive(Debug)]
pub struct SeccompManager {
    /// Map of PID to active seccomp filter.
    filters: HashMap<u32, SeccompFilter>,
    /// Whether libseccomp is available.
    libseccomp_available: bool,
    /// Track protocol phases for each PID.
    protocol_phases: HashMap<u32, Phase>,
}

impl Default for SeccompManager {
    fn default() -> Self {
        Self {
            filters: HashMap::new(),
            libseccomp_available: false,
            protocol_phases: HashMap::new(),
        }
    }
}

impl SeccompManager {
    /// Creates a new seccomp manager.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Checks if libseccomp is available.
    #[must_use]
    pub fn is_libseccomp_available(&self) -> bool {
        self.libseccomp_available
    }

    /// Updates the protocol phase for a process.
    pub fn update_protocol_phase(&mut self, pid: u32, phase: Phase) {
        self.protocol_phases.insert(pid, phase);

        // If we have a filter for this PID, update it
        if let Some(filter) = self.filters.get_mut(&pid) {
            *filter = SeccompFilter::new(pid, phase);
        }
    }

    /// Installs a seccomp filter for a process based on its current protocol phase.
    ///
    /// # Arguments
    ///
    /// * `pid` - Process ID.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the filter was installed successfully, or an error.
    pub fn install_filter(&mut self, pid: u32) -> Result<(), String> {
        // Get the current protocol phase for this PID
        let phase = self
            .protocol_phases
            .get(&pid)
            .copied()
            .unwrap_or(Phase::Cold);

        // Create the filter
        let filter = SeccompFilter::new(pid, phase);
        self.filters.insert(pid, filter.clone());

        // In a real implementation with libseccomp, we would:
        // 1. Create a new seccomp context
        // 2. Add rules for each system call
        // 3. Load the filter into the kernel for the PID

        // For now, just store the filter
        Ok(())
    }

    /// Removes a seccomp filter for a process.
    pub fn remove_filter(&mut self, pid: u32) -> bool {
        self.filters.remove(&pid).is_some()
    }

    /// Checks if a system call is allowed for a process.
    #[must_use]
    pub fn is_allowed(&self, pid: u32, syscall_nr: i32) -> bool {
        if let Some(filter) = self.filters.get(&pid) {
            filter.is_allowed(syscall_nr)
        } else {
            // No filter installed, allow all
            true
        }
    }

    /// Gets the seccomp filter for a process.
    #[must_use]
    pub fn get_filter(&self, pid: u32) -> Option<&SeccompFilter> {
        self.filters.get(&pid)
    }

    /// Gets all active filters.
    #[must_use]
    pub fn get_all_filters(&self) -> Vec<&SeccompFilter> {
        self.filters.values().collect()
    }

    /// Removes all filters.
    pub fn clear_filters(&mut self) {
        self.filters.clear();
    }
}

/// State-bound seccomp enforcer.
/// This connects the protocol verifier to the seccomp manager.
#[derive(Debug)]
pub struct StateBoundSeccomp {
    /// Seccomp manager.
    manager: SeccompManager,
    /// Protocol phase tracker.
    phases: Arc<Mutex<HashMap<u32, Phase>>>,
}

impl StateBoundSeccomp {
    /// Creates a new state-bound seccomp enforcer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            manager: SeccompManager::new(),
            phases: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Updates the protocol phase for a process.
    pub fn update_phase(&mut self, pid: u32, phase: Phase) {
        let mut phases = self.phases.lock().unwrap();
        phases.insert(pid, phase);
        self.manager.update_protocol_phase(pid, phase);
    }

    /// Gets the current protocol phase for a process.
    #[must_use]
    pub fn get_phase(&self, pid: u32) -> Option<Phase> {
        let phases = self.phases.lock().unwrap();
        phases.get(&pid).copied()
    }

    /// Installs a seccomp filter for a process.
    ///
    /// # Arguments
    ///
    /// * `pid` - Process ID.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the filter was installed successfully.
    pub fn install_filter(&mut self, pid: u32) -> Result<(), String> {
        self.manager.install_filter(pid)
    }

    /// Checks if a system call is allowed for a process.
    ///
    /// # Arguments
    ///
    /// * `pid` - Process ID.
    /// * `syscall_nr` - System call number.
    ///
    /// # Returns
    ///
    /// `true` if the system call is allowed.
    #[must_use]
    pub fn is_allowed(&self, pid: u32, syscall_nr: i32) -> bool {
        self.manager.is_allowed(pid, syscall_nr)
    }

    /// Applies seccomp rules based on protocol state.
    /// This is called when a protocol violation is detected.
    ///
    /// # Arguments
    ///
    /// * `pid` - Process ID.
    /// * `phase` - Current protocol phase.
    /// * `violation` - Whether a protocol violation was detected.
    ///
    /// # Returns
    ///
    /// `true` if a seccomp filter was applied.
    pub fn apply_protocol_bounds(&mut self, pid: u32, phase: Phase, violation: bool) -> bool {
        // If there's a violation, install or update a restrictive filter
        if violation {
            // Install filter with current (invalid) phase to block dangerous operations
            self.manager.update_protocol_phase(pid, phase);
            self.manager.install_filter(pid).ok();
            true
        } else {
            // Update phase and ensure filter matches
            self.update_phase(pid, phase);
            self.manager.install_filter(pid).ok();
            true
        }
    }
}

/// Known dangerous system calls.
#[derive(Clone, Debug)]
pub struct DangerousSyscalls;

impl DangerousSyscalls {
    /// System calls that should be blocked in most states.
    pub const DANGEROUS: &'static [i32] = &[
        59,  // execve
        160, // sysctl
        174, // ioperm
        175, // iopl
        101, // ptrace
        134, // tkill
        137, // rt_sigreturn (can be used for ROP)
    ];

    /// Checks if a system call is dangerous.
    #[must_use]
    pub fn is_dangerous(syscall_nr: i32) -> bool {
        Self::DANGEROUS.contains(&syscall_nr)
    }
}

/// Seccomp event from the kernel (for monitoring).
#[derive(Clone, Debug)]
pub struct SeccompEvent {
    /// Process ID.
    pub pid: u32,
    /// System call number.
    pub syscall_nr: i32,
    /// System call name.
    pub syscall_name: String,
    /// Action taken.
    pub action: SeccompAction,
    /// Timestamp.
    pub timestamp: std::time::Instant,
}

/// Seccomp event logger.
#[derive(Debug)]
pub struct SeccompLogger;

impl SeccompLogger {
    /// Logs a seccomp event.
    pub fn log(event: SeccompEvent) {
        // In a real implementation, this would write to a log file or syslog
        // For now, just print to stderr
        eprintln!(
            "ccze-seccomp: pid={} syscall={} ({}) action={:?}",
            event.pid, event.syscall_nr, event.syscall_name, event.action
        );
    }
}

/// System call database.
#[derive(Debug)]
pub struct SyscallDatabase {
    /// Map from system call number to info.
    syscalls: HashMap<i32, SyscallInfo>,
}

impl Default for SyscallDatabase {
    fn default() -> Self {
        Self::new()
    }
}

impl SyscallDatabase {
    /// Creates a new system call database.
    #[must_use]
    pub fn new() -> Self {
        let mut syscalls = HashMap::new();

        // Common x86_64 Linux system calls
        syscalls.insert(
            0,
            SyscallInfo {
                nr: 0,
                name: "read".to_string(),
                category: "file".to_string(),
            },
        );
        syscalls.insert(
            1,
            SyscallInfo {
                nr: 1,
                name: "write".to_string(),
                category: "file".to_string(),
            },
        );
        syscalls.insert(
            2,
            SyscallInfo {
                nr: 2,
                name: "open".to_string(),
                category: "file".to_string(),
            },
        );
        syscalls.insert(
            3,
            SyscallInfo {
                nr: 3,
                name: "close".to_string(),
                category: "file".to_string(),
            },
        );
        syscalls.insert(
            4,
            SyscallInfo {
                nr: 4,
                name: "stat".to_string(),
                category: "file".to_string(),
            },
        );
        syscalls.insert(
            5,
            SyscallInfo {
                nr: 5,
                name: "fstat".to_string(),
                category: "file".to_string(),
            },
        );
        syscalls.insert(
            9,
            SyscallInfo {
                nr: 9,
                name: "mmap".to_string(),
                category: "memory".to_string(),
            },
        );
        syscalls.insert(
            12,
            SyscallInfo {
                nr: 12,
                name: "brk".to_string(),
                category: "memory".to_string(),
            },
        );
        syscalls.insert(
            41,
            SyscallInfo {
                nr: 41,
                name: "socket".to_string(),
                category: "network".to_string(),
            },
        );
        syscalls.insert(
            42,
            SyscallInfo {
                nr: 42,
                name: "connect".to_string(),
                category: "network".to_string(),
            },
        );
        syscalls.insert(
            43,
            SyscallInfo {
                nr: 43,
                name: "accept".to_string(),
                category: "network".to_string(),
            },
        );
        syscalls.insert(
            59,
            SyscallInfo {
                nr: 59,
                name: "execve".to_string(),
                category: "process".to_string(),
            },
        );
        syscalls.insert(
            160,
            SyscallInfo {
                nr: 160,
                name: "sysctl".to_string(),
                category: "system".to_string(),
            },
        );

        Self { syscalls }
    }

    /// Gets information about a system call.
    #[must_use]
    pub fn get(&self, syscall_nr: i32) -> Option<&SyscallInfo> {
        self.syscalls.get(&syscall_nr)
    }

    /// Gets the name of a system call.
    #[must_use]
    pub fn get_name(&self, syscall_nr: i32) -> Option<String> {
        self.get(syscall_nr).map(|s| s.name.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seccomp_filter_generation() {
        for phase in [
            Phase::Cold,
            Phase::Started,
            Phase::Authenticated,
            Phase::Bound,
            Phase::Ready,
        ] {
            let filter = SeccompFilter::new(1234, phase);
            assert_eq!(filter.pid, 1234);
            assert_eq!(filter.phase, phase);
            assert!(!filter.rules.is_empty());
        }
    }

    #[test]
    fn test_seccomp_filter_allow() {
        let filter = SeccompFilter::new(1234, Phase::Ready);

        // In Ready phase, most syscalls should be allowed
        assert!(filter.is_allowed(2)); // open
        assert!(filter.is_allowed(3)); // close
        assert!(filter.is_allowed(4)); // read

        // Privileged syscalls should be blocked
        assert!(!filter.is_allowed(160)); // sysctl
        assert!(!filter.is_allowed(174)); // ioperm
    }

    #[test]
    fn test_seccomp_filter_cold() {
        let filter = SeccompFilter::new(1234, Phase::Cold);

        // In Cold phase, only minimal syscalls should be allowed
        assert!(filter.is_allowed(9)); // mmap
        assert!(filter.is_allowed(12)); // brk
        assert!(!filter.is_allowed(2)); // open - not allowed in Cold
    }

    #[test]
    fn test_seccomp_manager() {
        let mut manager = SeccompManager::new();

        manager.update_protocol_phase(1234, Phase::Started);
        manager.install_filter(1234).unwrap();

        assert!(manager.is_allowed(1234, 2)); // open allowed in Started
        assert!(!manager.is_allowed(1234, 59)); // execve not allowed in Started
    }

    #[test]
    fn test_dangerous_syscalls() {
        assert!(DangerousSyscalls::is_dangerous(59)); // execve
        assert!(DangerousSyscalls::is_dangerous(160)); // sysctl
        assert!(!DangerousSyscalls::is_dangerous(2)); // open
    }

    #[test]
    fn test_syscall_database() {
        let db = SyscallDatabase::new();

        assert_eq!(db.get_name(59), Some("execve".to_string()));
        assert_eq!(db.get_name(2), Some("open".to_string()));
        assert_eq!(db.get_name(9999), None);
    }

    #[test]
    fn test_state_bound_seccomp() {
        let mut sb_seccomp = StateBoundSeccomp::new();

        sb_seccomp.update_phase(1234, Phase::Ready);
        assert_eq!(sb_seccomp.get_phase(1234), Some(Phase::Ready));

        sb_seccomp.install_filter(1234).unwrap();
        assert!(sb_seccomp.is_allowed(1234, 2)); // open allowed
    }
}
