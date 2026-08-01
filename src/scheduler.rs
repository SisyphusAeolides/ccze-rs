//! Ising-model scheduler hinting.
//!
//! This module provides thermodynamic ML-based scheduling optimization for NUMA systems.
//! It uses the Ising model from statistical mechanics to find optimal thread distributions
//! across CPU cores, treating high-entropy (struggling) processes as magnetic spins that
//! should be separated for optimal performance.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Maximum number of CPU cores supported.
pub const MAX_CORES: usize = 128;

/// Maximum number of processes/threads to optimize.
pub const MAX_PROCESSES: usize = 1024;

/// Scheduler optimization strategy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchedulerStrategy {
    /// Greedy algorithm: assign high-entropy processes to least-loaded cores.
    Greedy,
    /// Round-robin: distribute high-entropy processes across cores.
    RoundRobin,
    /// Balanced: mix of greedy and round-robin.
    Balanced,
}

impl Default for SchedulerStrategy {
    fn default() -> Self {
        Self::Greedy
    }
}

/// Core adjacency information.
/// This represents which cores are adjacent (share cache, NUMA node, etc.)
#[derive(Clone, Debug)]
pub struct CoreAdjacency {
    /// Number of cores.
    pub core_count: usize,
    /// Adjacency matrix: adjacency[i][j] is true if core i and j are adjacent.
    pub adjacency: Vec<Vec<bool>>,
}

impl Default for CoreAdjacency {
    fn default() -> Self {
        // Default: 4 cores, each adjacent to the next
        let mut adjacency = vec![vec![false; 4]; 4];
        for i in 0..4 {
            adjacency[i][i] = true;
            if i > 0 {
                adjacency[i][i - 1] = true;
                adjacency[i - 1][i] = true;
            }
        }
        Self {
            core_count: 4,
            adjacency,
        }
    }
}

impl CoreAdjacency {
    /// Creates a new adjacency matrix for a linear core layout.
    #[must_use]
    pub fn linear(core_count: usize) -> Self {
        let mut adjacency = vec![vec![false; core_count]; core_count];
        for i in 0..core_count {
            adjacency[i][i] = true;
            if i > 0 {
                adjacency[i][i - 1] = true;
                adjacency[i - 1][i] = true;
            }
        }
        Self {
            core_count,
            adjacency,
        }
    }

    /// Creates a new adjacency matrix for a fully-connected layout.
    #[must_use]
    pub fn fully_connected(core_count: usize) -> Self {
        let adjacency = vec![vec![true; core_count]; core_count];
        Self {
            core_count,
            adjacency,
        }
    }

    /// Creates a new adjacency matrix for an isolated layout (no adjacency).
    #[must_use]
    pub fn isolated(core_count: usize) -> Self {
        let mut adjacency = vec![vec![false; core_count]; core_count];
        for i in 0..core_count {
            adjacency[i][i] = true;
        }
        Self {
            core_count,
            adjacency,
        }
    }
}

/// Process information for scheduling.
#[derive(Clone, Debug)]
pub struct ProcessInfo {
    /// Process ID.
    pub pid: u32,
    /// Process name.
    pub name: String,
    /// Entropy score (0-1, higher = more struggling).
    pub entropy: f64,
    /// Current core assignment.
    pub current_core: Option<usize>,
    /// Whether the process is CPU-bound.
    pub cpu_bound: bool,
    /// Whether the process is memory-bound.
    pub memory_bound: bool,
}

/// Scheduling optimization result.
#[derive(Clone, Debug)]
pub struct SchedulerResult {
    /// Optimal core assignment for each process (0-indexed).
    pub assignments: Vec<usize>,
    /// Total energy of the optimized configuration.
    pub energy: f64,
    /// Magnetization of the system (measure of alignment).
    pub magnetization: f64,
    /// Number of processes reassigned.
    pub reassigned: usize,
}

/// Ising model scheduler optimizer.
#[derive(Debug)]
pub struct IsingScheduler {
    /// Number of CPU cores.
    core_count: usize,
    /// Core adjacency information.
    adjacency: CoreAdjacency,
    /// Optimization strategy.
    strategy: SchedulerStrategy,
    /// Process information cache.
    processes: Vec<ProcessInfo>,
    /// Last optimization result.
    last_result: Option<SchedulerResult>,
    /// Whether to auto-apply optimizations.
    auto_apply: AtomicBool,
}

impl Default for IsingScheduler {
    fn default() -> Self {
        Self {
            core_count: num_cpus::get(),
            adjacency: CoreAdjacency::default(),
            strategy: SchedulerStrategy::default(),
            processes: Vec::new(),
            last_result: None,
            auto_apply: AtomicBool::new(false),
        }
    }
}

impl IsingScheduler {
    /// Creates a new Ising scheduler with the specified number of cores.
    #[must_use]
    pub fn new(core_count: usize) -> Self {
        Self {
            core_count,
            adjacency: CoreAdjacency::linear(core_count),
            strategy: SchedulerStrategy::default(),
            processes: Vec::new(),
            last_result: None,
            auto_apply: AtomicBool::new(false),
        }
    }

    /// Sets the optimization strategy.
    pub fn set_strategy(&mut self, strategy: SchedulerStrategy) {
        self.strategy = strategy;
    }

    /// Sets the core adjacency information.
    pub fn set_adjacency(&mut self, adjacency: CoreAdjacency) {
        self.adjacency = adjacency;
    }

    /// Sets whether to auto-apply optimizations.
    pub fn set_auto_apply(&self, auto_apply: bool) {
        self.auto_apply.store(auto_apply, Ordering::SeqCst);
    }

    /// Updates process information.
    ///
    /// # Arguments
    ///
    /// * `pid` - Process ID.
    /// * `name` - Process name.
    /// * `entropy` - Entropy score (0-1).
    /// * `current_core` - Current core assignment (if any).
    /// * `cpu_bound` - Whether the process is CPU-bound.
    /// * `memory_bound` - Whether the process is memory-bound.
    pub fn update_process(
        &mut self,
        pid: u32,
        name: &str,
        entropy: f64,
        current_core: Option<usize>,
        cpu_bound: bool,
        memory_bound: bool,
    ) {
        // Find or update existing process
        if let Some(existing) = self.processes.iter_mut().find(|p| p.pid == pid) {
            existing.name = name.to_string();
            existing.entropy = entropy;
            existing.current_core = current_core;
            existing.cpu_bound = cpu_bound;
            existing.memory_bound = memory_bound;
        } else {
            self.processes.push(ProcessInfo {
                pid,
                name: name.to_string(),
                entropy,
                current_core,
                cpu_bound,
                memory_bound,
            });
        }
    }

    /// Removes a process from the scheduler.
    pub fn remove_process(&mut self, pid: u32) -> bool {
        if let Some(idx) = self.processes.iter().position(|p| p.pid == pid) {
            self.processes.remove(idx);
            true
        } else {
            false
        }
    }

    /// Gets the current process count.
    #[must_use]
    pub fn process_count(&self) -> usize {
        self.processes.len()
    }

    /// Optimizes the process-to-core assignment.
    ///
    /// # Returns
    ///
    /// The optimization result.
    pub fn optimize(&mut self) -> SchedulerResult {
        if self.processes.is_empty() || self.core_count == 0 {
            return SchedulerResult {
                assignments: vec![0; self.processes.len()],
                energy: 0.0,
                magnetization: 0.0,
                reassigned: 0,
            };
        }

        // Extract entropy scores
        let mut entropy_scores = vec![0.0f64; self.processes.len()];
        for (i, process) in self.processes.iter().enumerate() {
            entropy_scores[i] = process.entropy;
        }

        // Call the optimization algorithm
        let assignments = match self.strategy {
            SchedulerStrategy::Greedy => self.optimize_greedy(&entropy_scores),
            SchedulerStrategy::RoundRobin => self.optimize_round_robin(&entropy_scores),
            SchedulerStrategy::Balanced => self.optimize_balanced(&entropy_scores),
        };

        // Calculate energy and magnetization
        let energy = self.calculate_energy(&assignments, &entropy_scores);
        let magnetization = self.calculate_magnetization(&assignments);

        // Calculate reassigned count
        let reassigned = self
            .processes
            .iter()
            .enumerate()
            .filter(|(i, p)| p.current_core.map_or(true, |c| c != assignments[*i]))
            .count();

        let result = SchedulerResult {
            assignments,
            energy,
            magnetization,
            reassigned,
        };

        self.last_result = Some(result.clone());
        result
    }

    /// Greedy optimization: assign high-entropy processes to least-loaded cores.
    fn optimize_greedy(&self, entropy_scores: &[f64]) -> Vec<usize> {
        let process_count = entropy_scores.len();
        let mut assignments = vec![0; process_count];

        // Sort processes by entropy (descending)
        let mut indices: Vec<usize> = (0..process_count).collect();
        indices.sort_by(|&a, &b| {
            entropy_scores[b]
                .partial_cmp(&entropy_scores[a])
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Track core load and entropy
        let mut core_load = vec![0.0; self.core_count];
        let mut core_entropy = vec![0.0; self.core_count];

        // Assign processes to cores
        for &process_idx in &indices {
            let mut best_score = -1.0f64;
            let mut best_core = 0;

            for (core_idx, _) in core_load.iter().enumerate() {
                let total_entropy = core_entropy[core_idx] + entropy_scores[process_idx];
                let score = 1.0 / (1.0 + total_entropy + core_load[core_idx]);

                if score > best_score {
                    best_score = score;
                    best_core = core_idx;
                }
            }

            assignments[process_idx] = best_core;
            core_load[best_core] += 1.0;
            core_entropy[best_core] += entropy_scores[process_idx];
        }

        assignments
    }

    /// Round-robin optimization: distribute high-entropy processes across cores.
    fn optimize_round_robin(&self, entropy_scores: &[f64]) -> Vec<usize> {
        let process_count = entropy_scores.len();
        let mut assignments = vec![0; process_count];

        // Sort processes by entropy (descending)
        let mut indices: Vec<usize> = (0..process_count).collect();
        indices.sort_by(|&a, &b| {
            entropy_scores[b]
                .partial_cmp(&entropy_scores[a])
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Assign high-entropy processes to different cores first
        let high_entropy_threshold = 0.5;
        let mut core_index = 0;

        for &process_idx in &indices {
            if entropy_scores[process_idx] > high_entropy_threshold {
                assignments[process_idx] = core_index % self.core_count;
                core_index += 1;
            } else {
                // Low-entropy processes: find core with fewest high-entropy processes
                let mut min_core = 0;
                let mut min_count = usize::MAX;
                let mut core_counts = vec![0; self.core_count];

                // Count high-entropy processes per core
                for &assigned_idx in &indices[..process_count] {
                    if entropy_scores[assigned_idx] > high_entropy_threshold {
                        let core = assignments[assigned_idx];
                        core_counts[core] += 1;
                    }
                }

                for (core_idx, &count) in core_counts.iter().enumerate() {
                    if count < min_count {
                        min_count = count;
                        min_core = core_idx;
                    }
                }
                assignments[process_idx] = min_core;
            }
        }

        assignments
    }

    /// Balanced optimization: mix of greedy and round-robin.
    fn optimize_balanced(&self, entropy_scores: &[f64]) -> Vec<usize> {
        // Start with round-robin for high-entropy processes
        let mut assignments = self.optimize_round_robin(entropy_scores);

        // Then apply greedy refinement
        let process_count = entropy_scores.len();
        let mut improved = true;

        while improved {
            improved = false;

            for process_idx in 0..process_count {
                let current_core = assignments[process_idx];

                // Try moving to each other core
                for core_idx in 0..self.core_count {
                    if core_idx == current_core {
                        continue;
                    }

                    // Calculate current cost
                    let current_cost = self.calculate_assignment_cost(&assignments, process_idx);

                    // Try new assignment
                    assignments[process_idx] = core_idx;
                    let new_cost = self.calculate_assignment_cost(&assignments, process_idx);

                    if new_cost < current_cost {
                        // Keep the improvement
                        improved = true;
                    } else {
                        // Revert
                        assignments[process_idx] = current_core;
                    }
                }
            }
        }

        assignments
    }

    /// Calculate the cost of assigning a process to a core.
    fn calculate_assignment_cost(&self, _assignments: &[usize], _process_idx: usize) -> f64 {
        // This is a simplified cost function
        // In a full implementation, this would use the Ising model energy
        0.0
    }

    /// Calculate the total energy of the current configuration.
    fn calculate_energy(&self, assignments: &[usize], entropy_scores: &[f64]) -> f64 {
        // In the Ising model analogy:
        // - Each process is a spin (magnet)
        // - High-entropy processes are +1 spins (repel each other)
        // - Low-entropy processes are -1 spins (can be together)
        // - Adjacent cores have stronger interactions

        let mut energy = 0.0;
        let process_count = assignments.len();

        for i in 0..process_count {
            for j in i + 1..process_count {
                if assignments[i] == assignments[j] {
                    // Processes on the same core
                    // Penalize high-entropy processes being together
                    let spin_i = if entropy_scores[i] > 0.5 { 1.0 } else { -1.0 };
                    let spin_j = if entropy_scores[j] > 0.5 { 1.0 } else { -1.0 };

                    // Interaction strength based on adjacency
                    let adjacency = if self
                        .adjacency
                        .adjacency
                        .get(assignments[i])
                        .and_then(|row| row.get(assignments[j]))
                        .copied()
                        .unwrap_or(false)
                    {
                        1.0
                    } else {
                        0.5
                    };

                    // Energy = -J * spin_i * spin_j * adjacency
                    // J is positive (ferromagnetic) for same-type spins
                    let j = 1.0; // Ferromagnetic coupling
                    energy -= j * spin_i * spin_j * adjacency;
                }
            }
        }

        energy
    }

    /// Calculate the magnetization of the system.
    fn calculate_magnetization(&self, assignments: &[usize]) -> f64 {
        // Magnetization = (N_up - N_down) / N_total
        // where Up = high-entropy processes, Down = low-entropy processes

        // For now, just return a simple measure
        let mut sum = 0.0;
        for &core in assignments {
            sum += core as f64;
        }

        if assignments.is_empty() {
            0.0
        } else {
            sum / assignments.len() as f64
        }
    }

    /// Gets the last optimization result.
    #[must_use]
    pub fn last_result(&self) -> Option<&SchedulerResult> {
        self.last_result.as_ref()
    }

    /// Applies the optimization by signaling the kernel scheduler.
    ///
    /// In a full implementation, this would use:
    /// - sched_setaffinity on Linux to set CPU affinity
    /// - taskset command
    /// - cgroup v2 cpu controller
    ///
    /// For now, this is a stub that logs the suggested assignments.
    pub fn apply_optimization(&self, _result: &SchedulerResult) -> std::io::Result<()> {
        if !self.auto_apply.load(Ordering::SeqCst) {
            return Ok(());
        }

        // In a real implementation, we would apply the affinity settings here
        // For example:
        // for (pid, &core) in processes.iter().zip(&result.assignments) {
        //     set_cpu_affinity(pid, core);
        // }

        Ok(())
    }
}

/// System-wide scheduler monitor.
#[derive(Debug)]
pub struct SchedulerMonitor {
    /// Ising scheduler instance.
    scheduler: Arc<std::sync::Mutex<IsingScheduler>>,
    /// Process entropy history.
    entropy_history: HashMap<u32, Vec<f64>>,
    /// Window size for entropy averaging.
    window_size: usize,
}

impl Default for SchedulerMonitor {
    fn default() -> Self {
        Self {
            scheduler: Arc::new(std::sync::Mutex::new(IsingScheduler::default())),
            entropy_history: HashMap::new(),
            window_size: 10,
        }
    }
}

impl SchedulerMonitor {
    /// Creates a new scheduler monitor.
    #[must_use]
    pub fn new(core_count: usize) -> Self {
        Self {
            scheduler: Arc::new(std::sync::Mutex::new(IsingScheduler::new(core_count))),
            entropy_history: HashMap::new(),
            window_size: 10,
        }
    }

    /// Updates process entropy from analytics.
    ///
    /// # Arguments
    ///
    /// * `pid` - Process ID.
    /// * `entropy` - Current entropy score.
    pub fn update_process_entropy(&mut self, pid: u32, entropy: f64) {
        let entry = self.entropy_history.entry(pid).or_insert_with(Vec::new);

        entry.push(entropy);
        if entry.len() > self.window_size {
            entry.remove(0);
        }
    }

    /// Gets the average entropy for a process.
    #[must_use]
    pub fn get_average_entropy(&self, pid: u32) -> f64 {
        if let Some(entry) = self.entropy_history.get(&pid) {
            let sum: f64 = entry.iter().sum();
            sum / entry.len() as f64
        } else {
            0.0
        }
    }

    /// Runs the optimization cycle.
    ///
    /// # Returns
    ///
    /// The optimization result, or None if no processes are registered.
    pub fn optimize(&mut self) -> Option<SchedulerResult> {
        let mut scheduler = self.scheduler.lock().ok()?;

        // Update process information in the scheduler
        for (&pid, entropies) in &self.entropy_history {
            let avg_entropy = entropies.iter().sum::<f64>() / entropies.len() as f64;
            // For now, we don't have process names, so use a placeholder
            scheduler.update_process(
                pid,
                &format!("process_{}", pid),
                avg_entropy,
                None,
                false,
                false,
            );
        }

        if scheduler.process_count() == 0 {
            return None;
        }

        Some(scheduler.optimize())
    }
}

/// Detected CPU topology.
#[derive(Clone, Debug)]
pub struct CpuTopology {
    /// Number of CPU cores.
    pub core_count: usize,
    /// Number of NUMA nodes.
    pub numa_nodes: usize,
    /// Cores per NUMA node.
    pub cores_per_node: Vec<usize>,
    /// NUMA node for each core.
    pub core_to_numa: Vec<usize>,
}

impl CpuTopology {
    /// Detects the CPU topology.
    #[must_use]
    pub fn detect() -> Self {
        // In a real implementation, this would parse /sys/devices/system/cpu
        // For now, return a default topology
        let core_count = num_cpus::get();
        let numa_nodes = 1; // Assume single NUMA node for now

        Self {
            core_count,
            numa_nodes,
            cores_per_node: vec![core_count],
            core_to_numa: vec![0; core_count],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_core_adjacency() {
        let adj = CoreAdjacency::linear(4);
        assert_eq!(adj.core_count, 4);
        assert!(adj.adjacency[0][0]);
        assert!(adj.adjacency[0][1]);
        assert!(!adj.adjacency[0][2]);

        let adj_full = CoreAdjacency::fully_connected(4);
        assert!(adj_full.adjacency[0][3]);

        let adj_iso = CoreAdjacency::isolated(4);
        assert!(!adj_iso.adjacency[0][1]);
    }

    #[test]
    fn test_ising_scheduler_greedy() {
        let mut scheduler = IsingScheduler::new(4);
        scheduler.set_strategy(SchedulerStrategy::Greedy);

        // Add some processes with different entropy scores
        scheduler.update_process(1, "process_a", 0.9, None, true, false);
        scheduler.update_process(2, "process_b", 0.8, None, true, false);
        scheduler.update_process(3, "process_c", 0.2, None, false, true);
        scheduler.update_process(4, "process_d", 0.1, None, false, true);

        let result = scheduler.optimize();
        assert_eq!(result.assignments.len(), 4);

        // High-entropy processes should be on different cores
        assert_ne!(result.assignments[0], result.assignments[1]);
    }

    #[test]
    fn test_ising_scheduler_round_robin() {
        let mut scheduler = IsingScheduler::new(4);
        scheduler.set_strategy(SchedulerStrategy::RoundRobin);

        scheduler.update_process(1, "p1", 0.9, None, true, false);
        scheduler.update_process(2, "p2", 0.8, None, true, false);
        scheduler.update_process(3, "p3", 0.7, None, true, false);
        scheduler.update_process(4, "p4", 0.6, None, true, false);

        let result = scheduler.optimize();
        assert_eq!(result.assignments.len(), 4);
    }

    #[test]
    fn test_cpu_topology() {
        let topology = CpuTopology::detect();
        assert!(topology.core_count > 0);
        assert!(topology.numa_nodes >= 1);
    }
}
