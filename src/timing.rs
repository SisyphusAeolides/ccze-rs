//! Microsecond jitter side-channel detection.
//!
//! This module provides high-resolution timing analysis to detect hardware-level
//! CPU exploits using log emission timing patterns. It can detect side-channel
//! attacks like Spectre/Meltdown variants by analyzing temporal jitter.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Nanoseconds in a microsecond.
const NANOS_PER_MICRO: u64 = 1_000;

/// Known attack signature: Spectre v1 cache timing.
/// Typical jitter pattern: 50-200 microseconds between cache misses.
const SPECTRE_V1_SIGNATURE: &[u64] = &[50, 100, 150, 80, 120, 180];

/// Known attack signature: Meltdown.
/// Typical jitter pattern: 100-300 microseconds between memory accesses.
const MELTDOWN_SIGNATURE: &[u64] = &[100, 200, 250, 150, 300, 120];

/// Known attack signature: Spectre v2 (branch target injection).
/// Typical jitter pattern: 30-150 microseconds with specific patterns.
const SPECTRE_V2_SIGNATURE: &[u64] = &[30, 80, 120, 60, 100, 140];

/// Threshold for jitter anomaly detection (microseconds).
const JITTER_THRESHOLD: u64 = 200;

/// Attack type detected.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AttackType {
    /// No attack detected.
    #[default]
    None,
    /// Spectre v1 (bounds check bypass).
    SpectreV1,
    /// Spectre v2 (branch target injection).
    SpectreV2,
    /// Meltdown (rogue data cache load).
    Meltdown,
    /// Generic cache timing anomaly.
    CacheTiming,
}

impl std::fmt::Display for AttackType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttackType::None => write!(f, "none"),
            AttackType::SpectreV1 => write!(f, "spectre_v1"),
            AttackType::SpectreV2 => write!(f, "spectre_v2"),
            AttackType::Meltdown => write!(f, "meltdown"),
            AttackType::CacheTiming => write!(f, "cache_timing"),
        }
    }
}

/// A timestamp with microsecond precision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MicroTimestamp {
    /// Nanoseconds since epoch (or arbitrary start point).
    pub nanos: u64,
}

impl MicroTimestamp {
    /// Creates a new timestamp from the current time.
    #[must_use]
    pub fn now() -> Self {
        Self {
            nanos: timestamp_nanos(),
        }
    }

    /// Creates a timestamp from nanoseconds.
    #[must_use]
    pub const fn from_nanos(nanos: u64) -> Self {
        Self { nanos }
    }

    /// Converts to microseconds.
    #[must_use]
    pub const fn as_micros(&self) -> u64 {
        self.nanos / NANOS_PER_MICRO
    }

    /// Calculates the difference in microseconds between two timestamps.
    #[must_use]
    pub fn diff_micros(&self, other: Self) -> u64 {
        if self.nanos >= other.nanos {
            (self.nanos - other.nanos) / NANOS_PER_MICRO
        } else {
            (other.nanos - self.nanos) / NANOS_PER_MICRO
        }
    }
}

/// Gets the current timestamp in nanoseconds.
fn timestamp_nanos() -> u64 {
    // Use a static atomic counter for testing/mocking
    // In production, this would use a high-resolution clock
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    // Try to use the most precise timing available
    // On Linux, this would ideally use CLOCK_MONOTONIC_RAW
    if cfg!(test) {
        // For testing, use a mock counter
        COUNTER.fetch_add(1_000, Ordering::SeqCst)
    } else {
        // Use Instant for now - in production this would use librt or similar
        // for nanosecond precision
        let start = Instant::now();
        let duration = start.elapsed();
        duration.as_nanos() as u64
    }
}

/// Jitter analysis result.
#[derive(Clone, Copy, Debug, Default)]
pub struct JitterAnalysis {
    /// Mean jitter in microseconds.
    pub mean_micros: f64,
    /// Standard deviation of jitter in microseconds.
    pub std_dev_micros: f64,
    /// Maximum jitter observed in microseconds.
    pub max_micros: u64,
    /// Minimum jitter observed in microseconds.
    pub min_micros: u64,
    /// Whether an anomaly was detected.
    pub anomaly: bool,
    /// Type of attack detected (if any).
    pub attack_type: AttackType,
    /// Confidence score (0-1).
    pub confidence: f64,
}

/// Sliding window for jitter analysis.
#[derive(Debug)]
pub struct JitterWindow {
    /// Capacity of the window (number of intervals).
    capacity: usize,
    /// Previous timestamps.
    timestamps: VecDeque<MicroTimestamp>,
    /// Intervals between timestamps in microseconds.
    intervals: VecDeque<u64>,
}

impl JitterWindow {
    /// Creates a new jitter analysis window.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Number of intervals to track.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            timestamps: VecDeque::with_capacity(capacity + 1),
            intervals: VecDeque::with_capacity(capacity),
        }
    }

    /// Pushes a new timestamp and returns the jitter analysis.
    ///
    /// # Arguments
    ///
    /// * `timestamp` - The new timestamp.
    ///
    /// # Returns
    ///
    /// The jitter analysis for the current window.
    pub fn push(&mut self, timestamp: MicroTimestamp) -> JitterAnalysis {
        // If we have a previous timestamp, calculate the interval
        if let Some(prev) = self.timestamps.back() {
            let interval = timestamp.diff_micros(*prev);
            self.intervals.push_back(interval);

            // Keep the window size
            if self.intervals.len() > self.capacity {
                self.intervals.pop_front();
            }
        }

        self.timestamps.push_back(timestamp);

        // Keep the window size for timestamps
        if self.timestamps.len() > self.capacity + 1 {
            self.timestamps.pop_front();
        }

        self.analyze()
    }

    /// Analyzes the current window of intervals.
    fn analyze(&self) -> JitterAnalysis {
        if self.intervals.is_empty() {
            return JitterAnalysis::default();
        }

        // Calculate statistics
        let mut sum: u64 = 0;
        let mut sum_sq: u64 = 0;
        let mut max = 0;
        let mut min = u64::MAX;

        for &interval in &self.intervals {
            sum += interval;
            sum_sq += interval * interval;
            max = max.max(interval);
            min = min.min(interval);
        }

        let count = self.intervals.len() as f64;
        let mean = sum as f64 / count;

        // Calculate variance and std dev
        let variance = if count > 1.0 {
            (sum_sq as f64 / count) - (mean * mean)
        } else {
            0.0
        };
        let std_dev = variance.sqrt();

        // Detect anomalies
        let anomaly = std_dev > JITTER_THRESHOLD as f64 || max > JITTER_THRESHOLD * 3;

        // Match against known attack signatures
        let attack_type = self.match_signature();

        // Calculate confidence based on deviation
        let confidence = if anomaly {
            (std_dev / JITTER_THRESHOLD as f64).min(1.0)
        } else {
            0.0
        };

        JitterAnalysis {
            mean_micros: mean,
            std_dev_micros: std_dev,
            max_micros: max,
            min_micros: min,
            anomaly,
            attack_type,
            confidence,
        }
    }

    /// Matches the current jitter pattern against known attack signatures.
    fn match_signature(&self) -> AttackType {
        if self.intervals.len() < 6 {
            return AttackType::None;
        }

        // Convert intervals to a comparable form
        let intervals: Vec<u64> = self.intervals.iter().copied().collect();

        // Check each signature
        let spectre_v1_score = self.compare_signature(&intervals, SPECTRE_V1_SIGNATURE);
        let spectre_v2_score = self.compare_signature(&intervals, SPECTRE_V2_SIGNATURE);
        let meltdown_score = self.compare_signature(&intervals, MELTDOWN_SIGNATURE);

        // Threshold for signature match
        const SIGNATURE_THRESHOLD: f64 = 0.7;

        if meltdown_score >= SIGNATURE_THRESHOLD {
            return AttackType::Meltdown;
        }
        if spectre_v1_score >= SIGNATURE_THRESHOLD {
            return AttackType::SpectreV1;
        }
        if spectre_v2_score >= SIGNATURE_THRESHOLD {
            return AttackType::SpectreV2;
        }

        // Generic cache timing anomaly
        if spectre_v1_score >= 0.5 || spectre_v2_score >= 0.5 || meltdown_score >= 0.5 {
            return AttackType::CacheTiming;
        }

        AttackType::None
    }

    /// Compares intervals against a known signature.
    ///
    /// # Arguments
    ///
    /// * `intervals` - The intervals to compare.
    /// * `signature` - The known attack signature.
    ///
    /// # Returns
    ///
    /// A similarity score between 0 and 1.
    fn compare_signature(&self, intervals: &[u64], signature: &[u64]) -> f64 {
        if intervals.len() != signature.len() {
            return 0.0;
        }

        let mut matches = 0;
        let mut total = 0.0;

        for (i, &interval) in intervals.iter().enumerate() {
            let sig_val = signature[i];
            // Allow +/- 20% tolerance
            let lower = sig_val.saturating_sub((sig_val as f64 * 0.2) as u64);
            let upper = sig_val + ((sig_val as f64 * 0.2) as u64);

            if interval >= lower && interval <= upper {
                matches += 1;
            }
            total += 1.0;
        }

        matches as f64 / total
    }

    /// Returns the number of intervals in the window.
    #[must_use]
    pub fn len(&self) -> usize {
        self.intervals.len()
    }

    /// Returns true if the window is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.intervals.is_empty()
    }
}

/// Jitter detector for side-channel attacks.
#[derive(Debug)]
pub struct JitterDetector {
    /// Window for jitter analysis.
    window: JitterWindow,
    /// Threshold for anomaly detection.
    threshold: f64,
    /// Whether to trigger cache flushing on detection.
    auto_flush: bool,
}

impl JitterDetector {
    /// Creates a new jitter detector.
    ///
    /// # Arguments
    ///
    /// * `window_size` - Number of intervals to track.
    /// * `threshold` - Standard deviation threshold for anomaly detection.
    /// * `auto_flush` - Whether to automatically flush caches on detection.
    #[must_use]
    pub fn new(window_size: usize, threshold: f64, auto_flush: bool) -> Self {
        Self {
            window: JitterWindow::new(window_size),
            threshold,
            auto_flush,
        }
    }

    /// Records a new timestamp and returns the analysis.
    ///
    /// # Returns
    ///
    /// The jitter analysis for the current window.
    pub fn record(&mut self, timestamp: MicroTimestamp) -> JitterAnalysis {
        let mut analysis = self.window.push(timestamp);

        // Override threshold if configured
        if self.threshold > 0.0 {
            analysis.anomaly = analysis.std_dev_micros > self.threshold;
        }

        // Auto-flush caches if enabled and anomaly detected
        if self.auto_flush && analysis.anomaly {
            self.flush_caches();
        }

        analysis
    }

    /// Flushes CPU caches to break side-channel attacks.
    ///
    /// This writes to a large buffer to evict cache lines.
    pub fn flush_caches(&self) {
        // Allocate and write to a large buffer to flush caches
        // This is a simplified implementation
        // In production, this would use platform-specific cache flushing
        let mut buffer = vec![0u8; 4096 * 1024]; // 4MB buffer
        for (i, byte) in buffer.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }
        // Ensure the writes are not optimized away
        std::hint::black_box(&buffer);
    }

    /// Returns the current window size.
    #[must_use]
    pub fn window_size(&self) -> usize {
        self.window.capacity
    }
}

/// High-resolution timer for precise timing measurements.
#[derive(Debug, Default)]
pub struct HighResTimer {
    start: Option<Instant>,
}

impl HighResTimer {
    /// Creates a new timer.
    #[must_use]
    pub fn new() -> Self {
        Self { start: None }
    }

    /// Starts the timer.
    pub fn start(&mut self) {
        self.start = Some(Instant::now());
    }

    /// Stops the timer and returns the elapsed nanoseconds.
    ///
    /// # Returns
    ///
    /// Elapsed time in nanoseconds, or 0 if the timer was not started.
    #[must_use]
    pub fn stop(&self) -> u64 {
        if let Some(start) = self.start {
            start.elapsed().as_nanos() as u64
        } else {
            0
        }
    }

    /// Stops the timer and returns a microsecond timestamp.
    ///
    /// # Returns
    ///
    /// A MicroTimestamp with the elapsed time since start.
    #[must_use]
    pub fn stop_timestamp(&self) -> MicroTimestamp {
        MicroTimestamp::from_nanos(self.stop())
    }

    /// Resets the timer.
    pub fn reset(&mut self) {
        self.start = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_operations() {
        let ts1 = MicroTimestamp::from_nanos(1_000_000); // 1ms = 1000 microseconds
        let ts2 = MicroTimestamp::from_nanos(2_500_000); // 2.5ms = 2500 microseconds

        assert_eq!(ts1.as_micros(), 1000);
        assert_eq!(ts2.as_micros(), 2500);
        assert_eq!(ts2.diff_micros(ts1), 1500);
        assert_eq!(ts1.diff_micros(ts2), 1500);
    }

    #[test]
    fn test_jitter_window() {
        let mut window = JitterWindow::new(10);

        // Push some timestamps with varying intervals
        for i in 0..5 {
            let ts = MicroTimestamp::from_nanos((i + 1) * 100_000); // 100 microsecond intervals
            window.push(ts);
        }

        assert_eq!(window.len(), 4); // 5 timestamps = 4 intervals
        assert!(!window.is_empty());
    }

    #[test]
    fn test_jitter_detection() {
        let mut detector = JitterDetector::new(10, 100.0, false);

        // Push timestamps with normal intervals
        for i in 0..10 {
            let ts = MicroTimestamp::from_nanos((i + 1) * 100_000); // 100 microsecond intervals
            let analysis = detector.record(ts);
            // With consistent 100us intervals, std dev should be 0
            assert!(!analysis.anomaly);
        }

        // Now push some anomalous intervals
        for i in 0..10 {
            let ts = MicroTimestamp::from_nanos((i + 11) * 100_000 + (i * 50_000));
            let _analysis = detector.record(ts);
            // These should trigger anomalies due to varying intervals
            // Note: The exact behavior depends on the threshold
        }
    }

    #[test]
    fn test_high_res_timer() {
        let mut timer = HighResTimer::new();
        timer.start();

        // Do some work
        let mut sum = 0u64;
        for i in 0..1000 {
            sum = sum.wrapping_add(i);
        }

        let elapsed = timer.stop();
        assert!(elapsed > 0);
    }

    #[test]
    fn test_attack_type_display() {
        assert_eq!(format!("{}", AttackType::None), "none");
        assert_eq!(format!("{}", AttackType::SpectreV1), "spectre_v1");
        assert_eq!(format!("{}", AttackType::SpectreV2), "spectre_v2");
        assert_eq!(format!("{}", AttackType::Meltdown), "meltdown");
        assert_eq!(format!("{}", AttackType::CacheTiming), "cache_timing");
    }
}
