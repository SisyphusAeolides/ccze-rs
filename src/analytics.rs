//! Batched stream analytics implemented through a Fortran-compatible C ABI.

use std::collections::VecDeque;
use std::ffi::{c_double, c_int};

extern "C" {
    fn ccze_analyze_metrics(
        lengths: *const c_int,
        errors: *const c_int,
        count: usize,
        threshold: c_double,
        zscore: *mut c_double,
        entropy: *mut c_double,
        anomaly: *mut c_int,
    );
}

/// Analytics output for the current rolling window.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Analysis {
    pub zscore: f64,
    pub error_entropy: f64,
    pub anomaly: bool,
}

/// Fixed-capacity metric window reused across the input stream.
#[derive(Debug)]
pub struct AnalyticsWindow {
    capacity: usize,
    threshold: f64,
    lengths: VecDeque<c_int>,
    errors: VecDeque<c_int>,
    length_batch: Vec<c_int>,
    error_batch: Vec<c_int>,
}

impl AnalyticsWindow {
    /// Creates an analytics window. Capacity is clamped to at least two samples.
    #[must_use]
    pub fn new(capacity: usize, threshold: f64) -> Self {
        let capacity = capacity.max(2);
        Self {
            capacity,
            threshold,
            lengths: VecDeque::with_capacity(capacity),
            errors: VecDeque::with_capacity(capacity),
            length_batch: Vec::with_capacity(capacity),
            error_batch: Vec::with_capacity(capacity),
        }
    }

    /// Adds a metric and analyzes the current window.
    pub fn push(&mut self, length: usize, is_error: bool) -> Analysis {
        if self.lengths.len() == self.capacity {
            self.lengths.pop_front();
            self.errors.pop_front();
        }
        self.lengths
            .push_back(c_int::try_from(length).unwrap_or(c_int::MAX));
        self.errors.push_back(c_int::from(is_error));

        self.length_batch.clear();
        self.length_batch.extend(self.lengths.iter().copied());
        self.error_batch.clear();
        self.error_batch.extend(self.errors.iter().copied());

        let mut result = Analysis::default();
        let mut anomaly = 0;
        // All pointers refer to initialized contiguous vectors and remain valid for the call.
        unsafe {
            ccze_analyze_metrics(
                self.length_batch.as_ptr(),
                self.error_batch.as_ptr(),
                self.length_batch.len(),
                self.threshold,
                &mut result.zscore,
                &mut result.error_entropy,
                &mut anomaly,
            );
        }
        result.anomaly = anomaly != 0;
        result
    }

    /// Reports which implementation was selected at build time.
    #[must_use]
    pub const fn backend() -> &'static str {
        env!("CCZE_ANALYTICS_BACKEND")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_length_outliers() {
        let mut window = AnalyticsWindow::new(8, 2.0);
        for _ in 0..7 {
            assert!(!window.push(10, false).anomaly);
        }
        assert!(window.push(1_000, false).anomaly);
    }

    #[test]
    fn detects_error_spikes() {
        let mut window = AnalyticsWindow::new(4, 10.0);
        window.push(10, false);
        window.push(10, false);
        let result = window.push(10, true);
        assert!(!result.anomaly);
        assert!(window.push(10, true).anomaly);
    }
}
