//! Severity reduction backed by the Agda-specified join operation.

use std::fmt;

/// Ordered syslog-style severity levels.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
#[repr(i32)]
pub enum Severity {
    Trace = 0,
    Debug = 1,
    #[default]
    Info = 2,
    Warn = 3,
    Error = 4,
    Fatal = 5,
}

extern "C" {
    fn ccze_severity_join(left: i32, right: i32) -> i32;
}

impl Severity {
    /// Computes the least severity at least as strong as both operands.
    #[must_use]
    pub fn join(self, other: Self) -> Self {
        // Both values come from a repr(i32) enum, and the C function accepts the full range.
        let value = unsafe { ccze_severity_join(self as i32, other as i32) };
        Self::from_code(value)
    }

    const fn from_code(value: i32) -> Self {
        match value {
            0 => Self::Trace,
            1 => Self::Debug,
            3 => Self::Warn,
            4 => Self::Error,
            5 => Self::Fatal,
            _ => Self::Info,
        }
    }

    /// Infers severity from conventional log terms without allocating.
    #[must_use]
    pub fn detect(line: &[u8]) -> Self {
        let mut result = Self::Info;
        for (needle, severity) in [
            (b"trace".as_slice(), Self::Trace),
            (b"debug".as_slice(), Self::Debug),
            (b"warn".as_slice(), Self::Warn),
            (b"error".as_slice(), Self::Error),
            (b"failed".as_slice(), Self::Error),
            (b"panic".as_slice(), Self::Fatal),
            (b"fatal".as_slice(), Self::Fatal),
        ] {
            if find_ascii_case_insensitive(line, needle).is_some() {
                result = result.join(severity);
            }
        }
        result
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
            Self::Fatal => "fatal",
        })
    }
}

/// Finds an ASCII needle case-insensitively and returns its byte offset.
#[must_use]
pub fn find_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_is_commutative_and_idempotent() {
        let values = [
            Severity::Trace,
            Severity::Debug,
            Severity::Info,
            Severity::Warn,
            Severity::Error,
            Severity::Fatal,
        ];
        for left in values {
            assert_eq!(left.join(left), left);
            for right in values {
                assert_eq!(left.join(right), right.join(left));
                assert_eq!(left.join(right), left.max(right));
            }
        }
    }

    #[test]
    fn detection_is_case_insensitive() {
        assert_eq!(Severity::detect(b"Kernel PANIC"), Severity::Fatal);
        assert_eq!(Severity::detect(b"ordinary notice"), Severity::Info);
    }
}
