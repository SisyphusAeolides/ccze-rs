//! Streaming log parsing, colorization, analytics, and protocol verification.

pub mod analytics;
#[cfg(feature = "system-integration")]
pub mod cgroup;
#[cfg(feature = "system-integration")]
pub mod config;
#[cfg(feature = "system-integration")]
pub mod dkms;
#[cfg(feature = "system-integration")]
pub mod gossip;
#[cfg(feature = "system-integration")]
pub mod lsm;
pub mod parser;
pub mod protocol;
#[cfg(feature = "system-integration")]
pub mod rollback;
#[cfg(feature = "system-integration")]
pub mod scheduler;
#[cfg(feature = "system-integration")]
pub mod seccomp;
pub mod severity;
#[cfg(feature = "system-integration")]
pub mod timing;
pub mod vector;
#[cfg(feature = "system-integration")]
pub mod xdp;
#[cfg(feature = "system-integration")]
pub mod zram;

use parser::{LogParser, Token, TokenKind};

/// Available parser names accepted by the command-line interface.
pub const PLUGINS: &[&str] = &["auto", "syslog", "httpd", "json"];

/// Reusable line processor that avoids copying input while parsing.
pub struct Processor {
    parser: Box<dyn LogParser + Send + Sync>,
    tokens: Vec<Token>,
}

impl Processor {
    /// Creates a processor for a named parser.
    ///
    /// # Errors
    ///
    /// Returns an error when `name` is not one of [`PLUGINS`].
    pub fn new(name: &str) -> Result<Self, String> {
        let parser = parser::by_name(name).ok_or_else(|| {
            format!(
                "unknown plugin '{name}'; expected one of {}",
                PLUGINS.join(", ")
            )
        })?;
        Ok(Self {
            parser,
            tokens: Vec::with_capacity(16),
        })
    }

    /// Returns the parser's stable name.
    #[must_use]
    pub fn plugin_name(&self) -> &'static str {
        self.parser.name()
    }

    /// Classifies and renders one line into `output`.
    pub fn process(
        &mut self,
        line: &[u8],
        color: bool,
        output: &mut Vec<u8>,
    ) -> severity::Severity {
        self.tokens.clear();
        let severity = self.parser.parse(line, &mut self.tokens);
        self.tokens.sort_unstable_by_key(|token| token.start);
        render(line, &self.tokens, color, output);
        severity
    }
}

fn render(input: &[u8], tokens: &[Token], color: bool, output: &mut Vec<u8>) {
    output.clear();
    if !color {
        output.extend_from_slice(input);
        return;
    }

    let mut cursor = 0;
    for token in tokens {
        if token.start < cursor || token.end > input.len() || token.start == token.end {
            continue;
        }
        output.extend_from_slice(&input[cursor..token.start]);
        output.extend_from_slice(token.kind.ansi().as_bytes());
        output.extend_from_slice(&input[token.start..token.end]);
        output.extend_from_slice(b"\x1b[0m");
        cursor = token.end;
    }
    output.extend_from_slice(&input[cursor..]);
}

impl TokenKind {
    const fn ansi(self) -> &'static str {
        match self {
            Self::Timestamp => "\x1b[33m",
            Self::Host => "\x1b[36m",
            Self::Process => "\x1b[35m",
            Self::Key => "\x1b[34m",
            Self::Value => "\x1b[32m",
            Self::Warning => "\x1b[1;33m",
            Self::Error => "\x1b[1;31m",
            Self::Fatal => "\x1b[1;37;41m",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_syslog_without_changing_payload() {
        let line = b"Jul 30 12:34:56 host sshd[42]: login failed";
        let mut processor = Processor::new("syslog").unwrap();
        let mut plain = Vec::new();
        let severity = processor.process(line, false, &mut plain);
        assert_eq!(plain, line);
        assert_eq!(severity, severity::Severity::Error);

        let mut colored = Vec::new();
        processor.process(line, true, &mut colored);
        assert!(colored.starts_with(b"\x1b[33mJul 30 12:34:56"));
        assert!(colored.ends_with(b"\x1b[1;31mfailed\x1b[0m"));
    }

    #[test]
    fn rejects_unknown_plugins() {
        assert!(Processor::new("made-up").is_err());
    }
}
