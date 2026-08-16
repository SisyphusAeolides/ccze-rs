//! Allocation-free token boundary discovery for common log formats.

use crate::severity::{find_ascii_case_insensitive, Severity};
use memchr::{memchr, memchr_iter};

/// Semantic class used by the renderer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenKind {
    Timestamp,
    Host,
    Process,
    Key,
    Value,
    Warning,
    Error,
    Fatal,
}

/// A borrowed byte range in the input line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Token {
    pub start: usize,
    pub end: usize,
    pub kind: TokenKind,
}

/// Extensible parser interface for log formats.
pub trait LogParser {
    fn name(&self) -> &'static str;
    fn parse(&self, line: &[u8], tokens: &mut Vec<Token>) -> Severity;
}

pub(crate) fn by_name(name: &str) -> Option<Box<dyn LogParser + Send + Sync>> {
    match name {
        "auto" => Some(Box::new(Auto)),
        "syslog" => Some(Box::new(Syslog)),
        "httpd" => Some(Box::new(Httpd)),
        "json" => Some(Box::new(Json)),
        _ => None,
    }
}

struct Auto;
struct Syslog;
struct Httpd;
struct Json;

impl LogParser for Auto {
    fn name(&self) -> &'static str {
        "auto"
    }

    fn parse(&self, line: &[u8], tokens: &mut Vec<Token>) -> Severity {
        if line.first() == Some(&b'{') {
            Json.parse(line, tokens)
        } else if is_syslog_timestamp(line) {
            Syslog.parse(line, tokens)
        } else if line.windows(3).any(|window| window == b"] \"") {
            Httpd.parse(line, tokens)
        } else {
            add_severity_token(line, tokens)
        }
    }
}

impl LogParser for Syslog {
    fn name(&self) -> &'static str {
        "syslog"
    }

    fn parse(&self, line: &[u8], tokens: &mut Vec<Token>) -> Severity {
        if is_syslog_timestamp(line) {
            tokens.push(Token {
                start: 0,
                end: 15,
                kind: TokenKind::Timestamp,
            });
            let host_start = line[15..]
                .iter()
                .position(|byte| !byte.is_ascii_whitespace())
                .map_or(15, |i| i + 15);
            if let Some(space) = memchr(b' ', &line[host_start..]) {
                let host_end = host_start + space;
                tokens.push(Token {
                    start: host_start,
                    end: host_end,
                    kind: TokenKind::Host,
                });
                let process_start = line[host_end..]
                    .iter()
                    .position(|byte| !byte.is_ascii_whitespace())
                    .map_or(host_end, |i| i + host_end);
                if let Some(colon) = memchr(b':', &line[process_start..]) {
                    tokens.push(Token {
                        start: process_start,
                        end: process_start + colon,
                        kind: TokenKind::Process,
                    });
                }
            }
        }
        add_severity_token(line, tokens)
    }
}

impl LogParser for Httpd {
    fn name(&self) -> &'static str {
        "httpd"
    }

    fn parse(&self, line: &[u8], tokens: &mut Vec<Token>) -> Severity {
        let mut detected = Severity::Info;
        if let Some(space) = memchr(b' ', line) {
            tokens.push(Token {
                start: 0,
                end: space,
                kind: TokenKind::Host,
            });
        }
        if let Some((open, close)) = memchr(b'[', line)
            .and_then(|open| memchr(b']', &line[open + 1..]).map(|close| (open, close)))
        {
            tokens.push(Token {
                start: open + 1,
                end: open + 1 + close,
                kind: TokenKind::Timestamp,
            });
        }
        let quotes: Vec<_> = memchr_iter(b'"', line).take(2).collect();
        if quotes.len() == 2 {
            let status_start = line[quotes[1] + 1..]
                .iter()
                .position(|byte| !byte.is_ascii_whitespace())
                .map(|offset| quotes[1] + 1 + offset);
            if let Some(start) = status_start {
                let end = line[start..]
                    .iter()
                    .position(u8::is_ascii_whitespace)
                    .map_or(line.len(), |offset| start + offset);
                let kind = if line.get(start) == Some(&b'5') {
                    detected = Severity::Error;
                    TokenKind::Error
                } else if line.get(start) == Some(&b'4') {
                    detected = Severity::Warn;
                    TokenKind::Warning
                } else {
                    TokenKind::Value
                };
                tokens.push(Token { start, end, kind });
            }
        }
        detected.join(add_severity_token(line, tokens))
    }
}

impl LogParser for Json {
    fn name(&self) -> &'static str {
        "json"
    }

    fn parse(&self, line: &[u8], tokens: &mut Vec<Token>) -> Severity {
        let mut cursor = 0;
        while let Some(open) = memchr(b'"', &line[cursor..]) {
            let start = cursor + open + 1;
            let Some(close) = memchr(b'"', &line[start..]) else {
                break;
            };
            let end = start + close;
            let after = line[end + 1..]
                .iter()
                .find(|byte| !byte.is_ascii_whitespace());
            let kind = if after == Some(&b':') {
                TokenKind::Key
            } else {
                TokenKind::Value
            };
            tokens.push(Token { start, end, kind });
            cursor = end + 1;
        }
        add_severity_token(line, tokens)
    }
}

fn is_syslog_timestamp(line: &[u8]) -> bool {
    line.len() >= 15
        && line[0].is_ascii_uppercase()
        && line[1..3].iter().all(u8::is_ascii_lowercase)
        && line[3] == b' '
        && line[6] == b' '
        && line[9] == b':'
        && line[12] == b':'
        && line[7..9].iter().all(u8::is_ascii_digit)
        && line[10..12].iter().all(u8::is_ascii_digit)
        && line[13..15].iter().all(u8::is_ascii_digit)
}

fn add_severity_token(line: &[u8], tokens: &mut Vec<Token>) -> Severity {
    let severity = Severity::detect(line);
    let needles: &[(&[u8], TokenKind)] = match severity {
        Severity::Fatal => &[(b"panic", TokenKind::Fatal), (b"fatal", TokenKind::Fatal)],
        Severity::Error => &[(b"error", TokenKind::Error), (b"failed", TokenKind::Error)],
        Severity::Warn => &[(b"warn", TokenKind::Warning)],
        _ => &[],
    };
    for (needle, kind) in needles {
        if let Some(start) = find_ascii_case_insensitive(line, needle) {
            tokens.push(Token {
                start,
                end: start + needle.len(),
                kind: *kind,
            });
            break;
        }
    }
    severity
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_detects_json() {
        let parser = Auto;
        let mut tokens = Vec::new();
        parser.parse(br#"{"level":"warn","message":"slow"}"#, &mut tokens);
        assert!(tokens.iter().any(|token| token.kind == TokenKind::Key));
        assert!(tokens.iter().any(|token| token.kind == TokenKind::Warning));
    }

    #[test]
    fn parses_http_status() {
        let parser = Httpd;
        let mut tokens = Vec::new();
        parser.parse(
            b"127.0.0.1 - - [30/Jul/2026:12:00:00] \"GET / HTTP/1.1\" 500 1",
            &mut tokens,
        );
        assert!(tokens.iter().any(|token| token.kind == TokenKind::Error));
    }
}
