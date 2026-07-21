use clap::Parser;
use crossterm::style::{Color, Stylize};
use std::io::{self, BufRead};
use regex::Regex;

// 1. The Core Architecture Trait
pub trait LogParser {
    fn parse(&self, line: &str) -> String;
}

// 2. The Syslog Plugin
struct SyslogParser {
    date_re: Regex,
    host_proc_re: Regex,
}

impl SyslogParser {
    fn new() -> Self {
        Self {
            // Matches "Jun 20 10:40:18"
            date_re: Regex::new(r"^[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}").unwrap(),
            // Matches " hostname systemd[20201]:"
            host_proc_re: Regex::new(r"^\s+([^\s]+)\s+([^:]+):").unwrap(),
        }
    }
}

impl LogParser for SyslogParser {
    fn parse(&self, line: &str) -> String {
        // First, extract the date
        if let Some(date_mat) = self.date_re.find(line) {
            let date_str = &line[date_mat.start()..date_mat.end()];
            let rest = &line[date_mat.end()..];

            // Next, extract the hostname and process name
            if let Some(proc_mat) = self.host_proc_re.find(rest) {
                let host_proc_str = &rest[proc_mat.start()..proc_mat.end()];
                let message = &rest[proc_mat.end()..];

                // Reconstruct the line with ANSI color formatting
                return format!(
                    "{}{}{}",
                    date_str.with(Color::DarkYellow),
                    host_proc_str.with(Color::DarkCyan),
                    message
                );
            }
            // Fallback if process regex fails but date matches
            return format!("{}{}", date_str.with(Color::DarkYellow), rest);
        }
        // Fallback for completely unrecognized lines
        line.to_string()
    }
}

// 3. The Default Fallback Plugin (No-op)
struct DefaultParser;
impl LogParser for DefaultParser {
    fn parse(&self, line: &str) -> String {
        line.to_string()
    }
}

/// A robust, memory-safe log colorizer (Oxidized)
#[derive(Parser, Debug)]
#[command(name = "ccze", version = "0.3.0", about, long_about = None)]
struct Cli {
    /// Load a specific plugin (e.g., syslog, httpd, exim)
    #[arg(short, long)]
    plugin: Option<String>,

    /// Output destination (kept for legacy compatibility)
    #[arg(short, long)]
    output: Option<String>,
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();
    
    // Dynamic Plugin Routing using Boxed Traits
    let parser: Box<dyn LogParser> = match cli.plugin.as_deref() {
        Some("syslog") => Box::new(SyslogParser::new()),
        _ => Box::new(DefaultParser),
    };

    let stdin = io::stdin();
    
    for line in stdin.lock().lines() {
        let line = line?;
        // Pass the line through the chosen parser
        println!("{}", parser.parse(&line));
    }
    
    Ok(())
}
