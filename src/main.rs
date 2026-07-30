use ccze_rs::analytics::AnalyticsWindow;
use ccze_rs::protocol::ProtocolVerifier;
use ccze_rs::severity::Severity;
use ccze_rs::{Processor, PLUGINS};
use clap::{Parser, ValueEnum};
use std::io::{self, IsTerminal};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ColorChoice {
    Auto,
    Always,
    Never,
}

/// A fast streaming log colorizer and verification pipeline.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Parser)]
#[command(name = "ccze", version, about)]
struct Cli {
    /// Force raw ANSI output, matching classic ccze's -A option.
    #[arg(short = 'A', long = "raw-ansi")]
    raw_ansi: bool,

    /// Choose when ANSI colors are emitted.
    #[arg(long, value_enum, default_value_t = ColorChoice::Auto)]
    color: ColorChoice,

    /// Select a parser.
    #[arg(short, long, default_value = "auto")]
    plugin: String,

    /// List available parser plugins and exit.
    #[arg(short, long)]
    list_plugins: bool,

    /// Enable rolling anomaly detection.
    #[arg(long)]
    analytics: bool,

    /// Number of samples in the analytics window.
    #[arg(long, default_value_t = 64)]
    analytics_window: usize,

    /// Z-score threshold used to identify anomalous line lengths.
    #[arg(long, default_value_t = 3.5)]
    anomaly_threshold: f64,

    /// Verify Start -> Authenticate -> Bind -> Ready event ordering.
    #[arg(long)]
    verify_protocol: bool,

    /// Print native backend information and exit.
    #[arg(long)]
    backend_info: bool,
}

#[tokio::main]
async fn main() {
    match run().await {
        Err(error) if error.kind() != io::ErrorKind::BrokenPipe => {
            eprintln!("ccze: {error}");
            std::process::exit(1);
        }
        _ => {}
    }
}

async fn run() -> io::Result<()> {
    let cli = Cli::parse();
    if cli.list_plugins {
        println!("{}", PLUGINS.join("\n"));
        return Ok(());
    }
    if cli.backend_info {
        println!("analytics={}", AnalyticsWindow::backend());
        println!("protocol=idris2-specified-c-abi");
        println!("severity=agda-specified-c-abi");
        return Ok(());
    }

    let color = cli.raw_ansi
        || matches!(cli.color, ColorChoice::Always)
        || matches!(cli.color, ColorChoice::Auto) && io::stdout().is_terminal();
    let mut processor = Processor::new(&cli.plugin)
        .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message))?;
    let mut analytics = cli
        .analytics
        .then(|| AnalyticsWindow::new(cli.analytics_window, cli.anomaly_threshold));
    let mut verifier = cli.verify_protocol.then(ProtocolVerifier::default);

    let mut input = BufReader::new(tokio::io::stdin());
    let mut stdout = tokio::io::stdout();
    let mut line = Vec::with_capacity(4096);
    let mut rendered = Vec::with_capacity(4096);

    loop {
        line.clear();
        let bytes_read = input.read_until(b'\n', &mut line).await?;
        if bytes_read == 0 {
            break;
        }
        let had_newline = line.last() == Some(&b'\n');
        let payload = line.strip_suffix(b"\n").unwrap_or(&line);
        let payload = payload.strip_suffix(b"\r").unwrap_or(payload);
        let severity = processor.process(payload, color, &mut rendered);

        if let Some(window) = analytics.as_mut() {
            let analysis = window.push(payload.len(), severity >= Severity::Error);
            if analysis.anomaly {
                rendered.extend_from_slice(
                    format!(
                        " [anomaly z={:.2} entropy={:.2}]",
                        analysis.zscore, analysis.error_entropy
                    )
                    .as_bytes(),
                );
            }
        }
        if let Some(Err(violation)) = verifier
            .as_mut()
            .and_then(|verifier| verifier.inspect(payload))
        {
            rendered.extend_from_slice(format!(" [protocol violation: {violation}]").as_bytes());
        }
        if had_newline {
            rendered.push(b'\n');
        }
        stdout.write_all(&rendered).await?;
    }
    stdout.flush().await
}
