use ccze_rs::analytics::{Analysis, AnalyticsWindow};
use ccze_rs::protocol::{Phase, ProtocolVerifier};
use ccze_rs::severity::Severity;
use ccze_rs::vector::{VectorEncoder, VectorReader, VectorWriter};
use ccze_rs::{Processor, PLUGINS};
use clap::{Parser, ValueEnum};
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};

const MAXIMUM_RECORD_BYTES: usize = 1024 * 1024;

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

    /// Encode logs to state vectors (compressed binary format).
    #[arg(long, conflicts_with = "vector_decode", requires = "output")]
    vector_encode: bool,

    /// Render state vectors as human-readable metric summaries.
    #[arg(long, conflicts_with = "vector_encode", requires = "vector_input")]
    vector_decode: bool,

    /// Path to the vector file created by --vector-encode.
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Path to input vector file for decoding.
    #[arg(long)]
    vector_input: Option<PathBuf>,
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
        println!("vector={}", VectorEncoder::backend());
        return Ok(());
    }

    if cli.vector_decode {
        let input_path = cli.vector_input.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "missing vector input path")
        })?;
        return decode_vectors(input_path);
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

    if cli.vector_encode {
        let output_path = cli.output.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "missing vector output path")
        })?;
        return encode_vectors(
            output_path,
            &mut processor,
            analytics.as_mut(),
            verifier.as_mut(),
        )
        .await;
    }

    let mut input = BufReader::new(tokio::io::stdin());
    let mut stdout = tokio::io::stdout();
    let mut line = Vec::with_capacity(4096);
    let mut rendered = Vec::with_capacity(4096);

    loop {
        line.clear();
        let bytes_read = read_record(&mut input, &mut line).await?;
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

fn decode_vectors(input_path: &std::path::Path) -> io::Result<()> {
    let mut reader = VectorReader::open(input_path)
        .map_err(|error| io::Error::other(format!("failed to open vector file: {error}")))?;
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    while let Some(vector) = reader.read()? {
        let severity = if vector.severity < 0.1 {
            Severity::Trace
        } else if vector.severity < 0.3 {
            Severity::Debug
        } else if vector.severity < 0.5 {
            Severity::Info
        } else if vector.severity < 0.7 {
            Severity::Warn
        } else if vector.severity < 0.9 {
            Severity::Error
        } else {
            Severity::Fatal
        };
        writeln!(
            handle,
            "[PID:{:.0}] [L:{:.0}] [F:{:.1}/s] [T:{:.1}s] [Z:{:.2}] [E:{:.2}] [P:{:.0}] {}",
            vector.process_id * 4_194_304.0,
            vector.length * 1024.0,
            vector.frequency * 1000.0,
            vector.timestamp * 60.0,
            vector.zscore * 10.0,
            vector.entropy,
            vector.protocol * 4.0,
            severity,
        )?;
    }
    Ok(())
}

async fn encode_vectors(
    output_path: &std::path::Path,
    processor: &mut Processor,
    mut analytics: Option<&mut AnalyticsWindow>,
    mut verifier: Option<&mut ProtocolVerifier>,
) -> io::Result<()> {
    let mut writer = VectorWriter::create(output_path)
        .map_err(|error| io::Error::other(format!("failed to create vector file: {error}")))?;
    let mut encoder = VectorEncoder::new();
    let mut input = BufReader::new(tokio::io::stdin());
    let mut line = Vec::with_capacity(4096);
    let mut scratch = Vec::with_capacity(4096);

    loop {
        line.clear();
        if read_record(&mut input, &mut line).await? == 0 {
            break;
        }
        let payload = line.strip_suffix(b"\n").unwrap_or(&line);
        let payload = payload.strip_suffix(b"\r").unwrap_or(payload);
        let severity = processor.process(payload, false, &mut scratch);
        let analysis = analytics.as_mut().map_or_else(Analysis::default, |window| {
            window.push(payload.len(), severity >= Severity::Error)
        });
        let protocol_phase = verifier
            .as_mut()
            .and_then(|state| state.inspect(payload))
            .and_then(Result::ok)
            .unwrap_or(Phase::Cold);
        let (vector, _) = encoder.encode(
            payload.len(),
            severity,
            &analysis,
            protocol_phase,
            extract_pid(payload),
        );
        writer.write(vector)?;
    }
    writer.flush()
}

/// Extracts the common `[1234]` or `pid=1234` forms without requiring UTF-8.
fn extract_pid(line: &[u8]) -> u32 {
    if let Some(start) = line.iter().position(|byte| *byte == b'[') {
        if let Some(end) = line[start + 1..].iter().position(|byte| *byte == b']') {
            if let Some(pid) = parse_decimal(&line[start + 1..start + 1 + end]) {
                return pid;
            }
        }
    }
    if let Some(position) = line.windows(4).position(|window| window == b"pid=") {
        let digits = &line[position + 4..];
        let length = digits
            .iter()
            .position(|byte| !byte.is_ascii_digit())
            .unwrap_or(digits.len());
        if let Some(pid) = parse_decimal(&digits[..length]) {
            return pid;
        }
    }
    0
}

fn parse_decimal(digits: &[u8]) -> Option<u32> {
    if digits.is_empty() || digits.iter().any(|byte| !byte.is_ascii_digit()) {
        return None;
    }
    digits.iter().try_fold(0_u32, |value, byte| {
        value.checked_mul(10)?.checked_add(u32::from(*byte - b'0'))
    })
}

async fn read_record(
    input: &mut (impl AsyncBufRead + Unpin),
    line: &mut Vec<u8>,
) -> io::Result<usize> {
    line.clear();
    loop {
        let (length, complete) = {
            let available = input.fill_buf().await?;
            if available.is_empty() {
                return Ok(line.len());
            }
            let length = available
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(available.len(), |index| index + 1);
            if line.len().saturating_add(length) > MAXIMUM_RECORD_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("input record exceeds {MAXIMUM_RECORD_BYTES} bytes"),
                ));
            }
            line.extend_from_slice(&available[..length]);
            (length, available[length - 1] == b'\n')
        };
        input.consume(length);
        if complete {
            return Ok(line.len());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{read_record, MAXIMUM_RECORD_BYTES};
    use std::io;
    use tokio::io::BufReader;

    #[tokio::test]
    async fn read_record_rejects_unterminated_oversized_input() {
        let input = vec![b'x'; MAXIMUM_RECORD_BYTES + 1];
        let mut input = BufReader::new(io::Cursor::new(input));
        let mut line = Vec::new();

        let error = read_record(&mut input, &mut line).await.unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(line.len() <= MAXIMUM_RECORD_BYTES);
    }
}
