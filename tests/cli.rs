use std::io::Write;
use std::process::{Command, Stdio};
use tempfile::tempdir;

fn run(args: &[&str], input: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ccze"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn preserves_arbitrary_bytes_and_missing_final_newline() {
    let input = b"message: \xff\xfe\0tail";
    let output = run(&["--color", "never"], input);
    assert!(output.status.success());
    assert_eq!(output.stdout, input);
}

#[test]
fn emits_ansi_only_when_requested() {
    let input = b"Jul 30 12:34:56 host service: fatal failure\n";
    let plain = run(&["--color", "never"], input);
    assert_eq!(plain.stdout, input);
    let colored = run(&["-A"], input);
    assert!(colored.stdout.starts_with(b"\x1b[33m"));
    assert!(colored.stdout.windows(4).any(|window| window == b"\x1b[0m"));
    assert!(colored.stdout.ends_with(b"\n"));
}

#[test]
fn reports_protocol_violations() {
    let output = run(
        &["--color", "never", "--verify-protocol"],
        b"server ready\n",
    );
    assert!(output.status.success());
    assert!(String::from_utf8(output.stdout)
        .unwrap()
        .contains("protocol violation"));
}

#[test]
fn vector_cli_writes_versioned_records_and_decodes_summaries() {
    let directory = tempdir().unwrap();
    let vector_path = directory.path().join("service.cczev");
    let encoded = run(
        &["--vector-encode", "--output", vector_path.to_str().unwrap()],
        b"service[42]: started\nservice pid=77: ready\n",
    );
    assert!(encoded.status.success());
    assert!(encoded.stdout.is_empty());
    assert_eq!(std::fs::metadata(&vector_path).unwrap().len(), 8 + 2 * 64);

    let decoded = run(
        &[
            "--vector-decode",
            "--vector-input",
            vector_path.to_str().unwrap(),
        ],
        b"",
    );
    assert!(decoded.status.success());
    let summaries = String::from_utf8(decoded.stdout).unwrap();
    assert_eq!(summaries.lines().count(), 2);
    assert!(summaries.contains("[PID:42]"));
    assert!(summaries.contains("[PID:77]"));
}

#[test]
fn vector_modes_are_mutually_exclusive() {
    let output = run(&["--vector-encode", "--vector-decode"], b"");
    assert!(!output.status.success());
}
