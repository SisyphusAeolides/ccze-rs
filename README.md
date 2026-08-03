# ccze-rs

`ccze-rs` is a fast streaming log colorizer with optional anomaly detection,
protocol-order verification, and fixed-width metric-vector export. It installs
the `ccze` executable and is designed for pipelines, live journal output, and
large log files.

The parser works on borrowed byte slices, reuses its input and output buffers,
and preserves non-UTF-8 input. Async standard I/O keeps the Rust layer responsive
while native components handle analytics and verified reductions.

## Highlights

- Automatic, syslog, Apache/Nginx access-log, and JSON parsers
- Terminal-aware color output plus classic `ccze -A` raw ANSI behavior
- Rolling anomaly detection implemented in Fortran through `iso_c_binding`
- Lifecycle validation for `Start -> Authenticate -> Bind -> Ready`
- Total Idris 2 protocol specification and Agda severity-algebra proofs
- Portable analytics fallback when GFortran is not installed
- Versioned 64-byte metric-vector records with strict corruption detection
- Optional Linux system-integration library APIs behind a Cargo feature
- Rust 1.75 minimum supported version

## Install

From the Sisyphus Arch repository:

```console
sudo pacman -Syy
sudo pacman -S ccze-rs
```

The package installs the `ccze` command. It includes the native analytics
backend and does not require a separate compiler at runtime.

From crates.io:

```console
cargo install ccze-rs
```

GFortran is optional for crates.io installs. When it is available, the build
uses the vector-friendly Fortran analytics engine; otherwise it compiles the
equivalent portable C implementation.

To build locally on Arch or an Arch-based distribution:

```console
sudo pacman -S --needed base-devel rust cargo gcc-fortran
makepkg -si
```

## Use

Color a stream when stdout is a terminal:

```console
journalctl -f | ccze
```

Force ANSI sequences in a pipeline:

```console
tail -f /var/log/messages | ccze -A | less -R
```

Analyze a stream with a 128-line window:

```console
ccze --analytics --analytics-window 128 < application.log
```

Verify a service lifecycle:

```console
ccze --verify-protocol < service.log
```

Encode one lossy metric vector per input record, then inspect those metrics:

```console
ccze --analytics --verify-protocol --vector-encode -o service.cczev < service.log
ccze --vector-decode --vector-input service.cczev
```

Vector files contain normalized metrics, not the original log payload. Decode
mode prints summaries such as length, severity, rate, entropy, z-score, process
identifier, and protocol phase; it cannot reconstruct discarded text. Files
carry a versioned header, and malformed headers, partial records, non-finite
values, and out-of-range features are rejected.

Select or list parsers:

```console
ccze --plugin syslog < /var/log/messages
ccze --list-plugins
```

Inspect the native implementation selected at build time:

```console
ccze --backend-info
```

Run `ccze --help` for all options.

## Architecture

```text
stdin -> Rust async I/O -> zero-copy token ranges -> ANSI renderer -> stdout
                          |                      |
                          |                      +-> Agda-specified severity join
                          +-> Fortran analytics +-> Idris-specified protocol step
                          |
                          +-> Fortran state-vector encoder -> versioned file
```

Rust owns all I/O, buffers, CLI behavior, and parsing. Fortran receives compact
arrays of line lengths and error flags through the C ABI, then computes rolling
z-scores and binary entropy. Idris defines the only valid service-state
transitions. Agda proves that severity reduction is commutative and idempotent.
The vector encoder uses the same build-selected Fortran or portable C policy as
analytics. Rust owns the on-disk little-endian format and validates every record
before exposing it.

Idris 2's RefC backend and Agda's MAlonzo backend do not expose portable,
stable C library symbols directly. The repository therefore keeps their total,
type-checked sources as the authoritative specifications and ships small C ABI
counterparts whose complete input domains are exercised by Rust tests. See
[`ARCHITECTURE.md`](ARCHITECTURE.md) for the boundary details.

### Optional system integration

The `system-integration` Cargo feature exposes Linux-oriented library modules
for cgroup observation, configuration repair, DKMS/module inspection, gossip,
LSM policy, rollback coordination, scheduling experiments, seccomp policy,
timing analysis, XDP state, and zram management:

```console
cargo build --features system-integration
```

These APIs are not activated by the `ccze` command and do not perform privileged
changes merely by compiling the crate. Applications must opt in, construct the
relevant manager, and provide the operating-system privileges required by each
operation. The LSM manager evaluates policy and observes active kernel state;
kernel enforcement requires a separately maintained, kernel-compatible module.
These modules are experimental Linux integration APIs, not portable
log-colorizer behavior.

## Build and verify

```console
make check
make test
```

`make proofs` requires Idris 2 and Agda. On Arch, install them with
`sudo pacman -S --needed agda idris2` when formal verification is required.

## License

MIT

## Current ArachOS integration status

This project is maintained as part of the ArachOS production graph. Its role is
measured log presentation and release diagnostics..

CI and release evidence are evaluated on immutable revisions. Hardware support
is reported by bounded route and support level; this README does not claim
universal native support. Gate 3 requires signed hardware identity, target
kernel provenance, package authority, health checks, rollback behavior, and
representative physical-hardware evidence before production qualification.
