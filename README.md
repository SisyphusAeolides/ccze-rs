# ccze-rs

`ccze-rs` is a fast streaming log colorizer with optional anomaly detection and
protocol-order verification. It installs the `ccze` executable and is designed
for pipelines, live journal output, and large log files.

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
- Rust 1.75 minimum supported version

## Install

From crates.io:

```console
cargo install ccze-rs
```

GFortran is optional for crates.io installs. When it is available, the build
uses the vector-friendly Fortran analytics engine; otherwise it compiles the
equivalent portable C implementation.

On Fedora, EPEL, or RHEL:

```console
sudo dnf copr enable sisyphuscode/ccze-rs
sudo dnf install ccze-rs
```

The COPR package always builds with GFortran.

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
```

Rust owns all I/O, buffers, CLI behavior, and parsing. Fortran receives compact
arrays of line lengths and error flags through the C ABI, then computes rolling
z-scores and binary entropy. Idris defines the only valid service-state
transitions. Agda proves that severity reduction is commutative and idempotent.

Idris 2's RefC backend and Agda's MAlonzo backend do not expose portable,
stable C library symbols directly. The repository therefore keeps their total,
type-checked sources as the authoritative specifications and ships small C ABI
counterparts whose complete input domains are exercised by Rust tests. See
[`ARCHITECTURE.md`](ARCHITECTURE.md) for the boundary details.

## Build and verify

```console
make check
make test
```

`make proofs` requires Idris 2 and Agda. `make srpm` creates a source RPM with
all Cargo dependencies vendored for an offline RPM build.

## License

MIT
