# Architecture

## Pipeline ownership

Rust owns resources: standard I/O, line buffers, CLI state, parser selection,
terminal detection, and rendering. A line is read once into a reusable byte
buffer. Parsers return byte ranges rather than copied strings, so invalid UTF-8
and arbitrary log payloads remain intact.

The native boundary contains three narrow, integer-and-array-only interfaces:

```c
void ccze_analyze_metrics(const int32_t *lengths, const int32_t *errors,
                          size_t count, double threshold, double *zscore,
                          double *entropy, int32_t *anomaly);
int32_t ccze_protocol_step(int32_t phase, int32_t event);
int32_t ccze_severity_join(int32_t left, int32_t right);
```

No component keeps a pointer after a call. Rust validates or constructs every
enum value before crossing the boundary and converts unknown return values to a
safe default.

## Fortran analytics

`native/fortran/analytics.f90` uses `iso_c_binding` and processes a rolling
batch of line lengths and error indicators. It computes population variance,
the newest sample's absolute z-score, and binary error entropy. A line is
anomalous when its z-score crosses the configured threshold or at least half of
the active window is error-level.

`build.rs` selects this implementation when `gfortran` is available. Setting
`CCZE_FORCE_FORTRAN=1` turns compiler absence or failure into a hard error; RPM
builds use that setting. The portable C implementation has the same signature
and equations.

## Idris protocol specification

`native/idris/Protocol.idr` is total and models the lifecycle with closed
`Phase` and `Event` types. Every accepted transition is explicit; every other
pair returns `Nothing`. Reset is proven to return every phase to `Cold`.

Idris 2 currently supports `%export` only in its JavaScript backend, so RefC
cannot provide a stable exported library symbol. `native/idris/protocol.c` is
the direct ordinal encoding of the total transition table. Rust tests cover the
valid sequence, invalid transitions, and non-advancement after rejection.

## Agda severity specification

`native/agda/Severity.agda` defines the ordered severity lattice and proves its
join operation is idempotent and commutative over all constructors. The runtime
counterpart in `native/agda/severity.c` is integer maximum after range checking.
Rust exhaustively checks all 36 input pairs against the native function.

Agda's supported native backend is MAlonzo-to-Haskell rather than a C library
backend. Keeping the proof artifact independent of the runtime shim avoids a
GHC runtime dependency in every `ccze` process while retaining a mechanically
checkable specification.

## Failure behavior

- Broken output pipes terminate successfully, as Unix filters should.
- Unknown parser names fail before input is consumed.
- Invalid protocol events annotate output but do not advance the state.
- A missing Fortran compiler selects the fallback unless explicitly forbidden.
- Empty and constant analytics windows never divide by zero.
