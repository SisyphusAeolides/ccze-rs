//! Vectorized generative log encoding.
//!
//! This module provides mathematical state vector encoding for log compression.
//! Instead of storing raw log text, we store tiny state vectors that represent
//! the "normal" behavior. A 50GB log file can be compressed to ~5MB of vectors.
//!
//! The state vector contains 8 normalized features:
//! - Line length
//! - Severity level
//! - Log frequency
//! - Timestamp (normalized)
//! - Process ID hash
//! - Information entropy
//! - Z-score (statistical deviation)
//! - Protocol phase

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::Instant;

use crate::analytics::Analysis;
use crate::protocol::Phase;
use crate::severity::Severity;

/// State vector dimension (8 features).
pub const VEC_DIM: usize = 8;

/// Binary size of a state vector (8 features * 8 bytes per f64).
pub const VEC_SIZE: usize = VEC_DIM * 8;
const VECTOR_FILE_HEADER: &[u8; 8] = b"CCZEVEC\x01";

extern "C" {
    fn ccze_compute_state_vector(
        length: i32,
        severity: i32,
        frequency: f64,
        timestamp: f64,
        process_id: i32,
        entropy: f64,
        zscore: f64,
        protocol_phase: i32,
        vector: *mut f64,
    );
    fn ccze_update_baseline(baseline: *mut f64, observed: *const f64, alpha: f64, count: i32);
    fn ccze_vector_is_anomaly(observed: *const f64, baseline: *const f64) -> i32;
}

/// State vector for log compression.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
#[repr(C)]
pub struct StateVector {
    /// Feature 0: Normalized line length (0-1).
    pub length: f64,
    /// Feature 1: Normalized severity level (0-1).
    pub severity: f64,
    /// Feature 2: Normalized frequency (0-1).
    pub frequency: f64,
    /// Feature 3: Normalized timestamp (0-1).
    pub timestamp: f64,
    /// Feature 4: Process ID hash (0-1).
    pub process_id: f64,
    /// Feature 5: Information entropy (0-1).
    pub entropy: f64,
    /// Feature 6: Normalized z-score (0-1).
    pub zscore: f64,
    /// Feature 7: Normalized protocol phase (0-1).
    pub protocol: f64,
}

impl StateVector {
    /// Creates a zero vector.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            length: 0.0,
            severity: 0.0,
            frequency: 0.0,
            timestamp: 0.0,
            process_id: 0.0,
            entropy: 0.0,
            zscore: 0.0,
            protocol: 0.0,
        }
    }

    /// Computes Euclidean distance between two vectors.
    #[must_use]
    pub fn distance(self, other: Self) -> f64 {
        let mut sum_sq = 0.0;
        sum_sq += (self.length - other.length).powi(2);
        sum_sq += (self.severity - other.severity).powi(2);
        sum_sq += (self.frequency - other.frequency).powi(2);
        sum_sq += (self.timestamp - other.timestamp).powi(2);
        sum_sq += (self.process_id - other.process_id).powi(2);
        sum_sq += (self.entropy - other.entropy).powi(2);
        sum_sq += (self.zscore - other.zscore).powi(2);
        sum_sq += (self.protocol - other.protocol).powi(2);
        sum_sq.sqrt()
    }

    /// Checks if this vector is an anomaly relative to a baseline.
    /// Uses the stable native ABI threshold of 0.75.
    #[must_use]
    pub fn is_anomaly(self, baseline: Self) -> bool {
        let observed = self.components();
        let baseline = baseline.components();
        // Both arrays contain exactly eight initialized finite-feature slots,
        // and the native function retains neither pointer.
        unsafe { ccze_vector_is_anomaly(observed.as_ptr(), baseline.as_ptr()) == 1 }
    }

    /// Normalizes the vector to unit magnitude.
    #[must_use]
    pub fn normalized(self) -> Self {
        let mag = self.magnitude();
        if mag > 0.0 {
            Self {
                length: self.length / mag,
                severity: self.severity / mag,
                frequency: self.frequency / mag,
                timestamp: self.timestamp / mag,
                process_id: self.process_id / mag,
                entropy: self.entropy / mag,
                zscore: self.zscore / mag,
                protocol: self.protocol / mag,
            }
        } else {
            Self::zero()
        }
    }

    /// Computes the magnitude (Euclidean norm) of the vector.
    #[must_use]
    pub fn magnitude(self) -> f64 {
        let mut sum_sq = 0.0;
        sum_sq += self.length.powi(2);
        sum_sq += self.severity.powi(2);
        sum_sq += self.frequency.powi(2);
        sum_sq += self.timestamp.powi(2);
        sum_sq += self.process_id.powi(2);
        sum_sq += self.entropy.powi(2);
        sum_sq += self.zscore.powi(2);
        sum_sq += self.protocol.powi(2);
        sum_sq.sqrt()
    }

    /// Reports whether every serialized feature is finite and normalized.
    #[must_use]
    pub fn is_valid(self) -> bool {
        self.components()
            .iter()
            .all(|component| component.is_finite() && (0.0..=1.0).contains(component))
    }

    /// Serializes the vector to binary format.
    #[must_use]
    pub fn to_binary(self) -> [u8; VEC_SIZE] {
        let mut buffer = [0u8; VEC_SIZE];
        buffer[0..8].copy_from_slice(&self.length.to_le_bytes());
        buffer[8..16].copy_from_slice(&self.severity.to_le_bytes());
        buffer[16..24].copy_from_slice(&self.frequency.to_le_bytes());
        buffer[24..32].copy_from_slice(&self.timestamp.to_le_bytes());
        buffer[32..40].copy_from_slice(&self.process_id.to_le_bytes());
        buffer[40..48].copy_from_slice(&self.entropy.to_le_bytes());
        buffer[48..56].copy_from_slice(&self.zscore.to_le_bytes());
        buffer[56..64].copy_from_slice(&self.protocol.to_le_bytes());
        buffer
    }

    /// Deserializes a vector from binary format.
    #[must_use]
    pub fn from_binary(buffer: [u8; VEC_SIZE]) -> Self {
        Self {
            length: decode_component(&buffer, 0),
            severity: decode_component(&buffer, 8),
            frequency: decode_component(&buffer, 16),
            timestamp: decode_component(&buffer, 24),
            process_id: decode_component(&buffer, 32),
            entropy: decode_component(&buffer, 40),
            zscore: decode_component(&buffer, 48),
            protocol: decode_component(&buffer, 56),
        }
    }

    const fn components(self) -> [f64; VEC_DIM] {
        [
            self.length,
            self.severity,
            self.frequency,
            self.timestamp,
            self.process_id,
            self.entropy,
            self.zscore,
            self.protocol,
        ]
    }

    const fn from_components(value: [f64; VEC_DIM]) -> Self {
        Self {
            length: value[0],
            severity: value[1],
            frequency: value[2],
            timestamp: value[3],
            process_id: value[4],
            entropy: value[5],
            zscore: value[6],
            protocol: value[7],
        }
    }
}

/// Builder for creating state vectors from log metrics.
#[derive(Debug)]
pub struct VectorBuilder {
    start_time: Instant,
    line_count: u64,
    last_pid: u32,
    baseline_alpha: f64,
}

impl Default for VectorBuilder {
    fn default() -> Self {
        Self {
            start_time: Instant::now(),
            line_count: 0,
            last_pid: 0,
            baseline_alpha: 0.01,
        }
    }
}

impl VectorBuilder {
    /// Creates a new vector builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the learning rate for baseline updates.
    #[must_use]
    pub fn with_alpha(mut self, alpha: f64) -> Self {
        if alpha.is_finite() {
            self.baseline_alpha = alpha.clamp(0.0, 1.0);
        }
        self
    }

    /// Builds a state vector from log metrics.
    ///
    /// # Arguments
    ///
    /// * `length` - Line length in bytes.
    /// * `severity` - Severity level from the parser.
    /// * `analysis` - Analytics result (z-score, entropy).
    /// * `protocol_phase` - Current protocol phase.
    /// * `pid` - Process ID of the logging process.
    #[must_use]
    pub fn build(
        &mut self,
        length: usize,
        severity: Severity,
        analysis: &Analysis,
        protocol_phase: Phase,
        pid: u32,
    ) -> StateVector {
        self.line_count += 1;
        self.last_pid = pid;

        let elapsed = self.start_time.elapsed().as_secs_f64();
        let frequency = if elapsed > 0.0 {
            f64::from(u32::try_from(self.line_count).unwrap_or(u32::MAX)) / elapsed
        } else {
            0.0
        };

        // Normalize timestamp to [0, 1] within a reasonable window
        // Use modulo to create a repeating pattern
        let timestamp = (elapsed % 60.0) / 60.0; // Normalize to 1-minute window

        let mut components = [0.0; VEC_DIM];
        let length = i32::try_from(length).unwrap_or(i32::MAX);
        let pid = i32::try_from(pid % 4_194_304).unwrap_or(0);
        // Scalars are bounded before conversion, the output has the exact
        // eight-element ABI extent, and the native function retains no pointer.
        unsafe {
            ccze_compute_state_vector(
                length,
                severity as i32,
                frequency,
                timestamp,
                pid,
                analysis.error_entropy,
                analysis.zscore,
                protocol_phase as i32,
                components.as_mut_ptr(),
            );
        }
        StateVector::from_components(components)
    }
}

fn decode_component(buffer: &[u8; VEC_SIZE], offset: usize) -> f64 {
    let mut encoded = [0_u8; 8];
    encoded.copy_from_slice(&buffer[offset..offset + 8]);
    f64::from_le_bytes(encoded)
}

/// Manager for rolling baseline and vector storage.
#[derive(Debug)]
pub struct VectorEncoder {
    baseline: StateVector,
    vector_count: u64,
    builder: VectorBuilder,
}

impl Default for VectorEncoder {
    fn default() -> Self {
        Self {
            baseline: StateVector::zero(),
            vector_count: 0,
            builder: VectorBuilder::new(),
        }
    }
}

impl VectorEncoder {
    /// Creates a new vector encoder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the native implementation selected at build time.
    #[must_use]
    pub const fn backend() -> &'static str {
        env!("CCZE_VECTOR_BACKEND")
    }

    /// Encodes a log line into a state vector.
    ///
    /// # Arguments
    ///
    /// * `length` - Line length in bytes.
    /// * `severity` - Severity level from the parser.
    /// * `analysis` - Analytics result.
    /// * `protocol_phase` - Current protocol phase.
    /// * `pid` - Process ID.
    ///
    /// # Returns
    ///
    /// The computed state vector and whether it's an anomaly.
    pub fn encode(
        &mut self,
        length: usize,
        severity: Severity,
        analysis: &Analysis,
        protocol_phase: Phase,
        pid: u32,
    ) -> (StateVector, bool) {
        let vector = self
            .builder
            .build(length, severity, analysis, protocol_phase, pid);

        // Update baseline
        self.vector_count += 1;
        let mut baseline = self.baseline.components();
        let observed = vector.components();
        let count = i32::try_from(self.vector_count).unwrap_or(i32::MAX);
        // Both arrays have the fixed native extent and remain alive for the
        // complete call; the implementation retains neither pointer.
        unsafe {
            ccze_update_baseline(
                baseline.as_mut_ptr(),
                observed.as_ptr(),
                self.builder.baseline_alpha,
                count,
            );
        }
        self.baseline = StateVector::from_components(baseline);

        (vector, vector.is_anomaly(self.baseline))
    }

    /// Gets the current baseline vector.
    #[must_use]
    pub const fn baseline(&self) -> StateVector {
        self.baseline
    }

    /// Gets the number of vectors processed.
    #[must_use]
    pub const fn vector_count(&self) -> u64 {
        self.vector_count
    }
}

/// Writer for binary vector files.
#[derive(Debug)]
pub struct VectorWriter {
    file: File,
    vectors_written: u64,
}

impl VectorWriter {
    /// Creates a new vector writer for a file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be created.
    pub fn create(path: &Path) -> io::Result<Self> {
        let mut file = File::create(path)?;
        file.write_all(VECTOR_FILE_HEADER)?;
        Ok(Self {
            file,
            vectors_written: 0,
        })
    }

    /// Writes a state vector to the file.
    ///
    /// # Errors
    ///
    /// Returns an error if the write fails.
    pub fn write(&mut self, vector: StateVector) -> io::Result<()> {
        self.file.write_all(&vector.to_binary())?;
        self.vectors_written += 1;
        Ok(())
    }

    /// Flushes the writer.
    ///
    /// # Errors
    ///
    /// Returns an error if the flush fails.
    pub fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }

    /// Returns the number of vectors written.
    #[must_use]
    pub const fn vectors_written(&self) -> u64 {
        self.vectors_written
    }
}

/// Reader for binary vector files.
#[derive(Debug)]
pub struct VectorReader {
    file: File,
    vectors_read: u64,
}

impl VectorReader {
    /// Opens a vector file for reading.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened.
    pub fn open(path: &Path) -> io::Result<Self> {
        let mut file = File::open(path)?;
        let mut header = [0_u8; VECTOR_FILE_HEADER.len()];
        file.read_exact(&mut header)?;
        if &header != VECTOR_FILE_HEADER {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported vector file header",
            ));
        }
        Ok(Self {
            file,
            vectors_read: 0,
        })
    }

    /// Reads a state vector from the file.
    ///
    /// # Returns
    ///
    /// `Some(vector)` if a vector was read, `None` if at EOF.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    pub fn read(&mut self) -> io::Result<Option<StateVector>> {
        let mut buffer = [0u8; VEC_SIZE];
        match self.file.read(&mut buffer[..1])? {
            0 => Ok(None),
            1 => {
                self.file.read_exact(&mut buffer[1..])?;
                self.vectors_read += 1;
                let vector = StateVector::from_binary(buffer);
                if !vector.is_valid() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "vector record contains a non-finite or out-of-range feature",
                    ));
                }
                Ok(Some(vector))
            }
            _ => unreachable!(),
        }
    }

    /// Returns the number of vectors read.
    #[must_use]
    pub const fn vectors_read(&self) -> u64 {
        self.vectors_read
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn vector_distance_is_commutative() {
        let v1 = StateVector {
            length: 0.5,
            severity: 0.3,
            frequency: 0.7,
            timestamp: 0.2,
            process_id: 0.8,
            entropy: 0.1,
            zscore: 0.9,
            protocol: 0.4,
        };
        let v2 = StateVector {
            length: 0.1,
            severity: 0.2,
            frequency: 0.3,
            timestamp: 0.4,
            process_id: 0.5,
            entropy: 0.6,
            zscore: 0.7,
            protocol: 0.8,
        };
        assert!((v1.distance(v2) - v2.distance(v1)).abs() < f64::EPSILON);
    }

    #[test]
    fn vector_serialization_roundtrip() {
        let original = StateVector {
            length: 0.5,
            severity: 0.3,
            frequency: 0.7,
            timestamp: 0.2,
            process_id: 0.8,
            entropy: 0.1,
            zscore: 0.9,
            protocol: 0.4,
        };
        let binary = original.to_binary();
        let deserialized = StateVector::from_binary(binary);
        assert_eq!(original, deserialized);
    }

    #[test]
    fn vector_file_rejects_bad_headers_and_partial_records() {
        let directory = tempdir().unwrap();
        let valid_path = directory.path().join("valid.vec");
        let partial_path = directory.path().join("partial.vec");
        let invalid_path = directory.path().join("invalid.vec");

        let mut writer = VectorWriter::create(&valid_path).unwrap();
        writer.write(StateVector::zero()).unwrap();
        writer.flush().unwrap();
        let mut reader = VectorReader::open(&valid_path).unwrap();
        assert_eq!(reader.read().unwrap(), Some(StateVector::zero()));
        assert_eq!(reader.read().unwrap(), None);

        let mut partial = File::create(&partial_path).unwrap();
        partial.write_all(VECTOR_FILE_HEADER).unwrap();
        partial.write_all(&[0; 7]).unwrap();
        drop(partial);
        let mut reader = VectorReader::open(&partial_path).unwrap();
        assert_eq!(
            reader.read().unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );

        let mut invalid = File::create(&invalid_path).unwrap();
        invalid.write_all(b"NOTAVEC!").unwrap();
        drop(invalid);
        assert_eq!(
            VectorReader::open(&invalid_path).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn zero_vector_is_not_anomaly() {
        let zero = StateVector::zero();
        assert!(!zero.is_anomaly(zero));
    }

    #[test]
    fn vector_builder_creates_valid_vectors() {
        let mut builder = VectorBuilder::new();
        let vector = builder.build(
            100,
            Severity::Error,
            &Analysis::default(),
            Phase::Ready,
            1234,
        );

        // All components should be in [0, 1]
        assert!(vector.length >= 0.0 && vector.length <= 1.0);
        assert!(vector.severity >= 0.0 && vector.severity <= 1.0);
        assert!(vector.frequency >= 0.0 && vector.frequency <= 1.0);
        assert!(vector.timestamp >= 0.0 && vector.timestamp <= 1.0);
        assert!(vector.process_id >= 0.0 && vector.process_id <= 1.0);
        assert!(vector.entropy >= 0.0 && vector.entropy <= 1.0);
        assert!(vector.zscore >= 0.0 && vector.zscore <= 1.0);
        assert!(vector.protocol >= 0.0 && vector.protocol <= 1.0);
    }

    #[test]
    fn vector_encoder_detects_anomalies() {
        let mut encoder = VectorEncoder::new();

        // Feed some normal vectors
        for _ in 0..10 {
            let (_, is_anomaly) = encoder.encode(
                100,
                Severity::Info,
                &Analysis::default(),
                Phase::Ready,
                1234,
            );
            assert!(!is_anomaly);
        }

        // Feed an anomalous vector (very different)
        let (_, is_anomaly) = encoder.encode(
            5000, // Very long line
            Severity::Fatal,
            &Analysis {
                zscore: 100.0,
                error_entropy: 1.0,
                anomaly: true,
            },
            Phase::Cold, // Wrong protocol phase
            99999,       // Different PID
        );
        assert!(is_anomaly);
    }
}
