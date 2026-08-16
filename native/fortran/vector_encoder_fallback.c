#include <stdint.h>
#include <math.h>
#include <string.h>

// State vector dimension - must match VEC_DIM in Vector.agda
#define VEC_DIM 8

// Feature indices - must match FeatureIndex in vector.c
#define FEATURE_LENGTH 0
#define FEATURE_SEVERITY 1
#define FEATURE_FREQUENCY 2
#define FEATURE_TIMESTAMP 3
#define FEATURE_PROCESS_ID 4
#define FEATURE_ENTROPY 5
#define FEATURE_ZSCORE 6
#define FEATURE_PROTOCOL 7

// Normalization constants
#define MAX_LENGTH 1024.0
#define MAX_FREQUENCY 1000.0
#define MAX_PID 4194304.0
#define MAX_ZSCORE 10.0
#define MAX_PROTOCOL 4.0

// Baseline update parameters
#define BASELINE_ALPHA 0.01

// State vector type
typedef double StateVector[VEC_DIM];

// Compute a state vector from log metrics
void ccze_compute_state_vector(int32_t length, int32_t severity, double frequency,
                                double timestamp, int32_t process_id, double entropy,
                                double zscore, int32_t protocol_phase, StateVector vector) {
    // Normalize all features to 0-1 range

    // Length: normalize to [0, 1]
    vector[FEATURE_LENGTH] = fmin(1.0, (double)length / MAX_LENGTH);

    // Severity: normalize to [0, 1] (0=trace, 5=fatal)
    vector[FEATURE_SEVERITY] = fmin(1.0, (double)severity / 5.0);

    // Frequency: normalize to [0, 1]
    vector[FEATURE_FREQUENCY] = fmin(1.0, frequency / MAX_FREQUENCY);

    // Timestamp: already normalized to [0, 1] within window
    vector[FEATURE_TIMESTAMP] = timestamp;

    // Process ID: hash to [0, 1] using simple modulo
    vector[FEATURE_PROCESS_ID] = fmod((double)process_id, MAX_PID) / MAX_PID;

    // Entropy: normalize to [0, 1] (binary entropy max is ~1)
    vector[FEATURE_ENTROPY] = fmin(1.0, entropy);

    // Z-score: clamp and normalize to [0, 1]
    vector[FEATURE_ZSCORE] = fmin(1.0, fmax(0.0, zscore / MAX_ZSCORE));

    // Protocol phase: normalize to [0, 1]
    vector[FEATURE_PROTOCOL] = fmin(1.0, (double)protocol_phase / MAX_PROTOCOL);
}

// Update the baseline vector with a new observed vector
void ccze_update_baseline(StateVector baseline, const StateVector observed,
                           double alpha, int32_t count) {
    int i;
    double inv_alpha = 1.0 - alpha;

    // If this is the first vector, just copy it
    if (count <= 1) {
        for (i = 0; i < VEC_DIM; i++) {
            baseline[i] = observed[i];
        }
        return;
    }

    // Apply exponential moving average
    for (i = 0; i < VEC_DIM; i++) {
        baseline[i] = baseline[i] * inv_alpha + observed[i] * alpha;
    }
}

// Serialize a state vector to binary format for storage
void ccze_vector_to_binary(const StateVector vector, int8_t buffer[64]) {
    memcpy(buffer, vector, 64);
}

// Deserialize a state vector from binary format
void ccze_vector_from_binary(const int8_t buffer[64], StateVector vector) {
    memcpy(vector, buffer, 64);
}
