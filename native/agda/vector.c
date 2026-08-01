#include <stddef.h>
#include <stdint.h>
#include <math.h>
#include <string.h>

// State vector dimension shared with Rust's stable vector format.
#define VEC_DIM 8

// Feature indices shared with Rust's stable vector format.
typedef enum {
    FEATURE_LENGTH = 0,
    FEATURE_SEVERITY = 1,
    FEATURE_FREQUENCY = 2,
    FEATURE_TIMESTAMP = 3,
    FEATURE_PROCESS_ID = 4,
    FEATURE_ENTROPY = 5,
    FEATURE_ZSCORE = 6,
    FEATURE_PROTOCOL = 7
} FeatureIndex;

// Anomaly threshold for vector distance (Euclidean distance)
// Version-one anomaly threshold (3/4 = 0.75).
#define ANOMALY_THRESHOLD 0.75

// State vector type
typedef double StateVector[VEC_DIM];

// Initialize a zero vector
void ccze_vector_zero(StateVector out) {
    for (int i = 0; i < VEC_DIM; i++) {
        out[i] = 0.0;
    }
}

// Compute Euclidean distance between two vectors
double ccze_vector_distance(const StateVector v1, const StateVector v2) {
    double sum_sq = 0.0;
    for (int i = 0; i < VEC_DIM; i++) {
        double diff = v1[i] - v2[i];
        sum_sq += diff * diff;
    }
    return sqrt(sum_sq);
}

// Normalize a vector to unit magnitude
void ccze_vector_normalize(StateVector v) {
    double mag = 0.0;
    for (int i = 0; i < VEC_DIM; i++) {
        mag += v[i] * v[i];
    }
    mag = sqrt(mag);

    if (mag > 0.0) {
        for (int i = 0; i < VEC_DIM; i++) {
            v[i] /= mag;
        }
    }
}

// Add two vectors component-wise
void ccze_vector_add(const StateVector v1, const StateVector v2, StateVector out) {
    for (int i = 0; i < VEC_DIM; i++) {
        out[i] = v1[i] + v2[i];
    }
}

// Scale a vector by a scalar
void ccze_vector_scale(double scalar, const StateVector v, StateVector out) {
    for (int i = 0; i < VEC_DIM; i++) {
        out[i] = scalar * v[i];
    }
}

// Check if observed vector is an anomaly relative to baseline
// Returns 1 if anomaly, 0 otherwise
int32_t ccze_vector_is_anomaly(const StateVector observed, const StateVector baseline) {
    double distance = ccze_vector_distance(observed, baseline);
    return distance >= ANOMALY_THRESHOLD ? 1 : 0;
}

// Blend two vectors (for rolling baseline update)
// new_baseline = baseline * (1 - alpha) + observed * alpha
void ccze_vector_blend(double alpha, const StateVector baseline,
                       const StateVector observed, StateVector out) {
    double inv_alpha = 1.0 - alpha;
    for (int i = 0; i < VEC_DIM; i++) {
        out[i] = baseline[i] * inv_alpha + observed[i] * alpha;
    }
}

// Compute the mean vector from a batch of vectors
void ccze_vector_mean(const StateVector* vectors, size_t count, StateVector out) {
    if (count == 0) {
        ccze_vector_zero(out);
        return;
    }

    StateVector sum;
    ccze_vector_zero(sum);

    for (size_t i = 0; i < count; i++) {
        for (int j = 0; j < VEC_DIM; j++) {
            sum[j] += vectors[i][j];
        }
    }

    double inv_count = 1.0 / (double)count;
    for (int j = 0; j < VEC_DIM; j++) {
        out[j] = sum[j] * inv_count;
    }
}

// Get the dimension of state vectors
int32_t ccze_vector_dimension(void) {
    return VEC_DIM;
}
