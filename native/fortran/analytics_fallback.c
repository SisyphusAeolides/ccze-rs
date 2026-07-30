#include <math.h>
#include <stddef.h>
#include <stdint.h>

void ccze_analyze_metrics(const int32_t *lengths, const int32_t *errors,
                          size_t count, double threshold, double *zscore,
                          double *entropy, int32_t *anomaly) {
    if (count == 0) {
        *zscore = 0.0;
        *entropy = 0.0;
        *anomaly = 0;
        return;
    }

    double mean = 0.0;
    double error_rate = 0.0;
    for (size_t i = 0; i < count; ++i) {
        mean += lengths[i];
        error_rate += errors[i];
    }
    mean /= (double)count;
    error_rate /= (double)count;

    double variance = 0.0;
    for (size_t i = 0; i < count; ++i) {
        const double delta = lengths[i] - mean;
        variance += delta * delta;
    }
    variance /= (double)count;
    *zscore = variance > 0.0 ? fabs(lengths[count - 1] - mean) / sqrt(variance) : 0.0;

    *entropy = 0.0;
    if (error_rate > 0.0) {
        *entropy -= error_rate * log2(error_rate);
    }
    const double normal_rate = 1.0 - error_rate;
    if (normal_rate > 0.0) {
        *entropy -= normal_rate * log2(normal_rate);
    }
    *anomaly = (*zscore >= threshold || error_rate >= 0.5) ? 1 : 0;
}
