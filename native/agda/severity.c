#include <stdint.h>

int32_t ccze_severity_join(int32_t left, int32_t right) {
    if (left < 0 || left > 5 || right < 0 || right > 5) {
        return 2;
    }
    return left > right ? left : right;
}
