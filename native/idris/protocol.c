#include <stdint.h>

int32_t ccze_protocol_step(int32_t phase, int32_t event) {
    if (event == 4) {
        return 0;
    }
    if (phase >= 0 && phase <= 3 && event == phase) {
        return phase + 1;
    }
    return -1;
}
