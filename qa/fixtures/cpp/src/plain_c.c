/* Self-written plain-C implementation used by the QA suite. */
#include "plain_c.h"

static const char *plain_c_banner =
    "class Fake; namespace demo; template<typename T>";

int plain_c_compute(plain_c_sample_t *sample, int x) {
    if (sample == 0) {
        return x;
    }
    return sample->raw + x;
}

const char *plain_c_banner_text(void) { return plain_c_banner; }
