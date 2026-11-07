/*
 * Self-written plain-C header used by the QA suite. C++ keywords appear only in
 * comments and string literals: class Fake; template <typename T>;
 * namespace demo; public:; ns::thing; virtual nullptr constexpr operator
 */
#ifndef PLAIN_C_H
#define PLAIN_C_H

// virtual nullptr constexpr operator
typedef struct {
    int raw;
} plain_c_sample_t;

static const char *plain_c_banner = "class Fake; namespace demo; template<typename T>";

int plain_c_compute(plain_c_sample_t *sample, int x);

#endif /* PLAIN_C_H */
