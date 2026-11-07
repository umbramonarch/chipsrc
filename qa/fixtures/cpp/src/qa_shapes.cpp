// Self-written QA fixture: out-of-line C++ member definitions, including a
// namespace-qualified nested class, constructor, destructor, and operator.
// Not derived from any third-party source.
#include "qa_shapes.h"

namespace qa_demo {

Outer::Outer(int seed) : value_(seed) {}

Outer::~Outer() = default;

int Outer::value() const { return value_; }

Outer Outer::operator+(const Outer &other) const {
    return Outer(value_ + other.value());
}

Outer::Inner::Inner(int tag) : tag_(tag) {}

int Outer::Inner::tag() const { return tag_; }

int helper_sum(int left, int right) { return left + right; }

}  // namespace qa_demo
