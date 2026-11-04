// Self-written QA fixture: C++ class templates, namespaces, nested classes,
// operator overloads, constructors, destructors, and a using alias.
// Not derived from any third-party source.
#ifndef QA_SHAPES_H
#define QA_SHAPES_H

#include <cstddef>

namespace qa_demo {

class Outer {
public:
    explicit Outer(int seed);
    ~Outer();

    int value() const;
    Outer operator+(const Outer &other) const;

    class Inner {
    public:
        explicit Inner(int tag);
        int tag() const;
    private:
        int tag_;
    };

private:
    int value_;
};

template <
    typename T,
    typename Allocator = std::allocator<T>,
    typename Comparator = std::less<T>>
class Box {
public:
    Box();
    ~Box();

    const T &value() const;
    T &operator[](std::size_t index);

    class Slot {
    public:
        explicit Slot(std::size_t index);
        std::size_t index() const;
    private:
        std::size_t index_;
    };

private:
    T value_;
};

using ShapeId = unsigned int;

int helper_sum(int left, int right);

}  // namespace qa_demo

#endif  // QA_SHAPES_H
