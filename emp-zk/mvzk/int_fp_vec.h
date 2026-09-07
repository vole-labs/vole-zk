#ifndef EMP_ZK_MVZK_INT_FP_VEC_H__
#define EMP_ZK_MVZK_INT_FP_VEC_H__
// IntFpVec for the multi-verifier backend: a batch of IntFp wires with the
// element-wise API of emp-zk-arith's IntFpVec (operators with vectors, public
// scalars and public vectors, operator[], sum, negate, compose / decompose,
// batched reveal / reveal_check). It is a convenience layer: the mvzk backend
// already packs k consecutive wires whatever the caller's grouping, so the
// element-wise operators cost the same as the scalar loops they replace.
// sum() and dot() build one linear node instead of a chain of additions.
#include "emp-zk/mvzk/int_fp.h"

namespace emp {
namespace mvzk {

template <typename IO>
class IntFpVecT {
public:
  using IntFp = IntFpT<IO>;
  using Exec = MvzkExec<IO>;
  std::vector<IntFp> value;

  IntFpVecT() {}
  explicit IntFpVecT(int64_t len) : value((std::size_t)len) {}

  // party == PUBLIC: constants; otherwise witnesses fed by the prover
  IntFpVecT(const uint64_t *input, int64_t len, int party = PUBLIC) : value((std::size_t)len) {
    for (int64_t i = 0; i < len; ++i) value[(std::size_t)i] = IntFp(input[i], party);
  }

  int64_t size() const { return (int64_t)value.size(); }

  // element-wise with another vector
  IntFpVecT operator*(const IntFpVecT &rhs) const { return zip(rhs, [](const IntFp &a, const IntFp &b) { return a * b; }); }
  IntFpVecT operator+(const IntFpVecT &rhs) const { return zip(rhs, [](const IntFp &a, const IntFp &b) { return a + b; }); }
  IntFpVecT operator-(const IntFpVecT &rhs) const { return zip(rhs, [](const IntFp &a, const IntFp &b) { return a - b; }); }
  // with a public scalar
  IntFpVecT operator*(uint64_t c) const { return map([c](const IntFp &a) { return a * c; }); }
  IntFpVecT operator+(uint64_t c) const { return map([c](const IntFp &a) { return a + c; }); }
  IntFpVecT operator-(uint64_t c) const { return map([c](const IntFp &a) { return a - c; }); }
  // with a public vector
  IntFpVecT operator*(const std::vector<uint64_t> &c) const { return zipPub(c, [](const IntFp &a, uint64_t v) { return a * v; }); }
  IntFpVecT operator+(const std::vector<uint64_t> &c) const { return zipPub(c, [](const IntFp &a, uint64_t v) { return a + v; }); }
  IntFpVecT operator-(const std::vector<uint64_t> &c) const { return zipPub(c, [](const IntFp &a, uint64_t v) { return a - v; }); }
  IntFpVecT negate() const { return map([](const IntFp &a) { return a.negate(); }); }

  IntFp operator[](int64_t i) const { return value[(std::size_t)i]; }

  // sum of all elements: one linear node (local, no communication)
  IntFp sum() const {
    if (value.empty()) return IntFp(0, PUBLIC);
    std::vector<std::pair<FP59, typename Exec::SlotP>> terms;
    terms.reserve(value.size());
    for (const auto &w : value) terms.emplace_back(FP59(1, false), w.s);
    IntFp r;
    r.s = Exec::exec->linear(std::move(terms), FP59(0, false));
    return r;
  }
  // inner product <this, rhs>: len multiplications and one linear node
  IntFp dot(const IntFpVecT &rhs) const { return ((*this) * rhs).sum(); }

  static IntFpVecT compose(const IntFp *a, int64_t len) {
    IntFpVecT r(len);
    for (int64_t i = 0; i < len; ++i) r.value[(std::size_t)i] = a[i];
    return r;
  }
  static IntFpVecT compose(const std::vector<IntFp> &a) { return compose(a.data(), (int64_t)a.size()); }
  std::vector<IntFp> decompose() const { return value; }
  void decompose(IntFp *out) const { for (int64_t i = 0; i < size(); ++i) out[i] = value[(std::size_t)i]; }

  // cleartext values: meaningful on the prover only (0 on verifiers), local
  void values(uint64_t *out) const {
    for (int64_t i = 0; i < size(); ++i) out[i] = Exec::exec->prover ? value[(std::size_t)i].s->val.val : 0;
  }
  std::vector<uint64_t> values() const { std::vector<uint64_t> o((std::size_t)size()); values(o.data()); return o; }

  // batched outputs (one MAC check for the whole vector)
  void reveal(uint64_t *out) { batch_reveal(value.data(), out, size()); }
  bool reveal_check(const uint64_t *expect) { return batch_reveal_check(value.data(), expect, size()); }
  bool reveal_check_zero() { return batch_reveal_check_zero(value.data(), size()); }

private:
  template <typename F> IntFpVecT map(F f) const {
    IntFpVecT r(size());
    for (int64_t i = 0; i < size(); ++i) r.value[(std::size_t)i] = f(value[(std::size_t)i]);
    return r;
  }
  template <typename F> IntFpVecT zip(const IntFpVecT &rhs, F f) const {
    if (rhs.size() != size()) error("mvzk IntFpVec: length mismatch");
    IntFpVecT r(size());
    for (int64_t i = 0; i < size(); ++i) r.value[(std::size_t)i] = f(value[(std::size_t)i], rhs.value[(std::size_t)i]);
    return r;
  }
  template <typename F> IntFpVecT zipPub(const std::vector<uint64_t> &c, F f) const {
    if ((int64_t)c.size() != size()) error("mvzk IntFpVec: length mismatch");
    IntFpVecT r(size());
    for (int64_t i = 0; i < size(); ++i) r.value[(std::size_t)i] = f(value[(std::size_t)i], c[(std::size_t)i]);
    return r;
  }
};

using IntFpVec = IntFpVecT<NetIO>;

}  // namespace mvzk
}  // namespace emp
#endif
