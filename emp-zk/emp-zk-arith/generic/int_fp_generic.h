#ifndef EMP_ZK_INT_FP_GENERIC_H__
#define EMP_ZK_INT_FP_GENERIC_H__

// Front end of the field-generic arithmetic engine.
//
//   IntFpG<FP, FPS>      committed field element (IntFp's API over any field)
//   IntFpVecG<FP, FPS>   batch of committed elements (IntFpVec's element-wise API)
//   IntFpT<FP, FPS>      the engine to use for a field: IntFp (the tuned FP61
//                        engine) for <FP61, FP61x2>, IntFpG otherwise
//   setup_zk_arith<FP, FPS>(io, party, threads, vole_io, vole_threads, delta)
//   finalize_zk_arith<FP, FPS>()
//   setup_zk_arith_generic / finalize_zk_arith_generic: always the generic
//                        engine (also for FP61; used to compare against it)
//
// FP / FPS are vole's single-element and value||MAC types:
//   FP61/FP61x2, FP107/FP107x2, FP192/FP192x2, FP25519/FP25519x2,
//   FPP256/FPP256x2 (prime fields) and
//   FP2x128/FP2x128x2 (GF(2^128)). Values are FP; uint64_t inputs are accepted
// and mapped with FP(uint64_t).

#include "emp-zk/emp-zk-arith/generic/field_exec.h"
#include "emp-zk/emp-zk-arith/emp-zk-arith.h"
#include <type_traits>

namespace emp {

template <class FP, class FPS>
class IntFpG {
public:
  using L = AuthF<FP>;
  using Exec = ZKFieldExec<FP, FPS>;
  L value;

  IntFpG() {}
  IntFpG(const FP &input, int party = PUBLIC) {
    if (party == PUBLIC) value = Exec::zk_exec->pub_label(input);
    else                 Exec::zk_exec->feed(value, input);
  }
  IntFpG(uint64_t input, int party = PUBLIC) : IntFpG(FP(input), party) {}

  FP reveal() const {
    FP out;
    Exec::zk_exec->reveal(&value, &out, 1);
    return out;
  }
  bool reveal(const FP &expect) const {
    Exec::zk_exec->reveal_check(&value, &expect, 1);
    return true;
  }
  void reveal_zero() const { Exec::zk_exec->reveal_check_zero(&value, 1); }

  IntFpG operator+(const IntFpG &rhs) const { return wrap(Exec::zk_exec->add_gate(value, rhs.value)); }
  IntFpG operator-(const IntFpG &rhs) const { return wrap(Exec::zk_exec->sub_gate(value, rhs.value)); }
  IntFpG operator*(const IntFpG &rhs) const { return wrap(Exec::zk_exec->mul_gate(value, rhs.value)); }
  IntFpG operator*(const FP &c) const { return wrap(Exec::zk_exec->mul_const_gate(value, c)); }
  IntFpG operator+(const FP &c) const { return wrap(Exec::zk_exec->add_gate(value, Exec::zk_exec->pub_label(c))); }
  IntFpG operator-(const FP &c) const { return wrap(Exec::zk_exec->sub_gate(value, Exec::zk_exec->pub_label(c))); }
  IntFpG operator*(uint64_t c) const { return *this * FP(c); }
  IntFpG operator+(uint64_t c) const { return *this + FP(c); }
  IntFpG operator-(uint64_t c) const { return *this - FP(c); }
  IntFpG negate() const { return wrap(Exec::zk_exec->neg_gate(value)); }

  static IntFpG wrap(const L &l) { IntFpG r; r.value = l; return r; }
};

template <class FP, class FPS>
class IntFpVecG {
public:
  using L = AuthF<FP>;
  using Exec = ZKFieldExec<FP, FPS>;
  using Elem = IntFpG<FP, FPS>;
  std::vector<L> value;

  IntFpVecG() {}
  explicit IntFpVecG(int64_t len) : value((size_t)len) {}
  // Commit `len` values: ALICE/BOB = one batched authenticated feed (the
  // verifier ignores `input`), PUBLIC = public constants.
  IntFpVecG(const FP *input, int64_t len, int party = PUBLIC) : value((size_t)len) {
    if (party == PUBLIC)
      for (int64_t i = 0; i < len; ++i) value[i] = Exec::zk_exec->pub_label(input[i]);
    else
      Exec::zk_exec->feed(value.data(), input, len);
  }

  int64_t size() const { return (int64_t)value.size(); }
  Elem operator[](int64_t i) const { return Elem::wrap(value[(size_t)i]); }

  IntFpVecG operator*(const IntFpVecG &rhs) const {
    IntFpVecG r(size());
    Exec::zk_exec->mul_gate(r.value.data(), value.data(), rhs.value.data(), size());
    return r;
  }
  template <class Op>
  IntFpVecG map2_(const IntFpVecG &rhs, Op op) const {
    IntFpVecG r(size());
    for (int64_t i = 0; i < size(); ++i) r.value[i] = op(value[i], rhs.value[i]);
    return r;
  }
  template <class Op>
  IntFpVecG map1_(Op op) const {
    IntFpVecG r(size());
    for (int64_t i = 0; i < size(); ++i) r.value[i] = op(value[i], i);
    return r;
  }
  IntFpVecG operator+(const IntFpVecG &rhs) const {
    return map2_(rhs, [](const L &a, const L &b) { return Exec::zk_exec->add_gate(a, b); });
  }
  IntFpVecG operator-(const IntFpVecG &rhs) const {
    return map2_(rhs, [](const L &a, const L &b) { return Exec::zk_exec->sub_gate(a, b); });
  }
  IntFpVecG operator*(const FP &c) const {
    return map1_([&](const L &a, int64_t) { return Exec::zk_exec->mul_const_gate(a, c); });
  }
  IntFpVecG operator+(const FP &c) const {
    const L pc = Exec::zk_exec->pub_label(c);
    return map1_([&](const L &a, int64_t) { return Exec::zk_exec->add_gate(a, pc); });
  }
  IntFpVecG operator-(const FP &c) const {
    const L pc = Exec::zk_exec->pub_label(c);
    return map1_([&](const L &a, int64_t) { return Exec::zk_exec->sub_gate(a, pc); });
  }
  IntFpVecG operator*(const std::vector<FP> &c) const {
    return map1_([&](const L &a, int64_t i) { return Exec::zk_exec->mul_const_gate(a, c[i]); });
  }
  IntFpVecG operator+(const std::vector<FP> &c) const {
    return map1_([&](const L &a, int64_t i) { return Exec::zk_exec->add_gate(a, Exec::zk_exec->pub_label(c[i])); });
  }
  IntFpVecG operator-(const std::vector<FP> &c) const {
    return map1_([&](const L &a, int64_t i) { return Exec::zk_exec->sub_gate(a, Exec::zk_exec->pub_label(c[i])); });
  }
  IntFpVecG negate() const {
    return map1_([](const L &a, int64_t) { return Exec::zk_exec->neg_gate(a); });
  }

  Elem sum() const {
    if (size() == 0) return Elem::wrap(Exec::zk_exec->pub_label(FP()));
    L acc = value[0];
    for (int64_t i = 1; i < size(); ++i) acc = Exec::zk_exec->add_gate(acc, value[i]);
    return Elem::wrap(acc);
  }

  std::vector<Elem> decompose() const {
    std::vector<Elem> out((size_t)size());
    for (int64_t i = 0; i < size(); ++i) out[i].value = value[i];
    return out;
  }
  static IntFpVecG compose(const Elem *a, int64_t len) {
    IntFpVecG r(len);
    for (int64_t i = 0; i < len; ++i) r.value[i] = a[i].value;
    return r;
  }
  static IntFpVecG compose(const std::vector<Elem> &a) { return compose(a.data(), (int64_t)a.size()); }

  // Local cleartext extract (prover: committed values; verifier: zeros).
  std::vector<FP> values() const {
    std::vector<FP> out((size_t)size());
    for (int64_t i = 0; i < size(); ++i) out[i] = value[i].val;
    return out;
  }
  void reveal(FP *out) const { Exec::zk_exec->reveal(value.data(), out, size()); }
  bool reveal_check(const FP *expect) const {
    Exec::zk_exec->reveal_check(value.data(), expect, size());
    return true;
  }
  void reveal_check_zero() const { Exec::zk_exec->reveal_check_zero(value.data(), size()); }
};

// ---- batch helpers (same names as the FP61 engine's, overloaded) ----
template <class FP, class FPS>
inline void batch_feed(IntFpG<FP, FPS> *obj, const FP *v, int64_t len) {
  ZKFieldExec<FP, FPS>::zk_exec->feed((AuthF<FP> *)obj, v, len);
}
template <class FP, class FPS>
inline void batch_reveal(const IntFpG<FP, FPS> *obj, FP *v, int64_t len) {
  ZKFieldExec<FP, FPS>::zk_exec->reveal((const AuthF<FP> *)obj, v, len);
}
template <class FP, class FPS>
inline bool batch_reveal_check(const IntFpG<FP, FPS> *obj, const FP *expect, int64_t len) {
  ZKFieldExec<FP, FPS>::zk_exec->reveal_check((const AuthF<FP> *)obj, expect, len);
  return true;
}
template <class FP, class FPS>
inline bool batch_reveal_check_zero(const IntFpG<FP, FPS> *obj, int64_t len) {
  ZKFieldExec<FP, FPS>::zk_exec->reveal_check_zero((const AuthF<FP> *)obj, len);
  return true;
}
template <class FP, class FPS>
inline void fp_zkp_poly_deg2(const IntFpG<FP, FPS> *x, const IntFpG<FP, FPS> *y,
                             const FP *coeff, int64_t len) {
  FieldPolyProof<FP, FPS>::instance->zkp_poly_deg2((const AuthF<FP> *)x,
                                                   (const AuthF<FP> *)y, coeff, len);
}
template <class FP, class FPS>
inline void fp_zkp_inner_prdt(const IntFpG<FP, FPS> *x, const IntFpG<FP, FPS> *y,
                              const FP &constant, int64_t len) {
  FieldPolyProof<FP, FPS>::instance->zkp_inner_prdt((const AuthF<FP> *)x,
                                                    (const AuthF<FP> *)y, constant, len);
}
static_assert(sizeof(IntFpG<FP61, FP61x2>) == sizeof(AuthF<FP61>), "IntFpG is a bare label");

// ---- setup / teardown ----
// `delta` (verifier, optional): use this Delta (e.g. the Boolean engine's
// GF(2^128) Delta for FP2x128) instead of a fresh one.
template <class FP, class FPS>
inline void setup_zk_arith_generic(BoolIO *io, int party, int threads = 1,
                                   BoolIO *vole_io = nullptr, int vole_threads = -1,
                                   const FP *delta = nullptr) {
  using Exec = ZKFieldExec<FP, FPS>;
  if (Exec::zk_exec != nullptr) error("setup_zk_arith: field engine already set up");
  Exec::zk_exec = new Exec(io, party, threads, vole_io, vole_threads, delta);
  FieldPolyProof<FP, FPS>::instance =
      new FieldPolyProof<FP, FPS>(party, io, Exec::zk_exec->ostriple);
}
template <class FP, class FPS>
inline void finalize_zk_arith_generic() {
  using Exec = ZKFieldExec<FP, FPS>;
  delete FieldPolyProof<FP, FPS>::instance;
  FieldPolyProof<FP, FPS>::instance = nullptr;
  delete Exec::zk_exec;
  Exec::zk_exec = nullptr;
}

template <class FP, class FPS>
inline constexpr bool uses_fp61_engine = std::is_same_v<FP, FP61> && std::is_same_v<FPS, FP61x2>;

// The engine for a field: FP61 -> the tuned FP61 engine (IntFp), others -> generic.
template <class FP, class FPS>
inline void setup_zk_arith(BoolIO *io, int party, int threads = 1,
                           BoolIO *vole_io = nullptr, int vole_threads = -1,
                           const FP *delta = nullptr) {
  if constexpr (uses_fp61_engine<FP, FPS>) {
    if (delta != nullptr) error("setup_zk_arith<FP61>: the FP61 engine draws its own Delta");
    setup_zk_arith(io, party, threads, 0, vole_io, vole_threads);
  } else {
    setup_zk_arith_generic<FP, FPS>(io, party, threads, vole_io, vole_threads, delta);
  }
}
template <class FP, class FPS>
inline void finalize_zk_arith() {
  if constexpr (uses_fp61_engine<FP, FPS>) {
    finalize_zk_arith();
    // the FP61 engine's teardown leaves its singletons dangling; clear them so
    // a later setup (of any field) starts from a clean state
    ZKFpExec::zk_exec = nullptr;
    FpPolyProof::fppolyproof = nullptr;
    EdaBits::conv = nullptr;
  } else {
    finalize_zk_arith_generic<FP, FPS>();
  }
}

template <class FP, class FPS>
using IntFpT = std::conditional_t<uses_fp61_engine<FP, FPS>, IntFp, IntFpG<FP, FPS>>;
template <class FP, class FPS>
using IntFpVecT = std::conditional_t<uses_fp61_engine<FP, FPS>, IntFpVec, IntFpVecG<FP, FPS>>;

}  // namespace emp
#endif
