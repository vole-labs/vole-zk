#ifndef EMP_ZK_FIELD_EXEC_H__
#define EMP_ZK_FIELD_EXEC_H__

// Field-generic arithmetic ZK executor and polynomial proofs (QuickSilver),
// one singleton per field type. Gates on AuthF<FP> labels; linear gates are
// local and identical on both parties (the verifier's value lane is 0).

#include "emp-zk/emp-zk-arith/generic/field_ostriple.h"

namespace emp {

template <class FP, class FPS>
class ZKFieldExec {
public:
  using L = AuthF<FP>;
  static inline ZKFieldExec *zk_exec = nullptr;

  int party;
  BoolIO *io;
  FieldOSTriple<FP, FPS> *ostriple;
  FP delta;    // verifier only
  FP pub_mac;  // public tag carried by public constants
  int64_t gid = 0;

  ZKFieldExec(BoolIO *io, int party, int threads = 1, BoolIO *vole_io = nullptr,
              int vole_threads = -1, const FP *delta_in = nullptr)
      : party(party), io(io) {
    ostriple = new FieldOSTriple<FP, FPS>(party, io, threads, vole_io, vole_threads, delta_in);
    delta = ostriple->delta;
    block t = zero_block;
    PRP(zero_block).permute_block(&t, 1);
    pub_mac.from_block(t);
  }
  ~ZKFieldExec() { delete ostriple; }

  // ---- inputs / outputs ----
  void feed(L &label, const FP &v) {
    label = (party == ALICE) ? ostriple->input_send(v) : ostriple->input_recv();
  }
  void feed(L *label, const FP *v, int64_t len) {
    if (party == ALICE) ostriple->input_send(label, v, len);
    else                ostriple->input_recv(label, len);
  }
  void reveal(const L *label, FP *v, int64_t len) {
    if (party == ALICE) ostriple->reveal_send(label, v, len);
    else                ostriple->reveal_recv(label, v, len);
  }
  void reveal_check(const L *label, const FP *expect, int64_t len) {
    if (party == ALICE) ostriple->reveal_check_send(label, len);
    else                ostriple->reveal_check_recv(label, expect, len);
  }
  void reveal_check_zero(const L *label, int64_t len) { ostriple->reveal_check_zero(label, len); }

  // ---- gates ----
  L add_gate(const L &a, const L &b) const { return L{a.val + b.val, a.mac + b.mac}; }
  L sub_gate(const L &a, const L &b) const { return L{a.val - b.val, a.mac - b.mac}; }
  L neg_gate(const L &a) const { return L{a.val.negate(), a.mac.negate()}; }
  L mul_const_gate(const L &a, const FP &c) const { return L{a.val * c, a.mac * c}; }
  // Public constant c: prover (c, pub_mac), verifier (0, pub_mac - c*Delta).
  L pub_label(const FP &c) const {
    return party == ALICE ? L{c, pub_mac} : L{FP(), pub_mac - c * delta};
  }
  L mul_gate(const L &a, const L &b) {
    ++gid;
    return party == ALICE ? ostriple->mul_send(a, b) : ostriple->mul_recv(a, b);
  }
  void mul_gate(L *out, const L *a, const L *b, int64_t len) {
    gid += len;
    if (party == ALICE) ostriple->mul_send(out, a, b, len);
    else                ostriple->mul_recv(out, a, b, len);
  }
};

// Degree-2 polynomial and inner-product proofs, batched (QuickSilver). Same
// statements as FpPolyProof:
//   zkp_poly_deg2(x, y, coeff, len): coeff[0] + sum_i coeff[i+1]*x_i*y_i = 0
//   zkp_inner_prdt(x, y, c, len):     c + sum_i x_i*y_i = 0
template <class FP, class FPS>
class FieldPolyProof {
public:
  using L = AuthF<FP>;
  static inline FieldPolyProof *instance = nullptr;

  int party;
  BoolIO *io;
  FieldOSTriple<FP, FPS> *ostriple;
  FP delta;
  int64_t buffer_sz = 1024;
  std::vector<FP> buf0, buf1;
  int64_t num = 0;
  static constexpr int64_t kParMin = 64;

  FieldPolyProof(int party, BoolIO *io, FieldOSTriple<FP, FPS> *ostriple)
      : party(party), io(io), ostriple(ostriple), delta(ostriple->delta) {
    buf0.resize(buffer_sz);
    buf1.resize(buffer_sz);
  }
  ~FieldPolyProof() { batch_check(); }

  template <class Fn>
  FP par_sum_(int64_t n, Fn &&f) const {
    const int T = ostriple->threads_;
    ThreadPool *pool = ostriple->pool_;
    if (T <= 1 || pool == nullptr || n < kParMin) {
      FP s;
      for (int64_t i = 0; i < n; ++i) s = s + f(i);
      return s;
    }
    std::vector<FP> part((size_t)T);
    const int64_t width = n / T;
    std::vector<std::future<void>> fut;
    for (int t = 0; t < T - 1; ++t) {
      const int64_t s = (int64_t)t * width, e = s + width;
      fut.push_back(pool->enqueue([&part, t, s, e, &f]() {
        FP acc;
        for (int64_t i = s; i < e; ++i) acc = acc + f(i);
        part[(size_t)t] = acc;
      }));
    }
    FP acc;
    for (int64_t i = (int64_t)(T - 1) * width; i < n; ++i) acc = acc + f(i);
    part[(size_t)(T - 1)] = acc;
    for (auto &fu : fut) fu.get();
    FP r;
    for (int t = 0; t < T; ++t) r = r + part[(size_t)t];
    return r;
  }

  // Prover: (U + M*, V + r*); verifier: W + K* + (V + r*)*Delta == U + M*.
  void batch_check() {
    if (num == 0) return;
    io->flush();
    block seed;
    if (party == ALICE) {
      io->recv_data(&seed, sizeof(block));
    } else {
      PRG().random_block(&seed, 1);
      io->send_data(&seed, sizeof(block));
    }
    std::vector<FP> chi((size_t)num);
    field_coeff_gen(chi.data(), seed, num);
    L mask;
    ostriple->draw_vole(&mask, 1);
    FP U, V;
    for (int64_t i = 0; i < num; ++i) {
      U = U + chi[i] * buf0[i];
      if (party == ALICE) V = V + chi[i] * buf1[i];
    }
    if (party == ALICE) {
      FP cs[2] = {U + mask.mac, V + mask.val};
      io->send_data(cs, 2 * sizeof(FP));
    } else {
      FP cs[2];
      io->recv_data(cs, 2 * sizeof(FP));
      if (U + mask.mac + field_canon(cs[1]) * delta != field_canon(cs[0]))
        error("polynomial zkp fails");
    }
    io->flush();
    num = 0;
  }

  void zkp_poly_deg2(const L *x, const L *y, const FP *coeff, int64_t len) {
    if (num >= buffer_sz) batch_check();
    if (party == ALICE) {
      buf0[num] = par_sum_(len, [&](int64_t i) { return coeff[i + 1] * (x[i].mac * y[i].mac); });
      buf1[num] = par_sum_(len, [&](int64_t i) {
        return coeff[i + 1] * (x[i].mac * y[i].val + y[i].mac * x[i].val);
      });
    } else {
      FP B = par_sum_(len, [&](int64_t i) { return coeff[i + 1] * (x[i].mac * y[i].mac); });
      buf0[num] = B + coeff[0] * (delta * delta);
    }
    num++;
  }

  void zkp_inner_prdt(const L *x, const L *y, const FP &constant, int64_t len) {
    if (num >= buffer_sz) batch_check();
    if (party == ALICE) {
      buf0[num] = par_sum_(len, [&](int64_t i) { return x[i].mac * y[i].mac; });
      buf1[num] = par_sum_(len, [&](int64_t i) {
        return x[i].mac * y[i].val + y[i].mac * x[i].val;
      });
    } else {
      FP B = par_sum_(len, [&](int64_t i) { return x[i].mac * y[i].mac; });
      buf0[num] = B + constant * (delta * delta);
    }
    num++;
  }
};

}  // namespace emp
#endif
