#ifndef ZK_FP_EXECUTION_H__
#define ZK_FP_EXECUTION_H__

#include "emp-zk/vole_stream.h"
#include "emp-ot/emp-ot.h"
#include "emp-zk/emp-zk-arith/ostriple.h"
#include "emp-zk/emp-zk-arith/edabit/edabits.h"

namespace emp {
using namespace std;

class ZKFpExec {
public:
  int64_t gid = 0;
  __uint128_t pub_mac;
  int B, c;

  static ZKFpExec *zk_exec;

  ZKFpExec() {
    // pub_mac is a public domain-separation tag from fixed-key PRP(0), reduced
    // into F_p. Prover and verifier use the same key so the tags match; it is
    // party-agnostic, so it is derived once here on the base.
    *(block *)&pub_mac = zero_block;
    PRP(zero_block).permute_block((block *)&pub_mac, 1);
    pub_mac = mod(pub_mac & (__uint128_t)0xFFFFFFFFFFFFFFFFULL, pr);
  }
  virtual ~ZKFpExec() {}

  virtual void feed(__uint128_t &label, const uint64_t &value) = 0;

  virtual void feed(__uint128_t *label, const uint64_t *value, int64_t len) = 0;

  virtual void reveal(__uint128_t *label, uint64_t *value, int64_t len) = 0;

  virtual void reveal_check(__uint128_t *label, const uint64_t *value,
                            int64_t len) = 0;

  virtual void reveal_check_zero(__uint128_t *label, int64_t len) = 0;

  virtual __uint128_t add_gate(const __uint128_t &a, const __uint128_t &b) = 0;

  // a - b = a + (p - b), componentwise modular subtraction on the shares
  // (local, no communication) — the additive counterpart of add_gate.
  virtual __uint128_t sub_gate(const __uint128_t &a, const __uint128_t &b) = 0;

  // -a = p - a componentwise (additive negation, local).
  virtual __uint128_t neg_gate(const __uint128_t &a) = 0;

  virtual __uint128_t mul_gate(const __uint128_t &a, const __uint128_t &b) = 0;

  // Vectorized multiply: `len` INDEPENDENT products out_i = a_i * b_i in one
  // batched, threaded call (routes to the vectorized auth_compute_mul). Used by
  // IntFpVec; equivalent to `len` scalar mul_gate calls but with a single
  // batched correction send and parallel field arithmetic.
  virtual void mul_gate(__uint128_t *out, const __uint128_t *a,
                        const __uint128_t *b, int64_t len) = 0;

  virtual __uint128_t mul_const_gate(const __uint128_t &a,
                                     const uint64_t &b) = 0;

  virtual __uint128_t pub_label(const uint64_t &a) = 0;
};

// ZKFpExec * ZKFpExec::zk_exec = nullptr;
}  // namespace emp

#endif
