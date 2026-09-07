#ifndef EMP_ZK_MVZK_FP59_H__
#define EMP_ZK_MVZK_FP59_H__
// F_p with p = 2^59 - 2^28 + 1, the NTT-friendly prime the MVZK protocol runs
// over (2^28 | p - 1, so power-of-two roots of unity up to 2^28 exist).
//
// The member set mirrors vole/fields/fp61.h so that vole's field-generic VOLE
// (CVoleFp, MpfssRegFp, BaseSvoleFp, AccumFp, LpnFpEA, ComMatrixFp) can be
// instantiated with <FP59, FP59x2>; the MVZK engine (Poly / Ntt / Lagrange)
// additionally uses Generator and PR_bit_len.
#include <emp-tool/emp-tool.h>
#include "vole/fields/utils.h"
#include <cstdint>

namespace emp {

class FP59 {
public:
  static constexpr uint64_t PR_bit_len       = 59;
  static constexpr uint64_t slot_stride_bits = 59;
  static constexpr uint64_t PR               = 576460752034988033ULL;  // 2^59 - 2^28 + 1
  static constexpr uint64_t PR_mask          = (1ULL << 59) - 1;
  static constexpr uint64_t PR_num_pack      = 1ULL;
  static constexpr uint64_t DS_byte_len      = 8;
  static constexpr uint64_t Generator        = 3;   // primitive root of F_p
  static block DoublePR() { return makeBlock(PR, PR); }
  static block DoubleMask() { return makeBlock(PR_mask, PR_mask); }
  static uint64_t copy_compose(uint64_t basis) { return basis; }

  uint64_t val;

  FP59() { val = 0; }
  FP59(uint64_t input, bool mod_it = true) { val = mod_it ? mod(input) : input; }

  void operator=(const uint64_t rhs) { this->val = mod(rhs); }
  void operator=(const FP59 rhs) { this->val = rhs.val; }

  void setZero() { this->val = 0ULL; }
  void from_block(block rhs) { this->val = mod((uint64_t)_mm_extract_epi64(rhs, 0)); }
  void assign_no_mod(const uint64_t rhs) { this->val = rhs; }
  uint64_t value() const { return val; }

  // Scalar field: the two "lanes" of the packed interface coincide.
  void setHigh(const uint64_t rhs) { this->val = rhs; }
  void setHigh(const FP59 &rhs) { this->val = rhs.val; }
  FP59 getHigh() const { return FP59(this->val, false); }
  void setLow(const FP59 &rhs) { this->val = rhs.val; }
  FP59 getLow() const { return FP59(this->val, false); }

  bool operator==(const uint64_t rhs) const { return this->val == mod(rhs); }
  bool operator==(const FP59 rhs) const { return this->val == rhs.val; }
  bool operator!=(const uint64_t rhs) const { return this->val != mod(rhs); }
  bool operator!=(const FP59 rhs) const { return this->val != rhs.val; }

  FP59 operator+(const FP59 rhs) const { return FP59(add_mod(val, rhs.val), false); }
  FP59 operator+(const uint64_t rhs) const { return FP59(add_mod(val, rhs), false); }
  FP59 operator-(const FP59 rhs) const { return FP59(add_mod(val, PR - rhs.val), false); }
  FP59 operator-(const uint64_t rhs) const { return FP59(add_mod(val, PR - rhs), false); }
  FP59 operator*(const FP59 rhs) const { return FP59(mult_mod(val, rhs.val), false); }
  FP59 operator*(const uint64_t rhs) const { return FP59(mult_mod(val, rhs), false); }
  FP59 operator<<(const int n_pos) const { return FP59(mult_mod(val, 1ULL << n_pos), false); }

  // Lazy reduction: values stay < 2^59, so up to 31 raw adds fit in 64 bits.
  static constexpr unsigned lazy_adds = 16;
  void add_raw(const FP59 &rhs) { val += rhs.val; }
  void reduce() { val = mod(val); }

  FP59 negate() const { return FP59(val == 0 ? 0 : PR - val, false); }

  template <typename IO> void send(IO *netio) { netio->send_data(&val, sizeof(uint64_t)); }
  template <typename IO> void recv(IO *netio) { netio->recv_data(&val, sizeof(uint64_t)); }

  // Uniform sampling by rejection: mask to 59 bits, retry if >= p. The
  // rejection probability is (2^59 - p) / 2^59 ~ 2^-31, so the retry loop
  // essentially never iterates; the result is exactly uniform (a plain
  // 64-bit reduction mod p would be biased by ~2^-5).
  template <typename PRNG> static uint64_t sample(PRNG &prg) {
    uint64_t raw;
    do {
      prg.random_data(&raw, sizeof(uint64_t));
      raw &= PR_mask;
    } while (raw >= PR);
    return raw;
  }
  template <typename PRNG> static void sample_many(PRNG &prg, uint64_t *out, std::size_t cnt) {
    prg.random_data(out, (int64_t)(cnt * sizeof(uint64_t)));
    for (std::size_t i = 0; i < cnt; ++i) {
      out[i] &= PR_mask;
      while (out[i] >= PR) { prg.random_data(&out[i], sizeof(uint64_t)); out[i] &= PR_mask; }
    }
  }
  // Uniform element from a hash digest (Fiat-Shamir): low word of dig[0]
  // masked to 59 bits; on rejection dig <- H(dig) and retry, deterministically
  // on every party.
  static uint64_t from_digest(block dig[2]) {
    for (;;) {
      uint64_t r = (uint64_t)_mm_extract_epi64(dig[0], 0) & PR_mask;
      if (r < PR) return r;
      Hash::hash_once(dig, dig, 2 * sizeof(block));
    }
  }
  template <typename PRNG> void rand(PRNG &prg) { this->val = sample(prg); }

  block hash() { return Hash::hash_for_block(&val, sizeof(uint64_t)); }

  FP59 inv() const { return FP59(mod_inv(val), false); }

  // x < 2^64 -> x mod p: 2^59 = 2^28 - 1 (mod p), so x = hi*2^59 + lo with
  // hi < 32 reduces to hi*(2^28 - 1) + lo < 2^59 + 2^33 < 2p.
  static uint64_t mod(const uint64_t x) {
    uint64_t hi = x >> 59;
    uint64_t r = (hi << 28) - hi + (x & PR_mask);
    return (r >= PR) ? r - PR : r;
  }

  static uint64_t add_mod(const uint64_t a, const uint64_t b) {
    uint64_t res = a + b;
    return (res >= PR) ? (res - PR) : res;
  }

  // a * b mod p for a, b < p: split the 128-bit product at bit 59.
  static uint64_t mult_mod(const uint64_t a, const uint64_t b) {
    uint64_t c = 0;
    uint64_t e = vole_mul64(a, b, (uint64_t *)&c);
    uint64_t i = (c << 5) + (e >> 59);            // high part (< 2^59)
    uint64_t j = i >> 31;                          // reduce i * 2^59 = i * (2^28 - 1)
    j = (j << 28) - j + ((i << 28) & PR_mask);
    j = (j >= PR) ? j - PR : j;
    i = j + (e & PR_mask) + PR - i;
    i = (i >= PR) ? (i - PR) : i;
    return (i >= PR) ? (i - PR) : i;
  }

  static uint64_t mod_inv(const uint64_t a) {
    if (a == 0) error("FP59: zero has no inverse");
    int64_t k = 0, new_k = 1;
    int64_t r = (int64_t)PR, new_r = (int64_t)a;
    while (new_r != 0) {
      int64_t q = r / new_r;
      int64_t tmp = new_k; new_k = k - q * tmp; k = tmp;
      tmp = new_r; new_r = r - q * tmp; r = tmp;
    }
    if (k < 0) k += (int64_t)PR;
    return (uint64_t)k;
  }

  static std::size_t size() { return sizeof(uint64_t); }

  // ---- two-lane block helpers (value || MAC in one block), used by FP59x2 ----
  // (c1 || c2) = (a1 || a2) (partial) mod p: subtract p from lanes >= p.
  static block vec_partial_mod(block i) {
    return _mm_sub_epi64(i, _mm_andnot_si128(_mm_cmpgt_epi64(DoublePR(), i), DoublePR()));
  }
  // lanes < 2^64 -> mod p
  static block vec_mod(block i) {
    block hi = _mm_srli_epi64(i, 59);
    block r = _mm_sub_epi64(_mm_slli_epi64(hi, 28), hi);
    r = _mm_add_epi64(r, _mm_and_si128(i, DoubleMask()));
    return vec_partial_mod(r);
  }
  // (a1 * b || a2 * b) mod p
  static block mult_mod(block a, uint64_t b) {
    uint64_t H = (uint64_t)_mm_extract_epi64(a, 1);
    uint64_t L = (uint64_t)_mm_extract_epi64(a, 0);
    block bs[2];
    uint64_t *is = (uint64_t *)(bs);
    is[1] = vole_mul64(H, b, (uint64_t *)(is + 3));
    is[0] = vole_mul64(L, b, (uint64_t *)(is + 2));
    // t1 = high part (bits >= 59) of each lane's 128-bit product
    block t1 = _mm_add_epi64(_mm_slli_epi64(bs[1], 5), _mm_srli_epi64(bs[0], 59));
    block t2 = _mm_srli_epi64(t1, 31);
    block t3 = _mm_sub_epi64(_mm_slli_epi64(t2, 28), t2);
    t3 = _mm_add_epi64(t3, _mm_and_si128(_mm_slli_epi64(t1, 28), DoubleMask()));
    t3 = vec_partial_mod(t3);
    t3 = _mm_add_epi64(t3, _mm_and_si128(bs[0], DoubleMask()));
    t1 = _mm_sub_epi64(DoublePR(), t1);
    t3 = _mm_add_epi64(t3, t1);
    t3 = vec_partial_mod(t3);
    return vec_partial_mod(t3);
  }
  static block add_mod(block a, uint64_t b) {
    return vec_partial_mod(_mm_add_epi64(a, makeBlock(b, b)));
  }
  static block add_mod(block a, block b) {
    return vec_partial_mod(_mm_add_epi64(a, b));
  }
};

}  // namespace emp
#endif
