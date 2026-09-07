#ifndef EMP_ZK_MVZK_FP59X2_H__
#define EMP_ZK_MVZK_FP59X2_H__
// (value || MAC) bundle over FP59: one block, value in the HIGH lane and MAC in
// the LOW lane (the layout vole's VOLE classes use for FPS types). Mirrors
// vole/fields/fp61x2.h.
#include <emp-tool/emp-tool.h>
#include "vole/fields/utils.h"
#include "emp-zk/mvzk/fields/fp59.h"

namespace emp {

class FP59x2 {
public:
  static constexpr uint64_t PR_bit_len       = 59;
  static constexpr uint64_t slot_stride_bits = 59;
  static constexpr uint64_t PR               = FP59::PR;
  static constexpr uint64_t DS_byte_len      = 16;
  static constexpr uint64_t PR_num_pack      = 1ULL;
  static block DoublePR() { return FP59::DoublePR(); }
  static uint64_t copy_compose(uint64_t basis) { return basis; }

  block val;

  FP59x2() { val = zero_block; }
  FP59x2(const FP59x2 &inp) : val(inp.val) {}
  FP59x2(block val_, bool mod_it = false) : val(val_) {
    if (mod_it) val = FP59::vec_mod(val);
  }
  FP59x2(uint64_t low, uint64_t high, bool mod_it = false) {
    if (mod_it) { low = FP59::mod(low); high = FP59::mod(high); }
    val = makeBlock(high, low);
  }
  FP59x2(FP59 low, FP59 high) { val = makeBlock(high.val, low.val); }

  FP59 operator[](bool idx) const {
    return FP59((uint64_t)(idx ? _mm_extract_epi64(val, 1) : _mm_extract_epi64(val, 0)), false);
  }
  FP59 getLow() const { return FP59((uint64_t)_mm_extract_epi64(val, 0), false); }
  FP59 getHigh() const { return FP59((uint64_t)_mm_extract_epi64(val, 1), false); }
  void setLow(FP59 low) { val = makeBlock((uint64_t)_mm_extract_epi64(val, 1), low.val); }
  void setHigh(FP59 high) { val = makeBlock(high.val, (uint64_t)_mm_extract_epi64(val, 0)); }
  void setZero() { val = zero_block; }
  void setLowHigh(const FP59 low, const FP59 high) { val = makeBlock(high.val, low.val); }
  void from_block(block rhs) { val = FP59::vec_mod(rhs); }
  // low lane <- leaf value from a GGM block (mod p), high lane <- 0.
  void set_low_from_block(block b) { val = makeBlock(0, FP59::mod((uint64_t)_mm_extract_epi64(b, 0))); }
  void getVal(FP59 *data) const { data[0] = getLow(); data[1] = getHigh(); }

  void operator=(const block rhs) { val = rhs; }
  void operator=(const FP59x2 rhs) { val = rhs.val; }

  bool operator==(const block rhs) const { __m128i c = _mm_xor_si128(val, rhs); return _mm_testz_si128(c, c); }
  bool operator==(const FP59x2 rhs) const { return *this == rhs.val; }
  bool operator!=(const block rhs) const { return !(*this == rhs); }
  bool operator!=(const FP59x2 rhs) const { return !(*this == rhs.val); }

  FP59x2 operator*(const FP59 b) const { return FP59x2(FP59::mult_mod(val, b.val)); }
  // lane-wise product with another bundle
  FP59x2 operator*(const FP59x2 b) const {
    return FP59x2(FP59::mult_mod(getLow().val, b.getLow().val),
                  FP59::mult_mod(getHigh().val, b.getHigh().val), false);
  }
  FP59x2 operator+(const FP59 b) const { return FP59x2(FP59::add_mod(val, b.val)); }
  FP59x2 operator+(const FP59x2 b) const { return FP59x2(FP59::add_mod(val, b.val)); }
  FP59x2 operator-(const FP59 b) const { return FP59x2(FP59::add_mod(val, FP59::PR - b.val)); }
  FP59x2 operator-(const FP59x2 b) const {
    return FP59x2(FP59::vec_partial_mod(_mm_add_epi64(val, _mm_sub_epi64(FP59::DoublePR(), b.val))));
  }

  static constexpr unsigned lazy_adds = 16;
  void add_raw(const FP59x2 &rhs) { val = _mm_add_epi64(val, rhs.val); }
  void reduce() { val = FP59::vec_mod(val); }

  FP59x2 negate() const { return FP59x2(getLow().negate(), getHigh().negate()); }

  static std::size_t size() { return sizeof(block); }
  template <typename IO> void send(IO *netio) { netio->send_data(&val, sizeof(block)); }
  template <typename IO> void recv(IO *netio) { netio->recv_data(&val, sizeof(block)); }
  block hash() { return Hash::hash_for_block(&val, sizeof(block)); }

  block vec_mod(block i) const { return FP59::vec_mod(i); }
  block vec_partial_mod(const block i) const { return FP59::vec_partial_mod(i); }
};

}  // namespace emp
#endif
