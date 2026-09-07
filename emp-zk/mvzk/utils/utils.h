#ifndef EMP_ZK_MVZK_UTILS_H__
#define EMP_ZK_MVZK_UTILS_H__
#include <emp-tool/emp-tool.h>
#include <vector>
#include <cstdint>

namespace emp {
namespace mvzk {

inline uint64_t reverse_bits(uint64_t x, uint64_t bit_width) {
  uint64_t rev = 0;
  for (uint64_t i = bit_width; i > 0; i--) {
    rev |= ((x & 1) << (i - 1));
    x >>= 1;
  }
  return rev;
}

template <typename IO>
inline void flush_io(std::vector<IO **> &ios, std::size_t num) {
  for (std::size_t i = 0; i < ios.size(); ++i) {
    if (ios[i] == nullptr) continue;
    for (std::size_t j = 0; j < num; ++j) ios[i][j]->flush();
  }
}

}  // namespace mvzk
}  // namespace emp
#endif
