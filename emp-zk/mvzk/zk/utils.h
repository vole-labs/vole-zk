#ifndef EMP_ZK_MVZK_ZK_UTILS_H__
#define EMP_ZK_MVZK_ZK_UTILS_H__
#include <cstddef>

namespace emp {
namespace mvzk {

// A verifier's additive share of an authenticated value:
//   sum_i share_i = v,   sum_i mac_i = sum_i key_i + Delta * v   (Delta = sum_i Delta_i)
template <typename T>
struct AuthShareT {
  T mac;
  T key;
  T share;
};

}  // namespace mvzk
}  // namespace emp
#endif
