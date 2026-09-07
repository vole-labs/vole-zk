#ifndef EMP_ZK_MVZK_NTT_H__
#define EMP_ZK_MVZK_NTT_H__
// Radix-2 NTT over a field T with T::PR_bit_len, T::inv(), T(uint64_t).
// Forward output is in bit-reversed order; inverse takes bit-reversed input and
// returns natural order (the conventions Poly relies on).
#include <emp-tool/emp-tool.h>
#include "emp-zk/mvzk/utils/utils.h"
#include <vector>

namespace emp {
namespace mvzk {

template <typename T>
class Ntt {
public:
  std::size_t logDim = 0;
  T unityRoot;
  std::size_t dim = 0;
  T invDim;
  std::vector<T> unity_root_powers;
  std::vector<T> inv_unity_root_powers;

  Ntt() {}
  Ntt(std::size_t log_dim, T unity_root) : logDim(log_dim), unityRoot(unity_root) {
    dim = (std::size_t)1 << logDim;
    invDim = T((uint64_t)dim).inv();

    unity_root_powers.resize(dim);
    unity_root_powers[0] = T(1, false);
    T powers(1, false);
    for (std::size_t i = 1; i < dim; ++i) {
      powers = powers * unity_root;
      unity_root_powers[reverse_bits(i, logDim)] = powers;
    }
    T inv_unity_root = unity_root.inv();
    inv_unity_root_powers.resize(dim);
    inv_unity_root_powers[0] = T(1, false);
    powers = T(1, false);
    for (std::size_t i = 1; i < dim; ++i) {
      powers = powers * inv_unity_root;
      inv_unity_root_powers[reverse_bits(i, logDim)] = powers;
    }
  }

  void nttInternalInplace(std::vector<T> &res, const std::vector<T> &powers) {
    std::size_t m = 1, t = dim >> 1;
    for (std::size_t s = 1; s <= logDim; ++s) {
      std::size_t l = 0;
      for (std::size_t i = 0; i < m; ++i) {
        T w = powers[m + i];
        for (std::size_t j = l; j < l + t; ++j) {
          T u = res[j];
          T v = res[j + t] * w;
          res[j] = u + v;
          res[j + t] = u - v;
        }
        l += (t << 1);
      }
      t >>= 1;
      m <<= 1;
    }
  }

  void inttInternalInplace(std::vector<T> &res, const std::vector<T> &powers) {
    std::size_t m = dim >> 1, t = 1;
    for (std::size_t s = 1; s <= logDim; ++s) {
      std::size_t l = 0;
      for (std::size_t i = 0; i < m; ++i) {
        T w = powers[m + i];
        for (std::size_t j = l; j < l + t; ++j) {
          T u = res[j];
          T v = res[j + t];
          res[j] = u + v;
          v = u - v;
          res[j + t] = v * w;
        }
        l += (t << 1);
      }
      t <<= 1;
      m >>= 1;
    }
    for (std::size_t i = 0; i < dim; ++i) res[i] = res[i] * invDim;
  }

  // Forward transform of a polynomial given by dim_in < dim coefficients
  // (bit-reversed), evaluated at all dim points.
  void nttInternalInplace(std::vector<T> &res, const std::vector<T> &in,
                          std::size_t log_dim_in, const std::vector<T> &powers) {
    std::size_t dim_in = (std::size_t)1 << log_dim_in;
    res.resize(dim);
    std::size_t dup = (std::size_t)1 << (logDim - log_dim_in);
    if (dup > 1) {
      for (std::size_t i = 0, l = 0; i < dim; i += dup, l++)
        for (std::size_t j = 0; j < dup; ++j) res[i + j] = in[l];
    } else {
      for (std::size_t i = 0; i < dim; ++i) res[i] = in[i];
    }
    std::size_t m = dim_in >> 1, t = (std::size_t)1 << (logDim - log_dim_in);
    for (std::size_t s = 1; s <= log_dim_in; ++s) {
      std::size_t l = 0;
      for (std::size_t i = 0; i < m; ++i) {
        for (std::size_t j = l, jj = 0; j < l + t; ++j, ++jj) {
          uint64_t idx = reverse_bits(m * (2 * jj + 1), logDim);
          T u = res[j];
          T v = res[j + t] * powers[idx];
          res[j] = u + v;
          res[j + t] = u - v;
        }
        l += (t << 1);
      }
      t <<= 1;
      m >>= 1;
    }
  }

  void forwardInplace(std::vector<T> &res) {
    if (res.size() != dim) error("ntt: input dimension mismatch");
    nttInternalInplace(res, unity_root_powers);
  }
  void forwardInplaceFixDegree(std::vector<T> &res, const std::vector<T> &in, std::size_t log_dim_in) {
    if (in.size() > dim) error("ntt: input dimension mismatch");
    nttInternalInplace(res, in, log_dim_in, unity_root_powers);
  }
  void backwardInplace(std::vector<T> &res) {
    if (res.size() != dim) error("ntt: input dimension mismatch");
    inttInternalInplace(res, inv_unity_root_powers);
  }
};

}  // namespace mvzk
}  // namespace emp
#endif
