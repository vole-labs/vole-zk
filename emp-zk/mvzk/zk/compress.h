#ifndef EMP_ZK_MVZK_ZK_COMPRESS_H__
#define EMP_ZK_MVZK_ZK_COMPRESS_H__
// Helpers shared by prover and verifier for the compression rounds of the
// multiplication check: evaluation points, Lagrange coefficients at a
// challenge, and the Fiat-Shamir derivations.
#include "emp-zk/mvzk/utils/poly.h"

namespace emp {
namespace mvzk {

template <typename T>
class Compress {
public:
  std::size_t m;
  Poly<T> poly;                     // Poly(1, log m): m base points, m-1 shifted points
  std::vector<T> lagEvalPoints;     // p_0..p_{m-1} (odd powers), p_m..p_{2m-2} (even powers)
  std::vector<T> lagCoeffDivLow, lagCoeffDivHigh;

  explicit Compress(std::size_t log_m) : m((std::size_t)1 << log_m), poly(1, log_m) {
    lagEvalPoints.resize(2 * m - 1);
    for (std::size_t i = 0; i < m; ++i) lagEvalPoints[i] = poly.evalPointsN[i];
    for (std::size_t i = 0; i + 1 < m; ++i) lagEvalPoints[m + i] = lagEvalPoints[i] * poly.unityRoot2N;
    lagCoeffDivLow.resize(m);
    for (std::size_t i = 0; i < m; ++i) {
      T res(1, false);
      for (std::size_t j = 0; j < m; ++j) if (j != i) res = res * (lagEvalPoints[i] - lagEvalPoints[j]);
      lagCoeffDivLow[i] = res.inv();
    }
    lagCoeffDivHigh.resize(2 * m - 1);
    for (std::size_t i = 0; i < 2 * m - 1; ++i) {
      T res(1, false);
      for (std::size_t j = 0; j < 2 * m - 1; ++j) if (j != i) res = res * (lagEvalPoints[i] - lagEvalPoints[j]);
      lagCoeffDivHigh[i] = res.inv();
    }
  }

  // Lagrange coefficients at `dest` for the m base points (low) and all 2m-1 points (high)
  void computeLagCoeff(std::vector<T> &low, std::vector<T> &high, T dest) {
    low.resize(m);
    for (std::size_t i = 0; i < m; ++i) {
      T res(1, false);
      for (std::size_t j = 0; j < m; ++j) if (j != i) res = res * (dest - lagEvalPoints[j]);
      low[i] = res * lagCoeffDivLow[i];
    }
    high.resize(2 * m - 1);
    for (std::size_t i = 0; i < 2 * m - 1; ++i) {
      T res(1, false);
      for (std::size_t j = 0; j < 2 * m - 1; ++j) if (j != i) res = res * (dest - lagEvalPoints[j]);
      high[i] = res * lagCoeffDivHigh[i];
    }
  }

  bool is_interpolation_point(T x) const {
    for (const auto &p : lagEvalPoints) if (p == x) return true;
    return false;
  }

  // random coefficients of the inner-product reduction from the commitment digest
  void challenge_stream(const block dig[2], std::size_t dim, std::vector<T> &out) {
    PRG prg(dig);
    std::vector<uint64_t> raw(dim);
    T::sample_many(prg, raw.data(), dim);          // uniform in F_p (rejection sampling)
    out.resize(dim);
    for (std::size_t i = 0; i < dim; ++i) out[i] = T(raw[i], false);
  }

  // next challenge: dig <- H(dig || msg), point = dig mod p; aborts on an
  // interpolation point of this round's polynomials (paper: abort on eta in
  // the evaluation set)
  T challenge_point(Hash &hash, block dig[2], const std::vector<T> &msg) {
    hash.put(dig, 2 * sizeof(block));
    hash.put(msg.data(), (int64_t)(msg.size() * T::size()));
    hash.digest(dig);
    T r(T::from_digest(dig), false);                 // uniform in F_p; re-hashes on rejection
    if (is_interpolation_point(r)) error("mvzk: challenge hits an interpolation point");
    return r;
  }
};

}  // namespace mvzk
}  // namespace emp
#endif
