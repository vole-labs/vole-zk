#ifndef EMP_ZK_MVZK_LAGRANGE_H__
#define EMP_ZK_MVZK_LAGRANGE_H__
// Lagrange machinery for the last compression step of the inner-product check,
// where the degree-m polynomials are defined on the points 1..2m+1.
#include <emp-tool/emp-tool.h>
#include <vector>

namespace emp {
namespace mvzk {

template <typename T>
class Lagrange {
public:
  std::size_t n = 0;         // degree
  std::size_t nPoints = 0;
  std::vector<T> evalPoints; // 1, 2, ..., 2n+1
  std::vector<T> lagrangeTable;
  std::vector<T> lagCoeffDivLow, lagCoeffDivHigh;

  Lagrange() {}
  Lagrange(std::size_t n_) : n(n_) {
    nPoints = 2 * n + 1;
    evalPoints.resize(nPoints);
    for (std::size_t i = 0; i < nPoints; ++i) evalPoints[i] = T((uint64_t)(i + 1));
  }

  // values at points 1..n+1 (degree n) -> values at points n+2 .. 2n+1
  void lagrangeEvalShiftPoints(std::vector<T> &out, const std::vector<T> &in) {
    if (in.size() != n + 1) error("Lagrange: input length");
    out.resize(n);
    std::size_t ptr = 0;
    for (std::size_t i = 0; i < n; ++i) {
      T res(0, false);
      for (std::size_t j = 0; j < n + 1; ++j) res = res + lagrangeTable[ptr++] * in[j];
      out[i] = res;
    }
  }

  void initLagrangeTable() {
    lagrangeTable.resize(n * (n + 1));
    std::size_t ptr = 0;
    for (std::size_t i = 0; i < n; ++i) {
      T dest = evalPoints[i + n + 1];
      for (std::size_t j = 0; j < n + 1; ++j) {
        T numer(1, false), denom(1, false);
        for (std::size_t l = 0; l <= n; ++l) {
          if (l == j) continue;
          numer = numer * (dest - evalPoints[l]);
          denom = denom * (evalPoints[j] - evalPoints[l]);
        }
        lagrangeTable[ptr++] = numer * denom.inv();
      }
    }
    lagCoeffDivLow.resize(n + 1);
    for (std::size_t i = 0; i < n + 1; ++i) {
      T res(1, false);
      for (std::size_t j = 0; j < n + 1; ++j) if (j != i) res = res * (evalPoints[i] - evalPoints[j]);
      lagCoeffDivLow[i] = res.inv();
    }
    lagCoeffDivHigh.resize(2 * n + 1);
    for (std::size_t i = 0; i < 2 * n + 1; ++i) {
      T res(1, false);
      for (std::size_t j = 0; j < 2 * n + 1; ++j) if (j != i) res = res * (evalPoints[i] - evalPoints[j]);
      lagCoeffDivHigh[i] = res.inv();
    }
  }

  // Lagrange basis values at `dest` for degree n (points 1..n+1) and 2n (1..2n+1).
  void computeLagCoeff(std::vector<T> &low, std::vector<T> &high, T dest) {
    low.resize(n + 1);
    for (std::size_t i = 0; i < n + 1; ++i) {
      T res(1, false);
      for (std::size_t j = 0; j < n + 1; ++j) if (j != i) res = res * (dest - evalPoints[j]);
      low[i] = res * lagCoeffDivLow[i];
    }
    high.resize(2 * n + 1);
    for (std::size_t i = 0; i < 2 * n + 1; ++i) {
      T res(1, false);
      for (std::size_t j = 0; j < 2 * n + 1; ++j) if (j != i) res = res * (dest - evalPoints[j]);
      high[i] = res * lagCoeffDivHigh[i];
    }
  }

  // true if `x` coincides with one of the interpolation points (the check must
  // abort on such a challenge, paper Procedure 1 step 5 / Procedure 2 step 7)
  bool is_interpolation_point(T x) const {
    for (std::size_t i = 0; i < nPoints; ++i) if (x == evalPoints[i]) return true;
    return false;
  }
};

}  // namespace mvzk
}  // namespace emp
#endif
