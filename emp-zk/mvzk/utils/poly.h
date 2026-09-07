#ifndef EMP_ZK_MVZK_POLY_H__
#define EMP_ZK_MVZK_POLY_H__
// Packed-Shamir conversions for the MVZK engine over an NTT-friendly field.
//
// Evaluation points: the n "party" points are the odd powers g, g^3, ..., g^{2n-1}
// of a 2n-th root of unity (evalPointsN) and the k "secret" points are the odd
// powers of a 2k-th root of unity (evalPointsK); all are distinct. A degree-(n-1)
// sharing held at the n party points stores k = sigma secrets at the k secret
// points (paper Sec. 3.3 / SuperPack). The conversions are:
//   nttEvalN2K : n party shares -> the k secrets (interpolate, then evaluate)
//   nttEvalK2N : k secrets      -> n party shares of the degree-(k-1) packing
//   lagrangeEvalOne2K : one party's share -> its additive share of each secret
//   nttEvalN2N : degree-(n-1) values at g^{odd} -> values at g^{even}
//                (the recursive check's h(X) extension)
// Everything is the naive radix-2 NTT (n, k <= a few hundred), no HEXL.
#include <emp-tool/emp-tool.h>
#include "emp-zk/mvzk/utils/ntt.h"
#include <vector>

namespace emp {
namespace mvzk {

template <typename T>
class Poly {
public:
  std::size_t logK, logN, k, n, nDivK;
  T unityRootK, unityRootN, unityRoot2K, unityRoot2N;
  Ntt<T> nttKNaive, nttNNaive;
  std::vector<T> evalPointsN, evalPointsK, evalPoints2N;
  std::vector<T> lagrangeTableKByN;       // k x n : party shares -> secrets
  std::vector<T> lagrangeTableNByK;       // n x k : secrets -> party shares
  std::vector<std::vector<T>> lagrangeTableKByTp1;     // Delta-sharing helpers
  std::vector<std::vector<T>> lagrangeTableKByTp1Inv;
  std::vector<T> fpGenPowers, fpInvGenPowers;

  Poly() { k = n = 0; }
  Poly(std::size_t log_k_, std::size_t log_n_) : logK(log_k_), logN(log_n_) {
    n = (std::size_t)1 << log_n_;
    k = (std::size_t)1 << log_k_;
    if (log_k_ > log_n_) error("Poly: k must not exceed n");
    nDivK = (std::size_t)1 << (log_n_ - log_k_);
    unityRoot2K = primitiveRoot(2 * k);
    unityRoot2N = primitiveRoot(2 * n);
    unityRootK = unityRoot2K * unityRoot2K;
    unityRootN = unityRoot2N * unityRoot2N;
    nttKNaive = Ntt<T>(log_k_, unityRoot2K);
    nttNNaive = Ntt<T>(log_n_, unityRoot2N);

    evalPointsK.resize(k);
    T powers = unityRoot2K;
    for (std::size_t i = 0; i < k; ++i) { evalPointsK[i] = powers; powers = powers * unityRootK; }
    evalPointsN.resize(n);
    powers = unityRoot2N;
    for (std::size_t i = 0; i < n; ++i) { evalPointsN[i] = powers; powers = powers * unityRootN; }
    evalPoints2N.resize(2 * n);
    powers = unityRoot2N;
    for (std::size_t i = 0; i < 2 * n; ++i) { evalPoints2N[i] = powers; powers = powers * unityRoot2N; }

    T offset = unityRoot2N;
    for (std::size_t i = 0; i + 2 < nDivK; ++i) offset = offset * unityRoot2N;
    initFpGenPowers(offset);
  }

  // n party shares (values at evalPointsN) -> the k secrets (values at evalPointsK).
  void nttEvalN2K(std::vector<T> &out, const std::vector<T> &in) {
    if (in.size() != n) error("Poly::nttEvalN2K: input length");
    std::vector<T> poly_coeff(in);
    for (std::size_t i = 0; i < n; ++i) {
      uint64_t j = reverse_bits(i, logN);
      if (i != j) poly_coeff[i] = in[j];
    }
    nttNNaive.backwardInplace(poly_coeff);                       // coefficients
    for (std::size_t i = 0; i < n; ++i) poly_coeff[i] = poly_coeff[i] * fpGenPowers[i];
    nttNNaive.forwardInplace(poly_coeff);                        // bit-reversed evals
    out.resize(k);
    std::size_t ptr = 0;
    for (std::size_t i = 0; i < k; ++i) {
      out[i] = poly_coeff[reverse_bits(ptr, logN)];
      ptr += nDivK;
    }
  }

  // k secrets -> n party shares of the degree-(k-1) packed sharing.
  void nttEvalK2N(std::vector<T> &out, const std::vector<T> &in) {
    if (in.size() != k) error("Poly::nttEvalK2N: input length");
    std::vector<T> poly_coeff(in);
    for (std::size_t i = 0; i < k; ++i) {
      uint64_t j = reverse_bits(i, logK);
      if (i != j) poly_coeff[i] = in[j];
    }
    nttKNaive.backwardInplace(poly_coeff);
    std::vector<T> buf(poly_coeff);
    for (std::size_t i = 0; i < k; ++i) {
      uint64_t j = reverse_bits(i, logK);
      if (i != j) poly_coeff[i] = buf[j];
    }
    out.resize(n);
    nttNNaive.forwardInplaceFixDegree(out, poly_coeff, logK);
  }

  // degree-(n-1) values at g, g^3, ... -> values at g^2, g^4, ... (2n-th root g)
  void nttEvalN2N(std::vector<T> &out, const std::vector<T> &in) {
    if (in.size() != n) error("Poly::nttEvalN2N: input length");
    std::vector<T> poly_coeff(in);
    for (std::size_t i = 0; i < n; ++i) {
      uint64_t j = reverse_bits(i, logN);
      if (i != j) poly_coeff[i] = in[j];
    }
    nttNNaive.backwardInplace(poly_coeff);
    for (std::size_t i = 1; i < n; ++i) poly_coeff[i] = poly_coeff[i] * evalPoints2N[i - 1];
    nttNNaive.forwardInplace(poly_coeff);
    out.resize(n);
    for (std::size_t i = 0; i < n; ++i) out[i] = poly_coeff[reverse_bits(i, logN)];
  }

  void lagrangeEvalN2K(std::vector<T> &out, const std::vector<T> &in) {
    if (in.size() != n) error("Poly::lagrangeEvalN2K: input length");
    out.resize(k);
    std::size_t ptr = 0;
    for (std::size_t i = 0; i < k; ++i) {
      T res(0, false);
      for (std::size_t j = 0; j < n; ++j) res = res + lagrangeTableKByN[ptr++] * in[j];
      out[i] = res;
    }
  }

  // party `index`'s share -> its additive share of each of the k secrets
  void lagrangeEvalOne2K(std::vector<T> &out, T in, std::size_t index) {
    out.resize(k);
    std::size_t ptr = index;
    for (std::size_t i = 0; i < k; ++i) { out[i] = lagrangeTableKByN[ptr] * in; ptr += n; }
  }
  T lagrangeEvalOne2K(T in, std::size_t index, std::size_t dest_index) {
    return lagrangeTableKByN[index + dest_index * n] * in;
  }

  void lagrangeEvalK2N(std::vector<T> &out, const std::vector<T> &in) {
    if (in.size() != k) error("Poly::lagrangeEvalK2N: input length");
    out.resize(n);
    std::size_t ptr = 0;
    for (std::size_t i = 0; i < n; ++i) {
      T res(0, false);
      for (std::size_t j = 0; j < k; ++j) res = res + lagrangeTableNByK[ptr++] * in[j];
      out[i] = res;
    }
  }

  void initFpGenPowers(T offset) {
    fpGenPowers.resize(n);
    fpGenPowers[0] = T(1, false);
    if (n > 1) fpGenPowers[1] = offset;
    for (std::size_t i = 2; i < n; ++i) fpGenPowers[i] = fpGenPowers[i - 1] * offset;
    fpInvGenPowers.resize(n);
    fpInvGenPowers[0] = T(1, false);
    if (n > 1) fpInvGenPowers[1] = offset.inv();
    for (std::size_t i = 2; i < n; ++i) fpInvGenPowers[i] = fpInvGenPowers[i - 1] * fpInvGenPowers[1];
  }

  static T lagrange_coeff(const std::vector<T> &pts, std::size_t j, T dest) {
    T numer(1, false), denom(1, false);
    for (std::size_t l = 0; l < pts.size(); ++l) {
      if (l == j) continue;
      numer = numer * (dest - pts[l]);
      denom = denom * (pts[j] - pts[l]);
    }
    return numer * denom.inv();
  }

  void initLagrangeTable() {
    lagrangeTableKByN.resize(k * n);
    std::size_t ptr = 0;
    for (std::size_t i = 0; i < k; ++i)
      for (std::size_t j = 0; j < n; ++j)
        lagrangeTableKByN[ptr++] = lagrange_coeff(evalPointsN, j, evalPointsK[i]);

    lagrangeTableNByK.resize(k * n);
    ptr = 0;
    for (std::size_t i = 0; i < n; ++i)
      for (std::size_t j = 0; j < k; ++j)
        lagrangeTableNByK[ptr++] = lagrange_coeff(evalPointsK, j, evalPointsN[i]);

    // Degree-t Shamir sharing of a key held at secret point mm: the polynomial
    // through (evalPointsK[mm], key) and t random values at evalPointsN[0..t-1],
    // evaluated at the remaining party points evalPointsN[t..n-1].
    std::size_t t = n - k;
    lagrangeTableKByTp1.resize(k);
    for (std::size_t mm = 0; mm < k; ++mm) {
      std::vector<T> pts(t + 1);
      pts[0] = evalPointsK[mm];
      for (std::size_t j = 0; j < t; ++j) pts[1 + j] = evalPointsN[j];
      lagrangeTableKByTp1[mm].resize(k * (t + 1));
      ptr = 0;
      for (std::size_t i = 0; i < k; ++i) {
        T dest = evalPointsN[t + i];
        for (std::size_t j = 0; j <= t; ++j)
          lagrangeTableKByTp1[mm][ptr++] = lagrange_coeff(pts, j, dest);
      }
    }
    // Inverse direction (debug): from party points 0..t back to secret point i.
    lagrangeTableKByTp1Inv.resize(k);
    for (std::size_t mm = 0; mm < k; ++mm) {
      std::vector<T> pts(t + 1);
      for (std::size_t j = 0; j <= t; ++j) pts[j] = evalPointsN[j];
      lagrangeTableKByTp1Inv[mm].resize(k * (t + 1));
      ptr = 0;
      for (std::size_t i = 0; i < k; ++i)
        for (std::size_t j = 0; j <= t; ++j)
          lagrangeTableKByTp1Inv[mm][ptr++] = lagrange_coeff(pts, j, evalPointsK[i]);
    }
  }

  // primitive 2*degree-th root of unity squared, i.e. a primitive degree-th
  // root ... (libfqfft's construction, as in the original mvzk code)
  T primitiveRoot(uint64_t degree) {
    std::vector<T> powers_of_gen(T::PR_bit_len);
    powers_of_gen[0] = T(1, false);
    powers_of_gen[1] = T(T::Generator, false);
    for (std::size_t i = 2; i < T::PR_bit_len; ++i)
      powers_of_gen[i] = powers_of_gen[i - 1] * powers_of_gen[i - 1];
    // exponent = (p-1)/degree, computed in the field (exact since degree | p-1)
    T exponent = T(T::PR - 1, false) * (T((uint64_t)degree, false).inv());
    T res(1, false);
    for (std::size_t i = 0; i < T::PR_bit_len; ++i)
      if (((exponent.val >> i) & 1ULL) == 1ULL) res = res * powers_of_gen[i];
    return res * res;
  }
};

}  // namespace mvzk
}  // namespace emp
#endif
