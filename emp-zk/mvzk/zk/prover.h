#ifndef EMP_ZK_MVZK_ZK_PROVER_H__
#define EMP_ZK_MVZK_ZK_PROVER_H__
// MVZK prover (paper Pi_Online): shares wire values as packed sharings
// (differences to preprocessed random sharings), records multiplication
// triples, and proves them in batches with the inner-product / polynomial
// compression argument made non-interactive by Fiat-Shamir.
#include "emp-zk/mvzk/utils/poly.h"
#include "emp-zk/mvzk/utils/lagrange.h"
#include "emp-zk/mvzk/zk/utils.h"
#include "emp-zk/mvzk/zk/auth.h"
#include "emp-zk/mvzk/zk/compress.h"
#include <memory>

namespace emp {
namespace mvzk {

template <typename IO, typename T, typename S>
class Prover {
public:
  static constexpr std::size_t logCompressParam = 4;
  static constexpr std::size_t preAuthSharingNum = (1 << 16);   // packed sharings per refill
  static constexpr std::size_t multGateBufSz = (1 << 18);       // triples per check

  std::size_t k, n, compressParam;
  uint64_t inputGateCount = 0, multGateCount = 0, checkCount = 0;
  double timeVerifyAuth = 0.0;

  std::vector<T> preAuthSharing;    // preAuthSharingNum * k secrets
  std::size_t preAuthSharingPtr;    // in packed sharings (k values)

  std::vector<std::unique_ptr<Hash>> hashes;   // Fiat-Shamir transcript per verifier (Hash is non-copyable)

  std::vector<T> multGateLeftWire, multGateRightWire, multGateOutWire;
  std::size_t multGatePtr = 0;

  std::vector<T> wiresVal;          // pending wires of the current packed sharing
  std::size_t wiresValPtr = 0;
  uint64_t batchesDone = 0;

  Compress<T> *comp = nullptr;      // polynomial-compression helpers
  Lagrange<T> *lagrange = nullptr;

  Prover(std::size_t k_, std::size_t n_) : k(k_), n(n_) {
    preAuthSharingPtr = preAuthSharingNum;
    for (std::size_t i = 0; i < n; ++i) hashes.emplace_back(new Hash());
    multGateLeftWire.resize(multGateBufSz + k);
    multGateRightWire.resize(multGateBufSz + k);
    multGateOutWire.resize(multGateBufSz + k);
    wiresVal.resize(k);
    compressParam = 1 << logCompressParam;
    comp = new Compress<T>(logCompressParam);
    lagrange = new Lagrange<T>(compressParam);
    lagrange->initLagrangeTable();
  }
  ~Prover() { delete comp; delete lagrange; }

  // ---------------- wire sharing ----------------
  void share(T val, Auth<IO, T, S> *auth, Poly<T> *poly, std::vector<IO **> &ios) {
    wiresVal[wiresValPtr++] = val;
    inputGateCount++;
    if (wiresValPtr == k) shareBatch(auth, poly, ios);
  }

  void shareFlush(Auth<IO, T, S> *auth, Poly<T> *poly, std::vector<IO **> &ios) {
    if (wiresValPtr != 0) {
      for (std::size_t i = wiresValPtr; i < k; ++i) wiresVal[i] = T(0, false);
      shareBatch(auth, poly, ios);
    }
    for (std::size_t i = 0; i < n; ++i) ios[i][0]->flush();
  }

  // send the packed sharing of the pending k wires; a multiplication check is
  // run at this batch boundary once enough triples are buffered (the verifiers
  // reach the same triple count at exactly this point).
  void shareBatch(Auth<IO, T, S> *auth, Poly<T> *poly, std::vector<IO **> &ios) {
    ensurePreAuth(1, auth, poly);
    std::vector<T> diff(k), shares;
    for (std::size_t i = 0; i < k; ++i)
      diff[i] = wiresVal[i] - preAuthSharing[k * preAuthSharingPtr + i];
    preAuthSharingPtr++;
    poly->nttEvalK2N(shares, diff);
    for (std::size_t i = 0; i < n; ++i) {
      ios[i][0]->send_data(&shares[i], (int64_t)T::size());
      hashes[i]->put(&shares[i], (int64_t)T::size());
    }
    wiresValPtr = 0;
    batchesDone++;
    if (multGatePtr >= multGateBufSz) verifyAuthTriple(auth, poly, ios);
  }

  // send opened values to every verifier (IntFp::reveal)
  void revealValues(const std::vector<T> &vals, std::vector<IO **> &ios) {
    for (std::size_t i = 0; i < n; ++i) {
      ios[i][0]->send_data(vals.data(), (int64_t)(vals.size() * T::size()));
      ios[i][0]->flush();
    }
  }

  // record a multiplication triple (checked at a later batch boundary / flush)
  void mult(T left, T right, T out) {
    multGateLeftWire[multGatePtr] = left;
    multGateRightWire[multGatePtr] = right;
    multGateOutWire[multGatePtr] = out;
    multGatePtr++;
    multGateCount++;
  }

  void multFlush(Auth<IO, T, S> *auth, Poly<T> *poly, std::vector<IO **> &ios) {
    shareFlush(auth, poly, ios);
    if (multGatePtr != 0) verifyAuthTriple(auth, poly, ios);
  }

  // ---------------- preprocessed sharings ----------------
  // make sure `num` packed sharings are available; refill (discarding the
  // remainder) otherwise. Verifiers apply the identical rule, so refills
  // happen at the same point of the transcript on every party.
  void ensurePreAuth(std::size_t num, Auth<IO, T, S> *auth, Poly<T> *poly) {
    if (preAuthSharingPtr + num > preAuthSharingNum) {
      auth->randAuthVal(preAuthSharing, poly, preAuthSharingNum);
      preAuthSharingPtr = 0;
    }
  }

  // public values -> differences to preprocessed secrets (broadcast to all)
  void genAddSharesDiff(std::vector<T> &diff, const std::vector<T> &vals,
                        Auth<IO, T, S> *auth, Poly<T> *poly) {
    std::size_t len = vals.size(), n_batch = (len + k - 1) / k;
    ensurePreAuth(n_batch, auth, poly);
    diff.resize(len);
    std::size_t p = k * preAuthSharingPtr;
    for (std::size_t i = 0; i < len; ++i) diff[i] = vals[i] - preAuthSharing[p + i];
    preAuthSharingPtr += n_batch;
  }

#ifdef MVZK_DEBUG
  // compare (x, y, z) with the verifiers' share sums (test builds only)
  void debug_check(Auth<IO, T, S> *auth, std::vector<IO **> &ios, T x, T y, T z, const char *where) {
    for (std::size_t i = 0; i < n; ++i) ios[i][0]->flush();
    std::vector<T> v = {x, y, z};
    if (!auth->check_auth_correctness(v, 3)) { std::cout << "mvzk debug: value mismatch at " << where << std::endl; error("debug"); }
    std::cout << "mvzk debug: ok at " << where << std::endl;
  }
#endif

  // ---------------- multiplication check ----------------
  void verifyAuthTriple(Auth<IO, T, S> *auth, Poly<T> *poly, std::vector<IO **> &ios) {
    auto t0 = clock_start();
    checkCount++;
    const std::size_t m = compressParam;
    std::size_t len_slice = (multGatePtr + m - 1) / m;
    std::size_t dim = len_slice * m;

    // Fiat-Shamir commitments com_i = H(transcript_i || nonces || i), sent to all
    std::vector<block> coms(2 * n);
    for (std::size_t i = 0; i < n; ++i) {
      hashes[i]->put(auth->allNonces.data(), (int64_t)(n * sizeof(block)));
      uint64_t idx = (uint64_t)i;
      hashes[i]->put(&idx, sizeof(uint64_t));
      hashes[i]->digest(coms.data() + 2 * i);
    }
    for (std::size_t i = 0; i < n; ++i) {
      ios[i][0]->send_data(coms.data(), (int64_t)(2 * n * sizeof(block)));
      ios[i][0]->flush();
    }
    Hash hash;
    block dig[2];
    hash.put(coms.data(), (int64_t)(2 * n * sizeof(block)));
    hash.digest(dig);

    // random linear combination -> one inner product  sum_i x_i * y_i = z
    std::vector<T> rand_stream;
    comp->challenge_stream(dig, dim, rand_stream);
    std::vector<T> val_x(dim, T(0, false)), val_y(dim, T(0, false));
    T val_z(0, false);
    for (std::size_t i = 0; i < multGatePtr; ++i) {
      val_x[i] = multGateLeftWire[i] * rand_stream[i];
      val_y[i] = multGateRightWire[i];
      val_z = val_z + multGateOutWire[i] * rand_stream[i];
    }

#ifdef MVZK_DEBUG
    {
      T chi0 = rand_stream[0];
      for (std::size_t i = 0; i < n; ++i) { ios[i][0]->send_data(&chi0, sizeof(T)); ios[i][0]->flush(); }
      std::cout << "mvzk debug: prover multGatePtr " << multGatePtr << std::endl;
    }
    debug_check(auth, ios, multGateLeftWire[0], multGateRightWire[0], multGateOutWire[0], "raw triple 0");
    debug_check(auth, ios, multGateLeftWire[multGatePtr - 1], multGateRightWire[multGatePtr - 1], multGateOutWire[multGatePtr - 1], "raw triple last");
    debug_check(auth, ios, val_x[0], val_y[0], val_z, "inner product");
#endif
    // recursive compression by a factor m
    std::vector<T> poly_h, vals_to_share, diff, lag_low, lag_high, ext_f, ext_g, buf(m);
    while (dim > m) {
      // h(X) = sum_i f_i(X) g_i(X), degree 2m-2: values at the m base points ...
      poly_h.assign(2 * m - 1, T(0, false));
      T z_rest = val_z;
      std::size_t p = 0;
      for (std::size_t i = 0; i + 1 < m; ++i) {
        for (std::size_t j = 0; j < len_slice; ++j) { poly_h[i] = poly_h[i] + val_x[p] * val_y[p]; ++p; }
        z_rest = z_rest - poly_h[i];
      }
      poly_h[m - 1] = z_rest;
      // ... and at the m-1 shifted points via NTT extension of every f_i, g_i
      for (std::size_t i = 0; i < len_slice; ++i) {
        for (std::size_t j = 0; j < m; ++j) buf[j] = val_x[i + j * len_slice];
        comp->poly.nttEvalN2N(ext_f, buf);
        for (std::size_t j = 0; j < m; ++j) buf[j] = val_y[i + j * len_slice];
        comp->poly.nttEvalN2N(ext_g, buf);
        for (std::size_t j = 0; j + 1 < m; ++j) poly_h[m + j] = poly_h[m + j] + ext_f[j] * ext_g[j];
      }
      // broadcast h's values (except h(p_0), implied by z) as authenticated sharings
      vals_to_share.assign(poly_h.begin() + 1, poly_h.end());
      genAddSharesDiff(diff, vals_to_share, auth, poly);
      for (std::size_t i = 0; i < n; ++i) {
        ios[i][0]->send_data(diff.data(), (int64_t)((2 * m - 2) * T::size()));
        ios[i][0]->flush();
      }
      T r = comp->challenge_point(hash, dig, diff);
      comp->computeLagCoeff(lag_low, lag_high, r);
      // fold: x_j <- f_j(r), y_j <- g_j(r), z <- h(r)
      std::vector<T> x_eval(len_slice, T(0, false)), y_eval(len_slice, T(0, false));
      p = 0;
      for (std::size_t i = 0; i < m; ++i)
        for (std::size_t j = 0; j < len_slice; ++j) {
          x_eval[j] = x_eval[j] + val_x[p] * lag_low[i];
          y_eval[j] = y_eval[j] + val_y[p] * lag_low[i];
          ++p;
        }
      val_z = T(0, false);
      for (std::size_t i = 0; i < 2 * m - 1; ++i) val_z = val_z + poly_h[i] * lag_high[i];
      dim = len_slice;
      len_slice = (dim + m - 1) / m;
      val_x.assign(len_slice * m, T(0, false));
      val_y.assign(len_slice * m, T(0, false));
      std::copy(x_eval.begin(), x_eval.end(), val_x.begin());
      std::copy(y_eval.begin(), y_eval.end(), val_y.begin());
      dim = len_slice * m;
#ifdef MVZK_DEBUG
      debug_check(auth, ios, val_x[0], val_y[0], val_z, "fold");
#endif
    }

    // last round: m values plus one random pair (x_m, y_m) masking the opening
    val_x.resize(m + 1); val_y.resize(m + 1);
    val_x[m].rand(auth->prg);
    val_y[m].rand(auth->prg);
    poly_h.assign(2 * m + 1, T(0, false));
    T z_rest = val_z;
    for (std::size_t i = 0; i + 1 < m; ++i) { poly_h[i] = val_x[i] * val_y[i]; z_rest = z_rest - poly_h[i]; }
    poly_h[m - 1] = z_rest;
    poly_h[m] = val_x[m] * val_y[m];
    lagrange->lagrangeEvalShiftPoints(ext_f, val_x);
    lagrange->lagrangeEvalShiftPoints(ext_g, val_y);
    for (std::size_t j = 0; j < m; ++j) poly_h[m + 1 + j] = ext_f[j] * ext_g[j];

    vals_to_share.assign(poly_h.begin() + 1, poly_h.end());   // 2m values
    vals_to_share.push_back(val_x[m]);
    vals_to_share.push_back(val_y[m]);
    genAddSharesDiff(diff, vals_to_share, auth, poly);         // 2m+2 values
    for (std::size_t i = 0; i < n; ++i) {
      ios[i][0]->send_data(diff.data(), (int64_t)((2 * m + 2) * T::size()));
      ios[i][0]->flush();
    }
    T r = comp->challenge_point(hash, dig, diff);              // binds all 2m+2 values
    if (lagrange->is_interpolation_point(r)) error("mvzk: challenge hits an interpolation point");
    lagrange->computeLagCoeff(lag_low, lag_high, r);
    T x(0, false), y(0, false), z(0, false);
    for (std::size_t i = 0; i <= m; ++i) { x = x + val_x[i] * lag_low[i]; y = y + val_y[i] * lag_low[i]; }
    for (std::size_t i = 0; i <= 2 * m; ++i) z = z + poly_h[i] * lag_high[i];
    if (z != x * y) error("mvzk prover: local multiplication check failed (bug)");
#ifdef MVZK_DEBUG
    debug_check(auth, ios, val_x[m], val_y[m], poly_h[m], "random pair");
    debug_check(auth, ios, x, y, z, "final");
#endif
    // the verifiers now open (x, y, z) among themselves and check z = x*y

    multGatePtr = 0;
    timeVerifyAuth += time_from(t0);
  }
};

}  // namespace mvzk
}  // namespace emp
#endif
