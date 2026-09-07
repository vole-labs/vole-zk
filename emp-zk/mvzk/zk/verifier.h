#ifndef EMP_ZK_MVZK_ZK_VERIFIER_H__
#define EMP_ZK_MVZK_ZK_VERIFIER_H__
// MVZK verifier i (paper Pi_Online): turns the prover's packed sharings into
// authenticated additive shares, runs the compression argument on its shares
// (values and MAC||key pairs in the two lanes of S), and finally opens the
// last triple among the verifiers with a MAC check.
#include "emp-zk/mvzk/utils/poly.h"
#include "emp-zk/mvzk/utils/lagrange.h"
#include "emp-zk/mvzk/zk/utils.h"
#include "emp-zk/mvzk/zk/auth.h"
#include "emp-zk/mvzk/zk/compress.h"
#include "emp-zk/mvzk/mesh.h"

namespace emp {
namespace mvzk {

template <typename IO, typename T, typename S>
class Verifier {
public:
  using AuthShare = AuthShareT<T>;
  static constexpr std::size_t logCompressParam = 4;
  static constexpr std::size_t preAuthSharingNum = (1 << 16);
  static constexpr std::size_t multGateBufSz = (1 << 18);

  std::size_t id_party, k, n, compressParam;
  uint64_t inputGateCount = 0, multGateCount = 0, checkCount = 0;
  double timeVerifyAuth = 0.0;

  std::vector<T> shareDelta;        // packed shares of sum_i Delta_i, one per slot
  std::vector<T> preAuthSharingMac, preAuthSharingKey, preAuthSharingVal;
  std::size_t preAuthSharingPtr;

  Hash hash;                        // Fiat-Shamir transcript (what the prover sent me)
  PRG prg;
  Mesh<IO> *mesh = nullptr;

  std::vector<T> multGateLeftWireVal, multGateRightWireVal, multGateOutWireVal;
  std::vector<S> multGateLeftWireMac, multGateRightWireMac, multGateOutWireMac;  // low = key, high = mac
  std::size_t multGatePtr = 0;

  // pending wires of the current packed sharing, in program order; a wire
  // that is the output of a multiplication carries its input wires so the
  // triple is recorded (inputs read) right before the output is filled
  std::vector<AuthShare *> wiresAuthShrs, wiresMultLeft, wiresMultRight;
  std::size_t wiresBufPtr = 0;

  Compress<T> *comp = nullptr;
  Lagrange<T> *lagrange = nullptr;

  Verifier(std::size_t id_party_, std::size_t k_, std::size_t n_, std::vector<IO **> &ios)
      : id_party(id_party_), k(k_), n(n_) {
    preAuthSharingPtr = preAuthSharingNum;
    mesh = new Mesh<IO>(id_party_, n_, ios);
    multGateLeftWireVal.resize(multGateBufSz + k); multGateLeftWireMac.resize(multGateBufSz + k);
    multGateRightWireVal.resize(multGateBufSz + k); multGateRightWireMac.resize(multGateBufSz + k);
    multGateOutWireVal.resize(multGateBufSz + k); multGateOutWireMac.resize(multGateBufSz + k);
    wiresAuthShrs.resize(k); wiresMultLeft.resize(k); wiresMultRight.resize(k);
    compressParam = 1 << logCompressParam;
    comp = new Compress<T>(logCompressParam);
    lagrange = new Lagrange<T>(compressParam);
    lagrange->initLagrangeTable();
  }
  ~Verifier() { delete comp; delete lagrange; delete mesh; }

  // ---------------- Delta sharing (paper Prep step 3) ----------------
  // For every slot m, verifier i deals a degree-t packed sharing that hides
  // Delta_i at slot m; shareDelta[m] is the sum over dealers.
  void shareMacKey(T delta, Poly<T> *poly, std::vector<IO **> &ios) {
    std::size_t degree = n - k;
    std::vector<std::vector<T>> out(k, std::vector<T>(n));
    for (std::size_t m = 0; m < k; ++m) {
      for (std::size_t i = 0; i < degree; ++i) out[m][i].rand(prg);
      std::size_t p = 0;
      for (std::size_t i = 0; i < k; ++i) {
        T res = poly->lagrangeTableKByTp1[m][p++] * delta;
        for (std::size_t j = 0; j < degree; ++j) res = res + poly->lagrangeTableKByTp1[m][p++] * out[m][j];
        out[m][degree + i] = res;
      }
    }
    shareDelta.assign(k, T(0, false));
    std::vector<T> buf(k);
    for (std::size_t i = 0; i < n; ++i) {
      if (i == id_party) {
        for (std::size_t j = 0; j < n; ++j) {
          for (std::size_t l = 0; l < k; ++l) buf[l] = out[l][j];
          if (j == id_party) { for (std::size_t l = 0; l < k; ++l) shareDelta[l] = shareDelta[l] + buf[l]; continue; }
          ios[j][0]->send_data(buf.data(), (int64_t)(k * T::size()));
          ios[j][0]->flush();
        }
      } else {
        ios[i][0]->recv_data(buf.data(), (int64_t)(k * T::size()));
        for (std::size_t l = 0; l < k; ++l) shareDelta[l] = shareDelta[l] + buf[l];
      }
    }
  }

  // ---------------- wire sharing ----------------
  void share(AuthShare *shr, Auth<IO, T, S> *auth, Poly<T> *poly, std::vector<IO **> &ios) {
    wiresMultLeft[wiresBufPtr] = nullptr;
    wiresAuthShrs[wiresBufPtr++] = shr;
    inputGateCount++;
    if (wiresBufPtr == k) shareBatch(auth, poly, ios);
  }

  void shareFlush(Auth<IO, T, S> *auth, Poly<T> *poly, std::vector<IO **> &ios) {
    if (wiresBufPtr != 0) {
      for (std::size_t i = wiresBufPtr; i < k; ++i) wiresAuthShrs[i] = nullptr;
      shareBatch(auth, poly, ios);
    }
  }

  // multiplication gate: output wire is shared like an input, the triple is
  // recorded once the output share has arrived
  void share(AuthShare *out, AuthShare *left, AuthShare *right,
             Auth<IO, T, S> *auth, Poly<T> *poly, std::vector<IO **> &ios) {
    wiresMultLeft[wiresBufPtr] = left;
    wiresMultRight[wiresBufPtr] = right;
    wiresAuthShrs[wiresBufPtr++] = out;
    if (wiresBufPtr == k) shareBatch(auth, poly, ios);
  }

  void shareBatch(Auth<IO, T, S> *auth, Poly<T> *poly, std::vector<IO **> &ios) {
    ensurePreAuth(1, auth, poly);
    T s;
    ios[n][0]->recv_data(&s, (int64_t)T::size());
    hash.put(&s, (int64_t)T::size());
    std::vector<T> m, kk, v;
    genShares(m, kk, v, s, poly);
    for (std::size_t i = 0; i < wiresBufPtr; ++i) {
      AuthShare *out = wiresAuthShrs[i];
      if (out == nullptr) continue;
      if (wiresMultLeft[i] == nullptr) { out->mac = m[i]; out->key = kk[i]; out->share = v[i]; continue; }
      // multiplication: read the inputs before the output is written (they may alias)
      AuthShare l = *wiresMultLeft[i], r = *wiresMultRight[i];
      out->mac = m[i]; out->key = kk[i]; out->share = v[i];
      mult(out, &l, &r);
    }
    wiresBufPtr = 0;
    if (multGatePtr >= multGateBufSz) verifyAuthTriple(auth, poly, ios);
  }

  void mult(AuthShare *out, AuthShare *left, AuthShare *right) {
    multGateLeftWireVal[multGatePtr] = left->share;
    multGateLeftWireMac[multGatePtr] = S(left->key, left->mac);
    multGateRightWireVal[multGatePtr] = right->share;
    multGateRightWireMac[multGatePtr] = S(right->key, right->mac);
    multGateOutWireVal[multGatePtr] = out->share;
    multGateOutWireMac[multGatePtr] = S(out->key, out->mac);
    multGatePtr++;
    multGateCount++;
  }

  void multFlush(Auth<IO, T, S> *auth, Poly<T> *poly, std::vector<IO **> &ios) {
    shareFlush(auth, poly, ios);
    if (multGatePtr != 0) verifyAuthTriple(auth, poly, ios);
  }

  // ---------------- preprocessed sharings ----------------
  void ensurePreAuth(std::size_t num, Auth<IO, T, S> *auth, Poly<T> *poly) {
    if (preAuthSharingPtr + num > preAuthSharingNum) {
      auth->randAuthVal(preAuthSharingMac, preAuthSharingKey, preAuthSharingVal, poly, preAuthSharingNum);
      preAuthSharingPtr = 0;
    }
  }

  // packed share s of (wires - r) -> authenticated shares of the k wires
  void genShares(std::vector<T> &mac, std::vector<T> &key, std::vector<T> &val, T s, Poly<T> *poly) {
    std::size_t off = k * preAuthSharingPtr;
    std::vector<T> diff;
    poly->lagrangeEvalOne2K(diff, s, id_party);
    val.assign(preAuthSharingVal.begin() + off, preAuthSharingVal.begin() + off + k);
    key.assign(preAuthSharingKey.begin() + off, preAuthSharingKey.begin() + off + k);
    mac.assign(preAuthSharingMac.begin() + off, preAuthSharingMac.begin() + off + k);
    for (std::size_t i = 0; i < k; ++i) {
      val[i] = val[i] + diff[i];
      // MAC of the public difference: product of the degree-(k-1) sharing of
      // the differences and the degree-t sharing of Delta hidden at slot i
      mac[i] = mac[i] + poly->lagrangeEvalOne2K(s * shareDelta[i], id_party, i);
    }
    preAuthSharingPtr++;
  }

  // public values (as differences to preprocessed secrets) -> authenticated
  // shares: verifier 0 adds the value, everyone lowers its key by diff*Delta_i
  void genAddSharesFromDiff(std::vector<S> &mac, std::vector<T> &val, const std::vector<T> &diff,
                            Auth<IO, T, S> *auth, Poly<T> *poly) {
    std::size_t len = diff.size(), n_batch = (len + k - 1) / k;
    ensurePreAuth(n_batch, auth, poly);
    mac.resize(len); val.resize(len);
    std::size_t p = k * preAuthSharingPtr;
    for (std::size_t i = 0; i < len; ++i, ++p) {
      val[i] = (id_party == 0) ? diff[i] + preAuthSharingVal[p] : preAuthSharingVal[p];
      mac[i] = S(preAuthSharingKey[p] - diff[i] * auth->delta, preAuthSharingMac[p]);
    }
    preAuthSharingPtr += n_batch;
  }

#ifdef MVZK_DEBUG
  void debug_check(Auth<IO, T, S> *auth, T xv, S xm, T yv, S ym, T zv, S zm, const char *where) {
    std::vector<AuthShare> as(3);
    as[0] = {xm.getHigh(), xm.getLow(), xv};
    as[1] = {ym.getHigh(), ym.getLow(), yv};
    as[2] = {zm.getHigh(), zm.getLow(), zv};
    if (!auth->check_auth_correctness(as, 3)) { std::cout << "mvzk debug: MAC mismatch at " << where << std::endl; error("debug"); }
  }
#endif

  // ---------------- multiplication check ----------------
  void verifyAuthTriple(Auth<IO, T, S> *auth, Poly<T> *poly, std::vector<IO **> &ios) {
    auto t0 = clock_start();
    checkCount++;
    const std::size_t m = compressParam;
    std::size_t len_slice = (multGatePtr + m - 1) / m;
    std::size_t dim = len_slice * m;

    // Fiat-Shamir commitments: mine must match the transcript I saw
    std::vector<block> coms(2 * n);
    hash.put(auth->allNonces.data(), (int64_t)(n * sizeof(block)));
    uint64_t idx = (uint64_t)id_party;
    hash.put(&idx, sizeof(uint64_t));
    block com_v[2];
    hash.digest(com_v);
    ios[n][0]->recv_data(coms.data(), (int64_t)(2 * n * sizeof(block)));
    if (memcmp(coms.data() + 2 * id_party, com_v, 2 * sizeof(block)) != 0)
      error("mvzk: Fiat-Shamir commitment mismatch (prover sent a different transcript)");
    Hash hash_fs, transcript;                 // transcript: everything received in this check
    block dig[2];
    hash_fs.put(coms.data(), (int64_t)(2 * n * sizeof(block)));
    hash_fs.digest(dig);
    transcript.put(coms.data(), (int64_t)(2 * n * sizeof(block)));
    transcript.put(auth->allNonces.data(), (int64_t)(n * sizeof(block)));

    std::vector<T> rand_stream;
    comp->challenge_stream(dig, dim, rand_stream);
    std::vector<T> val_x(dim, T(0, false)), val_y(dim, T(0, false));
    std::vector<S> mac_x(dim), mac_y(dim);
    T val_z(0, false);
    S mac_z;
    for (std::size_t i = 0; i < multGatePtr; ++i) {
      val_x[i] = multGateLeftWireVal[i] * rand_stream[i];
      mac_x[i] = multGateLeftWireMac[i] * rand_stream[i];
      val_y[i] = multGateRightWireVal[i];
      mac_y[i] = multGateRightWireMac[i];
      val_z = val_z + multGateOutWireVal[i] * rand_stream[i];
      mac_z = mac_z + multGateOutWireMac[i] * rand_stream[i];
    }

#ifdef MVZK_DEBUG
    {
      T chi0; ios[n][0]->recv_data(&chi0, sizeof(T));
      if (chi0 != rand_stream[0]) std::cout << "mvzk debug: verifier " << id_party << " chi_0 differs" << std::endl;
      std::cout << "mvzk debug: verifier " << id_party << " multGatePtr " << multGatePtr << std::endl;
    }
    debug_check(auth, multGateLeftWireVal[0], multGateLeftWireMac[0], multGateRightWireVal[0], multGateRightWireMac[0], multGateOutWireVal[0], multGateOutWireMac[0], "raw triple 0");
    debug_check(auth, multGateLeftWireVal[multGatePtr - 1], multGateLeftWireMac[multGatePtr - 1], multGateRightWireVal[multGatePtr - 1], multGateRightWireMac[multGatePtr - 1], multGateOutWireVal[multGatePtr - 1], multGateOutWireMac[multGatePtr - 1], "raw triple last");
    debug_check(auth, val_x[0], mac_x[0], val_y[0], mac_y[0], val_z, mac_z, "inner product");
#endif
    std::vector<T> poly_h_val, diff, rec_val, lag_low, lag_high;
    std::vector<S> poly_h_mac, rec_mac;
    while (dim > m) {
      diff.resize(2 * m - 2);
      ensurePreAuth((2 * m - 2 + k - 1) / k, auth, poly);   // refill before reading, as the prover does
      ios[n][0]->recv_data(diff.data(), (int64_t)((2 * m - 2) * T::size()));
      transcript.put(diff.data(), (int64_t)((2 * m - 2) * T::size()));
      genAddSharesFromDiff(rec_mac, rec_val, diff, auth, poly);
      poly_h_val.assign(2 * m - 1, T(0, false));
      poly_h_mac.assign(2 * m - 1, S());
      T z_rest = val_z;
      S mz_rest = mac_z;
      for (std::size_t i = 1; i < m; ++i) {
        poly_h_val[i] = rec_val[i - 1]; z_rest = z_rest - rec_val[i - 1];
        poly_h_mac[i] = rec_mac[i - 1]; mz_rest = mz_rest - rec_mac[i - 1];
      }
      poly_h_val[0] = z_rest; poly_h_mac[0] = mz_rest;
      for (std::size_t i = m; i < 2 * m - 1; ++i) { poly_h_val[i] = rec_val[i - 1]; poly_h_mac[i] = rec_mac[i - 1]; }

      T r = comp->challenge_point(hash_fs, dig, diff);
      comp->computeLagCoeff(lag_low, lag_high, r);
      std::vector<T> xv(len_slice, T(0, false)), yv(len_slice, T(0, false));
      std::vector<S> xm(len_slice), ym(len_slice);
      std::size_t p = 0;
      for (std::size_t i = 0; i < m; ++i)
        for (std::size_t j = 0; j < len_slice; ++j) {
          xv[j] = xv[j] + val_x[p] * lag_low[i];  xm[j] = xm[j] + mac_x[p] * lag_low[i];
          yv[j] = yv[j] + val_y[p] * lag_low[i];  ym[j] = ym[j] + mac_y[p] * lag_low[i];
          ++p;
        }
      val_z = T(0, false); mac_z = S();
      for (std::size_t i = 0; i < 2 * m - 1; ++i) { val_z = val_z + poly_h_val[i] * lag_high[i]; mac_z = mac_z + poly_h_mac[i] * lag_high[i]; }
      dim = len_slice;
      len_slice = (dim + m - 1) / m;
      val_x.assign(len_slice * m, T(0, false)); val_y.assign(len_slice * m, T(0, false));
      mac_x.assign(len_slice * m, S());          mac_y.assign(len_slice * m, S());
      std::copy(xv.begin(), xv.end(), val_x.begin()); std::copy(yv.begin(), yv.end(), val_y.begin());
      std::copy(xm.begin(), xm.end(), mac_x.begin()); std::copy(ym.begin(), ym.end(), mac_y.begin());
      dim = len_slice * m;
#ifdef MVZK_DEBUG
      debug_check(auth, val_x[0], mac_x[0], val_y[0], mac_y[0], val_z, mac_z, "fold");
#endif
    }

    // last round
    val_x.resize(m + 1); val_y.resize(m + 1); mac_x.resize(m + 1); mac_y.resize(m + 1);
    diff.resize(2 * m + 2);
    ensurePreAuth((2 * m + 2 + k - 1) / k, auth, poly);
    ios[n][0]->recv_data(diff.data(), (int64_t)((2 * m + 2) * T::size()));
    transcript.put(diff.data(), (int64_t)((2 * m + 2) * T::size()));
    genAddSharesFromDiff(rec_mac, rec_val, diff, auth, poly);
    poly_h_val.assign(2 * m + 1, T(0, false));
    poly_h_mac.assign(2 * m + 1, S());
    T z_rest = val_z;
    S mz_rest = mac_z;
    for (std::size_t i = 1; i < m; ++i) {
      poly_h_val[i] = rec_val[i - 1]; z_rest = z_rest - rec_val[i - 1];
      poly_h_mac[i] = rec_mac[i - 1]; mz_rest = mz_rest - rec_mac[i - 1];
    }
    poly_h_val[0] = z_rest; poly_h_mac[0] = mz_rest;
    for (std::size_t i = m; i < 2 * m + 1; ++i) { poly_h_val[i] = rec_val[i - 1]; poly_h_mac[i] = rec_mac[i - 1]; }
    val_x[m] = rec_val[2 * m]; mac_x[m] = rec_mac[2 * m];
    val_y[m] = rec_val[2 * m + 1]; mac_y[m] = rec_mac[2 * m + 1];

    T r = comp->challenge_point(hash_fs, dig, diff);
    if (lagrange->is_interpolation_point(r)) error("mvzk: challenge hits an interpolation point");
    lagrange->computeLagCoeff(lag_low, lag_high, r);
    T xv(0, false), yv(0, false), zv(0, false);
    S xm, ym, zm;
    for (std::size_t i = 0; i <= m; ++i) {
      xv = xv + val_x[i] * lag_low[i]; xm = xm + mac_x[i] * lag_low[i];
      yv = yv + val_y[i] * lag_low[i]; ym = ym + mac_y[i] * lag_low[i];
    }
    for (std::size_t i = 0; i <= 2 * m; ++i) { zv = zv + poly_h_val[i] * lag_high[i]; zm = zm + poly_h_mac[i] * lag_high[i]; }

#ifdef MVZK_DEBUG
    debug_check(auth, val_x[m], mac_x[m], val_y[m], mac_y[m], poly_h_val[m], poly_h_mac[m], "random pair");
    debug_check(auth, xv, xm, yv, ym, zv, zm, "final");
#endif
    // all verifiers must have seen the same prover messages
    block tdig[2];
    transcript.digest(tdig);
    mesh->echo_check(tdig, "mvzk: verifiers received inconsistent prover messages");

    // open (x, y, z) and check the MACs, then z == x*y
    T vals[3] = {xv, yv, zv};
    S macs[3] = {xm, ym, zm};
    openAndCheck(vals, macs, auth);

    multGatePtr = 0;
    timeVerifyAuth += time_from(t0);
  }

  // Reveal three authenticated values among the verifiers (paper Procedure 3):
  // broadcast the shares; then every verifier i publishes o_i = mac_i - key_i
  // - v*Delta_i masked with a share of zero, via commit-then-open, and all
  // check sum_i o_i = 0 (i.e. the opened sum is the authenticated value).
  void openAndCheck(const T vals[3], const S macs[3], Auth<IO, T, S> *auth) {
    std::vector<std::vector<uint8_t>> got;
    mesh->exchange_all(vals, got, 3 * T::size());
    T open[3] = {vals[0], vals[1], vals[2]};
    for (std::size_t j = 0; j < n; ++j) {
      if (j == id_party) continue;
      const T *v = reinterpret_cast<const T *>(got[j].data());
      for (int c = 0; c < 3; ++c) open[c] = open[c] + v[c];
    }
    std::vector<T> theta;
    mesh->template zero_shares<T>(theta, 3, prg);
    struct { T o[3]; block salt; } msg;
    for (int c = 0; c < 3; ++c) msg.o[c] = macs[c].getHigh() - macs[c].getLow() - open[c] * auth->delta + theta[c];
    prg.random_block(&msg.salt, 1);
    block com[2];
    Hash::hash_once(com, &msg, sizeof(msg));
    std::vector<std::vector<uint8_t>> coms;
    mesh->exchange_all(com, coms, 2 * sizeof(block));
    mesh->exchange_all(&msg, got, sizeof(msg));
    T sum[3] = {msg.o[0], msg.o[1], msg.o[2]};
    for (std::size_t j = 0; j < n; ++j) {
      if (j == id_party) continue;
      block c[2];
      Hash::hash_once(c, got[j].data(), sizeof(msg));
      if (memcmp(c, coms[j].data(), 2 * sizeof(block)) != 0) error("mvzk: verifier opened a different value than committed");
      const T *o = reinterpret_cast<const T *>(got[j].data());
      for (int cc = 0; cc < 3; ++cc) sum[cc] = sum[cc] + o[cc];
    }
    for (int c = 0; c < 3; ++c) if (sum[c] != 0) error("mvzk: MAC check of the opened triple failed");
    if (open[2] != open[0] * open[1]) error("mvzk: multiplication check failed");
  }

  // debug (test only): reconstruct Delta from the packed shares at verifier 0
  void check_delta_correctness(std::vector<IO **> &ios, Poly<T> *poly, T delta) {
    std::size_t t = n - k;
    if (id_party != 0) {
      ios[0][0]->send_data(shareDelta.data(), (int64_t)(k * T::size()));
      ios[0][0]->send_data(&delta.val, (int64_t)T::size());
      ios[0][0]->flush();
      return;
    }
    std::vector<std::vector<T>> deltas(n);
    T d = delta;
    for (std::size_t i = 1; i < n; ++i) {
      deltas[i].resize(k);
      ios[i][0]->recv_data(deltas[i].data(), (int64_t)(k * T::size()));
      T r; ios[i][0]->recv_data(&r, (int64_t)T::size());
      d = d + r;
    }
    for (std::size_t i = 0; i < k; ++i) {
      T out = shareDelta[i] * poly->lagrangeTableKByTp1Inv[i][i * (t + 1)];
      for (std::size_t j = 1; j <= t; ++j) out = out + poly->lagrangeTableKByTp1Inv[i][i * (t + 1) + j] * deltas[j][i];
      if (out != d) error("packed share of delta error");
    }
  }
};

}  // namespace mvzk
}  // namespace emp
#endif
