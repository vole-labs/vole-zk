#ifndef EMP_ZK_MVZK_ZK_AUTH_H__
#define EMP_ZK_MVZK_ZK_AUTH_H__
// Random authenticated packed sharings from the n-party VOLE (paper Pi_Prep):
// every VOLE correlation is reinterpreted as a degree-(n-1) packed Shamir
// sharing of k secrets, and each verifier converts its packed share into
// additive shares of the k secrets (and of their MACs / keys) with one row of
// Lagrange coefficients. The prover, who knows every u^i, obtains the secrets.
#include "emp-zk/mvzk/utils/poly.h"
#include "emp-zk/mvzk/utils/utils.h"
#include "emp-zk/mvzk/nvole.h"
#include "emp-zk/mvzk/nvole_primal.h"
#include "emp-zk/mvzk/mesh.h"
#include "emp-zk/mvzk/zk/utils.h"

namespace emp {
namespace mvzk {

// Which n-party VOLE backs the preprocessing:
//   Primal    - vole/mvole.h, primal LPN, ~10^7 correlations per extend,
//               consistency check per the paper (default)
//   Committed - vole/cvole.h, dual-LPN committed VOLE, 2^20 per extend by
//               default (vole_per_round), ~25x slower per correlation
enum class NVoleKind { Primal, Committed };

template <typename IO, typename T, typename S>
class Auth {
public:
  std::size_t id_party, k, n, threads;
  T delta;                          // verifier: Delta_i (zero on the prover)
  std::vector<IO **> ios;
  PRG prg;

  NVoleKind kind = NVoleKind::Primal;
  MvzkNVole<IO, T, S> *nvole = nullptr;             // Committed
  MvzkNVolePrimal<IO, T, S> *nvole_primal = nullptr; // Primal
  std::size_t usable = 0, ptr = 0;  // correlations per extend / consumed so far
  std::vector<T> secrets;           // verifier: u^i
  std::vector<std::vector<T>> macs, keys;      // verifier: M^i_j, K^i_j
  std::vector<std::vector<T>> secretsGroup;    // prover: u^i for every verifier i
  std::vector<T *> secrets_ptr, macs_ptr, keys_ptr;

  std::vector<block> allNonces;     // fresh nonces, refreshed after every extend
  std::size_t randAuthValCount = 0, extendCount = 0;
  double timeVOLE = 0.0, timeConversion = 0.0;

  Auth(std::size_t id_party_, std::size_t k_, std::size_t n_, std::size_t threads_,
       std::vector<IO **> ios_, std::size_t vole_per_round, std::size_t peer_par = 0,
       NVoleKind kind_ = NVoleKind::Primal)
      : id_party(id_party_), k(k_), n(n_), threads(threads_), ios(ios_), kind(kind_) {
    if (kind == NVoleKind::Primal) {
      nvole_primal = new MvzkNVolePrimal<IO, T, S>((int)id_party_, (int)n_, threads_, ios);
      nvole_primal->setup();
      usable = nvole_primal->usable();
    } else {
      nvole = new MvzkNVole<IO, T, S>((int)id_party_, (int)n_, threads_, ios, vole_per_round, 1, peer_par);
      nvole->setup();
      usable = nvole->usable();
    }
    ptr = usable;
    if (is_prover()) {
      secretsGroup.assign(n, std::vector<T>(usable));
      secrets_ptr.resize(n);
      for (std::size_t i = 0; i < n; ++i) secrets_ptr[i] = secretsGroup[i].data();
    } else {
      delta = (kind == NVoleKind::Primal) ? nvole_primal->delta : nvole->delta;
      secrets.resize(usable);
      macs.assign(n, std::vector<T>());
      keys.assign(n, std::vector<T>());
      macs_ptr.assign(n, nullptr);
      keys_ptr.assign(n, nullptr);
      for (std::size_t j = 0; j < n; ++j) {
        if (j == id_party) continue;
        macs[j].resize(usable); keys[j].resize(usable);
        macs_ptr[j] = macs[j].data(); keys_ptr[j] = keys[j].data();
      }
    }
    flush_io(ios, threads);
    nonces(id_party, n, ios, allNonces, prg);
  }
  ~Auth() { delete nvole; delete nvole_primal; }

  bool is_prover() const { return id_party == n; }

  // One VOLE extend on every party, followed by fresh nonces (paper Prep step
  // 5: the Fiat-Shamir nonces must not be reused across extensions).
  void refill() {
    auto t0 = clock_start();
    flush_io(ios, threads);
    if (kind == NVoleKind::Primal) {
      if (is_prover()) nvole_primal->extend_prover(secrets_ptr);
      else             nvole_primal->extend_verifier(secrets.data(), macs_ptr, keys_ptr);
    } else {
      if (is_prover()) nvole->extend_prover(secrets_ptr);
      else             nvole->extend_verifier(secrets.data(), macs_ptr, keys_ptr);
    }
    flush_io(ios, threads);
    ptr = 0;
    ++extendCount;
    nonces(id_party, n, ios, allNonces, prg);
    timeVOLE += time_from(t0);
  }

  // Prover: `num` packed sharings -> num*k secrets.
  void randAuthVal(std::vector<T> &out_val, Poly<T> *poly, std::size_t num) {
    out_val.resize(num * k);
    std::vector<T> in(n), buf;
    std::size_t done = 0;
    while (done < num) {
      if (ptr == usable) refill();
      auto t0 = clock_start();
      std::size_t take = std::min(num - done, usable - ptr);
      for (std::size_t l = 0; l < take; ++l) {
        for (std::size_t i = 0; i < n; ++i) in[i] = secretsGroup[i][ptr + l];
        poly->nttEvalN2K(buf, in);
        std::copy(buf.begin(), buf.end(), out_val.begin() + (done + l) * k);
      }
      ptr += take; done += take;
      timeConversion += time_from(t0);
    }
    randAuthValCount += num;
  }

  // Verifier: `num` packed sharings -> additive shares (mac, key, value) of num*k secrets.
  void randAuthVal(std::vector<T> &out_mac, std::vector<T> &out_key, std::vector<T> &out_val,
                   Poly<T> *poly, std::size_t num) {
    out_mac.resize(num * k); out_key.resize(num * k); out_val.resize(num * k);
    std::vector<T> key(n), buf;
    std::size_t done = 0;
    while (done < num) {
      if (ptr == usable) refill();
      auto t0 = clock_start();
      std::size_t take = std::min(num - done, usable - ptr);
      for (std::size_t l = 0; l < take; ++l) {
        T sec = secrets[ptr + l];
        T mac = sec * delta;                    // own key part: u^i * Delta_i
        for (std::size_t j = 0; j < n; ++j) {
          if (j == id_party) { key[j] = T(0, false); continue; }
          key[j] = keys[j][ptr + l];
          mac = mac + macs[j][ptr + l];
        }
        std::size_t off = (done + l) * k;
        poly->lagrangeEvalOne2K(buf, mac, id_party);
        std::copy(buf.begin(), buf.end(), out_mac.begin() + off);
        poly->lagrangeEvalOne2K(buf, sec, id_party);
        std::copy(buf.begin(), buf.end(), out_val.begin() + off);
        poly->nttEvalN2K(buf, key);
        std::copy(buf.begin(), buf.end(), out_key.begin() + off);
      }
      ptr += take; done += take;
      timeConversion += time_from(t0);
    }
    randAuthValCount += num;
  }

  // ---------------- debug helpers (test only) ----------------
  // Verifiers send their (mac, key, share, Delta_i) to verifier 0 who checks
  // sum mac == sum key + Delta * sum share; the prover receives sum share.
  bool check_auth_correctness(const std::vector<AuthShareT<T>> &as, std::size_t len) {
    std::vector<T> v(len);
    for (std::size_t i = 0; i < len; ++i) v[i] = as[i].share;
    ios[n][0]->send_data(v.data(), (int64_t)(len * T::size()));
    ios[n][0]->flush();
    if (id_party != 0) {
      for (std::size_t i = 0; i < len; ++i) v[i] = as[i].mac;
      ios[0][0]->send_data(v.data(), (int64_t)(len * T::size()));
      for (std::size_t i = 0; i < len; ++i) v[i] = as[i].key;
      ios[0][0]->send_data(v.data(), (int64_t)(len * T::size()));
      for (std::size_t i = 0; i < len; ++i) v[i] = as[i].share;
      ios[0][0]->send_data(v.data(), (int64_t)(len * T::size()));
      ios[0][0]->send_data(&delta.val, (int64_t)T::size());
      ios[0][0]->flush();
      return true;
    }
    std::vector<AuthShareT<T>> acc(as.begin(), as.begin() + len);
    T d = delta;
    for (std::size_t i = 1; i < n; ++i) {
      ios[i][0]->recv_data(v.data(), (int64_t)(len * T::size()));
      for (std::size_t j = 0; j < len; ++j) acc[j].mac = acc[j].mac + v[j];
      ios[i][0]->recv_data(v.data(), (int64_t)(len * T::size()));
      for (std::size_t j = 0; j < len; ++j) acc[j].key = acc[j].key + v[j];
      ios[i][0]->recv_data(v.data(), (int64_t)(len * T::size()));
      for (std::size_t j = 0; j < len; ++j) acc[j].share = acc[j].share + v[j];
      T r; ios[i][0]->recv_data(&r, (int64_t)T::size());
      d = d + r;
    }
    for (std::size_t j = 0; j < len; ++j)
      if (acc[j].key + d * acc[j].share != acc[j].mac) { std::cout << "auth error at entry " << j << std::endl; return false; }
    return true;
  }
  // prover side of the above: every verifier's share sum must equal `val`
  bool check_auth_correctness(const std::vector<T> &val, std::size_t len) {
    std::vector<T> v(len), acc(val.begin(), val.begin() + len);
    for (std::size_t i = 0; i < n; ++i) {
      ios[i][0]->recv_data(v.data(), (int64_t)(len * T::size()));
      for (std::size_t j = 0; j < len; ++j) acc[j] = acc[j] - v[j];
    }
    bool ok = true;
    for (std::size_t j = 0; j < len; ++j) if (acc[j] != 0) { std::cout << "  entry " << j << " differs by " << acc[j].val << std::endl; ok = false; }
    return ok;
  }
};

}  // namespace mvzk
}  // namespace emp
#endif
