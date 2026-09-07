#ifndef EMP_ZK_MVZK_ZK_BACKEND_H__
#define EMP_ZK_MVZK_ZK_BACKEND_H__
// Circuit-level API of the multi-verifier ZK proof. Party ids: verifiers
// 0..n-1, prover n. T is the field (FP59), S its two-lane form (FP59x2).
#include "emp-zk/mvzk/zk/auth.h"
#include "emp-zk/mvzk/zk/prover.h"
#include "emp-zk/mvzk/zk/verifier.h"
#include "emp-zk/mvzk/abort.h"

namespace emp {
namespace mvzk {

template <typename IO, typename T, typename S>
class MvzkBackend {
public:
  using AuthShare = AuthShareT<T>;

  MvzkBackend(std::size_t id_party_, std::size_t threads_, std::vector<IO **> ios_)
      : id_party(id_party_), threads(threads_), ios(ios_) {}
  ~MvzkBackend() {
    delete guard;
    delete prover;
    delete verifier;
    delete auth;
    delete poly;
  }

  // n = 2^log_n verifiers, k = 2^log_k secrets per packed sharing (t = n - k
  // corruptions tolerated). kind selects the n-party VOLE (NVoleKind::Primal,
  // the default, or Committed). For Committed, vole_per_round picks the LPN
  // scale (2^20 default; 2^14 is a test scale) and peer_par bounds how many
  // pairwise VOLEs a verifier (and local expansions the prover) runs
  // concurrently, 0 = all; each of them additionally uses `threads` threads.
  void param(std::size_t log_n, std::size_t log_k, std::size_t vole_per_round = (1ull << 20),
             std::size_t peer_par = 0, NVoleKind kind = NVoleKind::Primal) {
    n_server = (std::size_t)1 << log_n;
    n_honest_server = (std::size_t)1 << log_k;
    if (n_server < 2 || log_k >= log_n) error("mvzk: need n >= 2 and k < n");
    poly = new Poly<T>(log_k, log_n);
    poly->initLagrangeTable();
    auth = new Auth<IO, T, S>(id_party, n_honest_server, n_server, threads, ios, vole_per_round, peer_par, kind);
    if (is_prover()) {
      prover = new Prover<IO, T, S>(n_honest_server, n_server);
    } else {
      verifier = new Verifier<IO, T, S>(id_party, n_honest_server, n_server, ios);
      verifier->shareMacKey(auth->delta, poly, ios);
    }
  }

  bool is_prover() const { return id_party == n_server; }

  // Cooperative abort (abort.h): ctrl[j] is a socket to party j used only for
  // abort / done notifications (nullptr for self). Optional; without it a
  // failed check exits this party alone and the peers die on socket errors.
  void set_abort_channels(std::vector<IO *> ctrl) {
    delete guard;
    guard = new AbortGuard<IO>((int)id_party, (int)n_server + 1, std::move(ctrl));
  }

  // Verifier-side outputs (of auth_val_input and compute_mult) are filled when
  // the packed sharing they belong to arrives: at every k-th wire or at a
  // flush. Until then they must not be read (e.g. by compute_add); feeding a
  // pending wire into another compute_mult is fine.
  //
  // input gates
  void auth_val_input(T val) { prover->share(val, auth, poly, ios); }
  void auth_val_input(AuthShare *shr) { verifier->share(shr, auth, poly, ios); }
  void auth_val_input_flush_prover() { prover->shareFlush(auth, poly, ios); }
  void auth_val_input_flush_verifier() { verifier->shareFlush(auth, poly, ios); }

  // addition (local)
  void compute_add(T &res, T lhs, T rhs) { res = lhs + rhs; }
  void compute_add(AuthShare &res, const AuthShare &lhs, const AuthShare &rhs) {
    res.share = lhs.share + rhs.share;
    res.mac = lhs.mac + rhs.mac;
    res.key = lhs.key + rhs.key;
  }

  // multiplication: the prover shares the product and records the triple;
  // the verifiers record it once the product's share arrives
  void compute_mult(T &res, T lhs, T rhs) {
    res = lhs * rhs;
    prover->mult(lhs, rhs, res);
    prover->share(res, auth, poly, ios);
  }
  void compute_mult(AuthShare *res, AuthShare *lhs, AuthShare *rhs) {
    verifier->share(res, lhs, rhs, auth, poly, ios);
  }
  // lazily resolved multiplication inputs (see Verifier::Resolver)
  void compute_mult(AuthShare *res, typename Verifier<IO, T, S>::Resolver resolve, bool *ready) {
    verifier->share(res, std::move(resolve), ready, auth, poly, ios);
  }
  void auth_val_input(AuthShare *shr, bool *ready) { verifier->share(shr, auth, poly, ios, ready); }

  // outputs: check wires against public values (verifiers), send opened values (prover)
  void check_public(const std::vector<AuthShare> &sh, const std::vector<T> &claimed) {
    verifier->checkPublic(sh, claimed, auth);
  }
  void reveal_send(const std::vector<T> &vals) { prover->revealValues(vals, ios); }
  void reveal_recv(std::vector<T> &vals) {
    ios[n_server][0]->recv_data(vals.data(), (int64_t)(vals.size() * T::size()));
  }
  uint64_t batches_done() const { return is_prover() ? prover->batchesDone : verifier->batchesDone; }

  void auth_val_mult_flush_prover() { prover->multFlush(auth, poly, ios); }
  void auth_val_mult_flush_verifier() { verifier->multFlush(auth, poly, ios); }

  // make every pending wire available (partial packed sharing, padded)
  void flush_wires() {
    if (is_prover()) auth_val_input_flush_prover();
    else auth_val_input_flush_verifier();
  }
  // flush pending shares and prove/check all recorded multiplications
  void finalize() {
    if (is_prover()) auth_val_mult_flush_prover();
    else auth_val_mult_flush_verifier();
    if (guard) guard->stop();
  }

  T delta() { return auth->delta; }
  uint64_t mult_gates() const { return is_prover() ? prover->multGateCount : verifier->multGateCount; }
  uint64_t input_gates() const { return is_prover() ? prover->inputGateCount : verifier->inputGateCount; }

  void print_stats() {
    uint64_t mg = mult_gates();
    std::cout << "party " << id_party << ": input gates " << input_gates() << ", mult gates " << mg
              << ", VOLE extends " << auth->extendCount << " (" << auth->timeVOLE / 1000 << " ms)"
              << ", conversion " << auth->timeConversion / 1000 << " ms"
              << ", mult checks " << (is_prover() ? prover->checkCount : verifier->checkCount)
              << " (" << (is_prover() ? prover->timeVerifyAuth : verifier->timeVerifyAuth) / 1000 << " ms)" << std::endl;
  }

  std::size_t id_party, threads, n_server = 0, n_honest_server = 0;
  std::vector<IO **> ios;
  Poly<T> *poly = nullptr;
  Auth<IO, T, S> *auth = nullptr;
  Prover<IO, T, S> *prover = nullptr;
  Verifier<IO, T, S> *verifier = nullptr;
  AbortGuard<IO> *guard = nullptr;
};

}  // namespace mvzk
}  // namespace emp
#endif
