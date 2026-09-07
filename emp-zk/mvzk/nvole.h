#ifndef EMP_ZK_MVZK_NVOLE_H__
#define EMP_ZK_MVZK_NVOLE_H__
// Programmable n-party VOLE for MVZK (paper Protocol 1 / F_nVOLE), built on
// vole-labs/vole's committed VOLE (CVoleFp) exactly as vole's MCVoleFp does,
// but keeping the correlations for the caller instead of only checking them.
//
// Parties: verifiers 0..n-1, prover (the "king") = n.
//   * The prover samples a seed per verifier. Verifier i's VOLE input u^i is
//     Expand(seed_i), so the prover reproduces every u^i locally
//     (CVoleFp's king-local mode) -- this is the programmability the paper's
//     online phase relies on.
//   * Every ordered pair (i, j) runs a committed VOLE with i as committer
//     (value u^i, MACs M^i_j) and j as verifier (key K^j_i under j's Delta_j):
//         M^i_j = K^j_i + u^i * Delta_j.
//   * Consistency (the paper's Protocol 1 check, incomplete in the original
//     mvzk code) is replaced by the commitment: the prover publishes com^i for
//     every i and each pairwise verifier checks its keys against it, which
//     binds verifier i to one u^i across all its VOLE instances.
//
// Each extend() yields `usable()` correlations per party, in rounds of
// param.n outputs of which ot_limit are usable (CVoleFp self-seeds from the
// tail). The scheduling of the pairwise mesh is vole's antipode ring
// (deadlock-free with the two-thread split).
#include <emp-tool/emp-tool.h>
#include "vole/cvole.h"
#include <future>
#include <vector>
#include <cstring>

namespace emp {
namespace mvzk {

template <typename IO, typename FP, typename FPS>
class MvzkNVole {
public:
  int id, n;                 // this party, number of verifiers; prover has id == n
  std::size_t threads;
  CVoleFpParam param;
  std::size_t M = 0, ot_limit = 0, rounds = 1, cn = 0;
  FP delta;                  // verifier: its key share Delta_i
  PRG prg;
  std::vector<IO **> ios;
  ThreadPool *pool = nullptr;

  // verifier state
  block prog_seed;
  std::vector<CVoleFp<IO, FP, FPS> *> fwd;   // committer role, per peer
  std::vector<CVoleFp<IO, FP, FPS> *> inv;   // verifier role, per peer
  std::vector<std::vector<FP>> com_pub;      // this extend's published com^j
  // prover state
  std::vector<block> prog_seeds;
  std::vector<CVoleFp<IO, FP, FPS> *> local; // king-local reproduction per verifier

  // `per_round` selects vole's LPN scale (outputs per round); extends deliver
  // `rounds_per_extend` rounds at a time.
  MvzkNVole(int id_, int n_, std::size_t threads_, std::vector<IO **> &ios_,
            std::size_t per_round = (1ull << 20), std::size_t rounds_per_extend = 1)
      : id(id_), n(n_), threads(threads_), rounds(rounds_per_extend) {
    param = cvole_resolve_param<FP>(cvole_fp_param_for(per_round));
    M = (param.t + 1) + (param.t_com + 1);
    ot_limit = param.n - M;
    cn = rounds * param.n_com;
    ios.assign(ios_.begin(), ios_.end());
    pool = new ThreadPool(1);
    if (!is_prover()) delta.rand(prg);
  }
  ~MvzkNVole() {
    delete pool;
    for (auto p : fwd) delete p;
    for (auto p : inv) delete p;
    for (auto p : local) delete p;
  }

  bool is_prover() const { return id == n; }
  std::size_t usable() const { return rounds * ot_limit; }          // correlations per extend
  std::size_t x_buf() const { return (rounds - 1) * ot_limit + param.n; }

  // ---------------- setup ----------------
  void setup() {
    if (is_prover()) {
      prog_seeds.resize(n);
      prg.random_block(prog_seeds.data(), n);
      for (int i = 0; i < n; ++i) {
        ios[i][0]->send_data(&prog_seeds[i], sizeof(block));
        ios[i][0]->flush();
      }
      local.resize(n, nullptr);
      for (int i = 0; i < n; ++i) {
        local[i] = new CVoleFp<IO, FP, FPS>(threads, param);
        local[i]->setup_prog(prog_seeds[i]);
        local[i]->setup_local();
      }
      return;
    }
    ios[n][0]->recv_data(&prog_seed, sizeof(block));
    fwd.resize(n, nullptr);
    inv.resize(n, nullptr);
    com_pub.assign(n, std::vector<FP>());
    mesh_run(/*is_setup=*/true, nullptr, nullptr, nullptr);
  }

  // ---------------- one extend ----------------
  // Prover: secrets_all[i][0..usable) <- u^i for every verifier i.
  void extend_prover(std::vector<FP *> &secrets_all) {
    std::vector<FP> x(x_buf());
    std::vector<std::vector<FP>> com(n, std::vector<FP>(cn));
    for (int i = 0; i < n; ++i) {
      local[i]->extend_inplace_local(x.data(), com[i].data(), rounds);
      std::copy(x.begin(), x.begin() + usable(), secrets_all[i]);
    }
    // publish every verifier's commitment to every verifier
    for (int j = 0; j < n; ++j) {
      for (int i = 0; i < n; ++i)
        ios[j][0]->send_data(com[i].data(), (int64_t)(cn * sizeof(FP)));
      ios[j][0]->flush();
    }
  }

  // Verifier: secrets[0..usable) <- u^id, macs[j] <- M^id_j, keys[j] <- K^id_j
  // (entries for j == id are left untouched).
  void extend_verifier(FP *secrets, std::vector<FP *> &macs, std::vector<FP *> &keys) {
    for (int i = 0; i < n; ++i) {
      com_pub[i].resize(cn);
      ios[n][0]->recv_data(com_pub[i].data(), (int64_t)(cn * sizeof(FP)));
    }
    value_digest_.assign(n, std::vector<block>(2, zero_block));
    mesh_run(/*is_setup=*/false, secrets, &macs, &keys);
    // Every committer instance of this party reproduces the same u^id; check the
    // per-peer digests agree (they were written on two threads, see commit_round).
    int ref = -1;
    for (int j = 0; j < n; ++j) {
      if (j == id) continue;
      if (ref < 0) { ref = j; continue; }
      if (memcmp(value_digest_[j].data(), value_digest_[ref].data(), 2 * sizeof(block)) != 0)
        error("mvzk nVOLE: committed value differs across peers");
    }
  }

private:
  std::vector<std::vector<block>> value_digest_;
  int secrets_writer_ = -1;   // the peer whose commit_round fills `secrets`

  // antipode-ring schedule (vole/mcvole.h): forward arc on the main thread,
  // backward arc on the pool thread; each pair runs on exactly one thread per party.
  void mesh_run(bool is_setup, FP *secrets, std::vector<FP *> *macs, std::vector<FP *> *keys) {
    int half = n / 2;
    int dest_back = (id >= half) ? (id - half) : (id + half);
    int dest_frnt = (dest_back == 0) ? (n - 1) : (dest_back - 1);
    // the first peer of the forward arc writes `secrets`
    secrets_writer_ = (id == n - 1) ? 0 : (id + 1);
    if (n == 1) secrets_writer_ = -1;

    auto fut = pool->enqueue([this, dest_back, is_setup, secrets, macs, keys]() {
      int stop = (dest_back == 0) ? (n - 1) : (dest_back - 1);
      int j = (id == 0) ? (n - 1) : (id - 1);
      while (j != stop) {
        if (is_setup) setup_with(j);
        else extend_with(j, secrets, *macs, *keys);
        j = (j == 0) ? (n - 1) : (j - 1);
      }
    });
    int stop = (dest_frnt == n - 1) ? 0 : (dest_frnt + 1);
    int j = (id == n - 1) ? 0 : (id + 1);
    while (j != stop) {
      if (is_setup) setup_with(j);
      else extend_with(j, secrets, *macs, *keys);
      j = (j == n - 1) ? 0 : (j + 1);
    }
    fut.get();
  }

  void setup_with(int j) {
    if (id > j) { make_fwd(j); make_inv(j); }
    else        { make_inv(j); make_fwd(j); }
  }
  void make_fwd(int j) {
    fwd[j] = new CVoleFp<IO, FP, FPS>(BOB, threads, ios[j], param);
    fwd[j]->setup_prog(prog_seed);
    fwd[j]->setup();
    ios[j][0]->flush();
  }
  void make_inv(int j) {
    inv[j] = new CVoleFp<IO, FP, FPS>(ALICE, threads, ios[j], param);
    inv[j]->setup(delta);
    ios[j][0]->flush();
  }

  void extend_with(int j, FP *secrets, std::vector<FP *> &macs, std::vector<FP *> &keys) {
    if (id > j) { commit_round(j, secrets, macs[j]); verify_round(j, keys[j]); }
    else        { verify_round(j, keys[j]); commit_round(j, secrets, macs[j]); }
  }

  // committer side with peer j: u^id (value lane) and M^id_j (MAC lane)
  void commit_round(int j, FP *secrets, FP *macs_j) {
    std::vector<FPS> x(x_buf());
    std::vector<FPS> com(cn);
    fwd[j]->extend_inplace_recv(x.data(), com.data(), rounds);
    const std::size_t u = usable();
    for (std::size_t l = 0; l < u; ++l) macs_j[l] = x[l].getLow();
    if (j == secrets_writer_)
      for (std::size_t l = 0; l < u; ++l) secrets[l] = x[l].getHigh();
    // digest of the value lane, compared across peers after the mesh
    Hash h;
    for (std::size_t l = 0; l < u; ++l) { FP v = x[l].getHigh(); h.put(&v.val, sizeof(v.val)); }
    h.digest(value_digest_[j].data());
    fwd[j]->consistency_send_machash(com.data(), cn);
  }

  // verifier side with peer j: K^id_j, checked against the prover's com^j
  void verify_round(int j, FP *keys_j) {
    std::vector<FP> x(x_buf());
    std::vector<FP> com(cn);
    inv[j]->extend_inplace_send(x.data(), com.data(), rounds);
    std::copy(x.begin(), x.begin() + usable(), keys_j);
    inv[j]->consistency_check_pub(com.data(), com_pub[j].data(), cn);
  }
};

}  // namespace mvzk
}  // namespace emp
#endif
