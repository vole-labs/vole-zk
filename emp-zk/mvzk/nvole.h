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
// tail). Every pair (i, j) is independent: its two VOLE directions run back to
// back on one thread of each party (the lower id verifies first), and a
// verifier runs up to `peer_par` peers concurrently (default: all n-1). The
// prover expands its n local copies concurrently as well.
#include <emp-tool/emp-tool.h>
#include "emp-zk/mvzk/abort.h"
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
  ThreadPool *pool = nullptr;      // peer-level parallelism (verifier) / local expansions (prover)
  std::size_t peer_par = 0;

  // verifier state
  block prog_seed;
  std::vector<CVoleFp<IO, FP, FPS> *> fwd;   // committer role, per peer
  std::vector<CVoleFp<IO, FP, FPS> *> inv;   // verifier role, per peer
  std::vector<std::vector<FP>> com_pub;      // this extend's published com^j
  // prover state
  std::vector<block> prog_seeds;
  std::vector<CVoleFp<IO, FP, FPS> *> local; // king-local reproduction per verifier

  // timing of the last extend (microseconds), for benchmarks
  struct Stats {
    double prover_local = 0, prover_publish = 0;          // prover
    double wait_coms = 0, mesh_wall = 0;                  // verifier
    double peer_max = 0, peer_sum = 0;                    // per-peer wall time (max / sum over peers)
    double commit_extend = 0, commit_hash = 0;            // summed over peers
    double verify_extend = 0, verify_check = 0;
    std::size_t workers = 0;
  } stats;

  // `per_round` selects vole's LPN scale (outputs per round); extends deliver
  // `rounds_per_extend` rounds at a time.
  // peer_par_: concurrent peers per verifier / concurrent local expansions on
  // the prover; 0 = all (n-1 resp. n).
  MvzkNVole(int id_, int n_, std::size_t threads_, std::vector<IO **> &ios_,
            std::size_t per_round = (1ull << 20), std::size_t rounds_per_extend = 1,
            std::size_t peer_par_ = 0)
      : id(id_), n(n_), threads(threads_), rounds(rounds_per_extend) {
    param = cvole_resolve_param<FP>(cvole_fp_param_for(per_round));
    M = (param.t + 1) + (param.t_com + 1);
    ot_limit = param.n - M;
    cn = rounds * param.n_com;
    ios.assign(ios_.begin(), ios_.end());
    std::size_t all = is_prover() ? (std::size_t)n : (std::size_t)(n - 1);
    peer_par = (peer_par_ == 0 || peer_par_ > all) ? all : peer_par_;
    if (peer_par == 0) peer_par = 1;
    pool = new ThreadPool((int)peer_par);
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
      for_each_index(n, [this](int i) {
        local[i] = new CVoleFp<IO, FP, FPS>(threads, param);
        local[i]->setup_prog(prog_seeds[i]);
        local[i]->setup_local();
      });
      return;
    }
    ios[n][0]->recv_data(&prog_seed, sizeof(block));
    fwd.resize(n, nullptr);
    inv.resize(n, nullptr);
    com_pub.assign(n, std::vector<FP>());
    for_each_peer([this](int j) { setup_with(j); });
  }

  // ---------------- one extend ----------------
  // Prover: secrets_all[i][0..usable) <- u^i for every verifier i.
  void extend_prover(std::vector<FP *> &secrets_all) {
    stats = Stats();
    auto t0 = clock_start();
    std::vector<std::vector<FP>> com(n, std::vector<FP>(cn));
    for_each_index(n, [this, &com, &secrets_all](int i) {
      std::vector<FP> x(x_buf());
      local[i]->extend_inplace_local(x.data(), com[i].data(), rounds);
      std::copy(x.begin(), x.begin() + usable(), secrets_all[i]);
    });
    stats.prover_local = time_from(t0);
    stats.workers = peer_par;
    t0 = clock_start();
    // publish every verifier's commitment to every verifier
    for (int j = 0; j < n; ++j) {
      for (int i = 0; i < n; ++i)
        ios[j][0]->send_data(com[i].data(), (int64_t)(cn * sizeof(FP)));
      ios[j][0]->flush();
    }
    stats.prover_publish = time_from(t0);
  }

  // Verifier: secrets[0..usable) <- u^id, macs[j] <- M^id_j, keys[j] <- K^id_j
  // (entries for j == id are left untouched).
  void extend_verifier(FP *secrets, std::vector<FP *> &macs, std::vector<FP *> &keys) {
    stats = Stats();
    auto t0 = clock_start();
    for (int i = 0; i < n; ++i) {
      com_pub[i].resize(cn);
      ios[n][0]->recv_data(com_pub[i].data(), (int64_t)(cn * sizeof(FP)));
    }
    stats.wait_coms = time_from(t0);
    value_digest_.assign(n, std::vector<block>(2, zero_block));
    t0 = clock_start();
    tm_.assign(n, std::vector<double>(5, 0.0));
    secrets_writer_ = (id == 0) ? 1 : 0;   // one designated peer fills `secrets`
    for_each_peer([this, secrets, &macs, &keys](int j) {
      auto tp = clock_start();
      extend_with(j, secrets, macs, keys);
      tm_[j][4] = time_from(tp);
    });
    stats.mesh_wall = time_from(t0);
    stats.workers = peer_par;
    for (int j = 0; j < n; ++j) {
      if (j == id) continue;
      stats.commit_extend += tm_[j][0]; stats.commit_hash += tm_[j][1];
      stats.verify_extend += tm_[j][2]; stats.verify_check += tm_[j][3];
      stats.peer_sum += tm_[j][4]; stats.peer_max = std::max(stats.peer_max, tm_[j][4]);
    }
    // Every committer instance of this party reproduces the same u^id; check the
    // per-peer digests agree (they were written on two threads, see commit_round).
    int ref = -1;
    for (int j = 0; j < n; ++j) {
      if (j == id) continue;
      if (ref < 0) { ref = j; continue; }
      if (memcmp(value_digest_[j].data(), value_digest_[ref].data(), 2 * sizeof(block)) != 0)
        mvzk_fail<IO>("mvzk nVOLE: committed value differs across peers");
    }
  }

private:
  std::vector<std::vector<block>> value_digest_;
  int secrets_writer_ = -1;   // the peer whose commit_round fills `secrets`

  // run fn(j) for every peer j != id, up to peer_par concurrently (pairs are
  // independent, each uses only its own channels)
  template <typename F> void for_each_peer(F fn) {
    std::vector<std::future<void>> futs;
    for (int j = 0; j < n; ++j) {
      if (j == id) continue;
      futs.push_back(pool->enqueue([fn, j]() { fn(j); }));
    }
    for (auto &f : futs) f.get();
  }
  template <typename F> void for_each_index(int cnt, F fn) {
    std::vector<std::future<void>> futs;
    for (int i = 0; i < cnt; ++i) futs.push_back(pool->enqueue([fn, i]() { fn(i); }));
    for (auto &f : futs) f.get();
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

  // both directions of pair (id, j): the lower id verifies first
  void extend_with(int j, FP *secrets, std::vector<FP *> &macs, std::vector<FP *> &keys) {
    double *t = tm_[j].data();
    if (id > j) { commit_round(j, secrets, macs[j], t); verify_round(j, keys[j], t); }
    else        { verify_round(j, keys[j], t); commit_round(j, secrets, macs[j], t); }
  }
  std::vector<std::vector<double>> tm_;   // per peer: commit_extend, commit_hash, verify_extend, verify_check, wall

  // committer side with peer j: u^id (value lane) and M^id_j (MAC lane)
  void commit_round(int j, FP *secrets, FP *macs_j, double *tm) {
    std::vector<FPS> x(x_buf());
    std::vector<FPS> com(cn);
    auto t0 = clock_start();
    fwd[j]->extend_inplace_recv(x.data(), com.data(), rounds);
    tm[0] += time_from(t0);
    const std::size_t u = usable();
    for (std::size_t l = 0; l < u; ++l) macs_j[l] = x[l].getLow();
    if (j == secrets_writer_)
      for (std::size_t l = 0; l < u; ++l) secrets[l] = x[l].getHigh();
    // digest of the value lane, compared across peers after the mesh
    Hash h;
    for (std::size_t l = 0; l < u; ++l) { FP v = x[l].getHigh(); h.put(&v.val, sizeof(v.val)); }
    h.digest(value_digest_[j].data());
    t0 = clock_start();
    fwd[j]->consistency_send_machash(com.data(), cn);
    tm[1] += time_from(t0);
  }

  // verifier side with peer j: K^id_j, checked against the prover's com^j
  void verify_round(int j, FP *keys_j, double *tm) {
    std::vector<FP> x(x_buf());
    std::vector<FP> com(cn);
    auto t0 = clock_start();
    inv[j]->extend_inplace_send(x.data(), com.data(), rounds);
    tm[2] += time_from(t0);
    std::copy(x.begin(), x.begin() + usable(), keys_j);
    t0 = clock_start();
    inv[j]->consistency_check_pub(com.data(), com_pub[j].data(), cn);
    tm[3] += time_from(t0);
  }
};

}  // namespace mvzk
}  // namespace emp
#endif
