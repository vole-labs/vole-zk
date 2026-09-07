// (n+1)-party test of MvzkNVole: after setup + two extends every pair relation
// M^i_j = K^j_i + u^i * Delta_j holds, and the prover's local u^i equals
// verifier i's. usage: test_mvzk_nvole <party> <port> [log_n=2] [per_round=16384]
#include "test_mvzk.h"
#include "emp-zk/mvzk/fields/fp59.h"
#include "emp-zk/mvzk/fields/fp59x2.h"
#include "emp-zk/mvzk/nvole.h"
#include <iostream>
using namespace emp;
using namespace emp::mvzk;

int main(int argc, char **argv) {
  int party, port;
  parse_party_and_port(argv, &party, &port);
  int log_n = (argc > 3) ? atoi(argv[3]) : 2;
  std::size_t per_round = (argc > 4) ? (std::size_t)atoll(argv[4]) : (1u << 14);
  std::size_t threads = (argc > 5) ? (std::size_t)atoi(argv[5]) : 1;
  bool bench = (argc > 6) && atoi(argv[6]) != 0;     // print per-phase timing, skip the O(n^2) relation check
  int n = 1 << log_n;
  MeshIO mesh(party, n + 1, port, std::max<std::size_t>(2, threads));

  MvzkNVole<NetIO, FP59, FP59x2> nv(party, n, threads, mesh.ios, per_round);
  auto t0 = clock_start();
  nv.setup();
  double t_setup = time_from(t0);
  const std::size_t u = nv.usable();

  std::vector<std::vector<FP59>> S(n, std::vector<FP59>(u));   // prover: all u^i
  std::vector<FP59> sec(u);
  std::vector<std::vector<FP59>> macs(n, std::vector<FP59>(u)), keys(n, std::vector<FP59>(u));
  std::vector<FP59 *> Sp(n), mp(n), kp(n);
  for (int i = 0; i < n; ++i) { Sp[i] = S[i].data(); mp[i] = macs[i].data(); kp[i] = keys[i].data(); }

  for (int round = 0; round < 2; ++round) {
    t0 = clock_start();
    if (party == n) nv.extend_prover(Sp);
    else            nv.extend_verifier(sec.data(), mp, kp);
    double t_ext = time_from(t0);
    if (party == n) std::cout << "extend " << round << ": " << u << " correlations/party in " << t_ext / 1000 << " ms" << std::endl;
    if (bench && round == 1) {
      auto &st = nv.stats;
      if (party == n)
        std::cout << "  prover: local expansions x" << n << " on " << st.workers << " workers " << st.prover_local / 1000 << " ms, publish coms " << st.prover_publish / 1000 << " ms" << std::endl;
      else if (party == 0 || party == n - 1)
        std::cout << "  verifier " << party << ": wait coms " << st.wait_coms / 1000 << " ms, mesh wall " << st.mesh_wall / 1000
                  << " ms [" << st.workers << " workers; per-peer wall max " << st.peer_max / 1000 << " / sum " << st.peer_sum / 1000
                  << " ms]; committer extend " << st.commit_extend / 1000 << " + hash " << st.commit_hash / 1000
                  << ", verifier extend " << st.verify_extend / 1000 << " + check " << st.verify_check / 1000 << " ms (summed over peers)" << std::endl;
    }

    if (bench) continue;
    // ---- correctness (test only): prover sends u^i to verifier i; every
    // verifier i sends (u^i, M^i_j) to each j, who checks against K^j_i, Delta_j.
    if (party == n) {
      for (int i = 0; i < n; ++i) { mesh.ios[i][0]->send_data(S[i].data(), u * sizeof(FP59)); mesh.ios[i][0]->flush(); }
    } else {
      std::vector<FP59> from_p(u);
      mesh.ios[n][0]->recv_data(from_p.data(), u * sizeof(FP59));
      for (std::size_t l = 0; l < u; ++l) if (from_p[l] != sec[l]) error("prover's u^i differs from verifier's");
      // pairwise, in id order to avoid deadlock: lower id sends first
      for (int j = 0; j < n; ++j) {
        if (j == party) continue;
        auto send_mine = [&]() { mesh.ios[j][0]->send_data(sec.data(), u * sizeof(FP59)); mesh.ios[j][0]->send_data(macs[j].data(), u * sizeof(FP59)); mesh.ios[j][0]->flush(); };
        auto recv_check = [&]() {
          std::vector<FP59> uj(u), mj(u);
          mesh.ios[j][0]->recv_data(uj.data(), u * sizeof(FP59));
          mesh.ios[j][0]->recv_data(mj.data(), u * sizeof(FP59));
          for (std::size_t l = 0; l < u; ++l)
            if (mj[l] != keys[j][l] + uj[l] * nv.delta) error("nVOLE relation M = K + u*Delta violated");
        };
        if (party < j) { send_mine(); recv_check(); } else { recv_check(); send_mine(); }
      }
      if (party == 0) std::cout << "extend " << round << ": all pairwise relations hold" << std::endl;
    }
  }
  if (party == n) std::cout << "setup " << t_setup / 1000 << " ms; nvole test passed (n=" << n << ")" << std::endl;
  return 0;
}
