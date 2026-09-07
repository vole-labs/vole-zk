// (n+1)-party end-to-end test of the MVZK backend: inputs, additions,
// multiplications (including a partial last batch), then the final check.
// usage: test_mvzk_backend <party> <port> [log_k=1] [log_n=2] [log_mults=12] [vole_per_round=16384; 0 = primal n-party VOLE] [threads=1] [cheat=0] [peer_par=0]
// cheat=1 makes the prover claim one wrong product; the verifiers must abort.
#include "test_mvzk.h"
#include "emp-zk/mvzk/mvzk.h"
#include <iostream>
using namespace emp;
using namespace emp::mvzk;

using T = FP59;
using S = FP59x2;
using AS = AuthShareT<T>;

int main(int argc, char **argv) {
  int party, port;
  parse_party_and_port(argv, &party, &port);
  int log_k = (argc > 3) ? atoi(argv[3]) : 1;
  int log_n = (argc > 4) ? atoi(argv[4]) : 2;
  int log_mults = (argc > 5) ? atoi(argv[5]) : 12;
  std::size_t per_round = (argc > 6) ? (std::size_t)atoll(argv[6]) : (1u << 14);
  std::size_t threads = (argc > 7) ? (std::size_t)atoi(argv[7]) : 1;
  bool cheat = (argc > 8) && atoi(argv[8]) != 0;
  std::size_t peer_par = (argc > 9) ? (std::size_t)atoi(argv[9]) : 0;
  int n = 1 << log_n;
  std::size_t num = ((std::size_t)1 << log_mults) + 3;   // not a multiple of k: exercises partial batches
  MeshIO mesh(party, n + 1, port, std::max<std::size_t>(2, threads));

  MvzkBackend<NetIO, T, S> backend(party, threads, mesh.ios);
  auto t0 = clock_start();
  backend.param(log_n, log_k, per_round ? per_round : (1ull << 20), peer_par,
                per_round ? NVoleKind::Committed : NVoleKind::Primal);
  backend.set_abort_channels(mesh.ctrl);
  double t_setup = time_from(t0);
  t0 = clock_start();
  if (party == n) {
    PRG prg;
    std::vector<T> a(num), b(num), c(num), d(num);
    for (std::size_t i = 0; i < num; ++i) { a[i].rand(prg); b[i].rand(prg); }
    for (std::size_t i = 0; i < num; ++i) { backend.auth_val_input(a[i]); backend.auth_val_input(b[i]); }
    backend.auth_val_input_flush_prover();
    if (!backend.auth->check_auth_correctness(a, num)) error("input a not shared correctly");
    if (!backend.auth->check_auth_correctness(b, num)) error("input b not shared correctly");
    for (std::size_t i = 0; i < num; ++i) backend.compute_mult(c[i], a[i], b[i]);
    for (std::size_t i = 0; i < num; ++i) if (i % 3 == 0) backend.compute_mult(c[i], c[i], b[i]);  // chained, pending input
    backend.flush_wires();
    for (std::size_t i = 0; i < num; ++i) backend.compute_add(d[i], c[i], a[i]);
    for (std::size_t i = 0; i < num; ++i) if (i % 5 == 0) backend.compute_mult(d[i], d[i], b[i]);  // output aliases an input
    if (cheat) {   // claim a wrong product for the last gate (shared value != lhs * rhs)
      backend.prover->skipLocalCheck = true;
      T wrong = a[0] * b[0] + T(1);
      backend.prover->mult(a[0], b[0], wrong);
      backend.prover->share(wrong, backend.auth, backend.poly, backend.ios);
    }
    backend.finalize();
    if (!backend.auth->check_auth_correctness(c, num)) error("products not shared correctly");
    if (!backend.auth->check_auth_correctness(d, num)) error("sums not shared correctly");
  } else {
    std::vector<AS> a(num), b(num), c(num), d(num);
    for (std::size_t i = 0; i < num; ++i) { backend.auth_val_input(&a[i]); backend.auth_val_input(&b[i]); }
    backend.auth_val_input_flush_verifier();
    if (!backend.auth->check_auth_correctness(a, num)) error("input a MAC check failed");
    if (!backend.auth->check_auth_correctness(b, num)) error("input b MAC check failed");
    for (std::size_t i = 0; i < num; ++i) backend.compute_mult(&c[i], &a[i], &b[i]);
    for (std::size_t i = 0; i < num; ++i) if (i % 3 == 0) backend.compute_mult(&c[i], &c[i], &b[i]);
    backend.flush_wires();
    for (std::size_t i = 0; i < num; ++i) backend.compute_add(d[i], c[i], a[i]);
    for (std::size_t i = 0; i < num; ++i) if (i % 5 == 0) backend.compute_mult(&d[i], &d[i], &b[i]);
    if (cheat) { AS w; backend.compute_mult(&w, &a[0], &b[0]); }
    backend.finalize();
    if (!backend.auth->check_auth_correctness(c, num)) error("product MAC check failed");
    if (!backend.auth->check_auth_correctness(d, num)) error("sum MAC check failed");
  }
  double t_all = time_from(t0);
  backend.print_stats();
  if (party == n)
    std::cout << "setup " << t_setup / 1000 << " ms, circuit " << t_all / 1000 << " ms, "
              << t_all / (double)backend.mult_gates() << " us per mult gate; mvzk backend test passed (n=" << n
              << ", k=" << (1 << log_k) << ")" << std::endl;
  return 0;
}
