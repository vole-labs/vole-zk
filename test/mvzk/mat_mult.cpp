// (n+1)-party matrix multiplication proof C = A * B (dim x dim), the paper's
// benchmark circuit. usage: test_mvzk_mat_mult <party> <port> [log_k=1] [log_n=2] [dim=64] [vole_per_round=16384; 0 = primal n-party VOLE] [threads=1] [peer_par=0]
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
  std::size_t dim = (argc > 5) ? (std::size_t)atoll(argv[5]) : 64;
  std::size_t per_round = (argc > 6) ? (std::size_t)atoll(argv[6]) : (1u << 14);
  std::size_t threads = (argc > 7) ? (std::size_t)atoi(argv[7]) : 1;
  std::size_t peer_par = (argc > 8) ? (std::size_t)atoi(argv[8]) : 0;
  int n = 1 << log_n;
  MeshIO mesh(party, n + 1, port, std::max<std::size_t>(2, threads));

  MvzkBackend<NetIO, T, S> backend(party, threads, mesh.ios);
  backend.param(log_n, log_k, per_round ? per_round : (1ull << 20), peer_par,
                per_round ? NVoleKind::Committed : NVoleKind::Primal);
  backend.set_abort_channels(mesh.ctrl);
  auto t0 = clock_start();
  if (party == n) {
    PRG prg;
    std::vector<std::vector<T>> A(dim, std::vector<T>(dim)), B(dim, std::vector<T>(dim)), C(dim, std::vector<T>(dim));
    for (auto &row : A) for (auto &x : row) { x.rand(prg); backend.auth_val_input(x); }
    for (auto &row : B) for (auto &x : row) { x.rand(prg); backend.auth_val_input(x); }
    backend.auth_val_input_flush_prover();
    for (std::size_t r = 0; r < dim; ++r)
      for (std::size_t i = 0; i < dim; ++i)
        for (std::size_t j = 0; j < dim; ++j) {
          T t; backend.compute_mult(t, A[r][i], B[i][j]);
          backend.compute_add(C[r][j], C[r][j], t);
        }
    backend.finalize();
    std::vector<T> flat; for (auto &row : C) flat.insert(flat.end(), row.begin(), row.end());
    if (!backend.auth->check_auth_correctness(flat, flat.size())) error("C not shared correctly");
  } else {
    std::vector<std::vector<AS>> A(dim, std::vector<AS>(dim)), B(dim, std::vector<AS>(dim)), C(dim, std::vector<AS>(dim));
    for (auto &row : A) for (auto &x : row) backend.auth_val_input(&x);
    for (auto &row : B) for (auto &x : row) backend.auth_val_input(&x);
    backend.auth_val_input_flush_verifier();
    std::vector<AS> tmp(dim * dim * dim);   // outputs are filled at batch boundaries, so keep them alive
    std::size_t p = 0;
    for (std::size_t r = 0; r < dim; ++r)
      for (std::size_t i = 0; i < dim; ++i)
        for (std::size_t j = 0; j < dim; ++j) backend.compute_mult(&tmp[p++], &A[r][i], &B[i][j]);
    backend.finalize();
    p = 0;
    for (std::size_t r = 0; r < dim; ++r)
      for (std::size_t i = 0; i < dim; ++i)
        for (std::size_t j = 0; j < dim; ++j) backend.compute_add(C[r][j], C[r][j], tmp[p++]);
    std::vector<AS> flat; for (auto &row : C) flat.insert(flat.end(), row.begin(), row.end());
    if (!backend.auth->check_auth_correctness(flat, flat.size())) error("C MAC check failed");
  }
  double t_all = time_from(t0);
  backend.print_stats();
  if (party == n)
    std::cout << "matmul " << dim << "^3 = " << backend.mult_gates() << " mults in " << t_all / 1000 << " ms ("
              << t_all / (double)backend.mult_gates() << " us/mult); mvzk mat_mult test passed" << std::endl;
  return 0;
}
