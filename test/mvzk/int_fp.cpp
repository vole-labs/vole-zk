// (n+1)-party test of the IntFp wrapper: same circuit code on every party.
// usage: test_mvzk_int_fp <party> <port> [log_k=1] [log_n=2] [dim=16] [vole_per_round=16384] [cheat=0]
#include "test_mvzk.h"
#include "emp-zk/mvzk/mvzk.h"
#include <iostream>
using namespace emp;
using namespace emp::mvzk;

static uint64_t mulmod(uint64_t a, uint64_t b) { return (uint64_t)(((unsigned __int128)a * b) % FP59::PR); }
static uint64_t addmod(uint64_t a, uint64_t b) { return (uint64_t)(((unsigned __int128)a + b) % FP59::PR); }

int main(int argc, char **argv) {
  int party, port;
  parse_party_and_port(argv, &party, &port);
  int log_k = (argc > 3) ? atoi(argv[3]) : 1;
  int log_n = (argc > 4) ? atoi(argv[4]) : 2;
  std::size_t dim = (argc > 5) ? (std::size_t)atoll(argv[5]) : 16;
  std::size_t per_round = (argc > 6) ? (std::size_t)atoll(argv[6]) : (1u << 14);
  bool cheat = (argc > 7) && atoi(argv[7]) != 0;
  int n = 1 << log_n;
  MeshIO mesh(party, n + 1, port, 2);
  setup_mvzk<NetIO>(party, 1, mesh.ios, log_n, log_k, per_round, 0, mesh.ctrl);

  // plaintext inputs from a fixed seed so every party can compute the expected outputs
  std::size_t N = dim * dim;
  std::vector<uint64_t> wa(N), wb(N), wc(N, 0);
  block seed = makeBlock(0x6d767a6bULL, 0x696e745f6670ULL);   // fixed test seed
  PRG prg(&seed);
  prg.random_data(wa.data(), N * 8); prg.random_data(wb.data(), N * 8);
  for (auto &x : wa) x %= FP59::PR;
  for (auto &x : wb) x %= FP59::PR;
  for (std::size_t i = 0; i < dim; ++i)
    for (std::size_t j = 0; j < dim; ++j)
      for (std::size_t l = 0; l < dim; ++l) wc[i * dim + l] = addmod(wc[i * dim + l], mulmod(wa[i * dim + j], wb[j * dim + l]));
  if (cheat && party == n) wa[3] = addmod(wa[3], 1);   // prover feeds a wrong witness

  auto t0 = clock_start();
  std::vector<IntFp> a(N), b(N), c(N);
  batch_feed(a.data(), wa.data(), (int64_t)N);
  batch_feed(b.data(), wb.data(), (int64_t)N);
  for (std::size_t i = 0; i < N; ++i) c[i] = IntFp(0, PUBLIC);
  for (std::size_t i = 0; i < dim; ++i)
    for (std::size_t j = 0; j < dim; ++j)
      for (std::size_t l = 0; l < dim; ++l) c[i * dim + l] = c[i * dim + l] + a[i * dim + j] * b[j * dim + l];   // lazy chains
  batch_reveal_check(c.data(), wc.data(), (int64_t)N);

  // scalar API: constants, subtraction, negate, reveal()
  IntFp e = (a[0] * 3 + 5) - b[1] * a[1];
  uint64_t e_exp = addmod(addmod(mulmod(wa[0], 3), 5), FP59::PR - mulmod(wb[1], wa[1]));
  if (e.reveal() != e_exp) error("reveal() mismatch");
  IntFp z = e.negate() + e;
  z.reveal_zero();
  IntFp f = (a[2] - b[2]) * (a[2] + b[2]) - a[2] * a[2] + b[2] * b[2];  // == 0
  if (!f.reveal_zero()) error("prover sees a non-zero output");
  finalize_mvzk<NetIO>();
  double t = time_from(t0);
  if (party == n)
    std::cout << "IntFp: " << dim << "^3 + 6 mults in " << t / 1000 << " ms; mvzk int_fp test passed" << std::endl;
  return 0;
}
