// (n+1)-party test of IntFpVec: element-wise ops, public scalars / vectors,
// sum, dot, compose / decompose, batched reveal and reveal_check.
// usage: test_mvzk_int_fp_vec <party> <port> [log_k=1] [log_n=2] [len=1000] [vole_per_round=16384] [cheat=0]
#include "test_mvzk.h"
#include "emp-zk/mvzk/mvzk.h"
#include <iostream>
using namespace emp;
using namespace emp::mvzk;

static uint64_t mulmod(uint64_t a, uint64_t b) { return (uint64_t)(((unsigned __int128)a * b) % FP59::PR); }
static uint64_t addmod(uint64_t a, uint64_t b) { return (uint64_t)(((unsigned __int128)a + b) % FP59::PR); }
static uint64_t submod(uint64_t a, uint64_t b) { return addmod(a, FP59::PR - b); }

int main(int argc, char **argv) {
  int party, port;
  parse_party_and_port(argv, &party, &port);
  int log_k = (argc > 3) ? atoi(argv[3]) : 1;
  int log_n = (argc > 4) ? atoi(argv[4]) : 2;
  int64_t len = (argc > 5) ? atoll(argv[5]) : 1000;
  std::size_t per_round = (argc > 6) ? (std::size_t)atoll(argv[6]) : (1u << 14);
  bool cheat = (argc > 7) && atoi(argv[7]) != 0;
  int n = 1 << log_n;
  MeshIO mesh(party, n + 1, port, 2);
  setup_mvzk<NetIO>(party, 1, mesh.ios, log_n, log_k, per_round, 0, mesh.ctrl);

  std::vector<uint64_t> x(len), y(len), c(len);
  block seed = makeBlock(0x766563ULL, 0x696e745f6670ULL);
  PRG prg(&seed);
  prg.random_data(x.data(), len * 8); prg.random_data(y.data(), len * 8); prg.random_data(c.data(), len * 8);
  for (auto &v : x) v %= FP59::PR;
  for (auto &v : y) v %= FP59::PR;
  for (auto &v : c) v %= FP59::PR;
  if (cheat && party == n) y[7] = addmod(y[7], 1);

  auto t0 = clock_start();
  IntFpVec X(x.data(), len, ALICE), Y(y.data(), len, ALICE), C(c.data(), len, PUBLIC);
  // z = (x*y + c) * 3 - x + c_vec ; w = z - x*y*3 - 2c  (== c*2 + ... check below)
  IntFpVec XY = X * Y;
  IntFpVec Z = (XY + C) * 3 - X + c;
  std::vector<uint64_t> z_exp(len);
  for (int64_t i = 0; i < len; ++i) z_exp[i] = addmod(submod(mulmod(addmod(mulmod(x[i], y[i]), c[i]), 3), x[i]), c[i]);
  if (!Z.reveal_check(z_exp.data())) error("prover: Z mismatch");
  // zero vector: (X - Y) * (X + Y) - X*X + Y*Y
  IntFpVec Zero = (X - Y) * (X + Y) - X * X + Y * Y;
  Zero.reveal_check_zero();
  // sum, dot, negate, operator[], compose / decompose, batched reveal
  uint64_t s_exp = 0, d_exp = 0;
  for (int64_t i = 0; i < len; ++i) { s_exp = addmod(s_exp, x[i]); d_exp = addmod(d_exp, mulmod(x[i], y[i])); }
  X.sum().reveal(s_exp);
  X.dot(Y).reveal(d_exp);
  (X.negate() + X).sum().reveal_zero();
  IntFp x3 = X[3];
  x3.reveal(x[3]);
  std::vector<IntFp> parts = XY.decompose();
  IntFpVec back = IntFpVec::compose(parts);
  std::vector<uint64_t> opened(len);
  back.reveal(opened.data());
  for (int64_t i = 0; i < len; ++i) if (opened[i] != mulmod(x[i], y[i])) error("batched reveal mismatch");
  finalize_mvzk<NetIO>();
  double t = time_from(t0);
  if (party == n) std::cout << "IntFpVec: len " << len << " in " << t / 1000 << " ms; mvzk int_fp_vec test passed" << std::endl;
  return 0;
}
