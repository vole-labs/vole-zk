// Correctness when the multiplication check (AND-gate) and the inner-product
// check (FpPolyProof) COEXIST in one proof over the shared sVOLE. Interleaves
// IntFp multiplications with fp_zkp_inner_prdt so both checks' OPE draws pull
// from the same VOLE stream, then verifies products (reveal_check) and lets
// finalize run BOTH the AND-gate check and the FpPolyProof batch_check.
//
//   ./run ./build/test_arith_mixed_check [LOG2_N] [SZ]
#include "emp-tool/emp-tool.h"
#include <emp-zk/emp-zk.h>
#include "emp-zk/emp-zk-arith/emp-zk-arith.h"
#include <iostream>
#include <vector>
using namespace emp;
using namespace std;

int party;

void test_mixed(BoolIO *io, int party, int64_t N, int sz) {
  setup_zk_arith(io, party);

  // Fixed-seed shared witnesses (both parties identical → shared oracle).
  block seed = makeBlock(0x5151, 0x2626);
  PRG prg(&seed);

  // Multiplication witnesses + expected products.
  vector<uint64_t> av(N), bv(N), exp_prod(N);
  prg.random_data_unaligned(av.data(), N * sizeof(uint64_t));
  prg.random_data_unaligned(bv.data(), N * sizeof(uint64_t));
  for (int64_t i = 0; i < N; ++i) {
    av[i] %= PR; bv[i] %= PR;
    exp_prod[i] = mult_mod(av[i], bv[i]);
  }
  // Inner-product witnesses: prove Σ x_i·x_{sz+i} + constant == 0.
  vector<uint64_t> xv(2 * sz);
  prg.random_data_unaligned(xv.data(), 2 * sz * sizeof(uint64_t));
  uint64_t sum = 0;
  for (int i = 0; i < sz; ++i) {
    xv[i] %= PR; xv[sz + i] %= PR;
    sum = add_mod(sum, mult_mod(xv[i], xv[sz + i]));
  }
  uint64_t constant = PR - sum;
  if (getenv("EMP_BAD_IP")) constant = add_mod(constant, 1);   // wrong relation

  vector<IntFp> a(N), b(N), c(N);
  for (int64_t i = 0; i < N; ++i) { a[i] = IntFp(av[i], ALICE); b[i] = IntFp(bv[i], ALICE); }
  vector<IntFp> x(2 * sz);
  for (int i = 0; i < 2 * sz; ++i) x[i] = IntFp(xv[i], ALICE);

  // Interleave: mults, inner-product, more mults, inner-product again.
  for (int64_t i = 0; i < N / 2; ++i) c[i] = a[i] * b[i];
  fp_zkp_inner_prdt(x.data(), x.data() + sz, constant, sz);
  for (int64_t i = N / 2; i < N; ++i) c[i] = a[i] * b[i];
  fp_zkp_inner_prdt(x.data(), x.data() + sz, constant, sz);

  // Verify the products (value + MAC); the inner-product relation is checked
  // by FpPolyProof at finalize; the mult triples by the AND-gate check.
  batch_reveal_check(c.data(), exp_prod.data(), N);

  finalize_zk_arith();   // <- AND-gate check AND FpPolyProof batch_check run here
  cout << "mixed_check party " << party << ": N=" << N << " sz=" << sz
       << "  PASS (mult check + inner-product check coexist)" << endl;
}

int main(int argc, char **argv) {
  party = parse_party(argv);
  const int64_t N = int64_t{1} << ((argc > 2) ? atoi(argv[2]) : 14);
  const int sz = (argc > 3) ? atoi(argv[3]) : 100;
  auto netio = (party == ALICE) ? NetIO::listen(peer_port())
                                : NetIO::connect(peer_ip(), peer_port());
  BoolIO io(netio.get(), party == ALICE);

  cout << endl << "----- mult check + inner-product check coexistence -----" << endl;
  test_mixed(&io, party, N, sz);
  return 0;
}
