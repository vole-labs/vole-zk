#include "emp-tool/emp-tool.h"
#include <emp-zk/emp-zk.h>
#include "emp-zk/emp-zk-arith/emp-zk-arith.h"
#include <iostream>
#include <vector>
using namespace emp;
using namespace std;

int party;

// Exercises IntFpVec: batched commitment + the vectorized (batched + threaded)
// multiply that routes through ZKFpExec::mul_gate(out,a,b,len) ->
// auth_compute_mul_send/recv. Inputs use a FIXED seed so both parties hold the
// same correctness oracle (reveal_check compares against the public expected).
void test_int_fp_vec(BoolIO *io, int party, int64_t len, int threads) {
  setup_zk_arith(io, party, threads);

  // Same pseudo-random inputs on both sides (correctness oracle).
  block seed = makeBlock(0x1234567, 0x89abcdef);
  PRG prg(&seed);
  std::vector<uint64_t> av(len), bv(len), exp_mul(len), exp_add(len), exp_sub(len);
  prg.random_data_unaligned(av.data(), len * sizeof(uint64_t));
  prg.random_data_unaligned(bv.data(), len * sizeof(uint64_t));
  for (int64_t i = 0; i < len; ++i) {
    av[i] %= PR;
    bv[i] %= PR;
    exp_mul[i] = mult_mod(av[i], bv[i]);
    exp_add[i] = add_mod(av[i], bv[i]);
    exp_sub[i] = add_mod(av[i], PR - bv[i]);   // a - b mod p
  }

  auto start = clock_start();
  IntFpVec a(av.data(), len, ALICE);   // batched commit (prover owns; verifier ignores vals)
  IntFpVec b(bv.data(), len, ALICE);

  IntFpVec cprod = a * b;              // ONE batched + threaded auth_compute_mul
  double mul_ms = time_from(start) / 1000.0;
  IntFpVec csum = a + b;               // element-wise local add
  IntFpVec cdiff = a - b;              // element-wise local subtract

  cprod.reveal_check(exp_mul.data());  // verifies products under the MAC
  csum.reveal_check(exp_add.data());   // verifies sums
  cdiff.reveal_check(exp_sub.data());  // verifies differences

  // problem.txt repro: feed an operator+(uint64) result INTO a multiply (this is
  // the pattern that report claims corrupts the MAC and fails the mul-gate check
  // at teardown). chk = (a + k0) * b ; expect (av+k0)*bv mod p.
  const uint64_t k0 = 4242424242ULL;
  std::vector<uint64_t> exp_pk(len);
  for (int64_t i = 0; i < len; ++i)
    exp_pk[i] = mult_mod(add_mod(av[i], k0), bv[i]);
  IntFpVec chk = (a + k0) * b;
  chk.reveal_check(exp_pk.data());     // value + MAC; teardown runs the mul-gate check

  // Public F_p constant ops. Broadcast a scalar constant k, and element-wise a
  // constant vector (= bv, so the results reuse exp_add / exp_sub / exp_mul).
  const uint64_t k = 7777777ULL;
  std::vector<uint64_t> exp_addk(len), exp_subk(len), exp_mulk(len);
  for (int64_t i = 0; i < len; ++i) {
    exp_addk[i] = add_mod(av[i], k);
    exp_subk[i] = add_mod(av[i], PR - k);
    exp_mulk[i] = mult_mod(av[i], k);
  }
  bool pub_ok = true;
  pub_ok &= (a + k).reveal_check(exp_addk.data());   // broadcast +
  pub_ok &= (a - k).reveal_check(exp_subk.data());   // broadcast -
  pub_ok &= (a * k).reveal_check(exp_mulk.data());   // broadcast *
  pub_ok &= (a + bv).reveal_check(exp_add.data());   // element-wise +
  pub_ok &= (a - bv).reveal_check(exp_sub.data());   // element-wise -
  pub_ok &= (a * bv).reveal_check(exp_mul.data());   // element-wise *
  // scalar IntFp public-constant ops
  IntFp xk(av[1], ALICE);
  pub_ok &= (xk + k).reveal(add_mod(av[1], k));
  pub_ok &= (xk - k).reveal(add_mod(av[1], PR - k));
  pub_ok &= (xk * k).reveal(mult_mod(av[1], k));

  // Spot-check operator[] yields the matching scalar IntFp.
  bool spot = cprod[len / 2].reveal(exp_mul[len / 2]);

  // sum(): fold all committed elements into one IntFp = Sum(av) mod p.
  uint64_t exp_sum = 0;
  for (int64_t i = 0; i < len; ++i) exp_sum = add_mod(exp_sum, av[i]);
  bool sum_ok = a.sum().reveal(exp_sum);

  // Direct scalar IntFp::operator- correctness (both parties): a few
  // committed pairs, subtract, and reveal_check against a - b mod p.
  bool scalar_sub_ok = true;
  for (int64_t i = 0; i < 8 && i < len; ++i) {
    IntFp x(av[i], ALICE);
    IntFp y(bv[i], ALICE);
    IntFp z = x - y;                       // scalar sub_gate
    scalar_sub_ok &= z.reveal(exp_sub[i]); // aborts on a bad MAC; checks value
  }

  // Decompose the committed vector into `len` individual IntFp and confirm
  // each is a standalone valid commitment (reveals to the original value).
  std::vector<IntFp> a_elems = a.decompose();
  bool decomp_ok = ((int64_t)a_elems.size() == len);
  for (int64_t i = 0; i < 8 && i < len; ++i)
    decomp_ok &= a_elems[i].reveal(av[i]);

  // Compose round-trip: decompose b into IntFp, recompose into an IntFpVec,
  // and confirm the rebuilt batch still reveals to the original bv.
  std::vector<IntFp> b_elems = b.decompose();
  IntFpVec b2 = IntFpVec::compose(b_elems);
  bool compose_ok = ((int64_t)b2.size() == len) && b2.reveal_check(bv.data());

  // negate(): -av mod p.
  std::vector<uint64_t> exp_neg(len);
  for (int64_t i = 0; i < len; ++i) exp_neg[i] = (av[i] == 0) ? 0 : (PR - av[i]);
  bool neg_ok = a.negate().reveal_check(exp_neg.data());

  // Zero-copy subspan [W, W+T): multiply and sum a sub-range with no copy.
  const int64_t W = len / 4, T = len / 2;
  IntFpVec sub_prod = a.subspan(W, T) * b.subspan(W, T);   // a_i*b_i over [W,W+T)
  bool span_ok = sub_prod.reveal_check(exp_mul.data() + W);
  uint64_t exp_subsum = 0;
  for (int64_t i = W; i < W + T; ++i) exp_subsum = add_mod(exp_subsum, av[i]);
  span_ok &= a.subspan(W, T).sum().reveal(exp_subsum);
  // span +, -, public-const, and in-place negate over [W, W+T).
  span_ok &= (a.subspan(W, T) + b.subspan(W, T)).reveal_check(exp_add.data() + W);
  span_ok &= (a.subspan(W, T) - b.subspan(W, T)).reveal_check(exp_sub.data() + W);
  span_ok &= (a.subspan(W, T) + k).reveal_check(exp_addk.data() + W);
  IntFpVec acopy = a;                       // independent copy of the labels
  acopy.subspan(W, T).negate();             // negate [W, W+T) in place
  std::vector<uint64_t> exp_acopy(len);
  for (int64_t i = 0; i < len; ++i)
    exp_acopy[i] = (i >= W && i < W + T) ? exp_neg[i] : av[i];
  span_ok &= acopy.reveal_check(exp_acopy.data());
  // scalar IntFp::negate() method.
  span_ok &= IntFp(av[3], ALICE).negate().reveal(exp_neg[3]);

  // Batched cleartext VAL extract (ALICE-side reference reconstruction).
  bool values_ok = true;
  if (party == ALICE) {
    std::vector<uint64_t> got = a.values();
    values_ok = ((int64_t)got.size() == len) &&
                (memcmp(got.data(), av.data(), len * sizeof(uint64_t)) == 0);
    // and over a subspan
    std::vector<uint64_t> gsub = a.subspan(W, T).values();
    values_ok &= (memcmp(gsub.data(), av.data() + W, T * sizeof(uint64_t)) == 0);
  }

  finalize_zk_arith();
  cout << "IntFpVec len=" << len << " threads=" << threads
       << " : mul+commit " << mul_ms << " ms, party " << party
       << ((spot && scalar_sub_ok && decomp_ok && compose_ok && pub_ok &&
            sum_ok && neg_ok && span_ok && values_ok)
               ? "  PASS"
               : "  FAIL")
       << endl;
}

int main(int argc, char **argv) {
  party = parse_party(argv);
  auto netio = (party == ALICE) ? NetIO::listen(peer_port())
                                : NetIO::connect(peer_ip(), peer_port());
  BoolIO io(netio.get(), party == ALICE);

  int64_t len = (argc > 2) ? (int64_t{1} << atoi(argv[2])) : (int64_t{1} << 20);
  int threads = (argc > 3) ? std::max(1, atoi(argv[3])) : 1;

  std::cout << std::endl
            << "------------ IntFpVec (vectorized commitment) test ------------"
            << std::endl;
  test_int_fp_vec(&io, party, len, threads);
  return 0;
}
