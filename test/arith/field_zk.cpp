// Field-generic arithmetic ZK (emp-zk-arith/generic/) over vole's fields.
//
// usage: test_arith_field_zk <party> <field> [mode] [log2 N] [threads]
//   field: fp61g (generic engine on FP61) | fp107 | p192 | f2k (GF(2^128))
//   mode:  honest (default)  circuit + vector ops + polynomial proofs + opening
//          bg                honest, VOLE on a second socket (background producer)
//          delta             honest, verifier supplies its own Delta
//          cheat_mul         prover uses a wrong value in a multiplication
//          cheat_reveal      prover opens a wrong value with the honest MAC
//          cheat_poly        prover proves a false inner-product statement
//          cheat_deg2        prover proves a false degree-2 polynomial statement
//   In the cheat modes the verifier must abort (exit code != 0).
//
// The honest run lowers the multiplication-check batch (default_check_sz) so
// every scalar and vectorized multiply crosses many check/refill boundaries.
#include "emp-tool/emp-tool.h"
#include <emp-zk/emp-zk.h>
#include <iostream>
#include <string>
#include <vector>
using namespace emp;
using namespace std;

template <class FP, class FPS>
void run(BoolIO *io, BoolIO *vole_io, int party, const string &tag, const string &mode,
         int64_t N, int threads) {
  using I = IntFpG<FP, FPS>;
  using V = IntFpVecG<FP, FPS>;
  FieldOSTriple<FP, FPS>::default_check_sz = 1000;

  FP my_delta;
  const FP *dptr = nullptr;
  if (mode == "delta") { my_delta = FP(0x1234567ULL) * FP(0x89abcdefULL) + FP(3); dptr = &my_delta; }
  setup_zk_arith_generic<FP, FPS>(io, party, threads, mode == "bg" ? vole_io : nullptr, -1,
                                  party == BOB ? dptr : nullptr);
  auto *ex = ZKFieldExec<FP, FPS>::zk_exec;
  if (mode == "delta" && party == BOB && ex->delta != my_delta) error("delta not installed");

  // Shared deterministic test data (both parties derive the expected outputs).
  block seed = makeBlock(0x5eed, 0xf1e1d);
  PRG prg(&seed);
  auto rnd = [&]() { FP x; x.rand(prg); return x; };

  // 1) scalar circuit: b = b + a; a = b * a, plus every gate type
  FP ar = rnd(), br = rnd(), cr = rnd();
  I a(ar, ALICE), b(br, ALICE), c(cr, PUBLIC);
  for (int64_t i = 0; i < N; ++i) {
    br = br + ar; ar = br * ar;
    b = b + a; a = b * a;
  }
  if (mode == "cheat_mul") {
    // a product of a value the prover does not hold a MAC for; never opened,
    // so only the batched multiplication check can catch it
    I t = a;
    if (party == ALICE) t.value.val = t.value.val + FP(1);
    I u = t * b;
    (void)u;
  }
  FP er = ar * br + cr * FP(7ULL) - br.negate() + FP(5ULL) - ar;
  I e = a * b + c * FP(7ULL) - b.negate() + FP(5ULL) - a;
  e.reveal(er);
  FP got = a.reveal();
  if (got != ar) error("scalar reveal value mismatch");
  (a - a).reveal_zero();

  // 2) vector ops (vectorized multiply crosses the check boundary N/1000 times)
  vector<FP> xv(N), yv(N), cv(N), zv(N);
  for (int64_t i = 0; i < N; ++i) { xv[i] = rnd(); yv[i] = rnd(); cv[i] = rnd(); }
  V x(xv.data(), N, ALICE), y(yv.data(), N, ALICE);
  FP k = rnd();
  V z = x * y + x * k - y + cv - (x * cv).negate();
  FP zsum;
  for (int64_t i = 0; i < N; ++i) {
    zv[i] = xv[i] * yv[i] + xv[i] * k - yv[i] + cv[i] - (xv[i] * cv[i]).negate();
    zsum = zsum + zv[i];
  }
  if (mode == "cheat_reveal" && party == ALICE) z.value[N / 2].val = z.value[N / 2].val + FP(1);
  if (mode == "cheat_reveal") {
    vector<FP> opened(N);
    z.reveal(opened.data());  // MAC check catches it at finalize
  } else {
    z.reveal_check(zv.data());
    z.sum().reveal(zsum);
    vector<I> parts = z.decompose();
    V::compose(parts).reveal_check(zv.data());
  }

  // 3) batch helpers on scalars
  vector<I> s(N);
  vector<FP> sv(N), sopen(N);
  for (int64_t i = 0; i < N; ++i) sv[i] = rnd();
  batch_feed(s.data(), sv.data(), N);
  batch_reveal(s.data(), sopen.data(), N);
  for (int64_t i = 0; i < N; ++i) if (sopen[i] != sv[i]) error("batch_reveal mismatch");

  // 4) polynomial proofs: c + sum x_i y_i = 0 and coeff0 + sum coeff_{i+1} x_i y_i = 0
  FP ip;
  for (int64_t i = 0; i < N; ++i) ip = ip + xv[i] * yv[i];
  vector<I> xs = x.decompose(), ys = y.decompose();
  FP cst = ip.negate();
  if (mode == "cheat_poly") cst = cst + FP(1);
  fp_zkp_inner_prdt(xs.data(), ys.data(), cst, N);
  vector<FP> coeff(N + 1);
  FP acc;
  for (int64_t i = 0; i < N; ++i) { coeff[i + 1] = rnd(); acc = acc + coeff[i + 1] * xv[i] * yv[i]; }
  coeff[0] = acc.negate();
  if (mode == "cheat_deg2") coeff[0] = coeff[0] + FP(1);
  fp_zkp_poly_deg2(xs.data(), ys.data(), coeff.data(), N);

  // 5) MAC relation M = K + x*Delta on fresh labels (debug channel)
  ex->ostriple->check_auth_mac(&z.value[0], std::min<int64_t>(N, 64));

  finalize_zk_arith_generic<FP, FPS>();
  cout << "[" << tag << " " << mode << "] party " << party << " N=" << N
       << " threads=" << threads << " PASS" << endl;
}

int main(int argc, char **argv) {
  int party = parse_party(argv);
  string field = argc > 2 ? argv[2] : "p192";
  string mode = argc > 3 ? argv[3] : "honest";
  int64_t N = int64_t{1} << (argc > 4 ? atoi(argv[4]) : 14);
  int threads = argc > 5 ? std::max(1, atoi(argv[5])) : 2;
  const int p = peer_port();
  auto nio = (party == ALICE) ? NetIO::listen(p) : NetIO::connect(peer_ip(), p);
  BoolIO io(nio.get(), party == ALICE);
  std::unique_ptr<NetIO> vio;
  std::unique_ptr<BoolIO> vole_io;
  if (mode == "bg") {
    vio = (party == ALICE) ? NetIO::listen(p + 1) : NetIO::connect(peer_ip(), p + 1);
    vole_io = std::make_unique<BoolIO>(vio.get(), party == ALICE);
  }
  if (field == "fp61g")      run<FP61, FP61x2>(&io, vole_io.get(), party, field, mode, N, threads);
  else if (field == "fp107") run<FP107, FP107x2>(&io, vole_io.get(), party, field, mode, N, threads);
  else if (field == "p192")  run<FP192, FP192x2>(&io, vole_io.get(), party, field, mode, N, threads);
  else if (field == "f2k")   run<FP2x128, FP2x128x2>(&io, vole_io.get(), party, field, mode, N, threads);
  else error("unknown field: fp61g | fp107 | p192 | f2k");
  return 0;
}
