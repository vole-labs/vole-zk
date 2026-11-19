// Microbench for the feed() LOCAL compute (the per-element masking / key
// correction), over the background path so draw_vole_ is a fast pipe copy and
// the local loop is what's exposed. BOB (verifier) does a mult_mod per element
// and benefits most; ALICE (prover) does cheaper mod-adds.
//
//   ./run ./build/test_arith_feed_bench [THREADS] [LOG2_SZ] [ITERS]
#include "emp-tool/emp-tool.h"
#include <emp-zk/emp-zk.h>
#include "emp-zk/emp-zk-arith/emp-zk-arith.h"
#include <iostream>
#include <vector>
using namespace emp;
using namespace std;

int party;

void bench(BoolIO *io, BoolIO *vio, int party, int threads, int64_t sz,
           int iters) {
  setup_zk_arith(io, party, threads, /*expected_vole=*/0, vio);
  block seed = makeBlock(0x9, 0x9);
  PRG prg(&seed);
  vector<uint64_t> w(sz);
  vector<IntFp> x(sz);
  prg.random_data_unaligned(w.data(), sz * sizeof(uint64_t));
  for (int64_t i = 0; i < sz; ++i) w[i] %= PR;

  batch_feed(x.data(), w.data(), sz);   // warmup (prime the pipe / rounds)

  auto t = clock_start();
  for (int it = 0; it < iters; ++it) batch_feed(x.data(), w.data(), sz);
  double ms = time_from(t) / 1000.0;

  finalize_zk_arith();
  cout << "feed_bench party " << party << " threads=" << threads << ": " << iters
       << " x " << sz << " = " << ms << " ms  ("
       << (double)(iters * sz) / (ms * 1000.0) << " M/s)" << endl;
}

int main(int argc, char **argv) {
  party = parse_party(argv);
  const int threads = (argc > 2) ? std::max(1, atoi(argv[2])) : 1;
  const int64_t sz = int64_t{1} << ((argc > 3) ? atoi(argv[3]) : 20);
  const int iters = (argc > 4) ? atoi(argv[4]) : 20;
  const int p = peer_port();

  auto nio = (party == ALICE) ? NetIO::listen(p) : NetIO::connect(peer_ip(), p);
  auto vio = (party == ALICE) ? NetIO::listen(p + 1)
                              : NetIO::connect(peer_ip(), p + 1);
  BoolIO io(nio.get(), party == ALICE);
  BoolIO vole_io(vio.get(), party == ALICE);

  bench(&io, &vole_io, party, threads, sz, iters);
  return 0;
}
