// Background-sVOLE arith proof over TWO sockets: the sVOLE runs on `vole_io`
// (socket A) in a producer thread; the engine consumes correlations via the
// pipe while its own traffic (inputs, reveals, gate check) uses `io` (socket B).
// Verifies a batch of committed multiplications end-to-end (the malicious
// AND-gate check + reveal_check must pass with no abort).
//
//   ./run ./build/test_arith_bg_ostriple [LOG2_N] [THREADS]   (ports P, P+1)
#include "emp-tool/emp-tool.h"
#include <emp-zk/emp-zk.h>
#include "emp-zk/emp-zk-arith/emp-zk-arith.h"
#include <iostream>
#include <vector>
using namespace emp;
using namespace std;

int party;

void test_bg(BoolIO *io, BoolIO *vole_io, int party, int64_t N, int threads,
             int vole_threads) {
  // expected_vole is IGNORED in background mode (the producer streams on demand
  // and finalizes at teardown) — pass 0 to prove no size hint is required.
  // threads sizes ostriple's pool; vole_threads sizes the sVOLE's (independent).
  auto start = clock_start();
  setup_zk_arith(io, party, threads, /*expected_vole=*/0, vole_io, vole_threads);
  cout << "  setup: " << time_from(start) / 1000.0 << " ms  (party " << party
       << ")" << endl;

  // Fixed-seed inputs so both parties share the oracle.
  block seed = makeBlock(0x0abcdef, 0x1234567);
  PRG prg(&seed);
  vector<uint64_t> av(N), bv(N), exp_prod(N);
  prg.random_data_unaligned(av.data(), N * sizeof(uint64_t));
  prg.random_data_unaligned(bv.data(), N * sizeof(uint64_t));
  for (int64_t i = 0; i < N; ++i) {
    av[i] %= PR;
    bv[i] %= PR;
    exp_prod[i] = mult_mod(av[i], bv[i]);
  }

  start = clock_start();
  vector<IntFp> a(N), b(N), c(N);
  for (int64_t i = 0; i < N; ++i) {
    a[i] = IntFp(av[i], ALICE);
    b[i] = IntFp(bv[i], ALICE);
  }
  for (int64_t i = 0; i < N; ++i) c[i] = a[i] * b[i];   // multiplication gates
  batch_reveal_check(c.data(), exp_prod.data(), N);     // verifies products + MAC
  double proof_ms = time_from(start) / 1000.0;

  finalize_zk_arith();
  cout << "bg_ostriple party " << party << ": N=" << N << " threads=" << threads
       << "  proof " << proof_ms << " ms  PASS" << endl;
}

int main(int argc, char **argv) {
  party = parse_party(argv);
  const int64_t N = int64_t{1} << ((argc > 2) ? atoi(argv[2]) : 16);
  const int threads = (argc > 3) ? std::max(1, atoi(argv[3])) : 1;
  const int vole_threads = (argc > 4) ? atoi(argv[4]) : -1;   // -1 = same as threads
  const int p = peer_port();

  // TWO connections: main (P) and the dedicated sVOLE socket (P+1).
  auto nio = (party == ALICE) ? NetIO::listen(p) : NetIO::connect(peer_ip(), p);
  auto vio = (party == ALICE) ? NetIO::listen(p + 1)
                              : NetIO::connect(peer_ip(), p + 1);
  BoolIO io(nio.get(), party == ALICE);
  BoolIO vole_io(vio.get(), party == ALICE);

  cout << endl << "----- background-sVOLE arith proof (two sockets) -----" << endl;
  test_bg(&io, &vole_io, party, N, threads, vole_threads);
  return 0;
}
