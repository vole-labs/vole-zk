// Bursty background-sVOLE stress test — the repro from problem.txt.
// A long proof over the background path (two sockets) issuing large, bursty
// feed() calls interleaved with inner-product checks, with a deliberate
// per-iteration timing skew on ALICE to force the two parties' consumers out of
// step. With the old small-ring producer this DEADLOCKS (consumer in draw_vole_,
// producer mid-rollover in recv_data); with the round-sized double buffer it
// must run to completion.
//
//   ./run ./build/test_arith_bg_stress [ITERS] [LOG2_FEED]   (ports P, P+1)
#include "emp-tool/emp-tool.h"
#include <emp-zk/emp-zk.h>
#include "emp-zk/emp-zk-arith/emp-zk-arith.h"
#include <chrono>
#include <iostream>
#include <thread>
#include <vector>
using namespace emp;
using namespace std;

int party;

void test_stress(BoolIO *io, BoolIO *vole_io, int party, int iters,
                 int64_t sz) {
  setup_zk_arith(io, party, /*threads=*/4, /*expected_vole=*/0, vole_io);

  block seed = makeBlock(0x57, 0x1234);
  PRG prg(&seed);
  vector<uint64_t> w(2 * sz);
  vector<IntFp> x(2 * sz);

  auto start = clock_start();
  for (int it = 0; it < iters; ++it) {
    prg.random_data_unaligned(w.data(), 2 * sz * sizeof(uint64_t));
    for (int64_t i = 0; i < 2 * sz; ++i) w[i] %= PR;

    // one big bursty commitment (2*sz values → 2*sz draws from the pipe)
    batch_feed(x.data(), w.data(), 2 * sz);

    // an inner-product check over the just-committed witnesses
    uint64_t s = 0;
    for (int64_t i = 0; i < sz; ++i) s = add_mod(s, mult_mod(w[i], w[sz + i]));
    fp_zkp_inner_prdt(x.data(), x.data() + sz, PR - s, sz);

    // deliberate drift: ALICE lags a few ms every 5th iteration
    if (party == ALICE && (it % 5 == 0))
      std::this_thread::sleep_for(std::chrono::milliseconds(3));
    if (it % 20 == 0)
      cout << "  iter " << it << " (party " << party << ")" << endl;
  }
  finalize_zk_arith();
  cout << "bg_stress party " << party << ": " << iters << " iters x " << (2 * sz)
       << " feed  " << time_from(start) / 1000.0
       << " ms  COMPLETED (no deadlock)" << endl;
}

int main(int argc, char **argv) {
  party = parse_party(argv);
  const int iters = (argc > 2) ? atoi(argv[2]) : 40;
  const int64_t sz = int64_t{1} << ((argc > 3) ? atoi(argv[3]) : 19);  // 2*sz per feed
  const int p = peer_port();

  auto nio = (party == ALICE) ? NetIO::listen(p) : NetIO::connect(peer_ip(), p);
  auto vio = (party == ALICE) ? NetIO::listen(p + 1)
                              : NetIO::connect(peer_ip(), p + 1);
  BoolIO io(nio.get(), party == ALICE);
  BoolIO vole_io(vio.get(), party == ALICE);

  cout << endl << "----- background-sVOLE bursty stress (two sockets) -----" << endl;
  test_stress(&io, &vole_io, party, iters, sz);
  return 0;
}
