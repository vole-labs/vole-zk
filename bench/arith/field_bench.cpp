// Throughput of the arithmetic ZK engines per field.
//
// usage: bench_arith_field <party> <field> [log2 N] [threads]
//   field: fp61  (tuned FP61 engine, IntFp)
//          fp61g (generic engine on FP61) | fp107 | p192 | f2k (generic engine)
// Phases (N elements each; times in ms on this party, bytes = primary socket
// sent + received during the phase):
//   setup   engine setup, incl. the first VOLE batch
//   input   one batched feed of N committed values
//   vecmul  N independent products (vectorized multiply)
//   scalar  N/4 rounds of b = b + a; a = b * a (one gate at a time)
//   ip      inner-product proof of length N
//   final   teardown: the last multiplication check and the opening checks
#include "emp-tool/emp-tool.h"
#include <emp-zk/emp-zk.h>
#include <cstdio>
#include <string>
#include <vector>
using namespace emp;
using namespace std;

struct Meter {
  NetIO *nio;
  int party;
  const char *tag;
  int64_t N;
  uint64_t b0 = 0;
  time_point<high_resolution_clock> t0;
  void start() { b0 = nio->send_counter + nio->recv_counter; t0 = clock_start(); }
  void stop(const char *phase, int64_t per) {
    double ms = time_from(t0) / 1000.0;
    uint64_t bytes = nio->send_counter + nio->recv_counter - b0;
    if (party == ALICE)
      printf("RESULT field=%s phase=%s N=%lld ms=%.1f ns_per=%.1f bytes=%llu bytes_per=%.1f\n",
             tag, phase, (long long)N, ms, per ? ms * 1e6 / per : 0.0,
             (unsigned long long)bytes, per ? (double)bytes / per : 0.0);
  }
};

void bench_fp61(BoolIO *io, Meter &m, int threads) {
  const int64_t N = m.N;
  PRG prg;
  vector<uint64_t> xv(N), yv(N);
  prg.random_data(xv.data(), N * 8);
  prg.random_data(yv.data(), N * 8);
  for (int64_t i = 0; i < N; ++i) { xv[i] %= PR; yv[i] %= PR; }
  m.start(); setup_zk_arith(io, m.party, threads); m.stop("setup", 0);
  m.start(); IntFpVec x(xv.data(), N, ALICE), y(yv.data(), N, ALICE); m.stop("input", 2 * N);
  m.start(); IntFpVec z = x * y; m.stop("vecmul", N);
  IntFp a = x[0], b = y[0];
  m.start(); for (int64_t i = 0; i < N / 4; ++i) { b = b + a; a = b * a; } m.stop("scalar", N / 4);
  uint64_t ip = 0;
  for (int64_t i = 0; i < N; ++i) ip = add_mod(ip, mult_mod(xv[i], yv[i]));
  vector<IntFp> xs = x.decompose(), ys = y.decompose();
  uint64_t cst = (PR - ip) % PR;  // public statement: the prover announces it
  if (m.party == ALICE) io->send_data(&cst, sizeof(cst)); else io->recv_data(&cst, sizeof(cst));
  m.start(); fp_zkp_inner_prdt(xs.data(), ys.data(), cst, N); m.stop("ip", N);
  (void)z;
  m.start(); finalize_zk_arith(); m.stop("final", 0);
}

template <class FP, class FPS>
void bench_generic(BoolIO *io, Meter &m, int threads) {
  const int64_t N = m.N;
  PRG prg;
  vector<FP> xv(N), yv(N);
  for (int64_t i = 0; i < N; ++i) { xv[i].rand(prg); yv[i].rand(prg); }
  m.start(); setup_zk_arith_generic<FP, FPS>(io, m.party, threads); m.stop("setup", 0);
  using V = IntFpVecG<FP, FPS>;
  m.start(); V x(xv.data(), N, ALICE), y(yv.data(), N, ALICE); m.stop("input", 2 * N);
  m.start(); V z = x * y; m.stop("vecmul", N);
  IntFpG<FP, FPS> a = x[0], b = y[0];
  m.start(); for (int64_t i = 0; i < N / 4; ++i) { b = b + a; a = b * a; } m.stop("scalar", N / 4);
  FP ip;
  for (int64_t i = 0; i < N; ++i) ip = ip + xv[i] * yv[i];
  auto xs = x.decompose(), ys = y.decompose();
  FP cst = ip.negate();  // public statement: the prover announces it
  if (m.party == ALICE) io->send_data(&cst, sizeof(cst)); else io->recv_data(&cst, sizeof(cst));
  m.start(); fp_zkp_inner_prdt(xs.data(), ys.data(), cst, N); m.stop("ip", N);
  (void)z;
  m.start(); finalize_zk_arith_generic<FP, FPS>(); m.stop("final", 0);
}

int main(int argc, char **argv) {
  setvbuf(stdout, nullptr, _IOLBF, 0);
  int party = parse_party(argv);
  string field = argc > 2 ? argv[2] : "p192";
  int64_t N = int64_t{1} << (argc > 3 ? atoi(argv[3]) : 22);
  int threads = argc > 4 ? std::max(1, atoi(argv[4])) : 4;
  const int p = peer_port();
  auto nio = (party == ALICE) ? NetIO::listen(p) : NetIO::connect(peer_ip(), p);
  BoolIO io(nio.get(), party == ALICE);
  Meter m{nio.get(), party, field.c_str(), N};
  if (field == "fp61")       bench_fp61(&io, m, threads);
  else if (field == "fp61g") bench_generic<FP61, FP61x2>(&io, m, threads);
  else if (field == "fp107") bench_generic<FP107, FP107x2>(&io, m, threads);
  else if (field == "p192")  bench_generic<FP192, FP192x2>(&io, m, threads);
  else if (field == "f2k")   bench_generic<FP2x128, FP2x128x2>(&io, m, threads);
  else error("unknown field: fp61 | fp61g | fp107 | p192 | f2k");
  return 0;
}
