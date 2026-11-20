// Engine selection and engine interplay for the field-generic arithmetic API.
//
//  1) IntFpT / IntFpVecT / setup_zk_arith<FP, FPS> pick the tuned FP61 engine
//     (IntFp) for <FP61, FP61x2> and the generic engine for every other field;
//     the same template circuit runs on both and opens the expected values.
//  2) GF(2^128) with the Boolean engine's Delta: the verifier hands the
//     ZKBoolSession's Delta to setup_zk_arith<FP2x128, FP2x128x2>, so a value
//     committed in the Boolean engine (f2k_input) and the same value committed
//     in the arithmetic engine carry MACs under one Delta. The prover then
//     shows they are equal by sending M_bool ^ M_arith, which the verifier
//     compares with K_bool ^ K_arith (the v*Delta terms cancel). With a
//     different value the check must fail (mode "cheat_link").
//
// usage: test_arith_field_select <party> [honest | cheat_link]
#include "emp-tool/emp-tool.h"
#include <emp-zk/emp-zk.h>
#include <cstring>
#include <iostream>
#include <string>
#include <type_traits>
using namespace emp;
using namespace std;

static_assert(std::is_same_v<IntFpT<FP61, FP61x2>, IntFp>, "FP61 -> tuned engine");
static_assert(std::is_same_v<IntFpVecT<FP61, FP61x2>, IntFpVec>, "FP61 -> tuned engine");
static_assert(std::is_same_v<IntFpT<FP192, FP192x2>, IntFpG<FP192, FP192x2>>, "p192 -> generic");
static_assert(std::is_same_v<IntFpT<FP25519, FP25519x2>, IntFpG<FP25519, FP25519x2>>, "p25519 -> generic");
static_assert(std::is_same_v<IntFpT<FPP256, FPP256x2>, IntFpG<FPP256, FPP256x2>>, "p256 -> generic");
static_assert(std::is_same_v<IntFpT<FP107, FP107x2>, IntFpG<FP107, FP107x2>>, "fp107 -> generic");
static_assert(std::is_same_v<IntFpT<FP2x128, FP2x128x2>, IntFpG<FP2x128, FP2x128x2>>, "f2k -> generic");

template <class FP, class FPS>
void run_circuit(BoolIO *io, int party, const char *tag) {
  using I = IntFpT<FP, FPS>;
  setup_zk_arith<FP, FPS>(io, party, 2);
  const bool fast = uses_fp61_engine<FP, FPS>;
  if (fast != (ZKFpExec::zk_exec != nullptr) || fast == (ZKFieldExec<FP, FPS>::zk_exec != nullptr))
    error("wrong engine selected");
  I a(3ULL, ALICE), b(5ULL, ALICE), c(11ULL, PUBLIC);
  I d = a * b + c * 2ULL - a;
  // expected values in the field itself (GF(2^128): + is XOR, * carry-less)
  FP e = FP(uint64_t{3}) * FP(uint64_t{5}) + FP(uint64_t{11}) * FP(uint64_t{2}) - FP(uint64_t{3});
  FP e2 = e * e;
  if constexpr (uses_fp61_engine<FP, FPS>) {
    d.reveal((uint64_t)e.val);
    (d * d).reveal((uint64_t)e2.val);
  } else {
    d.reveal(e);
    (d * d).reveal(e2);
  }
  finalize_zk_arith<FP, FPS>();
  cout << "[" << tag << "] " << (fast ? "FP61 engine" : "generic engine") << " PASS" << endl;
}

static block to_blk(const FP2x128 &x) {
  block b;
  memcpy(&b, &x.val, sizeof(block));
  return b;
}

void link_f2k(BoolIO *io, int party, bool cheat) {
  using F = FP2x128;
  ZKBoolSession sess(io, party);
  block bd = sess.engine().delta;  // verifier's Delta (prover: unused)
  F fd;
  fd.from_block(bd);
  setup_zk_arith<F, FP2x128x2>(io, party, 1, nullptr, -1, party == BOB ? &fd : nullptr);
  if (party == BOB && ZKFieldExec<F, FP2x128x2>::zk_exec->delta != fd) error("Delta not shared");

  block v = makeBlock(0x0123456789abcdefULL, 0xfedcba9876543210ULL);
  F2kAuthValue wb = sess.engine().f2k_input(v);
  F fv;
  fv.from_block(cheat ? (v ^ makeBlock(0, 1)) : v);
  IntFpG<F, FP2x128x2> wa(fv, ALICE);

  block diff = wb.mac ^ to_blk(wa.value.mac);
  if (party == ALICE) {
    io->send_data(&diff, sizeof(block));
    io->flush();
  } else {
    block got;
    io->recv_data(&got, sizeof(block));
    if (!cmpBlock(&got, &diff, 1)) error("cross-engine equality check fails");
  }
  finalize_zk_arith<F, FP2x128x2>();
  sess.finalize();
  cout << "[f2k] Boolean-engine Delta shared, cross-engine equality PASS" << endl;
}

int main(int argc, char **argv) {
  int party = parse_party(argv);
  string mode = argc > 2 ? argv[2] : "honest";
  const int p = peer_port();
  auto nio = (party == ALICE) ? NetIO::listen(p) : NetIO::connect(peer_ip(), p);
  BoolIO io(nio.get(), party == ALICE);
  if (mode == "honest") {
    run_circuit<FP61, FP61x2>(&io, party, "fp61");
    run_circuit<FP107, FP107x2>(&io, party, "fp107");
    run_circuit<FP192, FP192x2>(&io, party, "p192");
    run_circuit<FP25519, FP25519x2>(&io, party, "p25519");
    run_circuit<FPP256, FPP256x2>(&io, party, "p256");
    run_circuit<FP2x128, FP2x128x2>(&io, party, "f2k");
  }
  link_f2k(&io, party, mode == "cheat_link");
  return 0;
}
