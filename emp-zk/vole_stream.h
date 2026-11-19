#ifndef EMP_ZK_VOLE_STREAM_H__
#define EMP_ZK_VOLE_STREAM_H__
// The correlation sources emp-zk takes from vole-labs/vole, shaped for the
// engines' buffers:
//   FpVoleStream  — random VOLE over F_p (p = 2^61 - 1) as AuthValueFp
//                   (the arithmetic engine, edabits, polynomial proofs);
//   F2kVoleStream — random VOLE over GF(2^128) as AuthValueF2k, keyed with the
//                   Boolean engine's Delta (f2k wires, RAM-ZK).
// Boolean COTs stay on emp-ot's SilentFerret, which arrives through vole's own
// emp-ot submodule.
//
// Roles: vole's ALICE holds Delta and the keys, emp-zk's verifier is BOB, so
// every vole object is constructed with `3 - party`. The verifier's outputs
// are keys, stored in the .mac lane with .val = 0, matching what the engines
// already assume for their AuthValue-shaped keys.
#include <emp-tool/emp-tool.h>
#include "vole/vole_f2k.h"
#include "emp-ot/emp-ot.h"
#include "emp-zk/emp-zk-bool/bool_io.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <memory>
#include <string>
#include <vector>

namespace emp {

// vole's MPFSS expansion sends each worker thread's trees on its own channel
// (ios[t]). Open `threads - 1` extra TCP connections for the extra workers,
// symmetrically on both parties at construction, with NetIO::make_sibling:
// the server accepts on the primary's listener (kept open and shared by the
// siblings) and the client reconnects to the same port. When the primary is
// not a NetIO (TLS, a custom channel) vole runs on one worker. Sibling
// traffic is vole's own OT-extension / MPFSS data; the emp-zk transcript
// digest lives on the primary channel, as it does for the background sVOLE
// socket.
struct VoleChannels {
  std::vector<std::unique_ptr<NetIO>> siblings;
  std::vector<IOChannel *> ios;
  int threads = 1;

  VoleChannels(IOChannel *primary, int want) {
    threads = want < 1 ? 1 : want;
    // Everything queued on the primary (e.g. the engine's staged gate bits)
    // must reach the peer before either side blocks in vole's handshakes
    // (sibling accept/connect, base OT); the peer may still be consuming it.
    primary->flush();
    ios.push_back(primary);
    IOChannel *inner = primary;
    if (auto *b = dynamic_cast<BoolIO *>(primary)) inner = b->io;
    auto *net = dynamic_cast<NetIO *>(inner);
    if (net == nullptr) { threads = 1; return; }
    for (int t = 1; t < threads; ++t) {
      // Another connection to the same peer: the server accepts on the
      // primary's listener, the client reconnects to the same port.
      siblings.emplace_back(net->make_sibling());
      ios.push_back(siblings.back().get());
    }
  }
};

class FpVoleStream {
public:
  using Src = RVole<IOChannel, FP61, FP61x2>;
  int party;
  VoleChannels ch;
  Src *src = nullptr;

  // `delta` is the verifier's (BOB's) F_p Delta; ignored on the prover.
  FpVoleStream(int party, IOChannel *io, int threads, uint64_t delta)
      : party(party), ch(io, threads) {
    src = new Src(3 - party, (std::size_t)ch.threads, ch.ios.data());
    if (party == BOB) src->setup(FP61(delta, false));
    else              src->setup();
  }
  ~FpVoleStream() { delete src; }

  // Usable correlations per vole extension round.
  int64_t round_size() const { return (int64_t)src->ot_limit(); }

  // Fill `n` fresh correlations. FP61x2 packs (MAC low, value high); AuthValueFp
  // is val-first, so the lanes are split into the struct fields. Bulk callers
  // pass millions; single draws must stay cheap, hence raw scratch (no
  // per-element construction).
  void next_n(AuthValueFp *out, int64_t n) {
    static_assert(sizeof(FP61x2) == 16 && sizeof(FP61) == 8, "vole field layouts");
    const int64_t CH = 2048;
    if (party == ALICE) {
      alignas(16) unsigned char raw[CH * sizeof(FP61x2)];
      FP61x2 *buf = reinterpret_cast<FP61x2 *>(raw);
      for (int64_t done = 0; done < n; done += CH) {
        const int64_t m = std::min(CH, n - done);
        src->rvole_recv(buf, (std::size_t)m);
        for (int64_t i = 0; i < m; ++i) {
          out[done + i].val = (uint64_t)_mm_extract_epi64(buf[i].val, 1);
          out[done + i].mac = (uint64_t)_mm_extract_epi64(buf[i].val, 0);
        }
      }
    } else {
      uint64_t raw[CH];
      FP61 *buf = reinterpret_cast<FP61 *>(raw);
      for (int64_t done = 0; done < n; done += CH) {
        const int64_t m = std::min(CH, n - done);
        src->rvole_send(buf, (std::size_t)m);
        for (int64_t i = 0; i < m; ++i) {
          out[done + i].val = 0;
          out[done + i].mac = raw[i];
        }
      }
    }
  }
};

// Authenticated value over any vole field FP: the prover holds (x, M), the
// verifier (0, K), with M = K + x * Delta. Used by the field-generic
// arithmetic engine (emp-zk-arith/generic/); the FP61 engine keeps its packed
// __uint128_t labels (FpVoleStream above).
template <class FP>
struct AuthF {
  FP val;
  FP mac;
};

// Random VOLE over any vole field (RVole<FP, FPS>) as AuthF<FP>. vole's
// value||MAC bundle FPS carries the MAC in its low lane and the value in its
// high lane (getLow / getHigh).
template <class FP, class FPS>
class FieldVoleStream {
public:
  using Src = RVole<IOChannel, FP, FPS>;
  int party;
  VoleChannels ch;
  Src *src = nullptr;
  std::vector<FPS> vm_;
  std::vector<FP> key_;
  static constexpr int64_t CH = 4096;

  // `delta` is the verifier's (BOB's) Delta; ignored on the prover.
  FieldVoleStream(int party, IOChannel *io, int threads, const FP &delta)
      : party(party), ch(io, threads) {
    src = new Src(3 - party, (std::size_t)ch.threads, ch.ios.data());
    if (party == BOB) src->setup(delta);
    else              src->setup();
  }
  ~FieldVoleStream() { delete src; }

  int64_t round_size() const { return (int64_t)src->ot_limit(); }

  void next_n(AuthF<FP> *out, int64_t n) {
    if (party == ALICE) {
      if ((int64_t)vm_.size() < CH) vm_.resize(CH);
      for (int64_t done = 0; done < n; done += CH) {
        const int64_t m = std::min(CH, n - done);
        src->rvole_recv(vm_.data(), (std::size_t)m);
        for (int64_t i = 0; i < m; ++i)
          out[done + i] = AuthF<FP>{vm_[i].getHigh(), vm_[i].getLow()};
      }
    } else {
      if ((int64_t)key_.size() < CH) key_.resize(CH);
      for (int64_t done = 0; done < n; done += CH) {
        const int64_t m = std::min(CH, n - done);
        src->rvole_send(key_.data(), (std::size_t)m);
        for (int64_t i = 0; i < m; ++i) out[done + i] = AuthF<FP>{FP(), key_[i]};
      }
    }
  }
};

class F2kVoleStream {
public:
  using Src = F2kVole<IOChannel>;
  int party;
  VoleChannels ch;
  Src *src = nullptr;
  std::vector<block> tv_, tm_;

  // `delta` is the Boolean engine's Delta on the verifier; ignored on the prover.
  F2kVoleStream(int party, IOChannel *io, int threads, block delta)
      : party(party), ch(io, threads) {
    src = new Src(3 - party, (std::size_t)ch.threads, ch.ios.data());
    if (party == BOB) src->setup(delta);
    else              src->setup();
  }
  ~F2kVoleStream() { delete src; }

  int64_t round_size() const { return (int64_t)src->ot_limit(); }

  void run(AuthValueF2k *out, int64_t n) {
    const int64_t CH = 4096;
    if ((int64_t)tm_.size() < CH) { tv_.resize(CH); tm_.resize(CH); }
    for (int64_t done = 0; done < n; done += CH) {
      const int64_t m = std::min(CH, n - done);
      if (party == ALICE) {
        src->rvole(tv_.data(), tm_.data(), (std::size_t)m);
        for (int64_t i = 0; i < m; ++i) out[done + i] = AuthValueF2k{tv_[i], tm_[i]};
      } else {
        src->rvole(tm_.data(), (std::size_t)m);
        for (int64_t i = 0; i < m; ++i) out[done + i] = AuthValueF2k{zero_block, tm_[i]};
      }
    }
  }
};

}  // namespace emp
#endif
