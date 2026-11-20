#ifndef EMP_ZK_FIELD_OS_TRIPLE_H__
#define EMP_ZK_FIELD_OS_TRIPLE_H__

// Field-generic QuickSilver core: authenticated inputs, multiplication gates
// with the batched multiplication check, and output opening, over any field
// type from vole-labs/vole (FP61, FP107, FP192, FP25519, FPP256, FP2x128, ...). Same protocol
// and message flow as the FP61 engine (emp-zk-arith/ostriple.h), written with
// the field's operators instead of packed 64-bit arithmetic.
//
// Labels are AuthF<FP>: the prover holds (x, M), the verifier (0, K), with
// M = K + x * Delta. Every value received from the peer is reduced to its
// canonical representative before use.

#include "emp-zk/vole_stream.h"
#include "emp-zk/emp-zk-arith/correlation_pipe.h"
#include "emp-zk/emp-zk-bool/bool_io.h"
#include <algorithm>
#include <future>
#include <memory>
#include <thread>
#include <vector>

namespace emp {

// Canonical representative of an element read off the wire (the reducing
// constructor of every vole field type).
template <class FP>
inline FP field_canon(const FP &x) { return FP(x.val); }

// Independent uniform coefficients chi_i, expanded from `seed` in fixed blocks
// of 4096 by AES-PRG (keyed on seed ^ const and the block index).
template <class FP>
inline void field_coeff_gen(FP *chi, block seed, int64_t n) {
  constexpr int64_t B = 4096;
  for (int64_t b = 0; b * B < n; ++b) {
    block sb = seed ^ makeBlock(0x9e3779b97f4a7c15ULL, (uint64_t)b);
    PRG prg(&sb);
    const int64_t base = b * B;
    const int64_t m = std::min(B, n - base);
    for (int64_t j = 0; j < m; ++j) chi[base + j].rand(prg);
  }
}

// Batched zero-MAC check of opened values: both parties hash the MACs (prover)
// / the recomputed MACs (verifier) and compare digests at the end.
template <class FP>
class FieldAuthHelper {
public:
  int party;
  BoolIO *io;
  Hash hash;

  FieldAuthHelper(int party, BoolIO *io) : party(party), io(io) {}

  void store(const FP &mac) { hash.put(&mac, sizeof(FP)); }

  void flush() {
    char dig[Hash::DIGEST_SIZE];
    hash.digest(dig);
    if (party == ALICE) {
      io->send_data(dig, Hash::DIGEST_SIZE);
      io->flush();
    } else {
      char dig_recv[Hash::DIGEST_SIZE];
      io->recv_data(dig_recv, Hash::DIGEST_SIZE);
      if (memcmp(dig, dig_recv, Hash::DIGEST_SIZE) != 0)
        error("field auth_helper check mac fails");
    }
  }
};

template <class FP, class FPS>
class FieldOSTriple {
public:
  using L = AuthF<FP>;

  int party;
  BoolIO *io;
  PRG prg;
  FP delta;  // verifier only

  FieldVoleStream<FP, FPS> *vole = nullptr;
  FieldAuthHelper<FP> *auth_helper = nullptr;

  // Multiplication triples buffered for the batched check. The default batch
  // keeps each buffer at ~128 MB (8M labels for FP61, as the FP61 engine);
  // tests may lower it through default_check_sz before construction.
  static inline int64_t default_check_sz = 0;  // 0 = auto
  int64_t CHECK_SZ;
  int64_t check_cnt = 0;
  std::vector<L> out_buf, left_buf, right_buf;
  std::vector<FP> s_scratch_;

  static constexpr int64_t kFeedParMin = ((int64_t)1 << 20) - 1;
  int threads_ = 1;
  int vole_threads_ = 1;
  ThreadPool *pool_ = nullptr;

  // Background sVOLE (second socket), as in the FP61 engine.
  bool bg_ = false;
  BoolIO *bg_io_ = nullptr;
  std::unique_ptr<CorrelationPipe<L>> pipe_;
  std::thread producer_;
  int64_t bg_batch_ = 1 << 20;
  int cur_slot_ = -1;
  int64_t cur_off_ = 0;

  // `delta_in` (verifier only, optional): use this Delta instead of a fresh
  // one, e.g. to share the Boolean engine's GF(2^128) Delta.
  FieldOSTriple(int party, BoolIO *io, int threads = 1, BoolIO *vole_io = nullptr,
                int vole_threads = -1, const FP *delta_in = nullptr)
      : party(party), io(io) {
    threads_ = threads < 1 ? 1 : threads;
    vole_threads_ = (vole_threads < 0) ? threads_ : (vole_threads < 1 ? 1 : vole_threads);
    if (threads_ > 1) pool_ = new ThreadPool((size_t)threads_);
    bg_ = (vole_io != nullptr);
    bg_io_ = vole_io;

    if (party == BOB) {
      if (delta_in != nullptr) {
        delta = *delta_in;
      } else {
        delta.rand(prg);
        restrict_delta(delta);
      }
    }
    vole = new FieldVoleStream<FP, FPS>(party, bg_ ? bg_io_ : io, vole_threads_, delta);

    const int64_t auto_sz =
        std::max<int64_t>((int64_t)1 << 20, ((int64_t)128 << 20) / (int64_t)sizeof(L));
    CHECK_SZ = default_check_sz > 0 ? default_check_sz : auto_sz;
    out_buf.resize(CHECK_SZ);
    left_buf.resize(CHECK_SZ);
    right_buf.resize(CHECK_SZ);
    s_scratch_.resize(CHECK_SZ);

    if (bg_) {
      bg_batch_ = vole->round_size();
      const int bg_slots = getenv("BG_SLOTS") ? atoi(getenv("BG_SLOTS")) : 4;
      pipe_ = std::make_unique<CorrelationPipe<L>>(bg_slots, bg_batch_);
      producer_ = std::thread([this] {
        for (int i; (i = pipe_->acquire_free()) >= 0;) {
          vole->next_n(pipe_->slot[i].data(), bg_batch_);
          pipe_->publish();
        }
      });
    }
    draw_vole(out_buf.data(), CHECK_SZ);
    auth_helper = new FieldAuthHelper<FP>(party, io);
  }

  ~FieldOSTriple() {
    if (check_cnt != 0) mul_check();
    auth_helper->flush();
    delete auth_helper;
    if (bg_) {
      if (cur_slot_ >= 0) { pipe_->release(); cur_slot_ = -1; }
      pipe_->finish();
      if (producer_.joinable()) producer_.join();
    }
    delete vole;
    delete pool_;
  }

  // ---- correlations -----------------------------------------------------
  void draw_vole(L *out, int64_t n) {
    if (!bg_) { vole->next_n(out, n); return; }
    int64_t done = 0;
    while (done < n) {
      if (cur_slot_ < 0) {
        io->flush();  // let the peer reach the same round before we block
        cur_slot_ = pipe_->acquire_ready();
        cur_off_ = 0;
        if (cur_slot_ < 0)
          error("background sVOLE pipe closed during a draw (internal error)");
      }
      const int64_t take = std::min(n - done, bg_batch_ - cur_off_);
      std::copy(pipe_->slot[cur_slot_].data() + cur_off_,
                pipe_->slot[cur_slot_].data() + cur_off_ + take, out + done);
      cur_off_ += take;
      done += take;
      if (cur_off_ == bg_batch_) { pipe_->release(); cur_slot_ = -1; }
    }
  }

  template <class F>
  void run_parallel_(F &&work, int64_t cnt) {
    if (threads_ <= 1 || pool_ == nullptr || cnt < (int64_t)threads_) {
      work((int64_t)0, cnt);
      return;
    }
    const int64_t per = cnt / threads_;
    std::vector<std::future<void>> fut;
    int64_t start = 0;
    for (int t = 0; t < threads_ - 1; ++t) {
      const int64_t lo = start, hi = start + per;
      fut.push_back(pool_->enqueue([&work, lo, hi]() { work(lo, hi); }));
      start += per;
    }
    work(start, cnt);
    for (auto &f : fut) f.get();
  }

  template <class F>
  void run_maybe_parallel_(F &&work, int64_t cnt) {
    if (cnt <= kFeedParMin) work((int64_t)0, cnt);
    else run_parallel_(work, cnt);
  }

  // ---- inputs -----------------------------------------------------------
  // Prover: fresh VOLE (r, M_r), send lam = r - w; label (w, M_r).
  L input_send(const FP &w) {
    L r;
    draw_vole(&r, 1);
    FP lam = r.val - w;
    io->send_data(&lam, sizeof(FP));
    return L{w, r.mac};
  }
  void input_send(L *label, const FP *w, int64_t len) {
    std::vector<FP> lam((size_t)len);
    draw_vole(label, len);
    run_maybe_parallel_([&](int64_t lo, int64_t hi) {
      for (int64_t i = lo; i < hi; ++i) {
        lam[i] = label[i].val - w[i];
        label[i] = L{w[i], label[i].mac};
      }
    }, len);
    io->send_data(lam.data(), len * sizeof(FP));
  }
  // Verifier: fresh key K_r, key of the input is K_r + lam * Delta.
  L input_recv() {
    L k;
    draw_vole(&k, 1);
    FP lam;
    io->recv_data(&lam, sizeof(FP));
    return L{FP(), k.mac + field_canon(lam) * delta};
  }
  void input_recv(L *label, int64_t len) {
    std::vector<FP> lam((size_t)len);
    draw_vole(label, len);
    io->recv_data(lam.data(), len * sizeof(FP));
    run_maybe_parallel_([&](int64_t lo, int64_t hi) {
      for (int64_t i = lo; i < hi; ++i)
        label[i] = L{FP(), label[i].mac + field_canon(lam[i]) * delta};
    }, len);
  }

  // ---- multiplication ---------------------------------------------------
  void refill_if_full_() {
    if (check_cnt == CHECK_SZ) {
      mul_check();
      check_cnt = 0;
      draw_vole(out_buf.data(), CHECK_SZ);
    }
  }

  // Prover: d = a*b, send s = r - d for the pre-drawn fresh VOLE (r, M_r).
  L mul_send(const L &a, const L &b) {
    refill_if_full_();
    L r = out_buf[check_cnt];
    left_buf[check_cnt] = a;
    right_buf[check_cnt] = b;
    FP d = a.val * b.val;
    FP s = r.val - d;
    io->send_data(&s, sizeof(FP));
    L c{d, r.mac};
    out_buf[check_cnt++] = c;
    return c;
  }
  // Verifier: key of the product is K_r + s * Delta.
  L mul_recv(const L &a, const L &b) {
    refill_if_full_();
    L k = out_buf[check_cnt];
    left_buf[check_cnt] = a;
    right_buf[check_cnt] = b;
    FP s;
    io->recv_data(&s, sizeof(FP));
    L c{FP(), k.mac + field_canon(s) * delta};
    out_buf[check_cnt++] = c;
    return c;
  }

  // n independent products in one batched, threaded call (byte-identical to
  // n scalar calls).
  void mul_send(L *out, const L *a, const L *b, int64_t n) {
    int64_t done = 0;
    while (done < n) {
      refill_if_full_();
      const int64_t take = std::min<int64_t>(CHECK_SZ - check_cnt, n - done);
      const int64_t base = check_cnt;
      run_parallel_([&](int64_t lo, int64_t hi) {
        for (int64_t i = lo; i < hi; ++i) {
          const L &x = a[done + i], &y = b[done + i];
          L r = out_buf[base + i];
          left_buf[base + i] = x;
          right_buf[base + i] = y;
          FP d = x.val * y.val;
          s_scratch_[i] = r.val - d;
          L c{d, r.mac};
          out_buf[base + i] = c;
          out[done + i] = c;
        }
      }, take);
      io->send_data(s_scratch_.data(), (size_t)take * sizeof(FP));
      check_cnt += take;
      done += take;
    }
  }
  void mul_recv(L *out, const L *a, const L *b, int64_t n) {
    int64_t done = 0;
    while (done < n) {
      refill_if_full_();
      const int64_t take = std::min<int64_t>(CHECK_SZ - check_cnt, n - done);
      const int64_t base = check_cnt;
      io->recv_data(s_scratch_.data(), (size_t)take * sizeof(FP));
      run_parallel_([&](int64_t lo, int64_t hi) {
        for (int64_t i = lo; i < hi; ++i) {
          left_buf[base + i] = a[done + i];
          right_buf[base + i] = b[done + i];
          L c{FP(), out_buf[base + i].mac + field_canon(s_scratch_[i]) * delta};
          out_buf[base + i] = c;
          out[done + i] = c;
        }
      }, take);
      check_cnt += take;
      done += take;
    }
  }

  // ---- batched multiplication check (QuickSilver) -----------------------
  // Prover:   A0 = Ma*Mb,  A1 = a*Mb + b*Ma - Mc;   U = sum chi*A0, V = sum chi*A1
  // Verifier: B  = Ka*Kb + Kc*Delta;                W = sum chi*B
  // With c = ab, B = A0 - A1*Delta. A fresh VOLE (r*, M*) / K* masks (U, V):
  // the prover sends (U + M*, V + r*), the verifier checks
  // U + M* == (W + K*) + (V + r*) * Delta.
  void mul_check() {
    io->flush();
    std::vector<block> seeds(threads_);
    share_seed_gen(seeds.data(), (uint32_t)threads_);
    io->flush();

    std::vector<FP> part(2 * (size_t)threads_);
    const int64_t n = check_cnt;
    if (threads_ <= 1 || pool_ == nullptr) {
      mul_check_range(part.data(), 0, 0, n, seeds.data());
    } else {
      const int64_t per = n / threads_;
      std::vector<std::future<void>> fut;
      int64_t start = 0;
      for (int t = 0; t < threads_ - 1; ++t) {
        const int64_t s = start;
        fut.push_back(pool_->enqueue([this, &part, &seeds, t, s, per]() {
          mul_check_range(part.data(), t, s, per, seeds.data());
        }));
        start += per;
      }
      mul_check_range(part.data(), threads_ - 1, start, n - start, seeds.data());
      for (auto &f : fut) f.get();
    }

    L mask;
    draw_vole(&mask, 1);
    if (party == ALICE) {
      FP U, V;
      for (int t = 0; t < threads_; ++t) { U = U + part[2 * t]; V = V + part[2 * t + 1]; }
      FP cs[2] = {U + mask.mac, V + mask.val};
      io->send_data(cs, 2 * sizeof(FP));
    } else {
      FP W;
      for (int t = 0; t < threads_; ++t) W = W + part[2 * t];
      W = W + mask.mac;
      FP cs[2];
      io->recv_data(cs, 2 * sizeof(FP));
      if (field_canon(cs[0]) != W + field_canon(cs[1]) * delta)
        error("multiplication gates check fails");
    }
    io->flush();
  }

  void mul_check_range(FP *part, int t, int64_t start, int64_t cnt, const block *seeds) {
    FP U, V;
    if (cnt > 0) {
      std::vector<FP> chi((size_t)cnt);
      field_coeff_gen(chi.data(), seeds[t], cnt);
      if (party == ALICE) {
        for (int64_t k = 0; k < cnt; ++k) {
          const L &a = left_buf[start + k], &b = right_buf[start + k];
          const FP &mc = out_buf[start + k].mac;
          FP A0 = a.mac * b.mac;
          FP A1 = a.val * b.mac + b.val * a.mac - mc;
          U = U + A0 * chi[k];
          V = V + A1 * chi[k];
        }
      } else {
        for (int64_t k = 0; k < cnt; ++k) {
          FP B = left_buf[start + k].mac * right_buf[start + k].mac +
                 out_buf[start + k].mac * delta;
          U = U + B * chi[k];
        }
      }
    }
    part[2 * t] = U;
    part[2 * t + 1] = V;
  }

  // ---- outputs ----------------------------------------------------------
  void reveal_send(const L *out, FP *value, int64_t len) {
    for (int64_t i = 0; i < len; ++i) {
      value[i] = out[i].val;
      auth_helper->store(out[i].mac);
    }
    io->send_data(value, len * sizeof(FP));
  }
  void reveal_recv(const L *out, FP *value, int64_t len) {
    io->recv_data(value, len * sizeof(FP));
    for (int64_t i = 0; i < len; ++i) {
      value[i] = field_canon(value[i]);
      auth_helper->store(value[i] * delta + out[i].mac);
    }
  }
  void reveal_check_send(const L *out, int64_t len) {
    std::vector<FP> v((size_t)len);
    reveal_send(out, v.data(), len);
  }
  void reveal_check_recv(const L *out, const FP *expect, int64_t len) {
    std::vector<FP> v((size_t)len);
    reveal_recv(out, v.data(), len);
    for (int64_t i = 0; i < len; ++i)
      if (v[i] != expect[i]) error("arithmetic reveal value not expected");
  }
  // Opening to zero: the prover's MAC must equal the verifier's key.
  void reveal_check_zero(const L *out, int64_t len) {
    for (int64_t i = 0; i < len; ++i) auth_helper->store(out[i].mac);
  }

  // ---- helpers ----------------------------------------------------------
  void share_seed_gen(block *seed, uint32_t num) {
    block seed0;
    if (party == ALICE) {
      io->recv_data(&seed0, sizeof(block));
    } else {
      prg.random_block(&seed0, 1);
      io->send_data(&seed0, sizeof(block));
    }
    PRG(&seed0).random_block(seed, num);
  }

  // Debug: the verifier checks M = K + x * Delta on `len` labels.
  void check_auth_mac(const L *auth, int64_t len) {
    if (party == ALICE) {
      io->send_data(auth, len * sizeof(L));
      io->flush();
    } else {
      std::vector<L> r((size_t)len);
      io->recv_data(r.data(), len * sizeof(L));
      for (int64_t i = 0; i < len; ++i)
        if (r[i].mac != auth[i].mac + r[i].val * delta)
          error("authenticated mac error");
    }
  }
};

}  // namespace emp
#endif
