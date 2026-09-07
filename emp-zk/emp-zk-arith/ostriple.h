#ifndef FP_OS_TRIPLE_H__
#define FP_OS_TRIPLE_H__

#include "emp-zk/vole_stream.h"   // must precede emp-ot (see there)
#include "emp-ot/emp-ot.h"
#include "emp-zk/emp-zk-arith/correlation_pipe.h"
#include "emp-zk/emp-zk-arith/triple_auth.h"
#include <algorithm>
#include <future>
#include <memory>
#include <thread>
#include <vector>
// PRG-INDEPENDENT RLC coefficients (replaces the s^(i+1) power chain of uni_hash_coeff_gen):
// each chi_i is a fresh uniform expanded from the seed by AES-PRG in fixed 4096-element
// blocks keyed on (seed ^ const, block) -- RLC failure prob 1/PR instead of n/PR.
#ifndef EMP_ZK_PRG_COEFF_GEN_
#define EMP_ZK_PRG_COEFF_GEN_
namespace emp {
inline void prg_coeff_gen_zk(uint64_t *coeff, uint64_t seed, int64_t n) {
  constexpr int64_t B = 4096;
  std::vector<uint64_t> w((size_t)B);
  for (int64_t b = 0; b * B < n; ++b) {
    block sb = makeBlock(seed ^ 0x9e3779b97f4a7c15ULL, (uint64_t)b);
    PRG prg(&sb);
    prg.random_data(w.data(), (int)(B * 8));
    const int64_t base = b * B;
    const int64_t m = (n - base) < B ? (n - base) : B;
    for (int64_t j = 0; j < m; ++j) coeff[base + j] = mod(w[(size_t)j]);
  }
}
}  // namespace emp
#endif


namespace emp {
using namespace std;

// Bit-position helpers (layout-agnostic).
#define LOW64(x) _mm_extract_epi64((block)x, 0)
#define HIGH64(x) _mm_extract_epi64((block)x, 1)

// AuthValue accessors (val-first layout: val in low 64, mac in high 64).
// Use these for AuthValue casts so the layout intent is explicit; keep
// LOW64/HIGH64 for raw block bit extraction (chi_seed, F_p deltas, etc.).
#define VAL(x) _mm_extract_epi64((block)x, 0)
#define MAC(x) _mm_extract_epi64((block)x, 1)
// Construct an AuthValue-bytes __uint128_t from (val, mac).
#define MAKE_AUTH(val_, mac_) \
    ((__uint128_t)makeBlock((uint64_t)(mac_), (uint64_t)(val_)))

class FpOSTriple {
public:
  int party;
  int64_t triple_n;
  __uint128_t delta;

  int64_t check_cnt = 0;
  std::vector<__uint128_t> andgate_out_buffer;
  std::vector<__uint128_t> andgate_left_buffer;
  std::vector<__uint128_t> andgate_right_buffer;

  BoolIO *io;
  PRG prg;
  // F_p VOLE from vole-labs/vole (RVole<FP61, FP61x2> behind FpVoleStream).
  // Borrowers (EdaBits / FpPolyProof) draw through draw_vole(), never here.
  FpVoleStream *vole = nullptr;
  FpAuthHelper *auth_helper = nullptr;

  static constexpr int64_t kFeedParMin = ((int64_t)1 << 20) - 1;  // thread feed() at >= 1M elements
  int threads_ = 1;              // ostriple's pool (checks, vectorized mul)
  int vole_threads_ = 1;         // sVOLE's pool (cGGM expand / produce)
  ThreadPool *pool_ = nullptr;   // null when threads_ <= 1

  int64_t CHECK_SZ = 8 * 1024 * 1024;

  // ---- Background sVOLE (opt-in; enabled when a second socket is provided) --
  // In background mode the F_p VOLE runs on its OWN socket (bg_io_) on a
  // dedicated producer thread, streaming correlations into a CorrelationPipe;
  // this engine consumes them via draw_vole() on the main socket. The sVOLE's
  // round-trips (corrections + rollovers + malicious check) overlap this
  // engine's work instead of stalling it. See correlation_pipe.h.
  bool bg_ = false;
  BoolIO *bg_io_ = nullptr;                         // caller-provided socket A
  std::unique_ptr<CorrelationPipe<AuthValueFp>> pipe_;
  std::thread producer_;
  int64_t bg_batch_ = 1 << 20;                      // correlations per pipe slot
  int cur_slot_ = -1;                               // consumer FIFO reader state
  int64_t cur_off_ = 0;

  // ---- Optional phase profiling (EMP_PROFILE=1) -----------------------
  // Accumulate wall-time per major component; printed once at teardown.
  double prof_fill_setup_us = 0.0;   // first VOLE fill (in ctor → counts as setup)
  double prof_fill_online_us = 0.0;  // VOLE refills during the gate loop
  double prof_check_us = 0.0;        // andgate batch correctness checks
  double prof_mul_compute_us = 0.0;  // vectorized mul: threaded field arithmetic
  double prof_mul_send_us = 0.0;     // vectorized mul: batched correction I/O
  int64_t prof_fills_done_ = 0;

  // Threaded batch fill of `n` (chunk-multiple) VOLE correlations into `buf`.
  // The per-gate path then just fetches from this in-memory buffer; this fill is
  // the actual VOLE-generation compute (cGGM eval + LPN), so it runs across the
  // worker pool via the silent VOLE's wire-free produce_range. n_threads=1 is
  // the serial path. CHECK_SZ is a chunk multiple for the b13 param.
  void fill_vole_(AuthValueFp *buf, int64_t n) {
    auto _t = clock_start();
    if (bg_) {
      draw_vole_(buf, n);                       // from the background pipe
    } else {
      vole->next_n(buf, n);   // vole's own pool (vole_threads_) runs the expansion
    }
    if (prof_fills_done_++ == 0) prof_fill_setup_us += time_from(_t);
    else                         prof_fill_online_us += time_from(_t);
  }

  // Unified VOLE draw. Default mode: straight from the (main-thread) sVOLE.
  // Background mode: FIFO from the pipe the producer thread fills (this thread
  // never touches the sVOLE / socket A). Same deterministic correlation stream
  // in the same order either way. All engine + borrower draws route here.
  void draw_vole_(AuthValueFp *out, int64_t n) {
    if (!bg_) { vole->next_n(out, n); return; }
    int64_t done = 0;
    while (done < n) {
      if (cur_slot_ < 0) {
        // About to (possibly) block waiting for the producer to fill the next
        // round-buffer, whose fill is a CROSS-PARTY sVOLE round-trip. FLUSH the
        // main socket first so the peer receives everything up to our position,
        // finishes its round, and its producer joins that round-trip — otherwise
        // an unflushed tail here would reintroduce the cross-party deadlock.
        io->flush();
        cur_slot_ = pipe_->acquire_ready();
        cur_off_ = 0;
        if (cur_slot_ < 0)   // producer only stops at teardown; never mid-proof
          error("background sVOLE pipe closed during a draw (internal error)");
      }
      const int64_t take = std::min(n - done, bg_batch_ - cur_off_);
      memcpy(out + done, pipe_->slot[cur_slot_].data() + cur_off_,
             (size_t)take * sizeof(AuthValueFp));
      cur_off_ += take;
      done += take;
      if (cur_off_ == bg_batch_) { pipe_->release(); cur_slot_ = -1; }
    }
  }

  // Public draw for borrowers (FpPolyProof) so every VOLE consumer shares the
  // one stream — in background mode they must NOT touch vole->next_n directly.
  void draw_vole(AuthValueFp *out, int64_t n) { draw_vole_(out, n); }

  // Batched send/recv correction values for the vectorized multiply (one
  // io->send_data / recv_data per CHECK_SZ-bounded block).
  std::vector<uint64_t> s_scratch_;

  // Split [0, cnt) across the worker pool; the last range runs on this thread.
  // Serial (no pool work) when threads_<=1 or the batch is smaller than the
  // worker count. The functor is joined before return, so capturing it by
  // reference in the tasks is safe.
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

  // Per-block sender compute: fresh VOLE → d=a·b, s=mac-d (batched into
  // s_scratch_), output MAC into buffer slot base+i and out[i]. Threaded.
  void mul_block_send_(__uint128_t *out, const __uint128_t *Ma,
                       const __uint128_t *Mb, int64_t base, int64_t cnt) {
    auto work = [&](int64_t lo, int64_t hi) {
      for (int64_t i = lo; i < hi; ++i) {
        __uint128_t mac = andgate_out_buffer[base + i];   // pre-drawn fresh VOLE
        andgate_left_buffer[base + i]  = Ma[i];
        andgate_right_buffer[base + i] = Mb[i];
        uint64_t d = mult_mod(VAL(Ma[i]), VAL(Mb[i]));
        s_scratch_[i] = add_mod(VAL(mac), PR - d);
        __uint128_t omac = MAKE_AUTH(d, MAC(mac));
        andgate_out_buffer[base + i] = omac;              // overwrite with output MAC
        out[i] = omac;
      }
    };
    run_parallel_(work, cnt);
  }

  // Per-block receiver compute: fresh VOLE key + the received d (in s_scratch_)
  // → wire key MAKE_AUTH(0, mac + d·Δ) into buffer slot base+i and out[i].
  void mul_block_recv_(__uint128_t *out, const __uint128_t *Ka,
                       const __uint128_t *Kb, int64_t base, int64_t cnt) {
    auto work = [&](int64_t lo, int64_t hi) {
      for (int64_t i = lo; i < hi; ++i) {
        __uint128_t key = andgate_out_buffer[base + i];   // pre-drawn fresh VOLE key
        andgate_left_buffer[base + i]  = Ka[i];
        andgate_right_buffer[base + i] = Kb[i];
        uint64_t delta_d = mult_mod(s_scratch_[i], (uint64_t)delta);
        __uint128_t wkey = MAKE_AUTH(0, add_mod(MAC(key), delta_d));
        andgate_out_buffer[base + i] = wkey;              // overwrite with wire key
        out[i] = wkey;
      }
    };
    run_parallel_(work, cnt);
  }

  // `vole_io` (optional): a SECOND socket, distinct from `io`. When provided,
  // the sVOLE runs on it in a background producer thread and this engine draws
  // correlations from a pipe (see draw_vole_). The producer streams on demand
  // and stops at teardown, so NO size hint is needed — `expected_vole` is
  // ignored in this mode. nullptr = the default single-socket path (where
  // expected_vole is still an optional whole-proof prepay hint).
  // `vole_threads` sizes the sVOLE's own worker pool (cGGM expand / produce)
  // INDEPENDENTLY of `threads` (which sizes ostriple's check / vectorized-mul
  // pool). In background mode the two run concurrently, so splitting them lets
  // you avoid 2x oversubscription (e.g. threads=cores/2, vole_threads=cores/2).
  // vole_threads < 0 → same as `threads` (backward compatible).
  FpOSTriple(int party, BoolIO *io, int threads = 1, int64_t expected_vole = 0,
             BoolIO *vole_io = nullptr, int vole_threads = -1) {
    this->party = party;
    this->io = io;
    this->threads_ = threads < 1 ? 1 : threads;
    this->vole_threads_ =
        (vole_threads < 0) ? this->threads_ : (vole_threads < 1 ? 1 : vole_threads);
    if (this->threads_ > 1) pool_ = new ThreadPool((size_t)this->threads_);
    bg_ = (vole_io != nullptr);
    bg_io_ = vole_io;

    if (party == BOB) delta_gen();
    // The VOLE lives on socket A (bg_io_) in background mode, else on `io`.
    // vole_threads_ sizes vole's MPFSS / LPN pool (one sibling socket per
    // extra worker, see VoleChannels).
    vole = new FpVoleStream(party, bg_ ? bg_io_ : io, this->vole_threads_,
                            party == BOB ? (uint64_t)delta : 0);

    andgate_out_buffer.resize(CHECK_SZ);
    andgate_left_buffer.resize(CHECK_SZ);
    andgate_right_buffer.resize(CHECK_SZ);
    s_scratch_.resize(CHECK_SZ);            // batched correction values (vectorized mul)

    if (bg_) {
      // Background mode: the producer thread owns the sVOLE + socket A; this
      // thread never touches them. `expected_vole` is not needed (ignored).
      //
      // ROUND-SIZED DOUBLE BUFFER (deadlock-free). Each pipe slot holds exactly
      // one vole extension round (round_size), and there are two of them: the producer
      // fills one (a cross-party round-trip on socket A) while the consumer drains
      // the other. Because the consumer always has a FULL round buffered locally,
      // it keeps driving the MAIN socket (sending lam / corrections) throughout a
      // background round-trip — so the peer never starves for main-socket data,
      // its consumer keeps advancing, and its producer joins the cross-party
      // round-trip. That, plus the flush in draw_vole_ before a block, prevents
      // the "one party's full local buffer stalls the peer's peer-synchronous
      // generation" deadlock. The cross-party round generation itself bounds the
      // drift to <= 2 rounds, exactly the double buffer's capacity.
      bg_batch_ = vole->round_size();     // one full round per buffer
      // BG_SLOTS (default 4): sVOLE-side banked rounds. 2 slots = only ~1 FINISHED round
      // banked (the other is mid-production), so a >15M refill (LogUp 16.8M chunks) waits
      // on the in-flight round. 4 = one draining + one filling + TWO fully banked (~31M),
      // so any single refill is served from finished buffers. +249 MB per extra slot.
      const int bg_slots = getenv("BG_SLOTS") ? atoi(getenv("BG_SLOTS")) : 4;
      pipe_ = std::make_unique<CorrelationPipe<AuthValueFp>>(bg_slots, bg_batch_);
      producer_ = std::thread([this] {
        // Each fill is one vole extension round (a cross-party exchange on
        // socket A, expanded across vole_threads_ workers); the consumer
        // drains finished rounds from the pipe on the main socket.
        for (int i; (i = pipe_->acquire_free()) >= 0;) {
          vole->next_n(pipe_->slot[i].data(), bg_batch_);
          pipe_->publish();
        }
      });
    }
    // Single-socket path: vole extends a round whenever its buffer runs out;
    // there is no whole-proof prepay, so `expected_vole` is accepted for API
    // compatibility and otherwise unused.
    (void)expected_vole;

    __uint128_t tmp;
    draw_vole_((AuthValueFp *)&tmp, 1);
    // Pre-draw the first batch of authenticated values into andgate_out_buffer;
    // each multiplication consumes one slot and the batch boundary reloads.
    fill_vole_((AuthValueFp *)andgate_out_buffer.data(), CHECK_SZ);

    auth_helper = new FpAuthHelper(party, io);
  }

  ~FpOSTriple() {
    if (check_cnt != 0)
      andgate_correctness_check_manage();
    auth_helper->flush();
    delete auth_helper;
    if (bg_) {
      // Signal the producer to stop: both parties reach here after consuming
      // identically, so their producers are at the same round; finish() wakes
      // the producer's acquire_free() (returns -1 → it exits the loop and runs
      // the local sv.end()). Any produced-but-unconsumed look-ahead is simply
      // discarded (it lives in an already-checked round).
      if (cur_slot_ >= 0) { pipe_->release(); cur_slot_ = -1; }
      pipe_->finish();
      if (producer_.joinable()) producer_.join();
    }
    delete vole;
    delete pool_;
    if (getenv("EMP_PROFILE")) {
      fprintf(stderr,
              "[arith-prof p%d] vole_fill_setup=%.1fms vole_refill=%.1fms "
              "andgate_check=%.1fms\n",
              party, prof_fill_setup_us / 1000.0, prof_fill_online_us / 1000.0,
              prof_check_us / 1000.0);
      fprintf(stderr,
              "[arith-prof p%d] vec_mul_compute=%.1fms vec_mul_io=%.1fms\n",
              party, prof_mul_compute_us / 1000.0, prof_mul_send_us / 1000.0);
    }
  }
  /* ---------------------inputs----------------------*/

  /*
   * authenticated bits for inputs of the prover
   */
  __uint128_t authenticated_val_input(uint64_t w) {
    __uint128_t mac;
    draw_vole_((AuthValueFp *)&mac, 1);

    uint64_t lam = PR - w;
    lam = add_mod(VAL(mac), lam);
    io->send_data(&lam, sizeof(uint64_t));
    return MAKE_AUTH(w, MAC(mac));
  }

  void authenticated_val_input(__uint128_t *label, const uint64_t *w, int64_t len) {
    std::vector<uint64_t> lam(len);
    draw_vole_((AuthValueFp *)label, len);

    // Per-element masking compute is independent (disjoint label[i]/lam[i]) →
    // split across the pool. Serial fallback for small len (see run_parallel_).
    if (len <= kFeedParMin) {   // serial fast path: dispatch loses on small/medium feeds
      for (int64_t i = 0; i < len; ++i) {
        lam[i] = add_mod(VAL(label[i]), PR - w[i]);
        label[i] = MAKE_AUTH(w[i], MAC(label[i]));
      }
    } else
      run_parallel_(
          [&](int64_t lo, int64_t hi) {
            for (int64_t i = lo; i < hi; ++i) {
            lam[i] = add_mod(VAL(label[i]), PR - w[i]);
            label[i] = MAKE_AUTH(w[i], MAC(label[i]));
            }
          },
          len);
    io->send_data(lam.data(), len * sizeof(uint64_t));
  }

  __uint128_t authenticated_val_input() {
    __uint128_t key;
    draw_vole_((AuthValueFp *)&key, 1);

    uint64_t lam;
    io->recv_data(&lam, sizeof(uint64_t));

    uint64_t delta_lam = mult_mod(lam, (uint64_t)delta);
    // BOB's key has val=0 in low, mac in high (val-first); only the mac
    // side picks up the correction.
    return MAKE_AUTH(0, add_mod(MAC(key), delta_lam));
  }

  void authenticated_val_input(__uint128_t *label, int64_t len) {
    std::vector<uint64_t> lam(len);
    draw_vole_((AuthValueFp *)label, len);

    io->recv_data(lam.data(), len * sizeof(uint64_t));

    // Per-element key correction (one mult_mod each) → split across the pool.
    if (len <= kFeedParMin) {   // serial fast path: dispatch loses on small/medium feeds
      for (int64_t i = 0; i < len; ++i) {
        uint64_t delta_lam = mult_mod(lam[i], (uint64_t)delta);
        label[i] = MAKE_AUTH(0, add_mod(MAC(label[i]), delta_lam));
      }
    } else
      run_parallel_(
          [&](int64_t lo, int64_t hi) {
            for (int64_t i = lo; i < hi; ++i) {
            uint64_t delta_lam = mult_mod(lam[i], (uint64_t)delta);
            label[i] = MAKE_AUTH(0, add_mod(MAC(label[i]), delta_lam));
            }
          },
          len);
  }

  /*
   * authenticated bits for computing AND gates
   */
  __uint128_t auth_compute_mul_send(__uint128_t Ma, __uint128_t Mb) {
    if (check_cnt == CHECK_SZ) {
      andgate_correctness_check_manage();
      check_cnt = 0;
      fill_vole_((AuthValueFp *)andgate_out_buffer.data(), CHECK_SZ);
    }
    __uint128_t mac = andgate_out_buffer[check_cnt];   // pre-drawn fresh VOLE
    andgate_left_buffer[check_cnt] = Ma;
    andgate_right_buffer[check_cnt] = Mb;

    uint64_t d = mult_mod(VAL(Ma), VAL(Mb));
    uint64_t s = PR - d;
    s = add_mod(VAL(mac), s);
    io->send_data(&s, sizeof(uint64_t));

    mac = MAKE_AUTH(d, MAC(mac));
    andgate_out_buffer[check_cnt] = mac;                // overwrite with output MAC
    check_cnt++;

    return mac;
  }

  __uint128_t auth_compute_mul_recv(__uint128_t Ka, __uint128_t Kb) {
    if (check_cnt == CHECK_SZ) {
      andgate_correctness_check_manage();
      check_cnt = 0;
      fill_vole_((AuthValueFp *)andgate_out_buffer.data(), CHECK_SZ);
    }
    __uint128_t key = andgate_out_buffer[check_cnt];   // pre-drawn fresh VOLE key
    andgate_left_buffer[check_cnt] = Ka;
    andgate_right_buffer[check_cnt] = Kb;

    uint64_t d;
    io->recv_data(&d, sizeof(uint64_t));
    uint64_t delta_d = mult_mod(d, (uint64_t)delta);
    // BOB's key: val=0 in low, mac in high (val-first); apply
    // correction to the mac side only.
    key = MAKE_AUTH(0, add_mod(MAC(key), delta_d));

    andgate_out_buffer[check_cnt] = key;                // overwrite with wire key
    check_cnt++;
    return key;
  }

  // ---- Vectorized AND-gate multiply (batched + threaded) --------------
  //
  // Computes `n` INDEPENDENT multiplications c_i = a_i * b_i in one shot:
  // takes the input wire arrays, writes the output wire MACs into `out`, and
  // ships every correction value `s_i` in a single send_data (the per-gate
  // scalar path sends them one at a time). All triples land in the
  // andgate_*_buffer slots [check_cnt, check_cnt+n) exactly as the scalar
  // path would, so the wire bytes and the batch check are byte-identical to
  // calling the scalar version n times — provided the n gates are independent
  // (no a_i/b_i depends on another c_j in the same call). The per-gate field
  // arithmetic is split across the worker pool; the batch send/recv is serial.
  // Crosses CHECK_SZ boundaries safely (runs the check + VOLE refill inline).
  void auth_compute_mul_send(__uint128_t *out, const __uint128_t *Ma,
                             const __uint128_t *Mb, int64_t n) {
    int64_t done = 0;
    while (done < n) {
      if (check_cnt == CHECK_SZ) {
        andgate_correctness_check_manage();
        check_cnt = 0;
        fill_vole_((AuthValueFp *)andgate_out_buffer.data(), CHECK_SZ);
      }
      const int64_t take = std::min<int64_t>(CHECK_SZ - check_cnt, n - done);
      auto _tc = clock_start();
      mul_block_send_(out + done, Ma + done, Mb + done, check_cnt, take);
      prof_mul_compute_us += time_from(_tc);
      auto _ts = clock_start();
      io->send_data(s_scratch_.data(), (size_t)take * sizeof(uint64_t));
      prof_mul_send_us += time_from(_ts);
      check_cnt += take;
      done += take;
    }
  }

  void auth_compute_mul_recv(__uint128_t *out, const __uint128_t *Ka,
                             const __uint128_t *Kb, int64_t n) {
    int64_t done = 0;
    while (done < n) {
      if (check_cnt == CHECK_SZ) {
        andgate_correctness_check_manage();
        check_cnt = 0;
        fill_vole_((AuthValueFp *)andgate_out_buffer.data(), CHECK_SZ);
      }
      const int64_t take = std::min<int64_t>(CHECK_SZ - check_cnt, n - done);
      auto _ts = clock_start();
      io->recv_data(s_scratch_.data(), (size_t)take * sizeof(uint64_t));
      prof_mul_send_us += time_from(_ts);
      auto _tc = clock_start();
      mul_block_recv_(out + done, Ka + done, Kb + done, check_cnt, take);
      prof_mul_compute_us += time_from(_tc);
      check_cnt += take;
      done += take;
    }
  }

  /* ---------------------check----------------------*/

  void andgate_correctness_check_manage() {
    auto _tprof = clock_start();
    io->flush();

    uint64_t U = 0, V = 0, W = 0;
    // One chi seed per worker — each thread folds its disjoint slice with an
    // independent universal hash, exchanged once on the main thread.
    std::vector<block> share_seed(threads_);
    share_seed_gen(share_seed.data(), (uint32_t)threads_);
    io->flush();

    // ret holds per-thread partials: (U_i, V_i) for ALICE, W_i for BOB.
    std::vector<uint64_t> sum(2 * (size_t)threads_, 0);
    if (threads_ <= 1 || pool_ == nullptr) {
      andgate_correctness_check(sum.data(), 0, 0, (uint32_t)check_cnt,
                                share_seed.data());
    } else {
      // Split the check_cnt buffered triples into disjoint ranges, one per
      // worker; the last (this) thread takes the remainder. Each writes its own
      // ret slot, so no synchronization until the join. (Port of legacy
      // emp-zk-arith/ostriple.h andgate_correctness_check_manage.)
      const uint32_t task_base = (uint32_t)(check_cnt / threads_);
      uint64_t *sum_ptr = sum.data();
      block *seed_ptr = share_seed.data();
      std::vector<std::future<void>> fut;
      uint32_t start = 0;
      for (int i = 0; i < threads_ - 1; ++i) {
        const uint32_t s = start;
        const int idx = i;
        fut.push_back(pool_->enqueue([this, sum_ptr, idx, s, task_base,
                                      seed_ptr]() {
          andgate_correctness_check(sum_ptr, idx, s, task_base, seed_ptr);
        }));
        start += task_base;
      }
      andgate_correctness_check(sum.data(), threads_ - 1, start,
                                (uint32_t)check_cnt - start, share_seed.data());
      for (auto &f : fut) f.get();
    }

    if (party == ALICE) {
      for (int i = 0; i < threads_; ++i) {
        U = add_mod(U, sum[2 * i]);
        V = add_mod(V, sum[2 * i + 1]);
      }
    } else {
      for (int i = 0; i < threads_; ++i) W = add_mod(W, sum[i]);
    }

    if (party == ALICE) {
      __uint128_t ope_data;
      draw_vole_((AuthValueFp *)&ope_data, 1);
      uint64_t A0_star = MAC(ope_data);
      uint64_t A1_star = VAL(ope_data);
      uint64_t check_sum[2];
      check_sum[0] = add_mod(U, A0_star);
      check_sum[1] = add_mod(V, A1_star);
      io->send_data(check_sum, 2 * sizeof(uint64_t));
    } else {
      __uint128_t ope_data;
      draw_vole_((AuthValueFp *)&ope_data, 1);
      uint64_t B_star = MAC(ope_data);
      W = add_mod(W, B_star);
      uint64_t check_sum[2];
      io->recv_data(check_sum, 2 * sizeof(uint64_t));
      check_sum[1] = mult_mod(check_sum[1], delta);
      check_sum[1] = add_mod(check_sum[1], W);
      if (check_sum[0] != check_sum[1])
        error("multiplication gates check fails");
    }
    io->flush();
    prof_check_us += time_from(_tprof);
  }

  void andgate_correctness_check(uint64_t *ret, int thr_idx, uint32_t start,
                                 uint32_t task_n, block *chi_seed) {
    if (task_n == 0)
      return;
    __uint128_t *left = andgate_left_buffer.data();
    __uint128_t *right = andgate_right_buffer.data();
    __uint128_t *gateout = andgate_out_buffer.data();

    std::vector<uint64_t> chi(task_n);
    uint64_t seed = mod(LOW64(chi_seed[thr_idx]));
    prg_coeff_gen_zk(chi.data(), seed, task_n);   // independent chi
    if (party == ALICE) {
      uint64_t A0, A1;
      uint64_t U = 0, V = 0;
      uint64_t a, b, ma, mb, mc;
      for (uint32_t i = start, k = 0; i < start + task_n; ++i, ++k) {
        a = VAL(left[i]);
        ma = MAC(left[i]);
        b = VAL(right[i]);
        mb = MAC(right[i]);
        mc = MAC(gateout[i]);
        A0 = mult_mod(ma, mb);
        A1 = add_mod(mult_mod(a, mb), mult_mod(b, ma));
        uint64_t tmp = PR - mc;
        A1 = add_mod(A1, tmp);
        U = add_mod(U, mult_mod(A0, chi[k]));
        V = add_mod(V, mult_mod(A1, chi[k]));
      }
      ret[2 * thr_idx] = U;
      ret[2 * thr_idx + 1] = V;
    } else {
      uint64_t B;
      uint64_t W = 0;
      uint64_t ka, kb, kc;
      for (uint32_t i = start, k = 0; i < start + task_n; ++i, ++k) {
        ka = MAC(left[i]);
        kb = MAC(right[i]);
        kc = MAC(gateout[i]);
        B = add_mod(mult_mod(ka, kb), mult_mod(kc, delta));
        W = add_mod(W, mult_mod(B, chi[k]));
      }
      ret[thr_idx] = W;
    }
  }

  /*
   * verify the output
   * open and check if the value equals 1
   */
  void reveal_send(const __uint128_t *output, uint64_t *value, int64_t len) {
    for (int64_t i = 0; i < len; ++i) {
      value[i] = VAL(output[i]);
      uint64_t mac = MAC(output[i]);
      auth_helper->store(mac); // TODO
    }
    io->send_data(value, len * sizeof(uint64_t));
  }

  void reveal_recv(const __uint128_t *output, uint64_t *value, int64_t len) {
    io->recv_data(value, len * sizeof(uint64_t));
    for (int64_t i = 0; i < len; ++i) {
      uint64_t mac = mult_mod(value[i], LOW64(delta));
      mac = add_mod(mac, MAC(output[i]));
      auth_helper->store(mac); // TODO
    }
  }

  void reveal_check_send(const __uint128_t *output, const uint64_t *value,
                         int64_t len) {
    std::vector<uint64_t> val_real(len);
    reveal_send(output, val_real.data(), len);
  }

  void reveal_check_recv(const __uint128_t *output, const uint64_t *val_exp,
                         int64_t len) {
    std::vector<uint64_t> val_real(len);
    reveal_recv(output, val_real.data(), len);
    if (memcmp(val_exp, val_real.data(), len * sizeof(uint64_t)) != 0)
      error("arithmetic reveal value not expected");
  }

  void reveal_check_zero(const __uint128_t *output, int64_t len) {
    for (int64_t i = 0; i < len; ++i) {
      uint64_t mac = MAC(output[i]);
      auth_helper->store(mac);
    }
  }

  /* ---------------------helper functions----------------------*/

  void delta_gen() {
    PRG prg;
    prg.random_data(&delta, sizeof(__uint128_t));
    extract_fp(delta);
  }

  void share_seed_gen(block *seed, uint32_t num) {
    block seed0;
    if (party == ALICE) {
      io->recv_data(&seed0, sizeof(block));
      PRG(&seed0).random_block(seed, num);
    } else {
      prg.random_block(&seed0, 1);
      io->send_data(&seed0, sizeof(block));
      PRG(&seed0).random_block(seed, num);
    }
  }

  // sender
  void refill_send(__uint128_t *yz, int64_t *cnt, int64_t sz) {
    draw_vole_((AuthValueFp *)yz, sz);
    *cnt = 0;
  }

  // recver
  void refill_recv(__uint128_t *yz, int64_t *cnt, int64_t sz) {
    draw_vole_((AuthValueFp *)yz, sz);
    *cnt = 0;
  }

  void compute_mu_prv(__uint128_t &ret, __uint128_t z1, __uint128_t *triple,
                      __uint128_t epsilon, __uint128_t sigma) {
    __uint128_t tmp1 = auth_mac_subtract(triple[2], z1);
    __uint128_t tmp2 = auth_mac_mul_const(triple[0], VAL(sigma));
    __uint128_t tmp3 = auth_mac_mul_const(triple[1], VAL(epsilon));
    __uint128_t tmp4 = mult_mod(VAL(epsilon), VAL(sigma));
    tmp1 = auth_mac_add(tmp1, tmp2);
    tmp1 = auth_mac_add(tmp1, tmp3);
    ret = auth_mac_add_const(tmp1, tmp4);
  }
  void compute_mu_vrf(__uint128_t &ret, __uint128_t z1, __uint128_t *triple,
                      __uint128_t epsilon, __uint128_t sigma) {
    __uint128_t tmp1 = auth_key_subtract(triple[2], z1);
    __uint128_t tmp2 = auth_key_mul_const(triple[0], sigma);
    __uint128_t tmp3 = auth_key_mul_const(triple[1], epsilon);
    __uint128_t tmp4 = mod(epsilon * sigma, pr);
    tmp1 = auth_key_add(tmp1, tmp2);
    tmp1 = auth_key_add(tmp1, tmp3);
    ret = auth_key_add_const(tmp1, tmp4);
  }

  __uint128_t compute_mu_prv_opt(__uint128_t la, __uint128_t lb,
                                 __uint128_t eta_wr, __uint128_t *triple) {
    __uint128_t tmp1 = auth_mac_subtract(triple[2], eta_wr);
    __uint128_t tmp2 = auth_mac_mul_const(triple[0], VAL(lb));
    __uint128_t tmp3 = auth_mac_mul_const(triple[1], VAL(la));
    __uint128_t tmp4 = mult_mod(VAL(la), VAL(lb));
    tmp1 = auth_mac_add(tmp1, tmp2);
    tmp1 = auth_mac_add(tmp1, tmp3);
    return auth_mac_add_const(tmp1, tmp4);
  }

  __uint128_t compute_mu_vrf_opt(__uint128_t la, __uint128_t lb,
                                 __uint128_t eta_wr, __uint128_t *triple) {
    __uint128_t tmp1 = auth_key_subtract(triple[2], eta_wr);
    __uint128_t tmp2 = auth_key_mul_const(triple[0], lb);
    __uint128_t tmp3 = auth_key_mul_const(triple[1], la);
    __uint128_t tmp4 = mult_mod((uint64_t)la, (uint64_t)lb);
    tmp1 = auth_key_add(tmp1, tmp2);
    tmp1 = auth_key_add(tmp1, tmp3);
    return auth_key_add_const(tmp1, tmp4);
  }

  // prover: add 2 IT-MACs
  // return: [a] + [b]
  __uint128_t auth_mac_add(__uint128_t a, __uint128_t b) {
    block res = _mm_add_epi64((block)a, (block)b);
    return (__uint128_t)vec_mod(res);
  }

  // prover: add a IT-MAC with a constant
  // return: [a] + c (adds c into the val lane only; mac unchanged)
  __uint128_t auth_mac_add_const(__uint128_t a, __uint128_t c) {
    block cc = makeBlock(0, c);   // (high=0=mac-delta, low=c=val-delta)
    cc = _mm_add_epi64((block)a, cc);
    return (__uint128_t)vec_mod(cc);
  }

  // prover: subtract 2 IT-MACs
  // return: [a] - [b]
  __uint128_t auth_mac_subtract(__uint128_t a, __uint128_t b) {
    block res = _mm_sub_epi64(PRs, (block)b);
    res = _mm_add_epi64((block)a, res);
    return (__uint128_t)vec_mod(res);
  }

  // prover: multiplies IT-MAC with a constatnt
  // return: c*[a]
  __uint128_t auth_mac_mul_const(__uint128_t a, uint64_t c) {
    return (__uint128_t)mult_mod((block)a, c);
  }

  // verifier: add 2 IT-MACs (mac-only on BOB; val=0 throughout)
  // return: [a] + [b]
  __uint128_t auth_key_add(__uint128_t a, __uint128_t b) {
    return MAKE_AUTH(0, add_mod(MAC(a), MAC(b)));
  }

  // verifier: add an IT-MAC with a constant — subtract Δ·c from the mac
  // (BOB's view of "adding c to the IT-MAC of value v" is to adjust
  // his mac by -Δ·c so that K = mac' + Δ·(v+c) = original K).
  __uint128_t auth_key_add_const(__uint128_t a, __uint128_t c) {
    uint64_t delta_c = mult_mod((uint64_t)c, (uint64_t)delta);
    uint64_t new_mac = add_mod(MAC(a), PR - delta_c);
    return MAKE_AUTH(0, new_mac);
  }

  // verifier: subtract 2 Keys
  // return: [a] - [b]
  __uint128_t auth_key_subtract(__uint128_t a, __uint128_t b) {
    uint64_t new_mac = add_mod(MAC(a), PR - MAC(b));
    return MAKE_AUTH(0, new_mac);
  }

  // verifier: multiplies Key (mac field) with a scalar constant c.
  // BOB's val=0 stays 0; mac becomes mac · c.
  __uint128_t auth_key_mul_const(__uint128_t a, __uint128_t c) {
    uint64_t new_mac = mult_mod(MAC(a), (uint64_t)c);
    return MAKE_AUTH(0, new_mac);
  }

  uint64_t communication() { return io->send_counter; }

  /* ---------------------debug functions----------------------*/

  void check_auth_mac(__uint128_t *auth, int64_t len) {
    if (party == ALICE) {
      io->send_data(auth, len * sizeof(__uint128_t));
    } else {
      std::vector<__uint128_t> auth_recv(len);
      io->recv_data(auth_recv.data(), len * sizeof(__uint128_t));
      for (int64_t i = 0; i < len; ++i) {
        uint64_t val   = VAL(auth_recv[i]);
        uint64_t mac_a = MAC(auth_recv[i]);
        uint64_t mac_b = MAC(auth[i]);
        uint64_t recomputed = mult_mod(val, (uint64_t)delta);
        recomputed = add_mod(recomputed, mac_b);
        if (mac_a != recomputed) {
          std::cout << "authenticated mac error at: " << i << std::endl;
          abort();
        }
      }
    }
  }

  void check_compute_mul(__uint128_t *a, __uint128_t *b, __uint128_t *c,
                         int64_t len) {
    if (party == ALICE) {
      io->send_data(a, len * sizeof(__uint128_t));
      io->send_data(b, len * sizeof(__uint128_t));
      io->send_data(c, len * sizeof(__uint128_t));
    } else {
      std::vector<__uint128_t> ar(len), br(len), cr(len);
      io->recv_data(ar.data(), len * sizeof(__uint128_t));
      io->recv_data(br.data(), len * sizeof(__uint128_t));
      io->recv_data(cr.data(), len * sizeof(__uint128_t));
      for (int64_t i = 0; i < len; ++i) {
        uint64_t product = mult_mod(VAL(ar[i]), VAL(br[i]));
        if (product != VAL(cr[i]))
          error("wrong product");
        uint64_t recomputed = mult_mod(product, (uint64_t)delta);
        recomputed = add_mod(recomputed, MAC(c[i]));
        if (recomputed != MAC(cr[i]))
          error("wrong mac");
      }
    }
  }
};
}  // namespace emp

#endif
