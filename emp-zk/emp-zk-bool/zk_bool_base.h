#ifndef EMP_ZK_BOOL_BASE_H__
#define EMP_ZK_BOOL_BASE_H__

// The emp-zk-bool proof engine — a standalone class (no emp-tool Backend
// inheritance, no global pointer) wrapped by ZKBoolContext (zk_context.h) and
// owned by ZKBoolSession (zk_session.h). By default one BoolIO* drives both
// the gate-level bool stream and Ferret's OT-extension data; with a second
// socket (`cot_io`) the Ferret runs on its own connection in a background
// producer thread (the bool analogue of arith's background sVOLE).
//
// Layout:
//   - zk_bool_base.h     — ZKBoolBase: shared state, the typed gate / I-O surface
//                          (public_block/xor_block + the virtual and_block /
//                          not_block / feed_bits / reveal_bits), and the AND-gate
//                          batch correctness-check entry point with virtual hooks
//                          for the role-specific check and aggregator.
//   - zk_bool_prover.h   — ZKBoolProver: ALICE-side methods (auth_compute_and,
//                          authenticated_bits_input, verify_output, finalize_macs,
//                          hooks) and the gate/I-O overrides routing to them.
//   - zk_bool_verifier.h — symmetric for the verifier.
//
// The triple-generation state and methods live directly on the engine
// hierarchy: shared state on the base, prover-specific methods in ZKBoolProver,
// verifier-specific in ZKBoolVerifier — the party split is by subclass, so no
// method carries runtime party dispatch (`if (party == ALICE) … else …`).

#include <emp-tool/emp-tool.h>
#include "emp-zk/vole_stream.h"   // F2kVoleStream; must precede emp-ot
#include "emp-ot/emp-ot.h"

#include "emp-zk/emp-zk-bool/zk_wire.h"
#include "emp-zk/emp-zk-bool/bool_io.h"
#include "emp-zk/emp-zk-bool/polynomial.h"
#include "emp-zk/emp-zk-arith/correlation_pipe.h"  // protocol-agnostic SPSC ring
#include <future>
#include <memory>
#include <thread>
#include <vector>

namespace emp {
using namespace std;

// The f2k wire type: an authenticated F(2^128) value (val, mac). Same
// storage as the sVOLE carrier; named for its role as a circuit wire.
using F2kAuthValue = AuthValueF2k;

// The emp-zk-bool proof engine: a standalone class (no emp-tool Backend, no
// global pointer) wrapped by ZKBoolContext (zk_context.h) and owned by
// ZKBoolSession (zk_session.h). It works purely in raw `block`s and never names
// the typed circuit layer, so it sits below ZKBoolContext / ZKInt in the include
// order. Party-specific gate and I/O behaviour is virtual on its own vtable: the
// prover /
// verifier subclasses implement and_block / not_block / feed_bits / reveal_bits.
class ZKBoolBase {
public:
  static constexpr int64_t CHECK_SZ = 1024 * 1024;

  int party;            // ALICE (prover) or BOB (verifier)

  // ---- Shared state (formerly OSTriple + ZKBoolBase) -----------
  block delta;          // Ferret global secret. Prover side just stores it.
  int64_t gid = 0;      // Number of AND gates issued.
  block pub_label[2];   // Labels for PUBLIC-input bits.

  // AND-gate triple buffer (ALICE-side: cleartext+MAC; BOB-side: keys only).
  int64_t check_cnt = 0;
  std::vector<block> andgate_out_buffer;
  std::vector<block> andgate_left_buffer;
  std::vector<block> andgate_right_buffer;
  // Masking-bit scratch for one vectorized-AND wave (<= CHECK_SZ entries):
  // the threaded per-gate compute writes here, the (ordered) bit send/recv
  // loop reads it. uint8_t, not vector<bool>, so workers write disjoint bytes.
  std::vector<uint8_t> and_bits_;

  // Below this per-call length the per-bit loops are cheaper serial than the
  // pool dispatch (the bool analogue of arith's feed threshold).
  static constexpr int64_t kFeedParMin = ((int64_t)1 << 20) - 1;

  // ---- f2k wire support (lazily initialised on first f2k op) ----------
  // The second wire type: authenticated F(2^128) values, sharing this
  // backend's Δ and its one Ferret. f2k_vole streams fresh authenticated
  // values for f2k_mul; the left/right val+mac buffers feed the batch
  // multiplication check (f2k_check_manage). The polynomial-product
  // variant lives in ZKPermProof, its sole caller. Conversion from bits
  // is a local Σ·Xⁱ map (same Δ), so only multiplication is interactive.
  bool f2k_ready = false;
  F2kVoleStream *f2k_vole = nullptr;
  int64_t f2k_buffer_sz = 0;
  int64_t f2k_authval_cnt = 0, f2k_check_cnt = 0;
  std::vector<AuthValueF2k> f2k_auth_buffer;       // pre-drawn VOLE values
  std::vector<block> f2k_left_val, f2k_left_mac;
  std::vector<block> f2k_rght_val, f2k_rght_mac;
  // Dedicated VOLE buffer for f2k_input (committing a cleartext field
  // element). Kept separate from the mul buffer so f2k_check's omac_base
  // bookkeeping — which assumes the last check_cnt VOLE draws are all mul
  // outputs — stays undisturbed. Filled lazily, refilled when exhausted.
  std::vector<AuthValueF2k> f2k_in_buffer;
  int64_t f2k_in_cnt = 0;

  GaloisFieldPacking pack;
  BoolIO  *io  = nullptr;
  PRG prg;
  SilentFerret *ferret = nullptr;
  PolyProof  *polyproof = nullptr;

  // Worker counts + pool for the parallel paths. `n_threads_` sizes the
  // ENGINE pool (AND-gate batch check, vectorized AND, threaded feeds,
  // PolyProof sums); `cot_threads_` INDEPENDENTLY sizes the correlation
  // producers (SilentFerret / f2k-VOLE begin-time expansion and the bulk
  // wire-free produce). In background mode the two run concurrently, so
  // splitting them avoids 2x oversubscription (e.g. threads=cores/2,
  // cot_threads=cores/2). cot_threads < 0 → same as n_threads (backward
  // compatible). 1 = single-threaded (pool_ null), wire-identical.
  int n_threads_ = 1;
  int cot_threads_ = 1;
  ThreadPool *pool_ = nullptr;

  // Split [0, cnt) across the worker pool; the last range runs on this thread.
  // Serial (no pool work) when n_threads_<=1 or the batch is smaller than the
  // worker count. The functor is joined before return, so capturing it by
  // reference in the tasks is safe.
  template <class F>
  void run_parallel_(F &&work, int64_t cnt) {
    if (n_threads_ <= 1 || pool_ == nullptr || cnt < (int64_t)n_threads_) {
      work((int64_t)0, cnt);
      return;
    }
    const int64_t per = cnt / n_threads_;
    std::vector<std::future<void>> fut;
    int64_t start = 0;
    for (int t = 0; t < n_threads_ - 1; ++t) {
      const int64_t lo = start, hi = start + per;
      fut.push_back(pool_->enqueue([&work, lo, hi]() { work(lo, hi); }));
      start += per;
    }
    work(start, cnt);
    for (auto &f : fut) f.get();
  }

  // ---- Optional phase profiling (EMP_PROFILE=1), printed at teardown ----
  double prof_ferret_begin_us = 0.0;  // SilentFerret begin() prepay (COT setup)
  double prof_check_us = 0.0;         // andgate batch correctness checks

  // ---- Threaded COT prefetch (the bool analogue of arith's fill_vole_) ----
  // Every COT the engine consumes (gates, inputs, OPE checks, PolyProof) is
  // served FIFO from this buffer, which refills in bulk via the SilentFerret
  // wire-free *threaded* produce (next_chunks_parallel) instead of the serial
  // per-gate next_n(). Because it serves the same deterministic COT stream in
  // the same order, consumption is byte-identical to the old per-gate path
  // (at cot_threads_==1 produce is the same serial next(); at >1 produce_range
  // yields the same COTs), so the wire transcript is unchanged.
  std::vector<block> cot_buf_;
  int64_t cot_pos_ = 0, cot_have_ = 0;

  // ---- Background COT producer (the bool analogue of arith's bg sVOLE) ----
  // With a second socket (cot_io) the SilentFerret runs on its OWN connection
  // in a dedicated producer thread, streaming COTs into a CorrelationPipe;
  // this thread never touches the Ferret / socket A after construction, and
  // every draw is served FIFO from the pipe instead of cot_buf_.
  bool bg_ = false;
  std::unique_ptr<CorrelationPipe<block>> pipe_;
  std::thread producer_;
  int64_t bg_batch_ = 1;              // COTs per pipe slot (one Ferret round)
  int cur_slot_ = -1;                 // pipe slot being drained (-1 = none)
  int64_t cur_off_ = 0;               // consume offset within cur_slot_

  // One fresh COT (hot path: one per AND gate).
  block draw_one_cot_() {
    if (bg_) {
      if (cur_slot_ < 0) bg_next_slot_();
      block r = pipe_->slot[cur_slot_][(size_t)cur_off_++];
      if (cur_off_ == bg_batch_) { pipe_->release(); cur_slot_ = -1; }
      return r;
    }
    if (cot_pos_ == cot_have_) cot_refill_();
    return cot_buf_[cot_pos_++];
  }
  // n fresh COTs, FIFO from the same stream (inputs / OPE / PolyProof).
  void draw_cot_(block *out, int64_t n) {
    int64_t done = 0;
    if (bg_) {
      while (done < n) {
        if (cur_slot_ < 0) bg_next_slot_();
        const int64_t take = std::min(n - done, bg_batch_ - cur_off_);
        memcpy(out + done, pipe_->slot[cur_slot_].data() + cur_off_,
               (size_t)take * sizeof(block));
        cur_off_ += take;
        done += take;
        if (cur_off_ == bg_batch_) { pipe_->release(); cur_slot_ = -1; }
      }
      return;
    }
    while (done < n) {
      if (cot_pos_ == cot_have_) cot_refill_();
      const int64_t take = std::min(n - done, cot_have_ - cot_pos_);
      memcpy(out + done, cot_buf_.data() + cot_pos_, (size_t)take * sizeof(block));
      cot_pos_ += take;
      done += take;
    }
  }
  void cot_refill_() {
    const int64_t chunk = ferret->chunk_size();
    const int64_t nch = (int64_t)cot_buf_.size() / chunk;
    ferret->next_chunks_parallel(cot_buf_.data(), nch, cot_threads_);
    cot_pos_ = 0;
    cot_have_ = nch * chunk;
  }
  void bg_next_slot_() {
    // About to (possibly) block waiting for the producer to fill the next
    // round-buffer, whose fill is a CROSS-PARTY Ferret round-trip. FLUSH the
    // main socket first so the peer receives everything up to our position,
    // finishes its round, and its producer joins that round-trip — otherwise
    // an unflushed tail here would reintroduce the cross-party deadlock.
    io->flush();
    cur_slot_ = pipe_->acquire_ready();
    cur_off_ = 0;
    if (cur_slot_ < 0)   // producer only stops at teardown; never mid-proof
      error("background COT pipe closed during a draw (internal error)");
  }

  // Output-MAC accumulator. Hash + scratch buffer; finalize at teardown.
  Hash auth_hash;
  vector<block> auth_tmp;

  // ---- Lifecycle ------------------------------------------------------

  // `expected_cots` sizes the SilentFerret prepay: pass the number of COTs the
  // proof will draw (≈ AND gates + authenticated inputs + check overhead) and
  // begin() ships ALL correction traffic + malicious checks up front, so the
  // whole proof's COT consumption is wire-free. 0 (the default) uses the
  // per-round streaming begin() — safe for an unknown circuit size, at the cost
  // of one COT-correction burst per ~15M-COT round.
  //
  // `cot_io` (optional): a SECOND socket, distinct from `io`. When provided,
  // the SilentFerret runs on it in a background producer thread and this
  // engine draws COTs from a pipe (see draw_cot_). The producer streams on
  // demand and stops at teardown, so NO size hint is needed — `expected_cots`
  // is ignored in this mode. nullptr = the default single-socket path.
  // `cot_threads` sizes the Ferret's own worker pool (cGGM expand / produce)
  // INDEPENDENTLY of `n_threads` (the engine's check / vectorized-gate pool);
  // cot_threads < 0 → same as n_threads (backward compatible).
  ZKBoolBase(int p, BoolIO *io_, int64_t expected_cots = 0, int n_threads = 1,
             BoolIO *cot_io = nullptr, int cot_threads = -1)
      : party(p), io(io_), n_threads_(n_threads < 1 ? 1 : n_threads) {
    cot_threads_ =
        (cot_threads < 0) ? n_threads_ : (cot_threads < 1 ? 1 : cot_threads);
    if (n_threads_ > 1) pool_ = new ThreadPool((size_t)n_threads_);
    bg_ = (cot_io != nullptr);
    // BoolIO inherits IOChannel publicly with the IOChannel subobject at
    // offset 0, so the cast is a no-op at runtime. Ferret now takes a
    // single IOChannel (post-unification with the other OT extensions).
    // cot_threads sizes SilentFerret's begin()-time expansion pool. The
    // Ferret lives on socket A (cot_io) in background mode, else on `io`.
    IOChannel *iochan = reinterpret_cast<IOChannel *>(bg_ ? cot_io : io_);
    ferret = new SilentFerret(3 - p, iochan, /*malicious=*/true,
                              tuning::ferret_b13, nullptr, cot_threads_);
    delta = ferret->Delta;           // Δ sampled in Ferret's ctor

    // Buffers for the QuickSilver AND-gate batch check (left/right inputs +
    // output MAC, folded once per CHECK_SZ gates with an FS-derived chi). The
    // out buffer holds only the per-gate output MAC now — the fresh COT comes
    // from ferret->next_n() at gate time, not a pre-draw.
    andgate_out_buffer.resize(CHECK_SZ);
    andgate_left_buffer.resize(CHECK_SZ);
    andgate_right_buffer.resize(CHECK_SZ);
    and_bits_.resize(CHECK_SZ);      // batched masking bits (vectorized AND)

    // Public-input label table — known to both parties by design.
    // PRP(1) key, distinct from ZKFpExec's PRP(0), so the two public
    // outputs live in disjoint pseudorandom domains. Both bits start
    // LSB-cleared; subclass ctor flips bit-1 of pub_label[1] (prover)
    // or xors zdelta (verifier).
    pub_label[0] = makeBlock(0, 0);
    pub_label[1] = makeBlock(0, 1);
    PRP(makeBlock(0, 1)).permute_block(pub_label, 2);
    pub_label[0] = clear_lsb(pub_label[0]);
    pub_label[1] = clear_lsb(pub_label[1]);

    polyproof = new PolyProof(p, io_, ferret);
    // Route PolyProof's COT draws through the same FIFO buffer so the single
    // shared COT stream stays in order (otherwise its next_n would desync the
    // cursor the prefetch buffer has already advanced). Share the engine pool
    // so its accumulate / batch-check sums split across the same workers.
    polyproof->draw_cot = [this](block *o, int64_t n) { draw_cot_(o, n); };
    polyproof->pool = pool_;
    polyproof->threads = n_threads_;

    if (bg_) {
      // Background mode: the producer thread owns the Ferret + socket A; this
      // thread never touches them again. `expected_cots` is not needed
      // (ignored).
      //
      // ROUND-SIZED ring (deadlock-free, mirroring arith's bg sVOLE). Each
      // pipe slot holds exactly one Ferret round (cots_per_round); the
      // producer fills one (a cross-party round-trip on socket A) while the
      // consumer drains another. Because the consumer always has a FULL round
      // buffered locally, it keeps driving the MAIN socket (gate bits /
      // corrections) throughout a background round-trip — so the peer never
      // starves for main-socket data, its consumer keeps advancing, and its
      // producer joins the cross-party round-trip. That, plus the flush in
      // bg_next_slot_ before a block, prevents the "one party's full local
      // buffer stalls the peer's peer-synchronous generation" deadlock.
      // BG_SLOTS (default 4): 2 = only ~1 FINISHED round banked (the other is
      // mid-production); 4 = one draining + one filling + two fully banked.
      // ~250 MB per extra slot at the b13 parameter.
      bg_batch_ = ferret->cots_per_round();   // one full round per buffer
      const int bg_slots = getenv("BG_SLOTS") ? atoi(getenv("BG_SLOTS")) : 4;
      pipe_ = std::make_unique<CorrelationPipe<block>>(bg_slots, bg_batch_);
      const int64_t bg_chunks = bg_batch_ / ferret->chunk_size();
      producer_ = std::thread([this, bg_chunks] {
        ferret->begin(ferret->cots_per_round()); // prepay round 0 (wire-free first fill)
        for (int i; (i = pipe_->acquire_free()) >= 0;) {
          // Fill one round with the THREADED produce (cot_threads_ workers) so
          // cot_threads actually parallelizes the bulk cGGM+LPN produce, not
          // just the rollover prepare. The cross-party rollover still happens
          // on the producer thread inside ensure_tree_available_ (socket A);
          // the parallel produce_range is wire-free.
          ferret->next_chunks_parallel(pipe_->slot[i].data(), bg_chunks,
                                       cot_threads_);
          pipe_->publish();
        }
        ferret->end();                 // local (checks already done at begin)
      });
    } else {
      // Default single-socket path: one persistent SilentFerret streaming
      // session for the whole proof, closed in the destructor.
      auto _tferret = clock_start();
      if (expected_cots > 0) ferret->begin(expected_cots);
      else                   ferret->begin();
      prof_ferret_begin_us += time_from(_tferret);

      // Threaded COT prefetch buffer (gap #3): 128 chunks (~1M COTs) per refill,
      // produced wire-free across cot_threads_ via SilentFerret::next_chunks_parallel.
      cot_buf_.resize((size_t)(128 * ferret->chunk_size()));
    }
  }

  virtual ~ZKBoolBase() {
    delete polyproof;   // PolyProof::batch_check draws COTs — stream still open
    if (bg_) {
      // Signal the producer to stop: both parties reach here after consuming
      // identically, so their producers are at the same round; finish() wakes
      // the producer's acquire_free() (returns -1 → it exits the loop and
      // runs the local ferret->end()). Any produced-but-unconsumed look-ahead
      // is simply discarded (it lives in an already-checked round).
      if (cur_slot_ >= 0) { pipe_->release(); cur_slot_ = -1; }
      pipe_->finish();
      if (producer_.joinable()) producer_.join();
    } else {
      ferret->end();    // close the persistent streaming session (final round + chi-fold check)
    }
    delete ferret;
    // f2k machinery (only allocated if some f2k op ran). The leftover
    // f2k batch check already happened in the subclass dtor — it needs
    // the live vtable and the open Ferret session — so here we only
    // free. delete nullptr is a no-op when f2k was unused.
    delete f2k_vole;
    delete pool_;
    if (getenv("EMP_PROFILE")) {
      fprintf(stderr,
              "[bool-prof p%d] ferret_begin=%.1fms andgate_check=%.1fms\n",
              party, prof_ferret_begin_us / 1000.0, prof_check_us / 1000.0);
    }
  }

  // ---- Helper bit ops -------------------------------------------------
  // The authenticated-bit format keeps the cleartext bit in the LSB and
  // the MAC in the upper 127 bits. clear_lsb / with_lsb / xor_delta_if
  // express that as named ops rather than ad-hoc choice[]/minusone tricks.
  static block clear_lsb(block b) {
    return b & makeBlock(0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFEULL);
  }
  // Branchless: bool → 0 or 1 directly.
  static block with_lsb(block b, bool v) {
    return clear_lsb(b) ^ makeBlock(0, static_cast<int64_t>(v));
  }
  // Branchless: -(int64_t)cond is 0 or all-ones; ANDing delta with that
  // mask gives delta or zero, which is then XORed unconditionally.
  block xor_delta_if(block b, bool cond) const {
    const int64_t m = -static_cast<int64_t>(cond);
    return b ^ (delta & makeBlock(m, m));
  }

  // ---- Gate surface (what ZKBoolContext's gate ops route to) ----------
  // Shared, non-virtual: public constants and XOR are party-agnostic.
  block public_block(bool b) const { return pub_label[b]; }
  block xor_block(block l, block r) const { return l ^ r; }
  uint64_t num_and() const { return gid; }

  // Party-specific gates / I-O, implemented by the prover / verifier subclass.
  virtual block and_block(block l, block r) = 0;
  // Vectorized AND: `len` INDEPENDENT gates out_i = l_i & r_i in one batched,
  // threaded call (no l_i/r_i may depend on another out_j of the same call).
  // `out` must NOT alias l/r: the wave's fresh COTs are drawn into `out`
  // before the inputs are read (the scalar gate has no such restriction).
  // Both parties must call it in lockstep with equal `len` — as with every
  // engine op — since the wave's draws precede the wave's gate bits. Under
  // matching calls the per-gate compute splits across the engine pool, the
  // masking bits ship through the same ordered send_bit stream, and the wire
  // bytes + batch-check folds are byte-identical to the scalar version.
  virtual void and_block(block *out, const block *l, const block *r,
                         int64_t len) = 0;
  virtual block not_block(block in) = 0;
  virtual void feed_bits(block *out, int from_party, const bool *in, size_t n) = 0;
  virtual void reveal_bits(bool *out, int to_party, const block *in, size_t n) = 0;

  // Commit `width` authenticated bits of `value`, ZERO-extended beyond bit 63,
  // into `out` via feed_bits. The f2k packing path uses this to commit a
  // cleartext field limb as prover-owned authenticated bits; it must NOT
  // sign-extend (which Int_T::constant would). Draws exactly `width` COTs.
  void authenticated_input_bits_zero_extend(block *out, int width,
                                            uint64_t value, int owner = ALICE) {
    auto b = std::make_unique<bool[]>((size_t)width);   // real bool[], no byte→bool cast
    for (int i = 0; i < width; ++i)
      b[(size_t)i] = (i < 64) ? (((value >> i) & 1) != 0) : false;
    feed_bits(out, owner, b.get(), (size_t)width);
  }

  // ---- AND-gate batch correctness check (threaded reduction) ---------
  //
  // Derives a Fiat-Shamir seed from the io hash, runs the role-specific
  // reduction over the check_cnt buffered triples in one pass, then
  // hands off to the role-specific aggregator that does the network
  // exchange + compare. Fires once per CHECK_SZ buffered ANDs.
  void andgate_correctness_check_manage() {
    auto _tprof = clock_start();
    io->flush();
    block seed = io->io->get_digest();
    const int T = n_threads_;
    // Per-worker partials: ALICE (A0_t, A1_t) at sum[2t..2t+1]; BOB B_t at
    // sum[2t]. GF(2^128) reduce is linear over XOR, so XOR-combining the
    // per-range reduced partials is bit-identical to one serial pass.
    std::vector<block> sum(2 * (size_t)T, zero_block);
    if (T <= 1 || pool_ == nullptr) {
      andgate_correctness_check(sum.data(), 0, 0, check_cnt, seed);
    } else {
      const int64_t task_base = check_cnt / T;
      block *sum_ptr = sum.data();
      std::vector<std::future<void>> fut;
      int64_t start = 0;
      for (int t = 0; t < T - 1; ++t) {
        const int64_t s = start;
        const int idx = t;
        fut.push_back(pool_->enqueue([this, sum_ptr, idx, s, task_base, seed]() {
          andgate_correctness_check(sum_ptr, idx, s, task_base, seed);
        }));
        start += task_base;
      }
      andgate_correctness_check(sum.data(), T - 1, start, check_cnt - start,
                                seed);
      for (auto &f : fut) f.get();
    }
    block agg[2] = {zero_block, zero_block};
    for (int t = 0; t < T; ++t) {
      agg[0] = agg[0] ^ sum[2 * t];
      agg[1] = agg[1] ^ sum[2 * t + 1];
    }
    andgate_correctness_aggregate(agg);
    io->flush();
    prof_check_us += time_from(_tprof);
  }

  // Reduction over the buffered triples [start, start+task_n). ALICE writes the
  // (Δ⁰, Δ¹) coefficients into ret[2*thr_idx .. 2*thr_idx+1]; BOB writes its
  // check polynomial into ret[2*thr_idx]. Each worker re-derives its chi slice
  // by seeking PRG(chi_seed) to `start`, so the split is bit-identical to a
  // single serial pass.
  virtual void andgate_correctness_check(block *ret, int thr_idx, int64_t start,
                                         int64_t task_n, block chi_seed) = 0;

  // Trailing role-specific aggregation: ALICE packs + sends `A_star`,
  // BOB receives and verifies with cmpBlock.
  virtual void andgate_correctness_aggregate(block *sum) = 0;

  // ---- f2k wire ops ---------------------------------------------------
  //
  // Authenticated F(2^128) arithmetic on (val, mac) block pairs. Linear
  // ops (f2k_add_const) are local; f2k_mul is interactive and buffers its
  // triples for the batch check (f2k_check_manage), which fires once per
  // f2k_buffer_sz multiplications and again at teardown. (The degree-N
  // product variant lives in ZKPermProof.)

  // Allocate the f2k stream + buffers on first use; pure-bool proofs never
  // pay for it. The f2k VOLE shares this backend's Δ (BOB pins it); its
  // own inner Ferret keeps its wire bytes separate from the bit Ferret.
  void f2k_init() {
    if (f2k_ready) return;
    // GF(2^128) VOLE from vole-labs/vole, keyed with this engine's Delta on
    // the verifier. cot_threads_ sizes vole's expansion pool (a correlation
    // producer, so it shares the Ferret's budget, not the engine pool's).
    f2k_vole = new F2kVoleStream(party, io, cot_threads_,
                                 party == BOB ? ferret->Delta : zero_block);
    // Refill granularity of the f2k buffers (vole serves any length); the
    // batch check fires once per buffer, as before.
    f2k_buffer_sz = 1 << 20;
    f2k_auth_buffer.resize(f2k_buffer_sz);
    f2k_left_val.resize(f2k_buffer_sz);
    f2k_left_mac.resize(f2k_buffer_sz);
    f2k_rght_val.resize(f2k_buffer_sz);
    f2k_rght_mac.resize(f2k_buffer_sz);
    f2k_in_buffer.resize(f2k_buffer_sz);
    f2k_in_cnt = f2k_buffer_sz;        // sentinel: refill on first f2k_input
    f2k_ready = true;
    f2k_pre_buffer_refill();
  }

  // Commit a cleartext F(2^128) value as an authenticated wire (the f2k
  // analogue of authenticated-bit input). `v` is the cleartext on the
  // prover; the verifier's `v` argument is ignored and its returned val
  // lane is zero. Draws a fresh VOLE pair from the dedicated input buffer
  // and ships the masking difference so the wire carries `v` under the
  // shared Δ: mac_A == key_B ^ v·Δ. Party-agnostic signature.
  F2kAuthValue f2k_input(block v) {
    f2k_init();
    if (f2k_in_cnt == f2k_buffer_sz) {
      f2k_vole->run(f2k_in_buffer.data(), f2k_buffer_sz);
      f2k_in_cnt = 0;
    }
    AuthValueF2k r = f2k_in_buffer[f2k_in_cnt++];
    if (party == ALICE) {
      block diff = v ^ r.val;
      io->send_data(&diff, sizeof(block));
      return AuthValueF2k{ v, r.mac };
    }
    block diff;
    io->recv_data(&diff, sizeof(block));
    gfmul(delta, diff, &diff);
    return AuthValueF2k{ zero_block, r.mac ^ diff };
  }

  // Bulk-refill the pre-drawn VOLE buffer (one chunk-aligned run, so no
  // leftover) and reset the consume cursor.
  void f2k_pre_buffer_refill() {
    f2k_vole->run(f2k_auth_buffer.data(), f2k_buffer_sz);
    f2k_authval_cnt = 0;
  }

  // Pack a cleartext F(2^128) value v into the MAC layout the polynomial
  // product expects (Σ vᵢ·Xⁱ over the 128 bits of v, via the 65-bit
  // lo/hi SignedInt feed).
  block f2k_pack_v(block v) {
    uint64_t low  = _mm_extract_epi64(v, 0);
    uint64_t high = _mm_extract_epi64(v, 1);
    // Commit 65 zero-extended authenticated bits per limb. Only the low 64 are
    // packed, but the 65th is still drawn (one COT each) so Ferret consumption —
    // and the honest-path transcript — stays byte-identical to the old
    // SignedInt(65, ., ALICE) path this replaces.
    block lowbits[65], highbits[65], packbuf[128], m;
    authenticated_input_bits_zero_extend(lowbits, 65, low, ALICE);
    authenticated_input_bits_zero_extend(highbits, 65, high, ALICE);
    memcpy(packbuf,      lowbits,  64 * sizeof(block));
    memcpy(packbuf + 64, highbits, 64 * sizeof(block));
    pack.packing(&m, packbuf);
    return m;
  }

  // Bundle a (cleartext-field, mac) pair into an f2k wire. The cleartext
  // val is meaningful only on the prover; the verifier's val lane is
  // forced to zero. This is the bit→f2k conversion's output shape — the
  // mac is already Σ wireᵢ·Xⁱ — so callers can hand the same code path the
  // wire on both sides without a party branch.
  F2kAuthValue f2k_wire(block val, block mac) const {
    return AuthValueF2k{ party == ALICE ? val : zero_block, mac };
  }

  // Local linear f2k ops (no VOLE, no communication, party-agnostic): the
  // val/mac lanes are both linear in the wire, so scaling by a *public*
  // field constant or adding two wires is just the same gfmul / XOR on each
  // share. Used to collapse a multi-block element into one via a public
  // random linear combination Σ cⱼ·Bⱼ before the permutation product.
  F2kAuthValue f2k_mul_const(const F2kAuthValue &a, block c) const {
    F2kAuthValue r;
    gfmul(c, a.val, &r.val);
    gfmul(c, a.mac, &r.mac);
    return r;
  }
  F2kAuthValue f2k_add(const F2kAuthValue &a, const F2kAuthValue &b) const {
    return AuthValueF2k{ a.val ^ b.val, a.mac ^ b.mac };
  }

  // Role-specific f2k arithmetic + batch check (implemented by the
  // prover / verifier subclasses). Wires are F2kAuthValue (val, mac).
  virtual void f2k_add_const(F2kAuthValue &out, const F2kAuthValue &in,
                             block c) = 0;
  virtual void f2k_mul(F2kAuthValue &out, const F2kAuthValue &a,
                       const F2kAuthValue &b) = 0;
  virtual block f2k_mul_v(int64_t N, const block *vals) = 0;
  virtual void f2k_check_manage() = 0;
};

} // namespace emp

#include "emp-zk/emp-zk-bool/zk_bool_prover.h"
#include "emp-zk/emp-zk-bool/zk_bool_verifier.h"

#endif
