#ifndef EMP_ZK_MVZK_INT_FP_H__
#define EMP_ZK_MVZK_INT_FP_H__
// IntFp-style wire type for the multi-verifier ZK backend: every party runs
// the same circuit code,
//     IntFp a(7, ALICE), b(11, ALICE), c(5, PUBLIC);
//     IntFp d = a * b + c * 3;   d.reveal(82);
// A wire is a handle to an immutable slot. On the prover a slot holds the
// value. On a verifier it holds the authenticated share once its packed
// sharing has arrived (every k-th wire); until then a linear combination of
// pending wires is kept symbolically and resolved when a multiplication or a
// reveal needs it, so no flush is ever forced and packing stays full.
#include "emp-zk/mvzk/zk/backend.h"
#include <memory>
#include <vector>

namespace emp {
namespace mvzk {

template <typename IO>
class MvzkExec {
public:
  using T = FP59;
  using S = FP59x2;
  using AS = AuthShareT<T>;
  struct Slot {
    T val;                                                    // prover
    AS sh;                                                    // verifier, valid iff ready
    bool ready = false;
    std::vector<std::pair<T, std::shared_ptr<Slot>>> lin;    // verifier: pending sum coef * child
    T pub;                                                    //           + public constant
  };
  using SlotP = std::shared_ptr<Slot>;

  static MvzkExec *exec;

  MvzkBackend<IO, T, S> backend;
  int party;
  bool prover;
  std::size_t n;
  std::vector<SlotP> hold;      // slots of the current packed sharing (kept alive until filled)
  uint64_t seenBatches = 0;

  MvzkExec(int party_, std::size_t threads, std::vector<IO **> ios, std::size_t log_n, std::size_t log_k,
           std::size_t vole_per_round, std::size_t peer_par = 0, std::vector<IO *> ctrl = {})
      : backend((std::size_t)party_, threads, ios), party(party_) {
    n = (std::size_t)1 << log_n;
    prover = ((std::size_t)party_ == n);
    backend.param(log_n, log_k, vole_per_round, peer_par);
    if (!ctrl.empty()) backend.set_abort_channels(std::move(ctrl));
  }

  // ---- wires ----
  SlotP feed(uint64_t v) {
    auto s = std::make_shared<Slot>();
    if (prover) { s->val = T(v); s->ready = true; backend.auth_val_input(s->val); }
    else { backend.auth_val_input(&s->sh, &s->ready); hold.push_back(s); }
    afterOp();
    return s;
  }
  SlotP pub(uint64_t v) {
    auto s = std::make_shared<Slot>();
    s->ready = true;
    if (prover) s->val = T(v);
    else s->sh = pubShare(T(v));
    return s;
  }
  // sum_i coef_i * x_i + c
  SlotP linear(std::vector<std::pair<T, SlotP>> terms, T c) {
    auto s = std::make_shared<Slot>();
    if (prover) {
      T acc = c;
      for (auto &t : terms) acc = acc + t.first * t.second->val;
      s->val = acc; s->ready = true;
      return s;
    }
    bool all_ready = true;
    for (auto &t : terms) if (!t.second->ready) { all_ready = false; break; }
    if (all_ready) { s->sh = evalLinear(terms, c); s->ready = true; }
    else { s->lin = std::move(terms); s->pub = c; }
    return s;
  }
  SlotP mult(SlotP a, SlotP b) {
    auto s = std::make_shared<Slot>();
    if (prover) {
      s->ready = true;
      backend.compute_mult(s->val, a->val, b->val);
    } else {
      MvzkExec *self = this;
      backend.compute_mult(&s->sh, [self, a, b](AS &l, AS &r) {
        self->materialize(a.get()); self->materialize(b.get());
        l = a->sh; r = b->sh;
      }, &s->ready);
      hold.push_back(s);
    }
    afterOp();
    return s;
  }

  // ---- outputs ----
  // open wires: the prover sends the values, verifiers check them against the MACs
  void reveal(const std::vector<SlotP> &w, std::vector<uint64_t> &out) {
    flush();
    std::vector<T> vals(w.size());
    if (prover) {
      for (std::size_t i = 0; i < w.size(); ++i) vals[i] = w[i]->val;
      backend.reveal_send(vals);
    } else {
      backend.reveal_recv(vals);
      checkClaimed(w, vals);
    }
    out.resize(w.size());
    for (std::size_t i = 0; i < w.size(); ++i) out[i] = vals[i].val;
  }
  // assert wires equal public values known to everyone
  bool revealCheck(const std::vector<SlotP> &w, const std::vector<uint64_t> &expected) {
    flush();
    std::vector<T> vals(w.size());
    for (std::size_t i = 0; i < w.size(); ++i) vals[i] = T(expected[i]);
    if (prover) {
      bool ok = true;
      for (std::size_t i = 0; i < w.size(); ++i) if (w[i]->val != vals[i]) ok = false;
      return ok;   // the verifiers will abort; let the prover see it too
    }
    checkClaimed(w, vals);
    return true;
  }

  void flush() { backend.flush_wires(); afterOp(); }
  void finalize() { backend.finalize(); afterOp(); }

  // ---- verifier internals ----
  AS pubShare(T c) {
    AS r;
    r.share = (party == 0) ? c : T(0, false);
    r.mac = T(0, false);
    r.key = (c * backend.delta()).negate();   // sum key = -c*Delta, so sum mac = sum key + Delta*c
    return r;
  }
  AS evalLinear(const std::vector<std::pair<T, SlotP>> &terms, T c) {
    AS acc = pubShare(c);
    for (auto &t : terms) {
      acc.share = acc.share + t.first * t.second->sh.share;
      acc.mac = acc.mac + t.first * t.second->sh.mac;
      acc.key = acc.key + t.first * t.second->sh.key;
    }
    return acc;
  }
  // resolve a pending linear expression (iteratively: chains can be long)
  void materialize(Slot *s) {
    if (s->ready) return;
    std::vector<Slot *> st{s};
    while (!st.empty()) {
      Slot *t = st.back();
      if (t->ready) { st.pop_back(); continue; }
      if (t->lin.empty()) error("mvzk IntFp: wire resolved before its packed sharing arrived (internal error)");
      Slot *child = nullptr;
      for (auto &c : t->lin) if (!c.second->ready) { child = c.second.get(); break; }
      if (child != nullptr) { st.push_back(child); continue; }
      t->sh = evalLinear(t->lin, t->pub);
      t->ready = true;
      t->lin.clear();
      st.pop_back();
    }
  }
  void checkClaimed(const std::vector<SlotP> &w, const std::vector<T> &vals) {
    std::vector<AS> sh(w.size());
    for (std::size_t i = 0; i < w.size(); ++i) { materialize(w[i].get()); sh[i] = w[i]->sh; }
    backend.check_public(sh, vals);
  }
  void afterOp() {
    if (prover) return;
    uint64_t b = backend.batches_done();
    if (b != seenBatches) { seenBatches = b; hold.clear(); }   // the batch just got filled
  }
};
template <typename IO> MvzkExec<IO> *MvzkExec<IO>::exec = nullptr;

template <typename IO>
class IntFpT {
public:
  using Exec = MvzkExec<IO>;
  typename Exec::SlotP s;

  IntFpT() {}
  // party == PUBLIC: constant; otherwise a witness fed by the prover (the
  // value is ignored on verifiers)
  IntFpT(uint64_t input, int party = PUBLIC) {
    s = (party == PUBLIC) ? Exec::exec->pub(input) : Exec::exec->feed(input);
  }

  IntFpT operator+(const IntFpT &rhs) const { return wrap(Exec::exec->linear({{FP59(1, false), s}, {FP59(1, false), rhs.s}}, FP59(0, false))); }
  IntFpT operator-(const IntFpT &rhs) const { return wrap(Exec::exec->linear({{FP59(1, false), s}, {FP59(1, false).negate(), rhs.s}}, FP59(0, false))); }
  IntFpT operator*(const IntFpT &rhs) const { return wrap(Exec::exec->mult(s, rhs.s)); }
  IntFpT operator+(uint64_t c) const { return wrap(Exec::exec->linear({{FP59(1, false), s}}, FP59(c))); }
  IntFpT operator-(uint64_t c) const { return wrap(Exec::exec->linear({{FP59(1, false), s}}, FP59(c).negate())); }
  IntFpT operator*(uint64_t c) const { return wrap(Exec::exec->linear({{FP59(c), s}}, FP59(0, false))); }
  IntFpT negate() const { return wrap(Exec::exec->linear({{FP59(1, false).negate(), s}}, FP59(0, false))); }

  uint64_t reveal() const {
    std::vector<uint64_t> out;
    Exec::exec->reveal({s}, out);
    return out[0];
  }
  bool reveal(uint64_t expect) const { return Exec::exec->revealCheck({s}, {expect}); }
  bool reveal_zero() const { return reveal(0); }

private:
  static IntFpT wrap(typename Exec::SlotP p) { IntFpT r; r.s = std::move(p); return r; }
};

template <typename IO>
inline void batch_feed(IntFpT<IO> *obj, const uint64_t *value, int64_t len) {
  for (int64_t i = 0; i < len; ++i) obj[i] = IntFpT<IO>(value[i], ALICE);
}
template <typename IO>
inline void batch_reveal(IntFpT<IO> *obj, uint64_t *value, int64_t len) {
  std::vector<typename MvzkExec<IO>::SlotP> w(len);
  for (int64_t i = 0; i < len; ++i) w[i] = obj[i].s;
  std::vector<uint64_t> out;
  MvzkExec<IO>::exec->reveal(w, out);
  std::copy(out.begin(), out.end(), value);
}
template <typename IO>
inline bool batch_reveal_check(IntFpT<IO> *obj, const uint64_t *expected, int64_t len) {
  std::vector<typename MvzkExec<IO>::SlotP> w(len);
  for (int64_t i = 0; i < len; ++i) w[i] = obj[i].s;
  return MvzkExec<IO>::exec->revealCheck(w, std::vector<uint64_t>(expected, expected + len));
}
template <typename IO>
inline bool batch_reveal_check_zero(IntFpT<IO> *obj, int64_t len) {
  std::vector<uint64_t> z(len, 0);
  return batch_reveal_check(obj, z.data(), len);
}

// party: verifiers 0..n-1, prover n; ios[j] -> channels to party j; ctrl[j]
// (optional) -> one extra socket per party for cooperative aborts (abort.h).
template <typename IO>
inline void setup_mvzk(int party, std::size_t threads, std::vector<IO **> ios, std::size_t log_n, std::size_t log_k,
                       std::size_t vole_per_round = (1ull << 20), std::size_t peer_par = 0,
                       std::vector<IO *> ctrl = {}) {
  MvzkExec<IO>::exec = new MvzkExec<IO>(party, threads, ios, log_n, log_k, vole_per_round, peer_par, std::move(ctrl));
}
// runs the batched multiplication check; verifiers abort on a cheating prover
template <typename IO>
inline void finalize_mvzk() {
  MvzkExec<IO>::exec->finalize();
  delete MvzkExec<IO>::exec;
  MvzkExec<IO>::exec = nullptr;
}

using IntFp = IntFpT<NetIO>;

}  // namespace mvzk
}  // namespace emp
#endif
