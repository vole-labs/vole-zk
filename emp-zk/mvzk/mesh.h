#ifndef EMP_ZK_MVZK_MESH_H__
#define EMP_ZK_MVZK_MESH_H__
// All-to-all helpers among the n verifiers (party ids 0..n-1; id n is the
// prover). Every pair (i, j) has at least two channels ios[j][0], ios[j][1];
// party i sends to j on channel (j < i ? 0 : 1) and receives from j on the other
// one, so the two directions never share a socket and a party can send on a
// pool thread while receiving on the main thread without deadlock.
//
//   exchange_all  - send one buffer to every other verifier, receive theirs
//   echo_check    - broadcast consistency (paper: "each verifier hashes what it
//                   received and compares with the others"); abort on mismatch
//   zero_shares   - each verifier deals an additive sharing of 0 (paper
//                   Procedure 3 step 3); returns this party's share of the sum
//   nonces        - every verifier sends a fresh nonce to the prover, who
//                   relays the vector to all (paper Prep step 5, plus the relay
//                   the online cross-check needs)
#include <emp-tool/emp-tool.h>
#include <future>
#include <vector>
#include <cstring>

namespace emp {
namespace mvzk {

template <typename IO>
class Mesh {
public:
  std::size_t id, n;            // this verifier, number of verifiers
  std::vector<IO **> ios;
  ThreadPool *pool = nullptr;

  Mesh(std::size_t id_, std::size_t n_, std::vector<IO **> &ios_) : id(id_), n(n_), ios(ios_) {
    pool = new ThreadPool(1);
  }
  ~Mesh() { delete pool; }

  IO *send_ch(std::size_t j) { return ios[j][(j < id) ? 0 : 1]; }
  IO *recv_ch(std::size_t j) { return ios[j][(j < id) ? 1 : 0]; }

  // send `bytes` at send_buf to every other verifier; recv_buf[j] gets j's.
  void exchange_all(const void *send_buf, std::vector<std::vector<uint8_t>> &recv_buf,
                    std::size_t bytes) {
    recv_buf.assign(n, std::vector<uint8_t>());
    auto fut = pool->enqueue([this, send_buf, bytes]() {
      std::size_t j = (id + 1) % n;
      while (j != id) {
        send_ch(j)->send_data(send_buf, (int64_t)bytes);
        send_ch(j)->flush();
        j = (j + 1) % n;
      }
    });
    std::size_t j = (id + n - 1) % n;
    while (j != id) {
      recv_buf[j].resize(bytes);
      recv_ch(j)->recv_data(recv_buf[j].data(), (int64_t)bytes);
      j = (j + n - 1) % n;
    }
    fut.get();
  }

  // Broadcast-consistency check: abort unless every verifier holds the same digest.
  void echo_check(const block digest[2], const char *what) {
    std::vector<std::vector<uint8_t>> got;
    exchange_all(digest, got, 2 * sizeof(block));
    for (std::size_t j = 0; j < n; ++j) {
      if (j == id) continue;
      if (memcmp(got[j].data(), digest, 2 * sizeof(block)) != 0) error(what);
    }
  }

  // This party's share of sum_i <theta^i> where every theta^i is a fresh
  // additive sharing of zero dealt by verifier i; `cnt` values at once.
  template <typename T>
  void zero_shares(std::vector<T> &out, std::size_t cnt, PRG &prg) {
    std::vector<std::vector<T>> deal(n, std::vector<T>(cnt));
    std::vector<T> own(cnt, T(0, false));
    for (std::size_t c = 0; c < cnt; ++c) {
      T acc(0, false);
      for (std::size_t j = 0; j < n; ++j) {
        if (j == id) continue;
        deal[j][c].rand(prg);
        acc = acc + deal[j][c];
      }
      own[c] = acc.negate();   // own + sum(dealt) = 0
    }
    // exchange: sends differ per peer, so run the ring by hand
    auto fut = pool->enqueue([this, &deal, cnt]() {
      std::size_t j = (id + 1) % n;
      while (j != id) {
        send_ch(j)->send_data(deal[j].data(), (int64_t)(cnt * sizeof(T)));
        send_ch(j)->flush();
        j = (j + 1) % n;
      }
    });
    out = own;
    std::vector<T> buf(cnt);
    std::size_t j = (id + n - 1) % n;
    while (j != id) {
      recv_ch(j)->recv_data(buf.data(), (int64_t)(cnt * sizeof(T)));
      for (std::size_t c = 0; c < cnt; ++c) out[c] = out[c] + buf[c];
      j = (j + n - 1) % n;
    }
    fut.get();
  }
};

// Nonces: verifiers -> prover, prover relays the whole vector. Called by
// verifiers (id < n) and by the prover (id == n).
template <typename IO>
inline void nonces(std::size_t id, std::size_t n, std::vector<IO **> &ios,
                   std::vector<block> &all, PRG &prg) {
  all.resize(n);
  if (id == n) {
    for (std::size_t i = 0; i < n; ++i) ios[i][0]->recv_data(&all[i], sizeof(block));
    for (std::size_t i = 0; i < n; ++i) {
      ios[i][0]->send_data(all.data(), (int64_t)(n * sizeof(block)));
      ios[i][0]->flush();
    }
  } else {
    block c;
    prg.random_block(&c, 1);
    ios[n][0]->send_data(&c, sizeof(block));
    ios[n][0]->flush();
    ios[n][0]->recv_data(all.data(), (int64_t)(n * sizeof(block)));
    if (memcmp(&all[id], &c, sizeof(block)) != 0) error("mvzk: prover altered my nonce");
  }
}

}  // namespace mvzk
}  // namespace emp
#endif
