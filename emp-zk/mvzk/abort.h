#ifndef EMP_ZK_MVZK_ABORT_H__
#define EMP_ZK_MVZK_ABORT_H__
// Cooperative abort. Every party owns one control socket per peer, used for
// nothing else. A party that detects cheating calls mvzk_fail(): it prints the
// reason, tells every peer over the control sockets and exits with code 1. A
// watchdog thread per party polls the control sockets; on an abort message it
// prints "peer j aborted: <reason>" and exits with code 2, so nobody is left
// blocking on a data socket or dying with a misleading socket error. On a
// normal finish the party sends DONE on its control sockets and stops the
// watchdog; a control socket closing before DONE is reported as a crash.
#include <emp-tool/emp-tool.h>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>
#include <poll.h>
#include <unistd.h>
#include <sys/socket.h>

namespace emp {
namespace mvzk {

template <typename IO>
class AbortGuard {
public:
  static AbortGuard *current;
  enum : uint32_t { ABORT = 1, DONE = 2 };

  int id = 0, P = 0;
  std::vector<IO *> ctrl;       // ctrl[j]: control socket to party j (nullptr for self)
  int wake[2] = {-1, -1};
  std::thread th;
  std::atomic<bool> aborting{false}, stopped{false};

  AbortGuard(int id_, int P_, std::vector<IO *> ctrl_) : id(id_), P(P_), ctrl(std::move(ctrl_)) {
    if (::pipe(wake) != 0) error("mvzk AbortGuard: pipe");
    th = std::thread([this]() { run(); });
    current = this;
  }
  ~AbortGuard() { stop(); if (current == this) current = nullptr; }

  // normal completion: tell the peers, then wait until every peer has also
  // finished (or aborted, in which case the watchdog exits the process), so
  // e.g. the prover learns the verifiers' verdict before returning.
  void stop(bool wait_peers = true) {
    if (stopped.exchange(true)) return;
    for (int j = 0; j < P; ++j) if (j != id && ctrl[j]) send_msg(ctrl[j]->sock, DONE, "");
    if (!wait_peers) {
      char c = 1;
      if (::write(wake[1], &c, 1) < 0) {}
    }
    if (th.joinable()) th.join();
    ::close(wake[0]); ::close(wake[1]);
  }

  [[noreturn]] void fail(const char *what) {
    if (aborting.exchange(true)) { std::_Exit(1); }
    std::printf("mvzk: party %d aborting: %s\n", id, what);
    std::fflush(stdout);
    for (int j = 0; j < P; ++j) if (j != id && ctrl[j]) send_msg(ctrl[j]->sock, ABORT, what);
    std::_Exit(1);
  }

private:
  static bool io_full(int fd, void *buf, std::size_t n, bool write) {
    char *p = (char *)buf;
    while (n > 0) {
      ssize_t r = write ? ::send(fd, p, n, MSG_NOSIGNAL) : ::recv(fd, p, n, 0);
      if (r > 0) { p += r; n -= (std::size_t)r; continue; }
      if (r == 0) return false;
      if (errno == EINTR) continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        struct pollfd pf = {fd, (short)(write ? POLLOUT : POLLIN), 0};
        ::poll(&pf, 1, -1);
        continue;
      }
      return false;
    }
    return true;
  }
  static void send_msg(int fd, uint32_t code, const std::string &reason) {
    uint32_t hdr[2] = {code, (uint32_t)reason.size()};
    if (!io_full(fd, hdr, sizeof(hdr), true)) return;
    if (!reason.empty()) io_full(fd, (void *)reason.data(), reason.size(), true);
  }

  void run() {
    std::vector<struct pollfd> pfds;
    std::vector<int> who;
    for (int j = 0; j < P; ++j) {
      if (j == id || !ctrl[j]) continue;
      pfds.push_back({ctrl[j]->sock, POLLIN, 0});
      who.push_back(j);
    }
    pfds.push_back({wake[0], POLLIN, 0});
    who.push_back(-1);
    while (pfds.size() > 1) {
      if (::poll(pfds.data(), pfds.size(), -1) < 0) { if (errno == EINTR) continue; return; }
      for (std::size_t q = 0; q < pfds.size(); ++q) {
        if (!(pfds[q].revents & (POLLIN | POLLHUP | POLLERR))) continue;
        if (who[q] < 0) return;                       // stop() requested
        int j = who[q];
        uint32_t hdr[2];
        bool ok = io_full(pfds[q].fd, hdr, sizeof(hdr), false);
        std::string reason;
        if (ok && (hdr[1] > 4096 || (hdr[0] != ABORT && hdr[0] != DONE))) ok = false;   // not our framing
        if (ok && hdr[1] > 0) { reason.resize(hdr[1]); ok = io_full(pfds[q].fd, &reason[0], hdr[1], false); }
        if (!ok) {
          if (aborting.load()) return;
          std::printf("mvzk: party %d: peer %d closed its control channel without finishing (crashed?)\n", id, j);
          std::fflush(stdout);
          std::_Exit(2);
        }
        if (hdr[0] == ABORT) {
          if (aborting.load()) return;              // we are aborting ourselves
          std::printf("mvzk: party %d: peer %d aborted: %s\n", id, j, reason.c_str());
          std::fflush(stdout);
          std::_Exit(2);
        }
        // DONE: this peer finished normally; stop watching it
        pfds.erase(pfds.begin() + (long)q); who.erase(who.begin() + (long)q);
        --q;
      }
    }
  }
};
template <typename IO> AbortGuard<IO> *AbortGuard<IO>::current = nullptr;

// protocol-level failure: cooperative abort if a guard is installed, else emp's error()
template <typename IO>
[[noreturn]] inline void mvzk_fail(const char *what) {
  if (AbortGuard<IO>::current) AbortGuard<IO>::current->fail(what);
  error(what);
  std::_Exit(1);
}

}  // namespace mvzk
}  // namespace emp
#endif
