// Shared harness for the (n+1)-party mvzk tests: party 0..n-1 are verifiers,
// party n is the prover. Full mesh of NetIO channels, num_io per pair, lower id
// listens. usage: <binary> <party> <port> ...
#pragma once
#include <emp-tool/emp-tool.h>
#include <vector>
#include <string>
#include <cstdlib>
#include <algorithm>

namespace emp {
namespace mvzk {

struct MeshIO {
  std::vector<std::vector<NetIO *>> owned;
  std::vector<NetIO **> ios;   // ios[j] -> channels to party j (nullptr for self)
  std::vector<NetIO *> ctrl;   // ctrl[j] -> control socket to party j (cooperative abort)
  int P = 0;
  std::size_t num_io = 0;

  MeshIO(int party, int P_, int port, std::size_t num_io_) : P(P_), num_io(num_io_) {
    owned.assign(P, {});
    ios.assign(P, nullptr);
    ctrl.assign(P, nullptr);
    for (int j = 0; j < P; ++j) {
      if (j == party) continue;
      owned[j].resize(num_io + 1);   // data channels + one control socket
      int lo = std::min(party, j), hi = std::max(party, j);
      for (std::size_t i = 0; i <= num_io; ++i) {
        int port_ = port + (lo * P + hi) * (int)(num_io + 1) + (int)i;
        if (party < j) owned[j][i] = new NetIO(nullptr, port_, true);
        else           owned[j][i] = new NetIO("127.0.0.1", port_, true);
      }
      ios[j] = owned[j].data();
      ctrl[j] = owned[j][num_io];
    }
  }
  ~MeshIO() {
    for (auto &v : owned) for (auto *p : v) delete p;
  }
};

inline void parse_party_and_port(char **argv, int *party, int *port) {
  *party = std::atoi(argv[1]);
  *port = std::atoi(argv[2]);
}

}  // namespace mvzk
}  // namespace emp
