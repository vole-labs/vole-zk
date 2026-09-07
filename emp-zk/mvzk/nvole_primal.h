#ifndef EMP_ZK_MVZK_NVOLE_PRIMAL_H__
#define EMP_ZK_MVZK_NVOLE_PRIMAL_H__
// Programmable n-party VOLE for MVZK on vole's primal-LPN MVoleFp (vole/mvole.h):
// the paper's Protocol 1 as intended -- every pair runs a plain VoleTriple at
// the primal rate, a verifier reuses one programming seed towards all peers,
// the prover regenerates every u^i locally, and the verifiers run the
// paper's consistency check (fold with a fresh coin, zero-sharings,
// commit-and-open) that pins each verifier to a single value vector. Same
// interface as MvzkNVole (nvole.h, the committed-VOLE variant). One extend
// delivers about 10^7 correlations per party (Wolverine's F_p parameters).
#include <emp-tool/emp-tool.h>
#include "vole/mvole.h"
#include "emp-zk/mvzk/abort.h"
#include <vector>

namespace emp {
namespace mvzk {

template <typename IO, typename FP, typename FPS>
class MvzkNVolePrimal {
public:
  int id, n;
  std::size_t threads;
  MVoleFp<IO, FP, FPS> *mv = nullptr;
  FP delta;
  double t_last = 0;   // microseconds, last extend (incl. the consistency check)

  MvzkNVolePrimal(int id_, int n_, std::size_t threads_, std::vector<IO **> &ios)
      : id(id_), n(n_), threads(threads_) {
    mv = new MVoleFp<IO, FP, FPS>(id_, n_, threads_, ios);
    if (!is_prover()) delta = mv->delta;
  }
  ~MvzkNVolePrimal() { delete mv; }

  bool is_prover() const { return id == n; }
  void setup() { mv->setup(); }
  std::size_t usable() const { return mv->usable; }

  // Prover: secrets_all[i][0..usable) <- u^i for every verifier i.
  void extend_prover(std::vector<FP *> &secrets_all) {
    auto t0 = clock_start();
    mv->extend_local(secrets_all);
    t_last = time_from(t0);
  }
  // Verifier: u^id, M^id_j, K^id_j; then the consistency check of this round
  // (Protocol 1 steps 3-7 among the verifiers).
  void extend_verifier(FP *secrets, std::vector<FP *> &macs, std::vector<FP *> &keys) {
    auto t0 = clock_start();
    mv->extend(secrets, macs, keys);
    mv->check();
    t_last = time_from(t0);
  }
};

}  // namespace mvzk
}  // namespace emp
#endif
