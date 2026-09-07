#ifndef EMP_ZK_ARITH_H__
#define EMP_ZK_ARITH_H__
#include "emp-zk/emp-zk-arith/conversion.h"
#include "emp-zk/emp-zk-arith/int_fp.h"
#include "emp-zk/emp-zk-arith/int_fp_vec.h"
#include "emp-zk/emp-zk-arith/ostriple.h"
#include "emp-zk/emp-zk-arith/polynomial.h"
#include "emp-zk/emp-zk-arith/triple_auth.h"
#include "emp-zk/emp-zk-arith/zk_fp_exec.h"
#include "emp-zk/emp-zk-arith/zk_fp_exec_prover.h"
#include "emp-zk/emp-zk-arith/zk_fp_exec_verifier.h"
#include "emp-zk/emp-zk-bool/zk_bool_base.h"

namespace emp {
using namespace std;

// Arithmetic-only setup (no bool<->arith conversion). `threads` sizes the
// FpOSTriple AND-triple-check pool and vole's inner F_p VOLE expansion pool
// (1 = single-threaded, wire-equivalent to the prior FpVOLE path).
// `vole_io` (optional): a second socket enabling the background sVOLE path (the
// sVOLE runs on it in a producer thread; the engine consumes via a pipe). The
// producer streams on demand and finalizes at teardown, so no size hint is
// needed — expected_vole is ignored when vole_io is set. Does NOT support
// bool<->arith conversion (use the single-socket overload for that).
// `vole_threads` (optional): worker count for the sVOLE's own pool, separate
// from `threads` (ostriple's checks / vectorized mul). In background mode the
// two run concurrently, so pick e.g. threads=vole_threads=cores/2 to avoid 2x
// oversubscription. vole_threads < 0 → same as `threads` (default).
inline void setup_zk_arith(BoolIO *io, int party, int threads = 1,
                           int64_t expected_vole = 0, BoolIO *vole_io = nullptr,
                           int vole_threads = -1) {
  if (party == ALICE) {
    ZKFpExec::zk_exec =
        new ZKFpExecPrv(io, threads, expected_vole, vole_io, vole_threads);
    FpPolyProof::fppolyproof =
        new FpPolyProof(ALICE, io,
                            ((ZKFpExecPrv *)(ZKFpExec::zk_exec))->ostriple);
  } else {
    ZKFpExec::zk_exec =
        new ZKFpExecVer(io, threads, expected_vole, vole_io, vole_threads);
    FpPolyProof::fppolyproof = new FpPolyProof(
        BOB, io, ((ZKFpExecVer *)(ZKFpExec::zk_exec))->ostriple);
  }
}

// Setup with bool<->arith conversion. `bool_sess` is the live ZKBoolSession the
// conversion shares (its engine / Δ); the caller keeps it alive until after
// finalize_zk_arith().
inline void setup_zk_arith(BoolIO *io, int party, ZKBoolSession &bool_sess,
                           int threads = 1) {
  setup_zk_arith(io, party, threads);
  if (party == ALICE) {
    EdaBits::conv = new EdaBits(
        bool_sess, io, ((ZKFpExecPrv *)(ZKFpExec::zk_exec))->ostriple);
  } else {
    EdaBits::conv = new EdaBits(
        bool_sess, io, ((ZKFpExecVer *)(ZKFpExec::zk_exec))->ostriple);
    EdaBits::conv->install_boolean(bool_sess.engine().delta);
  }
}

inline void finalize_zk_arith() {
  if (EdaBits::conv != nullptr)
    delete EdaBits::conv;
  delete FpPolyProof::fppolyproof;
  delete ZKFpExec::zk_exec;
}
}  // namespace emp

#endif
