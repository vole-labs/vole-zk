// Local unit test: FP59 / FP59x2 arithmetic against 128-bit reference, NTT and
// packed-sharing conversions of Poly, Lagrange evaluation helpers.
#include <emp-tool/emp-tool.h>
#include "emp-zk/mvzk/fields/fp59.h"
#include "emp-zk/mvzk/fields/fp59x2.h"
#include "emp-zk/mvzk/utils/poly.h"
#include "emp-zk/mvzk/utils/lagrange.h"
#include <iostream>
using namespace emp;
using namespace emp::mvzk;

static uint64_t ref_mul(uint64_t a, uint64_t b) { return (uint64_t)(((unsigned __int128)a * b) % FP59::PR); }
static uint64_t ref_add(uint64_t a, uint64_t b) { return (uint64_t)(((unsigned __int128)a + b) % FP59::PR); }

int main() {
  PRG prg;
  int bad = 0;
  // ---- FP59 scalar ----
  for (int it = 0; it < 200000; ++it) {
    uint64_t a, b; prg.random_data(&a, 8); prg.random_data(&b, 8);
    FP59 fa(a), fb(b);
    if (fa.val != a % FP59::PR || fb.val != b % FP59::PR) { ++bad; break; }
    if ((fa * fb).val != ref_mul(fa.val, fb.val)) { ++bad; break; }
    if ((fa + fb).val != ref_add(fa.val, fb.val)) { ++bad; break; }
    if ((fa - fb).val != ref_add(fa.val, FP59::PR - fb.val)) { ++bad; break; }
    if (fa.val != 0 && (fa * fa.inv()).val != 1) { ++bad; break; }
    FP59 lazy(0, false); for (int r = 0; r < 16; ++r) lazy.add_raw(fa); lazy.reduce();
    if (lazy.val != ref_mul(fa.val, 16)) { ++bad; break; }
  }
  std::cout << "FP59 scalar: " << (bad ? "MISMATCH" : "ok") << std::endl;
  // ---- FP59x2 lanes ----
  for (int it = 0; it < 100000 && !bad; ++it) {
    uint64_t a0, a1, b0, b1, c; prg.random_data(&a0, 8); prg.random_data(&a1, 8);
    prg.random_data(&b0, 8); prg.random_data(&b1, 8); prg.random_data(&c, 8);
    FP59x2 A{FP59(a0), FP59(a1)}, B{FP59(b0), FP59(b1)}; FP59 C(c);
    FP59x2 m = A * C;
    if (m.getLow().val != ref_mul(FP59(a0).val, C.val) || m.getHigh().val != ref_mul(FP59(a1).val, C.val)) { ++bad; break; }
    FP59x2 s = A + B;
    if (s.getLow().val != ref_add(FP59(a0).val, FP59(b0).val) || s.getHigh().val != ref_add(FP59(a1).val, FP59(b1).val)) { ++bad; break; }
    FP59x2 d = A - B;
    if (d.getLow().val != ref_add(FP59(a0).val, FP59::PR - FP59(b0).val)) { ++bad; break; }
    FP59x2 lazy; for (int r = 0; r < 16; ++r) lazy.add_raw(A); lazy.reduce();
    if (lazy.getHigh().val != ref_mul(FP59(a1).val, 16)) { ++bad; break; }
  }
  std::cout << "FP59x2 lanes: " << (bad ? "MISMATCH" : "ok") << std::endl;
  // ---- Poly conversions (n=8, k=2 / n=16, k=4) ----
  for (std::size_t logn = 3; logn <= 5 && !bad; ++logn) {
    for (std::size_t logk = 1; logk < logn && !bad; ++logk) {
      Poly<FP59> poly(logk, logn);
      poly.initLagrangeTable();
      std::size_t n = (std::size_t)1 << logn, k = (std::size_t)1 << logk;
      // secrets -> shares -> secrets round trip
      std::vector<FP59> sec(k), sh, back;
      for (auto &s : sec) s.rand(prg);
      poly.nttEvalK2N(sh, sec);
      poly.nttEvalN2K(back, sh);
      for (std::size_t i = 0; i < k; ++i) if (back[i] != sec[i]) { ++bad; std::cout << "K2N/N2K mismatch n=" << n << " k=" << k << std::endl; break; }
      // lagrange table agrees with NTT conversion
      std::vector<FP59> lag; poly.lagrangeEvalN2K(lag, sh);
      for (std::size_t i = 0; i < k; ++i) if (lag[i] != sec[i]) { ++bad; std::cout << "lagrangeEvalN2K mismatch" << std::endl; break; }
      // additive decomposition: sum over parties of lagrangeEvalOne2K == secrets,
      // for a random degree-(n-1) sharing (random party values)
      std::vector<FP59> rnd(n), sum(k, FP59(0, false)), one;
      for (auto &r : rnd) r.rand(prg);
      for (std::size_t p = 0; p < n; ++p) { poly.lagrangeEvalOne2K(one, rnd[p], p); for (std::size_t i = 0; i < k; ++i) sum[i] = sum[i] + one[i]; }
      std::vector<FP59> viaNtt; poly.nttEvalN2K(viaNtt, rnd);
      for (std::size_t i = 0; i < k; ++i) if (sum[i] != viaNtt[i]) { ++bad; std::cout << "One2K decomposition mismatch" << std::endl; break; }
      // N2N: values at odd powers -> even powers, checked by direct evaluation
      // through the Lagrange interpolation at evalPoints2N[1]
      std::vector<FP59> ev; poly.nttEvalN2N(ev, rnd);
      FP59 direct(0, false);
      for (std::size_t j = 0; j < n; ++j) direct = direct + Poly<FP59>::lagrange_coeff(poly.evalPointsN, j, poly.evalPoints2N[1]) * rnd[j];
      if (ev[0] != direct) { ++bad; std::cout << "N2N mismatch" << std::endl; }
    }
  }
  std::cout << "Poly conversions: " << (bad ? "MISMATCH" : "ok") << std::endl;
  // ---- Lagrange (m = 16): shift points and coefficient evaluation ----
  if (!bad) {
    std::size_t m = 16;
    Lagrange<FP59> lag(m); lag.initLagrangeTable();
    std::vector<FP59> coeff(m + 1), vals(m + 1);
    for (auto &c : coeff) c.rand(prg);
    auto evalp = [&](FP59 x) { FP59 r(0, false), pw(1, false); for (auto &c : coeff) { r = r + c * pw; pw = pw * x; } return r; };
    for (std::size_t i = 0; i <= m; ++i) vals[i] = evalp(lag.evalPoints[i]);
    std::vector<FP59> shifted; lag.lagrangeEvalShiftPoints(shifted, vals);
    for (std::size_t i = 0; i < m; ++i) if (shifted[i] != evalp(lag.evalPoints[m + 1 + i])) { ++bad; std::cout << "Lagrange shift mismatch" << std::endl; break; }
    FP59 x; x.rand(prg);
    std::vector<FP59> lo, hi; lag.computeLagCoeff(lo, hi, x);
    FP59 acc(0, false); for (std::size_t i = 0; i <= m; ++i) acc = acc + lo[i] * vals[i];
    if (acc != evalp(x)) { ++bad; std::cout << "Lagrange coeff mismatch" << std::endl; }
    if (!lag.is_interpolation_point(FP59(3)) || lag.is_interpolation_point(FP59(2 * m + 5))) { ++bad; std::cout << "is_interpolation_point wrong" << std::endl; }
  }
  std::cout << "Lagrange: " << (bad ? "MISMATCH" : "ok") << std::endl;
  if (bad) error("mvzk fields/poly test failed");
  std::cout << "mvzk fields_poly: all checks passed" << std::endl;
  return 0;
}
