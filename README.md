# EMP-zk
![build](https://github.com/vole-labs/vole-zk/workflows/build/badge.svg)
[![CodeQL](https://github.com/vole-labs/vole-zk/actions/workflows/codeql.yml/badge.svg)](https://github.com/vole-labs/vole-zk/actions/workflows/codeql.yml)

<img src="https://raw.githubusercontent.com/emp-toolkit/emp-readme/main/art/logo-full.jpg" width=300px/>

> **Which version do I want?**
>
> - **Existing projects pinned to a published release: stay on `v0.3.x`** —
>   upstream emp-zk's `python3 install.py --tool=v0.3.x --ot=v0.3.x --zk=v0.3.x`
>   reproduces the prior emp-zk line. This repository's `vole-backend`
>   branch is that line with its VOLE layer replaced by vole-labs/vole
>   (emp-tool / emp-ot 0.3.0 vendored through vole); it is slower than
>   `main` on Boolean circuits and kept only for 0.3-era API users.
> - **New projects, or willing to migrate: track `main`** — the C++20
>   BooleanContext line. `emp-zk-bool` is a native `BooleanContext`
>   (`ZKBoolContext`) driven by an explicit `ZKBoolSession` handle — no global
>   backend; gadgets receive the session and circuit values are
>   `Bit_T<ZKBoolContext>` / `Int_T<…>`. `emp-zk-arith` still keeps its own
>   `ZKFpExec::zk_exec` singleton (staged).
>
> The only dependency is [vole-labs/vole](https://github.com/vole-labs/vole),
> vendored as the git submodule `thirdparty/vole`; it carries emp-tool and
> emp-ot 1.0 as its own pinned submodules and both are built in-tree. vole
> provides the F_p and GF(2^128) VOLEs (`RVole`, `F2kVole`, wrapped by
> `emp-zk/vole_stream.h`); Boolean correlated OTs come from emp-ot's
> `SilentFerret` out of the same tree. No emp-tool / emp-ot install step is
> needed, and the `emp-ot` fork's `silent_svole.h` is no longer required.

Protocols
=====
The code in this repo implements a fast, scalable, communication-efficient zero-knowledge proof protocol for Boolean/arithmetic circuits and polynomials. The protocols are described in [Wolverine](https://eprint.iacr.org/2020/925), [Quicksilver](https://eprint.iacr.org/2021/076) and [Mystique](https://eprint.iacr.org/2021/730).

## Requirements

- CMake ≥ 3.21
- A C++20 compiler (GCC 11+ / Clang 14+)
- OpenSSL (≥ 1.1)
- a recursive submodule checkout (`thirdparty/vole` and, inside it,
  emp-tool / emp-ot 1.0)

## Build and install

```bash
git clone --recursive https://github.com/vole-labs/vole-zk.git
# or, in an existing checkout:  git submodule update --init --recursive
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
sudo cmake --install build      # respects CMAKE_INSTALL_PREFIX
```

The install step ships emp-zk together with the emp-tool / emp-ot targets and
the vole headers it was built against, so `find_package(emp-zk)` stays
self-contained. Pass `-DEMP_TOOL_NATIVE_ARCH=OFF` for a binary that is not
tuned to the build host.

## Consuming from another CMake project

After `cmake --install build`:

```cmake
find_package(emp-zk 1.0 REQUIRED)
target_link_libraries(my-app PRIVATE emp-zk::emp-zk)
```

The `emp-zk::emp-zk` target transitively pulls in `emp-ot::emp-ot` and
`emp-tool::emp-tool`.

## Test

```bash
ctest --test-dir build --output-on-failure
```

Tests under `test/bool/`, `test/arith/`, and `test/ram-zk/` exercise every
module end-to-end: Boolean / arithmetic ZK (single-socket and the
two-socket background-producer modes), polynomial / inner-product proofs,
SHA-256, edabit bool↔arith conversion, and RAM / ROM / set ZK. The VOLE
and COT primitives themselves are tested in `thirdparty/vole` and in
emp-ot. Two-party tests are driven by the top-level `./run` wrapper,
which picks a random port and starts party 1 then party 2 on localhost.
`arith_abconversion` carries the `slow` label (`ctest -LE slow` skips it).

Party and endpoint are read from the command line and environment:
`<binary> 1` is ALICE (prover, listens), `<binary> 2` is BOB (verifier,
connects); `EMP_PORT` sets the port (default 12345) and `EMP_PEER_IP` the
address BOB connects to (default 127.0.0.1). For a two-machine run:

```bash
EMP_PORT=12345 ./build/test_bool_example 1                      # host A
EMP_PORT=12345 EMP_PEER_IP=<host A> ./build/test_bool_example 2  # host B
```

## Threads, background producers, and sockets

Both engines take a thread count for their own work (batched checks,
vectorized gates) and a separate count for the correlation producer:
`ZKBoolSession(io, party, expected_cots, n_threads, cot_io, cot_threads)`
and `setup_zk_arith(io, party, threads, expected_vole, vole_io, vole_threads)`.

- With a second socket (`cot_io` / `vole_io`) the producer runs in a
  background thread on that socket and the engine drains a pipe, so
  correlation rounds overlap the proof instead of stalling it. Without
  one, rounds run inline on the main socket whenever the buffer empties.
- `vole_threads` / `cot_threads` size the producer's own worker pool. vole
  sends each worker's MPFSS trees on its own connection, so for
  `vole_threads > 1` the parties open `vole_threads - 1` extra TCP
  connections, negotiated over the primary socket on OS-assigned ports.
  Across machines, allow those ephemeral ports between the two hosts;
  with a non-`NetIO` channel (e.g. TLS) vole falls back to one worker.
- `expected_cots` still prepays the Boolean COTs (SilentFerret).
  `expected_vole` is accepted for API compatibility but vole has no
  prepay, so it has no effect.

## Multi-verifier ZK (`emp-zk/mvzk`)

`emp-zk/mvzk` implements the multi-verifier zero-knowledge protocol of
[Escudero, Polychroniadou, Song, Weng](https://eprint.iacr.org/2022/1750)
(one prover, `n` verifiers, up to `t = n - k` of them corrupt) over
F_p with p = 2^59 - 2^28 + 1, on top of vole's committed VOLE:

- `nvole.h` — programmable n-party VOLE (paper protocol Π_nVOLE) built
  from vole's `CVoleFp`: the prover seeds every verifier's VOLE input and
  reproduces it locally, every ordered pair of verifiers runs a committed
  VOLE, and the prover's published commitments bind each verifier to a
  single input across all its instances (the consistency check the
  original implementation left incomplete). Pairs are independent, so a
  verifier runs all its `n-1` peers concurrently and the prover its `n`
  local expansions (`peer_par` bounds that; each instance additionally
  uses `threads` threads for its LPN expansion).
- `zk/auth.h` — packed-Shamir reinterpretation of the VOLE outputs into
  authenticated additive sharings of `k` values at a time (Π_Prep);
  fresh Fiat-Shamir nonces after every VOLE extension.
- `zk/prover.h`, `zk/verifier.h`, `zk/compress.h` — wire sharing, the
  batched multiplication check (inner-product reduction, 16-way
  polynomial compression, Fiat-Shamir over all prover messages), a
  broadcast-consistency echo among the verifiers, and the final opening
  of the compressed triple with a zero-share-masked, commit-then-open MAC
  check (Π_Online).
- `zk/backend.h` — the low-level circuit API `MvzkBackend<IO, FP59, FP59x2>`:
  `param(log_n, log_k)`, `auth_val_input`, `compute_add`,
  `compute_mult`, `flush_wires`, `finalize`. Verifier-side outputs are
  filled when their packed sharing arrives (every `k`-th wire or at a
  flush); do not read them before that.
- `int_fp.h` — the `IntFp`-style wire type on top of it, same shape as
  `emp-zk-arith`'s `IntFp`: every party runs the same circuit code.
  Verifier wires are handles to immutable slots; a linear combination of
  wires whose packed sharing has not arrived yet is kept symbolically and
  resolved when a multiplication or a reveal needs it, so no flush is
  forced and packing stays full. Outputs are checked with a batched,
  zero-share-masked MAC check among the verifiers (`reveal`,
  `reveal(expected)`, `reveal_zero`, `batch_reveal*`). `int_fp_vec.h`
  adds `IntFpVec` with emp-zk-arith's element-wise API (`+ - *` with
  vectors, public scalars and public vectors, `operator[]`, `sum`, `dot`,
  `compose` / `decompose`, batched `reveal` / `reveal_check`); it is a
  convenience layer, packing is already done by the backend.

```cpp
#include "emp-zk/mvzk/mvzk.h"
using namespace emp::mvzk;
// party: verifiers 0..n-1, prover n; ios[j] -> >= max(2, threads) sockets to party j
setup_mvzk<NetIO>(party, threads, ios, log_n, log_k);   // n = 2^log_n, k = 2^log_k
IntFp a(7, ALICE), b(11, ALICE), c(5, PUBLIC);           // ALICE = prover's witness
IntFp d = a * b + c * 3 - a;                             // usable immediately on every party
d.reveal(85);                                            // verifiers abort if false
uint64_t v = (d * d).reveal();                           // opened value on all parties
finalize_mvzk<NetIO>();                                  // batched multiplication check
```

Failed checks abort cooperatively (`abort.h`): with one extra control
socket per pair (`set_abort_channels` / the `ctrl` argument of
`setup_mvzk`), the detecting party reports the reason to everyone and exits
with code 1, the others print `peer j aborted: <reason>` and exit with code
2, and `finalize` returns only once every party has finished, so the prover
learns the verdict. Without control sockets a failed check still exits the
detecting party, and its peers die on socket errors.

Tests live in `test/mvzk/` and are (n+1)-party processes on localhost,
started by the top-level `./run_mvzk <binary> <n+1> [args]` (party ids
`0..n-1` are verifiers, `n` is the prover); ctest registers them as
`mvzk_*`, including a soundness test with a cheating prover. Each pair of
parties needs `max(2, threads)` sockets, `port + (lo*P + hi)*num_io + i`.
Measured on a 32-core EPYC box with all parties on one host, one thread
per VOLE instance, 2^20 VOLE rounds (one extension each):

| verifiers `n` | `k` | circuit | VOLE extension | per mult gate |
|---|---|---|---|---|
| 4 | 2 | 2^18.6 mults | 4.8 s | 12.5 µs |
| 8 | 4 | 2^19.6 mults | 10.4 s | 13.6 µs |
| 16 | 4 | 64³ matmul (2^18 mults) | 43 s | 166 µs (extension mostly unused) |

The cost is the committed VOLE: one direction of one pair costs ~1.9 s
per 2^20 correlations (1.8 µs each, vole's native speed, half LPN
expansion and half the commitment), and every verifier runs 2(n-1)
directions. They run concurrently per peer, so on one machine per
verifier an extension takes about one pair's time (~4 s) plus the
prover's parallel local expansions (~1 s) regardless of `n`; co-located
on one box the runs above are bound by the total CPU work
(n · 2(n-1) · 1.9 s over 32 cores). Each instance can additionally use
`threads` threads for its LPN expansion. The ring variant of the paper is
not implemented.

## Benchmarks

`-DEMP_ZK_BUILD_BENCHMARKS=ON` builds the throughput drivers under
`build/bench/` (not registered with ctest):

```bash
./run ./build/bench/bench_bool_circuit_scalability  20 8   # log2(gates/100), threads
./run ./build/bench/bench_arith_circuit_scalability 24 8   # log2(multiplications), threads
```

## [Questions]

Please send email to Chenkai Weng (chenkai.weng@asu.edu).

## License

Licensed under the Apache License, Version 2.0 — see [LICENSE](LICENSE).
