# EMP-zk
![build](https://github.com/emp-toolkit/emp-zk/workflows/build/badge.svg)
[![CodeQL](https://github.com/emp-toolkit/emp-zk/actions/workflows/codeql.yml/badge.svg)](https://github.com/emp-toolkit/emp-zk/actions/workflows/codeql.yml)

<img src="https://raw.githubusercontent.com/emp-toolkit/emp-readme/main/art/logo-full.jpg" width=300px/>

> **Which version do I want?**
>
> - **Existing projects pinned to a published release: stay on `v0.3.x`** —
>   `python3 install.py --tool=v0.3.x --ot=v0.3.x --zk=v0.3.x`
>   reproduces the prior emp-zk line. Bug fixes will be backported.
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

Tests under `test/bool/`, `test/arith/`, `test/vole/`, and `test/ram/`
exercise every module end-to-end: Boolean / arithmetic ZK,
polynomial / inner-product proofs, SHA-256 + LowMC circuits, edabit
bool↔arith conversion, VOLE bootstrap (cope / lpn / base_svole /
vole_triple / vole_f2k_triple), and RAM ZK (read-only, read-write,
extended). Two-party tests are driven by the top-level `./run`
wrapper (spawns party 1 then party 2 on localhost).

For a two-machine run: `./bin/test_bool_<name> 1 <port>` on host A and
`./bin/test_bool_<name> 2 <port>` on host B; edit the test source if
the IP needs to be other than `127.0.0.1`.

## Performance

The test is done by two AWS EC2 m5.2xlarge servers with throttled network.

### Throughput of circuit-based ZK protocol

All values are "million gates per second".

#### Boolean circuits

|Threads|10 Mbps|20 Mbps|30 Mbps|50 Mbps|Localhost|
|-------|-------|-------|-------|-------|---------|
|1|5.1|7.8|8.6|8.6|8.6|
|2|6|10|12.9|14.3|13.6|
|3|6.3|10.9|14.5|17.3|18|
|4|6.4|11.4|15.1|19|19.4|

#### Arithmetic circuits

|Threads|100 Mbps|500 Mbps|1 Gbps|2 Gbps|Localhost|
|-------|-------|-------|-------|-------|---------|
|1|1.4|4.8|6.8|7.8|7.8|
|2|1.4|5.6|8.7|10.2|10.4|
|3|1.4|5.9|9.3|11.7|12.5|

(Numbers measured on the v0.3.x line; `main` runs the same protocols,
so re-measured numbers should be in the same ballpark.)

## [Acknowledgement, Reference, and Questions](https://github.com/emp-toolkit/emp-readme/blob/main/README.md#citation)

Please send email to Xiao Wang (wangxiao1254@gmail.com).

## License

Licensed under the Apache License, Version 2.0 — see [LICENSE](LICENSE).
