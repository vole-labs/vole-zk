# Performance benchmarks: BUILD-ONLY. Built when EMP_ZK_BUILD_BENCHMARKS is ON,
# but NOT registered as ctest cases (they run at large / arg-scalable sizes and
# report throughput, not correctness). Run a benchmark two-party via the `run`
# script, e.g.
#   ./run ./build/bench/bench_bool_circuit_scalability
# Correctness for these protocols lives in ../test (the small-default drivers).
function(add_bench folder name)
    add_executable(bench_${folder}_${name} ${folder}/${name}.cpp)
    target_link_libraries(bench_${folder}_${name} PRIVATE emp-zk::emp-zk)
    set_target_properties(bench_${folder}_${name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bench")
endfunction()

# Boolean ZK
add_bench(bool input_scalability)
add_bench(bool circuit_scalability)
add_bench(bool f2k_scalability)
add_bench(bool memory_scalability)

# Arithmetic ZK
add_bench(arith input_scalability)
add_bench(arith circuit_scalability)
add_bench(arith field_bench)   # per-field throughput: tuned FP61 engine vs the generic engine (fp61g, fp107, p192, f2k)
