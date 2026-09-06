function(add_test_case folder name)
    set(target test_${folder}_${name})
    add_executable(${target} ${folder}/${name}.cpp)
    target_link_libraries(${target} PRIVATE emp-zk::emp-zk)
    set_target_properties(${target} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
    add_test(NAME ${folder}_${name}
             COMMAND ${target}
             WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
endfunction()

function(add_test_case_with_run folder name)
    set(target test_${folder}_${name})
    add_executable(${target} ${folder}/${name}.cpp)
    target_link_libraries(${target} PRIVATE emp-zk::emp-zk)
    set_target_properties(${target} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
    add_test(NAME ${folder}_${name}
             COMMAND ${PROJECT_SOURCE_DIR}/run $<TARGET_FILE:${target}>
             WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
endfunction()

# Boolean ZK
add_test_case_with_run(bool example)
# A BooleanContext circuit run in ZK (ZKBoolContext / ZKBoolSession), validated
# bit-for-bit against a ClearCtx replay of the same circuit.
add_test_case_with_run(bool test_context_zk)
add_test_case_with_run(bool bool_io)
add_test_case_with_run(bool perm_proof)
add_test_case_with_run(bool polynomial)
add_test_case_with_run(bool inner_prdt)
# ZK SHA-256 on the IR-replay model: the sha256_256 builtin replayed over the ZK
# context and validated against a ClearCtx replay.
add_test_case_with_run(bool sha256)
# Background-Ferret engine (two sockets) + threaded feeds / vectorized AND /
# PolyProof sums — the bool analogue of arith_bg_ostriple.
add_test_case_with_run(bool bg_engine)
# (input/circuit/f2k/memory _scalability are build-only benchmarks — see ../bench)

# Arithmetic ZK
add_test_case_with_run(arith abconversion)
set_tests_properties(arith_abconversion PROPERTIES LABELS slow)
add_test_case_with_run(arith zk_proof)
add_test_case_with_run(arith ostriple)
add_test_case_with_run(arith bg_ostriple)
add_test_case_with_run(arith bg_stress)
add_test_case_with_run(arith feed_bench)
add_test_case_with_run(arith int_fp_vec)
# (input/circuit _scalability are build-only benchmarks — see ../bench)
add_test_case_with_run(arith polynomial)
add_test_case_with_run(arith inner_prdt)
add_test_case_with_run(arith mixed_check)
add_test_case_with_run(arith matrix_mul)
add_test_case_with_run(arith sis)

# RAM ZK
add_test_case_with_run(ram-zk ram_test)
add_test_case_with_run(ram-zk rom_test)
add_test_case_with_run(ram-zk set_test)
