add_executable(sotOs-bench_sto_ops main.c)
target_include_directories(sotOs-bench_sto_ops PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(sotOs-bench_sto_ops
    sotOs-bench-common sel4 muslc sel4muslcsys sel4debug utils)
