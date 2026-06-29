add_library(sotOs-bench-common STATIC bench_common.c)
target_include_directories(sotOs-bench-common PUBLIC .)
target_link_libraries(sotOs-bench-common sel4 muslc)

add_subdirectory(micro_baseline)
add_subdirectory(micro_sto_ops)
add_subdirectory(throughput)
add_subdirectory(sweep_cost)
