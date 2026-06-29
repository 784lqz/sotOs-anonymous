add_executable(sotOs-bench_sweep_cost main.c)
target_include_directories(sotOs-bench_sweep_cost PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(sotOs-bench_sweep_cost
    sotOs-bench-common sel4 muslc sel4muslcsys sel4debug utils)
