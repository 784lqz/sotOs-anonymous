add_executable(sotOs-bench_throughput main.c)
target_include_directories(sotOs-bench_throughput PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(sotOs-bench_throughput
    sotOs-bench-common sel4 muslc sel4muslcsys sel4debug utils)
