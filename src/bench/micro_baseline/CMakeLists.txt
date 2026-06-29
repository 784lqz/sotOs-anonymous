add_executable(sotOs-bench_baseline main.c)
target_include_directories(sotOs-bench_baseline PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(sotOs-bench_baseline
    sotOs-bench-common sel4 muslc sel4muslcsys sel4debug utils)
