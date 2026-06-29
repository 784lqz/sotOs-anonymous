add_executable(sotOs-sto_isolation_test main.c)
target_include_directories(sotOs-sto_isolation_test PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(sotOs-sto_isolation_test
    sel4 muslc sel4muslcsys sel4debug utils)
