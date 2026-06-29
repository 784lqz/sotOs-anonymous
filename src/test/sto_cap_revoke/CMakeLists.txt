add_executable(sotOs-sto_cap_revoke main.c)
target_include_directories(sotOs-sto_cap_revoke PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(sotOs-sto_cap_revoke
    sel4 muslc sel4muslcsys sel4debug utils)
