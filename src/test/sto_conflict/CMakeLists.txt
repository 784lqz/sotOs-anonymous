add_executable(sotOs-sto_conflict main.c)
target_include_directories(sotOs-sto_conflict PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(sotOs-sto_conflict
    sel4 muslc sel4muslcsys sel4debug utils)
