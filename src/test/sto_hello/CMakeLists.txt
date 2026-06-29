add_executable(sotOs-sto_hello
    main.c
)

target_include_directories(sotOs-sto_hello PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(sotOs-sto_hello
    sel4
    muslc
    sel4muslcsys
    sel4debug
    utils
)
