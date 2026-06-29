add_executable(sotOs-sto
    main.c
    ipc.c
    registry.c
)

target_include_directories(sotOs-sto PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    .
)

target_link_libraries(sotOs-sto
    sel4
    muslc
    sel4muslcsys
    sel4debug
    utils
)
