add_executable(sotOs-wl-canary main.c)

target_include_directories(sotOs-wl-canary PRIVATE
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(sotOs-wl-canary
    sotos-string
    sel4
    muslc
    sel4muslcsys
    sel4debug
    utils)
