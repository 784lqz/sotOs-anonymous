add_executable(sotOs-wl-compositor main.c)

target_include_directories(sotOs-wl-compositor PRIVATE
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(sotOs-wl-compositor
    sotos-string
    sel4
    muslc
    sel4muslcsys
    sel4debug
    utils)

