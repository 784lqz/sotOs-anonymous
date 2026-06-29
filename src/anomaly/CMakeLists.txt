add_executable(sotOs-anomaly main.c)

target_include_directories(sotOs-anomaly PRIVATE
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(sotOs-anomaly
    sotos-string
    sel4
    muslc
    sel4muslcsys
    sel4debug
    utils)
