# sotcrt · the crt0 / C-runtime bridge for world-#3 NATIVE sotOs binaries.
#
# The seL4 process startup (_start → TLS + IPC-buffer + auxv → main) is provided
# by sel4runtime (load-bearing · the seL4 ABI).  sotcrt is the THIN layer on top
# bridging the few STANDARD C-runtime symbols a native binary (and the seL4
# support libs) reference to sotlibc's sot_* implementations — so a world-#3
# binary links sotcrt + sotlibc + sel4 + sel4runtime and needs NO sel4muslcsys
# (the Linux-syscall stdio backend the LUCAS guests use).
add_library(sotcrt STATIC sotcrt.c)

target_include_directories(sotcrt PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(sotcrt
    sel4
    sel4_autoconf
    sotlibc
    muslc)

set_source_files_properties(sotcrt.c
    PROPERTIES COMPILE_FLAGS "-Os")
