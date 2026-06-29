# sotOs · procd · process server.
#
# Composed as:
#   - sotos-procd-lib (static library) · slot/thread table allocator.
#     Linked into both the procd ELF and the procd unit-test ELF so the
#     tests can exercise the slot allocator without spinning up the full
#     procd process.  Deliberately omits shm_init.c so the test ELF does
#     NOT carry an unused 1 MiB .bss buffer (it carries its own).
#   - sotOs-procd (ELF) · the daemon itself · main.c + shm_init.c + lib.
set(PROCD_LIB_SOURCES
    table.c
    event_ring.c)

add_library(sotos-procd-lib STATIC ${PROCD_LIB_SOURCES})

target_include_directories(sotos-procd-lib PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(sotos-procd-lib
    sel4
    muslc
    sel4_autoconf)

# PR 5 · handlers_lifecycle.c lives in the procd ELF (not the shared lib)
# so the procd-unit test ELF doesn't drag in a printf-using object it
# never calls.  Mirrors the shm_init.c split for the same reason.
add_executable(sotOs-procd main.c shm_init.c handlers_lifecycle.c)

target_include_directories(sotOs-procd PRIVATE
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(sotOs-procd
    sotos-procd-lib
    sotos-string
    sel4
    muslc
    sel4muslcsys
    sel4debug
    utils)
