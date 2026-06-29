# sotOs · sotcron · cron-like timer scheduler.
#
# Composed as:
#   - sotos-sotcron-lib (static library) · TSC helpers + (PR 8+) calendar /
#     interval parsers + timer registry.  Linked into the sotcron ELF and
#     reusable by any future unit-test ELF that wants to exercise the
#     scheduler without spinning up the daemon.
#   - sotOs-sotcron (ELF) · the Path D scheduler process · main.c + lib.
#
# Spec: init-cron-scheduler-design §4.
set(SOTCRON_LIB_SOURCES
    tsc.c
    calendar.c
    scan.c
    sotfs_scan.c
    queries.c
    audit_ipc.c)

add_library(sotos-sotcron-lib STATIC ${SOTCRON_LIB_SOURCES})

target_include_directories(sotos-sotcron-lib PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(sotos-sotcron-lib
    sel4
    muslc
    sel4_autoconf)

add_executable(sotOs-sotcron main.c)

target_include_directories(sotOs-sotcron PRIVATE
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(sotOs-sotcron
    sotos-sotcron-lib
    sotos-string
    sel4
    muslc
    sel4muslcsys
    sel4debug
    utils)
