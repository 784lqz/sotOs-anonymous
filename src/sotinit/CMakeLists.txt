# sotOs · sotinit · init scheduler.
#
# Composed as:
#   - sotos-sotinit-lib (static library) · INI parser + (PR 2+) unit
#     registry helpers.  Linked into the sotinit ELF and reusable by any
#     future unit-test ELF that wants to exercise the parser without
#     spinning up the daemon.
#   - sotOs-sotinit (ELF) · the Path D init process · main.c + lib.
#
# Spec: init-cron-scheduler-design §3.
set(SOTINIT_LIB_SOURCES
    ini_parser.c
    unit_registry.c
    scan.c
    launcher.c
    topo_sort.c
    queries.c
    restart.c
    audit_ipc.c
    sotfs_scan.c)

add_library(sotos-sotinit-lib STATIC ${SOTINIT_LIB_SOURCES})

target_include_directories(sotos-sotinit-lib PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(sotos-sotinit-lib
    sel4
    muslc
    sel4_autoconf)

add_executable(sotOs-sotinit main.c)

target_include_directories(sotOs-sotinit PRIVATE
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(sotOs-sotinit
    sotos-sotinit-lib
    sotos-string
    sel4
    muslc
    sel4muslcsys
    sel4debug
    utils)
