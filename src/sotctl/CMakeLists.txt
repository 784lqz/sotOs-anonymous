# sotctl · the native operator control CLI (sotabi · M4/M5).  A native seL4
# executable (NOT a Linux guest, NOT Wine).  Staged into the binstore and
# spawned via orch_spawn_native with a libsot endpoint cap.
#
# World-#3 RUNTIME: sotctl links the sotOs-native C runtime — sotcrt (the crt0
# bridge over sel4runtime) + sotlibc (freestanding mem/str/printf→seL4-serial) —
# instead of the LUCAS guests' Linux-syscall stdio backend (sel4muslcsys).  Its
# printf/strtoul/snprintf resolve to sotcrt (ahead of muslc on the link line),
# so stdout is seL4_DebugPutChar, NOT a Linux write(2).  muslc remains ONLY as
# the -nostdinc freestanding-header provider + incidental support-lib symbols.
add_executable(sotctl
    main.c
    ${CMAKE_SOURCE_DIR}/src/sotabi/sotabi_client.c   # sotabi · native client helpers (M4)
)

target_include_directories(sotctl PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    .
)

target_link_libraries(sotctl
    sel4
    sotcrt          # world-#3 crt0/bridge — provides printf/strtoul/snprintf (seL4 serial)
    sotlibc         # world-#3 freestanding C runtime core
    sel4runtime     # _start → main (SysV stack/auxv from sel4utils_spawn_process_v)
    sel4debug
    muslc           # -nostdinc freestanding headers + incidental support symbols only
    utils
)
