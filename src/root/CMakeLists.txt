include(${CMAKE_SOURCE_DIR}/tools/cmake-tool/helpers/cpio.cmake)

# Bundle the child binaries into a CPIO archive that the rootserver
# embeds. sel4utils_configure_process(elf_name) does a lookup against
# the _cpio_archive symbol the linker resolves from this .o.
# L4: sotOs-shell lives in orch's CPIO (orch has its own delegated untypeds).
# Root's untyped budget covers orch + 2 Linux demos.  sotOs-shell is spawned
# by orch via ORCH_OP_SPAWN_NATIVE so it draws from orch's budget, not root's.
set(CHILD_BINS
    "$<TARGET_FILE:sotOs-sto>"
    "$<TARGET_FILE:sotOs-sto_hello>"
    "$<TARGET_FILE:sotOs-sto_conflict>"
    "$<TARGET_FILE:sotOs-sto_isolation_test>"
    "$<TARGET_FILE:sotOs-sto_cap_revoke>"
    "$<TARGET_FILE:sotOs-lucas-orch>"
    "$<TARGET_FILE:sotOs-anomaly>"
    "$<TARGET_FILE:sotOs-net-synth>"
    "$<TARGET_FILE:sotOs-procd>"
    "$<TARGET_FILE:sotOs-procd-unit>"
    "$<TARGET_FILE:sotOs-wal-unit>"
    "$<TARGET_FILE:sotOs-sotnano-unit>"
    "$<TARGET_FILE:sotOs-sotinit>"
    "$<TARGET_FILE:sotOs-sotcron>"
    "$<TARGET_FILE:sotOs-wl-compositor>"
    "$<TARGET_FILE:sotOs-wl-canary>"
    "${LUCAS_HELLO_BIN}"
    "${LUCAS_BUSYBOX_BIN}"
    "${LUCAS_UDP_SEND_BIN}"
    "${LUCAS_PTHREAD_BIN}"
    "${LUCAS_ARCH_PRCTL_BIN}")
MakeCPIO(children_archive.o "${CHILD_BINS}"
    DEPENDS sotOs-sto sotOs-sto_hello sotOs-sto_conflict sotOs-sto_isolation_test
            sotOs-sto_cap_revoke
            sotOs-lucas-orch
            sotOs-anomaly
            sotOs-net-synth
            sotOs-procd
            sotOs-procd-unit
            sotOs-wal-unit
            sotOs-sotnano-unit
            sotOs-sotinit
            sotOs-sotcron
            sotOs-wl-compositor
            sotOs-wl-canary
            "${LUCAS_HELLO_BIN}"
            "${LUCAS_BUSYBOX_BIN}"
            "${LUCAS_UDP_SEND_BIN}"
            "${LUCAS_PTHREAD_BIN}"
            "${LUCAS_ARCH_PRCTL_BIN}")

add_executable(sotOs-root
    main.c
    bootstrap.c
    procd_shm_map.c
    bytepipe_shm_map.c
    children_archive.o
)

target_include_directories(sotOs-root PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    .
)

target_link_libraries(sotOs-root
    sotos-string
    sel4
    muslc
    sel4muslcsys
    sel4platsupport
    sel4simple
    sel4simple-default
    sel4allocman
    sel4vka
    sel4utils
    sel4debug
    utils
    sotOs-lucas
)
