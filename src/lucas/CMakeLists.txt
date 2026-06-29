# Embed scripts/demo/simulated_attacker.py into lucas as a C array so the root
# task can install it into sotfs at boot.  Generated header lives in the build
# tree; sotOs-lucas re-fires the conversion when the .py file changes.
set(AGENT_DECEPTION_HEADER
    "${CMAKE_BINARY_DIR}/include/lucas/simulated_attacker_py.h")
add_custom_command(
    OUTPUT "${AGENT_DECEPTION_HEADER}"
    COMMAND ${CMAKE_COMMAND} -E make_directory
            "${CMAKE_BINARY_DIR}/include/lucas"
    COMMAND bash -c
            "cd ${CMAKE_SOURCE_DIR} && xxd -i scripts/demo/simulated_attacker.py \
                > ${AGENT_DECEPTION_HEADER}"
    DEPENDS "${CMAKE_SOURCE_DIR}/scripts/demo/simulated_attacker.py"
    COMMENT "Embedding simulated_attacker.py as a C array"
    VERBATIM
)
add_custom_target(agent-deception-header
    DEPENDS "${AGENT_DECEPTION_HEADER}")

# SP1 PR 5 · embed the vendored TinyCC `runmain.o` (the `-run` startup
# stub that calls main) as a C array so the root task can install it into
# sotfs at boot.  `tcc -run` of a freestanding source needs only this one
# runtime object (with -nostdlib · no libc, no libtcc1.a); installing it at
# sotfs /runmain.o lets the trusted tcc sotbox find it via -B/tmp.
set(TCC_RUNMAIN_HEADER
    "${CMAKE_BINARY_DIR}/include/lucas/tcc_runmain_o.h")
add_custom_command(
    OUTPUT "${TCC_RUNMAIN_HEADER}"
    COMMAND ${CMAKE_COMMAND} -E make_directory
            "${CMAKE_BINARY_DIR}/include/lucas"
    COMMAND bash -c
            "cd ${CMAKE_SOURCE_DIR}/src/test/tcc-bin && xxd -i runmain.o \
                > ${TCC_RUNMAIN_HEADER}"
    DEPENDS "${CMAKE_SOURCE_DIR}/src/test/tcc-bin/runmain.o"
    COMMENT "Embedding TinyCC runmain.o as a C array"
    VERBATIM
)
add_custom_target(tcc-runmain-header
    DEPENDS "${TCC_RUNMAIN_HEADER}")

# apk-fs Phase 3 Task 4 · embed hello_dyn.bin as a C array so the root task can
# install it into the writable sotfs at boot (/tmp/hello_dyn.bin).  The ELF is
# ~7.5 KiB; guests can `cat /tmp/hello_dyn.bin > /usr/bin/upbin && /usr/bin/upbin`
# to prove a runtime-staged upper ELF runs (ld-musl resolves libc.so, outputs
# "[hello-dyn] dynamic musl OK", exits 0).  The blob ships as a C array (NOT a
# binstore entry) so it rides the per-session VFS upper read path.
set(HELLO_DYN_BIN_HEADER
    "${CMAKE_BINARY_DIR}/include/lucas/hello_dyn_bin.h")
add_custom_command(
    OUTPUT "${HELLO_DYN_BIN_HEADER}"
    COMMAND ${CMAKE_COMMAND} -E make_directory
            "${CMAKE_BINARY_DIR}/include/lucas"
    COMMAND bash -c
            "cd ${CMAKE_SOURCE_DIR}/src/test/sotOs-hello-dyn && xxd -i hello_dyn.bin \
                > ${HELLO_DYN_BIN_HEADER}"
    DEPENDS "${CMAKE_SOURCE_DIR}/src/test/sotOs-hello-dyn/hello_dyn.bin"
    COMMENT "Embedding hello_dyn.bin as a C array"
    VERBATIM
)
add_custom_target(hello-dyn-bin-header
    DEPENDS "${HELLO_DYN_BIN_HEADER}")

# apk-fs slice-2 C4 spike · embed spike_dyn.bin + libspikelib.so as C arrays.
# Neither is baked into the sysroot; the gate copies BOTH into the per-session
# upper (/usr/bin/spikebin + /usr/lib/libspikelib.so) and execs spikebin so
# ld-musl must open the NEEDED .so FROM THE UPPER (the libncursesw.so.6 case).
set(SPIKE_DYN_BIN_HEADER
    "${CMAKE_BINARY_DIR}/include/lucas/spike_dyn_bin.h")
add_custom_command(
    OUTPUT "${SPIKE_DYN_BIN_HEADER}"
    COMMAND ${CMAKE_COMMAND} -E make_directory
            "${CMAKE_BINARY_DIR}/include/lucas"
    COMMAND bash -c
            "cd ${CMAKE_SOURCE_DIR}/src/test/sotOs-upper-so && xxd -i spike_dyn.bin \
                > ${SPIKE_DYN_BIN_HEADER}"
    DEPENDS "${CMAKE_SOURCE_DIR}/src/test/sotOs-upper-so/spike_dyn.bin"
    COMMENT "Embedding spike_dyn.bin as a C array"
    VERBATIM
)
add_custom_target(spike-dyn-bin-header
    DEPENDS "${SPIKE_DYN_BIN_HEADER}")

set(SPIKELIB_SO_HEADER
    "${CMAKE_BINARY_DIR}/include/lucas/spikelib_so.h")
add_custom_command(
    OUTPUT "${SPIKELIB_SO_HEADER}"
    COMMAND ${CMAKE_COMMAND} -E make_directory
            "${CMAKE_BINARY_DIR}/include/lucas"
    COMMAND bash -c
            "cd ${CMAKE_SOURCE_DIR}/src/test/sotOs-upper-so && xxd -i libspikelib.so \
                > ${SPIKELIB_SO_HEADER}"
    DEPENDS "${CMAKE_SOURCE_DIR}/src/test/sotOs-upper-so/libspikelib.so"
    COMMENT "Embedding libspikelib.so as a C array"
    VERBATIM
)
add_custom_target(spikelib-so-header
    DEPENDS "${SPIKELIB_SO_HEADER}")

# Install-arc P0.1 · embed the real Debian hello_*.deb as a C array so the root
# task can install it into the writable sotfs at boot (/tmp/hello.deb).  The
# .deb is DATA (an ar archive), NOT an executable — so it ships as a blob (like
# runmain.o above), NOT a binstore entry.  Phase 0.2's `dpkg-deb -x` then reads
# it back off /tmp.  Generated header lives in the build tree.
set(DPKG_HELLO_DEB_HEADER
    "${CMAKE_BINARY_DIR}/include/lucas/dpkg_hello_deb.h")
add_custom_command(
    OUTPUT "${DPKG_HELLO_DEB_HEADER}"
    COMMAND ${CMAKE_COMMAND} -E make_directory
            "${CMAKE_BINARY_DIR}/include/lucas"
    COMMAND bash -c
            "cd ${CMAKE_SOURCE_DIR}/src/test/sotOs-dpkg/deb && xxd -i hello.deb \
                > ${DPKG_HELLO_DEB_HEADER}"
    DEPENDS "${CMAKE_SOURCE_DIR}/src/test/sotOs-dpkg/deb/hello.deb"
    COMMENT "Embedding hello.deb as a C array"
    VERBATIM
)
add_custom_target(dpkg-hello-deb-header
    DEPENDS "${DPKG_HELLO_DEB_HEADER}")

# Install-arc P1b · embed sotmark.deb (a package whose postinst writes /etc) the
# same way, so the root task installs it at boot (/tmp/sotmark.deb) and `dpkg -i`
# runs its maintainer script (fork+execve /bin/sh → /etc/sotmark.conf).
set(DPKG_SOTMARK_DEB_HEADER
    "${CMAKE_BINARY_DIR}/include/lucas/dpkg_sotmark_deb.h")
add_custom_command(
    OUTPUT "${DPKG_SOTMARK_DEB_HEADER}"
    COMMAND ${CMAKE_COMMAND} -E make_directory
            "${CMAKE_BINARY_DIR}/include/lucas"
    COMMAND bash -c
            "cd ${CMAKE_SOURCE_DIR}/src/test/sotOs-dpkg/deb && xxd -i sotmark.deb \
                > ${DPKG_SOTMARK_DEB_HEADER}"
    DEPENDS "${CMAKE_SOURCE_DIR}/src/test/sotOs-dpkg/deb/sotmark.deb"
    COMMENT "Embedding sotmark.deb as a C array"
    VERBATIM
)
add_custom_target(dpkg-sotmark-deb-header
    DEPENDS "${DPKG_SOTMARK_DEB_HEADER}")

# Install-arc P1.3 · embed the trimmed /var/lib/dpkg DB (status + arch + a couple
# of info/*.list + format) as C arrays so the root task can boot-seed it into the
# writable /var.  Captured from debian:13-slim (8 base stanzas all "install ok
# installed" so hello's Depends: libc6 resolves and dpkg -i won't refuse).  One
# combined header with distinct symbol names via `xxd -i -n`.
set(DPKG_DB_SEED_HEADER
    "${CMAKE_BINARY_DIR}/include/lucas/dpkg_db_seed.h")
set(DPKG_DB_DIR "${CMAKE_SOURCE_DIR}/src/test/sotOs-dpkg/var/lib/dpkg")
add_custom_command(
    OUTPUT "${DPKG_DB_SEED_HEADER}"
    COMMAND ${CMAKE_COMMAND} -E make_directory
            "${CMAKE_BINARY_DIR}/include/lucas"
    COMMAND bash -c
            "cd ${DPKG_DB_DIR} && { \
                xxd -i -n dpkg_status         status; \
                xxd -i -n dpkg_arch           arch; \
                xxd -i -n dpkg_info_dpkg_list info/dpkg.list; \
                xxd -i -n dpkg_info_tar_list  info/tar.list; \
                xxd -i -n dpkg_info_format    info/format; \
            } > ${DPKG_DB_SEED_HEADER}"
    DEPENDS "${DPKG_DB_DIR}/status"
            "${DPKG_DB_DIR}/arch"
            "${DPKG_DB_DIR}/info/dpkg.list"
            "${DPKG_DB_DIR}/info/tar.list"
            "${DPKG_DB_DIR}/info/format"
    COMMENT "Embedding the /var/lib/dpkg DB seed as C arrays"
    VERBATIM
)
add_custom_target(dpkg-db-seed-header
    DEPENDS "${DPKG_DB_SEED_HEADER}")

# apk-local-install Task 6 · embed the local .apk fixture as a C array so the
# canary base exposes it at /root/fixture.apk (the attacker's install source).
# The .apk is a BINARY (embedded NULs) so we must use xxd -i -n (explicit
# symbol name) and pair it with ENTRY_BLOB (explicit length) in backends_static.
set(APK_FIXTURE_HEADER "${CMAKE_BINARY_DIR}/include/lucas/apk_fixture.h")
add_custom_command(
    OUTPUT "${APK_FIXTURE_HEADER}"
    COMMAND ${CMAKE_COMMAND} -E make_directory
            "${CMAKE_BINARY_DIR}/include/lucas"
    COMMAND bash -c
            "cd ${CMAKE_SOURCE_DIR}/src/test/sotOs-apk/deb && xxd -i -n apk_fixture fixture.apk \
                > ${APK_FIXTURE_HEADER}"
    DEPENDS "${CMAKE_SOURCE_DIR}/src/test/sotOs-apk/deb/fixture.apk"
    COMMENT "Embedding fixture.apk as a C array"
    VERBATIM)
add_custom_target(apk-fixture-header DEPENDS "${APK_FIXTURE_HEADER}")

# apk-local-install Task 6 · embed the Alpine 3.20 signing key as a C array so
# the canary base exposes it at /etc/apk/keys/alpine-3.20.rsa.pub (opt-in verify
# path used by Task 9; --allow-untrusted skips it).
set(APK_KEYS_HEADER "${CMAKE_BINARY_DIR}/include/lucas/apk_keys.h")
add_custom_command(
    OUTPUT "${APK_KEYS_HEADER}"
    COMMAND ${CMAKE_COMMAND} -E make_directory
            "${CMAKE_BINARY_DIR}/include/lucas"
    COMMAND bash -c
            "cd ${CMAKE_SOURCE_DIR}/src/test/sotOs-apk/keys && xxd -i -n apk_key_alpine_3_20 alpine-3.20.rsa.pub \
                > ${APK_KEYS_HEADER}"
    DEPENDS "${CMAKE_SOURCE_DIR}/src/test/sotOs-apk/keys/alpine-3.20.rsa.pub"
    COMMENT "Embedding Alpine 3.20 apk signing key as a C array"
    VERBATIM)
add_custom_target(apk-keys-header DEPENDS "${APK_KEYS_HEADER}")

# apk-network-install Task 1 (C2) · embed a credible Alpine 3.20 base
# installed-DB (the verbatim /lib/apk/db/installed from alpine:3.20 · 14 base
# packages: musl, busybox, alpine-baselayout, ca-certificates-bundle, libcrypto3,
# libssl3, zlib, …) as a C array so the root task boot-seeds it into the writable
# sotfs at /lib/apk/db/installed.  With this base present, apk's dependency solver
# closes a REALISTIC closure (`apk add nano` → exactly ncurses-terminfo-base +
# libncursesw + nano, not the whole world).  `-n apk_basedb` forces the C symbols
# (apk_basedb / apk_basedb_len) since the source file is named `installed`.
set(APK_BASEDB_HEADER "${CMAKE_BINARY_DIR}/include/lucas/apk_basedb.h")
add_custom_command(
    OUTPUT "${APK_BASEDB_HEADER}"
    COMMAND ${CMAKE_COMMAND} -E make_directory
            "${CMAKE_BINARY_DIR}/include/lucas"
    COMMAND bash -c
            "cd ${CMAKE_SOURCE_DIR}/src/test/sotOs-apk/db && xxd -i -n apk_basedb installed \
                > ${APK_BASEDB_HEADER}"
    DEPENDS "${CMAKE_SOURCE_DIR}/src/test/sotOs-apk/db/installed"
    COMMENT "Embedding the Alpine 3.20 base installed-DB as a C array"
    VERBATIM)
add_custom_target(apk-basedb-header DEPENDS "${APK_BASEDB_HEADER}")

add_library(sotOs-lucas STATIC
    functor.c
    truth_core.c
    ${CMAKE_SOURCE_DIR}/src/libsot/sot_session.c   # libsot · native operator API (sotctl) over truth-core
    clock.c
    vvar_fill.c
    cow_overlay.c
    sotfs_session.c
    persona_session.c
    apk_ioc.c
    sotfs_session_route.c
    symlink_table.c
    tty_session.c
    lucas_l1.c
    elf_loader.c
    elf_segments.c
    stack_setup.c
    client_setup.c
    fault_loop.c
    dispatch.c
    handlers_fs.c
    handlers_abi.c
    handlers_fb.c
    handlers_proc.c
    antidos.c
    handlers_mem.c
    handlers_net.c
    handlers_python.c
    handlers_sched.c
    iomux.c
    vfs.c
    backends_static.c
    backends_proc.c
    backends_python_stdlib.c
    backends_sysroot.c
    backends_binstore.c
    backends_doom_wad.c
    backends_cacert.c
    backends_rwbinstore.c
    backends_sotfs.c
    backends_union.c
    backends_union_ops.c
    backends_pty.c
    backends_shm.c
    handlers_shm.c
    sto_local.c
    pledge.c
    unveil.c
    anomaly.c
    signals.c
    threading.c
    procd_view.c
    shellhook.c
    path_matcher.c
    audit_ipc.c
)

add_dependencies(sotOs-lucas agent-deception-header)
add_dependencies(sotOs-lucas tcc-runmain-header)
add_dependencies(sotOs-lucas hello-dyn-bin-header)
add_dependencies(sotOs-lucas spike-dyn-bin-header)
add_dependencies(sotOs-lucas spikelib-so-header)
add_dependencies(sotOs-lucas dpkg-hello-deb-header)
add_dependencies(sotOs-lucas dpkg-sotmark-deb-header)
add_dependencies(sotOs-lucas dpkg-db-seed-header)
add_dependencies(sotOs-lucas apk-fixture-header)
add_dependencies(sotOs-lucas apk-keys-header)
add_dependencies(sotOs-lucas apk-basedb-header)

target_include_directories(sotOs-lucas PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/include
    ${CMAKE_SOURCE_DIR}/src   # vDSO arc · so "vdso/sotos_vvar.h" resolves (vvar_fill.c + orch/vdso_map.c)
    .
)

target_link_libraries(sotOs-lucas
    sotos-string
    sotos-sotfs
    sotos-sotguard
    sotos-sottrace
    sel4
    muslc
    sel4muslcsys
    sel4platsupport
    sel4simple
    sel4allocman
    sel4vka
    sel4utils
    sel4debug
    utils
    cpio
    sotos-sotguard      # SG-FS Phase 2 · sotGuard event bus producers
)
