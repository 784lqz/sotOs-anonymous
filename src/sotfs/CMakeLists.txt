add_library(sotos-sotfs STATIC graph.c rewrite.c io.c graph_curvature.c wal.c wal_replay.c
    replay_anomaly.c replay_sotnet.c
    crc64.c storage_ram.c blkdev.c)
target_include_directories(sotos-sotfs PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(sotos-sotfs sel4 muslc sotos-string)
# Use -Os ONLY on sotfs files · keeps the .a small.  Does NOT affect any
# existing orch/lucas code (hard constraint from Phase 2 spec §12.6).
# PR 6 · replay_anomaly.c + replay_sotnet.c are light (no autoconf
# deps) so they live in sotos-sotfs alongside wal_replay.c.  replay_procd.c
# needs procd/proc.h which pulls in <sel4/sel4.h>'s autoconf · it's
# compiled as part of the orch executable directly in src/orch/CMakeLists.txt
# (same pattern as storage_virtio_blk.c).
set_source_files_properties(graph.c rewrite.c io.c graph_curvature.c wal.c wal_replay.c
    replay_anomaly.c replay_sotnet.c
    crc64.c storage_ram.c blkdev.c
    PROPERTIES COMPILE_FLAGS "-Os")

# virtio-blk Phase 2b: storage_virtio_blk.c requires seL4 syscall headers
# (autoconf.h path) so it is compiled as part of the sotOs-lucas-orch executable
# directly in src/orch/CMakeLists.txt.  It lives in src/sotfs/ for source
# locality with other storage backends (Phase 2c/2d will use the same file).
# The -Os flag is applied via set_source_files_properties in orch/CMakeLists.txt.

# Optional test-only target · NOT linked into anything in Phase 2.
# selftest.c contains 115 LoC + heavy printf strings; keeping it out of
# sotos-sotfs prevents it from being pulled into orch's text section when
# LUCAS links sotos-sotfs.
add_library(sotos-sotfs-test STATIC selftest.c)
target_include_directories(sotos-sotfs-test PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(sotos-sotfs-test sotos-sotfs sel4 muslc sotos-string)
set_source_files_properties(selftest.c PROPERTIES COMPILE_FLAGS "-Os")
