# sotOs · sotGuard · event bus (G1) + policy engine (G2).
#
# This library is intentionally NOT linked into any executable yet.
# sotos-sotguard exposes the public headers under include/sotguard/.
# No malloc, no kernel calls, snake_case throughout.
#
# Composed library:
#   - event_bus.c     (G1) · bounded ring + sotguard_emit / sotguard_recent.
#   - policy_engine.c (G2) · per-pid context + correlation rule evaluator.
set(SOTGUARD_SOURCES
    event_bus.c
    policy_engine.c
)

add_library(sotos-sotguard STATIC ${SOTGUARD_SOURCES})

target_include_directories(sotos-sotguard PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

# Under -nostdinc the muslc target supplies <stdint.h>/<stddef.h>; sel4
# carries the platform autoconf headers musllibc transitively pulls in.
target_link_libraries(sotos-sotguard
    sel4
    muslc)

# Keep the .a small so future links into orch do not bloat the CPIO image.
set_source_files_properties(${SOTGUARD_SOURCES}
    PROPERTIES COMPILE_FLAGS "-Os")
