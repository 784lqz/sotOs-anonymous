# sotOs · sottrace · native observability plane (v0).
# Reuses sotguard's event struct/enum but has its own non-blocking emit + ring.
set(SOTTRACE_SOURCES
    trace.c
    capture.c
)

add_library(sotos-sottrace STATIC ${SOTTRACE_SOURCES})

target_include_directories(sotos-sottrace PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(sotos-sottrace
    sel4
    muslc)

set_source_files_properties(${SOTTRACE_SOURCES}
    PROPERTIES COMPILE_FLAGS "-Os")
