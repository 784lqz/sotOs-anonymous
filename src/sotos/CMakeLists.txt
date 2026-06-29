add_library(sotos-string STATIC string.c chacha.c arc4random.c sha256.c pidrand.c)
target_include_directories(sotos-string PUBLIC ${CMAKE_SOURCE_DIR}/include PRIVATE .)
target_link_libraries(sotos-string sel4 muslc)   # muslc brings in musl stddef.h under -nostdinc
# Compile chacha.c, arc4random.c and sha256.c with -Os to keep the CPIO
# image within root's allocman pool budget.  The cryptographic logic is
# correct at any optimisation level; only code density differs.
set_source_files_properties(chacha.c arc4random.c sha256.c
    PROPERTIES COMPILE_FLAGS "-Os")
