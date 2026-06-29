# sotOs · procd unit test ELF.
#
# Spawned by root at boot.  Exercises the procd table allocator and
# seqlock helpers against a static .bss buffer that mimics the SHM
# region layout.  Prints PASS/FAIL lines that scripts/smoke-procd.sh
# greps from the QEMU serial log.
add_executable(sotOs-procd-unit procd_unit.c)

target_include_directories(sotOs-procd-unit PRIVATE
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(sotOs-procd-unit
    sotos-procd-lib
    sotos-string
    sel4
    muslc
    sel4muslcsys
    sel4debug
    utils)
