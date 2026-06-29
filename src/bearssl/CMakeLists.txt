# sotOs · BearSSL 0.6 static lib for the seL4/musl target (sotNet γ-3-γ-2).
#
# Tracked build glue. The upstream BearSSL source is bootstrap-fetched
# (gitignored, like util_libs/musllibc) under external/bearssl/ — see
# bootstrap.sh section 4b. This file globs that source and builds it as a
# static lib for the responder's toolchain, mirroring the
# external/util_libs/libfdt recipe (add_library STATIC + link muslc +
# EXCLUDE_FROM_ALL · find_package(musllibc) is global in base.cmake).
set(BEARSSL_DIR "${CMAKE_SOURCE_DIR}/external/bearssl")

file(GLOB_RECURSE bearssl_srcs CONFIGURE_DEPENDS "${BEARSSL_DIR}/src/*.c")
list(SORT bearssl_srcs)

add_library(bearssl STATIC EXCLUDE_FROM_ALL ${bearssl_srcs})
# inc/ = public API (<bearssl.h>) · src/ = internal headers (inner.h, config).
target_include_directories(bearssl
    PUBLIC  "${BEARSSL_DIR}/inc"
    PRIVATE "${BEARSSL_DIR}/src")
target_link_libraries(bearssl muslc)

# Force the portable constant-time C implementations: disable the x86 (AES-NI,
# SSE2, RDRAND) and POWER8 hardware-crypto paths. These macros are #ifndef-
# guarded in inner.h, so a -D here wins. Rationale: (1) an seL4 userspace
# process should not depend on the kernel preserving XMM/AVX state across
# context switches; (2) the QEMU target may not advertise AES-NI. The portable
# paths (aes_ct/ct64, ghash_ctmul, chacha20_ct, poly1305_ctmul) are sufficient
# for a deception responder.
target_compile_definitions(bearssl PRIVATE
    BR_AES_X86NI=0 BR_SSE2=0 BR_RDRAND=0 BR_POWER8=0)

# Even with the hardware paths disabled, the intrinsic source files still
# #define BR_ENABLE_INTRINSICS=1 unconditionally and #include <x86intrin.h>
# (their bodies are the portable #else branch). <x86intrin.h> is a compiler
# header removed by the build's -nostdinc, so re-add the compiler's own include
# dir (intrinsic headers only · libc still comes from muslc) for bearssl alone.
execute_process(
    COMMAND "${CMAKE_C_COMPILER}" -print-file-name=include
    OUTPUT_VARIABLE BEARSSL_CC_INC OUTPUT_STRIP_TRAILING_WHITESPACE)

# BearSSL is freestanding C; silence its benign warnings under the project flags.
target_compile_options(bearssl PRIVATE
    -isystem "${BEARSSL_CC_INC}"
    -Wno-unused-function -Wno-sign-compare -Wno-unused-parameter)
