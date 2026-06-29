# EXPERIMENT T5 · SYSCALL LATENCY EVALUATION HARNESS
# 
# Integrates the microbench fixture into the sotOs build system.
# The binary is pre-compiled (like syscall_test.bin) and bundled into CPIO.
#
# Build:
#   gcc -O2 -static -o microbench.bin microbench.c -lc
#   strip microbench.bin
#
# Integration (orch demo_commands[]):
#   { "microbench", LUCAS_TIER_TRUSTED, &cmd_microbench },

set(T5_MICROBENCH_BIN
    "${CMAKE_CURRENT_SOURCE_DIR}/microbench.bin"
    CACHE FILEPATH "EXPERIMENT T5 syscall latency microbench fixture"
    FORCE)

# Validate the fixture exists (pre-built, committed binary).
if(NOT EXISTS "${T5_MICROBENCH_BIN}")
    message(WARNING
        "t5-syscall-microbench: ${T5_MICROBENCH_BIN} not found · "
        "rebuild per: gcc -O2 -static -o microbench.bin microbench.c")
endif()

# Export path for orch CPIO bundling.
set(SOTOS_T5_MICROBENCH_BIN "${T5_MICROBENCH_BIN}" CACHE INTERNAL "")
