cmake_minimum_required(VERSION 3.16.0)
project(sotOs NONE)

# Loaded via -C settings.cmake by init-build.sh; reload here so direct cmake
# invocations also see the kernel/platform selection.
include(settings.cmake)

# sotOs PY7 · propagate KernelLucAsTrace (see settings.cmake) into the kernel
# compile.  Must run before all.cmake adds the kernel subdirectory, otherwise
# add_compile_definitions won't reach kernel.elf.  Default-OFF keeps default
# builds byte-identical to before.
if(KernelLucAsTrace)
    add_compile_definitions(CONFIG_LucAs_KERNEL_TRACE=1)
    message(STATUS "sotOs PY7: CONFIG_LucAs_KERNEL_TRACE enabled")
endif()

# sotOs VFS-FS-TRACE · propagate KernelLucAsFsTrace (see settings.cmake)
# into the user-side compile.  Default-OFF keeps default builds
# byte-identical to before (LucAs_FS_TRACE expands to a no-op).
if(KernelLucAsFsTrace)
    add_compile_definitions(CONFIG_LucAs_FS_TRACE=1)
    message(STATUS "sotOs VFS-FS-TRACE: CONFIG_LucAs_FS_TRACE enabled")
endif()

# sotOs OBSD-eta · propagate KernelLucAsMPK (see settings.cmake) into the
# kernel compile.  Default-OFF keeps default builds byte-identical to
# before (the boot CR4.PKE probe compiles to nothing).  When ON the
# kernel enables CR4.PKE at boot if the CPU advertises PKU support.
if(KernelLucAsMPK)
    add_compile_definitions(CONFIG_LucAs_MPK=1)
    message(STATUS "sotOs OBSD-eta: CONFIG_LucAs_MPK enabled (forking verified seL4)")
endif()

# T5 A/B measurement toggles for the getpid trivial fast-path.  DEFAULT OFF = correct
# shipping behavior; only set ON for a single measurement build to isolate component cost.
# When a toggle is ON the bench output is GARBAGE (the gate is the cycle delta, not the
# syscall result).  Both toggles are mutually exclusive; combine them for a combined-elide
# build if you need the residual fault-round-trip directly.
#
#   cmake -DT5ElideWriteRegs=ON ..   → T5_ELIDE_WRITEREGS: skip WriteRegisters; use
#                                        the seL4 fault-reply IPC path instead.
#                                        Delta (baseline − this) ≈ WriteRegisters cost.
#   cmake -DT5ElideDispatch=ON ..    → T5_ELIDE_DISPATCH: skip lucas_dispatch_call;
#                                        stub fp_ret=1.
#                                        Delta (baseline − this) ≈ dispatch cost.
if(T5ElideWriteRegs)
    add_compile_definitions(T5_ELIDE_WRITEREGS=1)
    message(STATUS "T5 measurement: T5_ELIDE_WRITEREGS ON (WriteRegisters elided · bench is garbage)")
endif()
if(T5ElideDispatch)
    add_compile_definitions(T5_ELIDE_DISPATCH=1)
    message(STATUS "T5 measurement: T5_ELIDE_DISPATCH ON (dispatch elided · bench is garbage)")
endif()

# Canonical seL4 build composition. all.cmake:
#   - sets CMAKE_MODULE_PATH (helpers/, projects/musllibc)
#   - find_file(KERNEL_PATH kernel ...) and add_subdirectory(kernel)
#   - add_subdirectory(elfloader-tool)
#   - find_package(musllibc REQUIRED) + musllibc_set_environment_flags()
#   - add_subdirectory(libsel4)
#   - file(GLOB projects/*/CMakeLists.txt) and add_subdirectory each
#
# Our user code lives in src/, exposed to projects.cmake as projects/sotOs/
# via symlink. Sort order: musllibc, seL4_libs, sotOs, util_libs.
# CMake resolves target_link_libraries at link time, so projects/util_libs
# coming after projects/sotOs in the GLOB is fine.
include(tools/cmake-tool/all.cmake)

# Compose the boot image AFTER projects/* have been processed and all
# executables are defined. DeclareRootserver bundles them into the image.
include(tools/cmake-tool/helpers/rootserver.cmake)
DeclareRootserver(sotOs-root)

# Final image lives at build/images/sotOs-image-x86_64-pc99
