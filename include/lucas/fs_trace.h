/*
 * sotOs · LUCAS · fs syscall trace macro.
 *
 * Companion to KernelLucasTrace (which gates kernel-side iretq/sysrt
 * diagnostic lines).  This header gates user-side VFS syscall trace
 * lines emitted from src/lucas/handlers_fs.c.
 *
 * Default OFF: LUCAS_FS_TRACE expands to a no-op that the optimizer
 * removes, so the gated printf call sites have zero runtime cost when
 * the toggle is disabled.  Enable by configuring with
 *     -DKernelLucasFsTrace=ON
 * (mirrors KernelLucasTrace handling in settings.cmake / CMakeLists.txt).
 */
#pragma once
#include <stdio.h>

#ifdef CONFIG_LUCAS_FS_TRACE
# define LUCAS_FS_TRACE(fmt, ...) printf("[fs] " fmt "\n", ##__VA_ARGS__)
#else
# define LUCAS_FS_TRACE(fmt, ...) do { (void)(fmt); } while (0)
#endif
