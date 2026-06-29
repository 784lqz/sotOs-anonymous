/*
 * sotOs · LUCAS L1 public API.
 *
 * For L1: a single entry point `lucas_run_l1()` called by root after
 * server spawning. It loads the named Linux ELF from root's CPIO archive,
 * creates a client process, and runs the syscall fault loop until the
 * client exits. Returns the client's exit code.
 */

#ifndef SOTOS_LUCAS_L1_H
#define SOTOS_LUCAS_L1_H

#include <sel4/sel4.h>
#include <vka/vka.h>
#include <vspace/vspace.h>
#include <simple/simple.h>

/* Run one Linux ELF to completion under LUCAS.
 *
 * Inputs:
 *   simple, vka, parent_vspace · the host (root task) environment.
 *   elf_bytes, elf_size        · pointer to the static Linux ELF in memory
 *                                 (usually retrieved via cpio_get_file).
 *
 * Returns the client's exit_group code on normal termination, or -1 on
 * setup failure.
 *
 * For L1 this is single-shot: one ELF, one client TCB, the function
 * returns when exit_group is called.
 */
int lucas_run_l1(simple_t *simple,
                 vka_t *vka,
                 vspace_t *parent_vspace,
                 const void *elf_bytes,
                 unsigned long elf_size,
                 const char *const argv[]);

#endif /* SOTOS_LUCAS_L1_H */
