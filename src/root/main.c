/*
 * sotOs · root task entry point
 *
 * Se ejecuta primero después del kernel. Su job:
 *   1. Bootstrap del environment (allocators, simple, vspace).
 *   2. Spawn del STO server con un endpoint nuevo.
 *   3. Spawn del test client con un cap minted del MISMO endpoint del
 *      server pero badged distinto (cada cliente = badge único).
 *   4. Esperar.
 *
 * The CPIO archive with child ELFs (sotOs-sto, sotOs-sto_hello,
 * sotOs-sto_conflict, sotOs-sto_isolation_test) is bundled into this binary
 * by src/root/CMakeLists.txt via MakeCPIO from seL4_tools. sel4utils
 * resolves the elf_name parameter against that embedded archive.
 */

#include "bootstrap.h"
#include "procd_shm_map.h"
#include "bytepipe_shm_map.h"
#include <stdio.h>
#include <string.h>
#include <sotos/string.h>
#include <sel4/sel4.h>
#include <simple/simple.h>
#include <sel4utils/process.h>
#include <vka/vka.h>
#include <vka/capops.h>
#include <orch/proto.h>

#define BADGE_STO_SERVER             0x1000  /* the server's listen endpoint badge */
#define BADGE_HELLO                  0xA001  /* sto_hello session badge */
#define BADGE_CAP_REVOKE             0xA002  /* sto_cap_revoke session badge */
#define BADGE_ORCH_STO               0xA003  /* sotFS-β-Phase-B · orch's STO session badge */
#define BADGE_ORCH_ANOMALY_EVENT    0xA004  /* Path D · badged anomaly event EP in orch's CSpace */
#define BADGE_ANOMALY_ORCH_CALLBACK 0xA005  /* Path D · badged orch EP in anomaly's CSpace */
#define BADGE_ORCH_SYNTH_EVENT     0xA006  /* sotNet-γ Phase 3-A · synth event EP in orch's CSpace */
#define BADGE_SYNTH_RESPONSE_TO_ORCH 0xA007 /* sotNet-γ Phase 3-D · badged orch main EP in synth's CSpace */
#define BADGE_PROCD_EVENT            0xA008  /* procd PR 4 · badged NTF cap in procd's CSpace (signals OR'd) */
#define BADGE_ANOMALY_OP_SET_TIER   0xA009  /* procd PR 10 · anomaly's badged procd EP (OP_SET_TIER + OP_REBIND_FUNCTOR) */

static sotos_env_t env;

extern char _cpio_archive[];
extern char _cpio_archive_end[];

int main(void)
{
    printf("\n=================================\n");
    printf("  sotOs · root task starting\n");
    printf("=================================\n");

    if (sotos_bootstrap(&env) != 0) {
        printf("[root] bootstrap failed, halting\n");
        return -1;
    }

    /* Path D · Phase 1: allocate anomaly event EP + configure anomaly process
     * BEFORE spawning orch, while root's allocman pool is fresh.
     * Orch's 14-bit CNode consumes significant untyped budget; anomaly must
     * be configured first.  Anomaly is spawned after orch's EP is known so
     * the callback slot (argv[2]) can be minted before process resume. */
    vka_object_t anomaly_event_ep_obj;
    memset(&anomaly_event_ep_obj, 0, sizeof(anomaly_event_ep_obj));
    sel4utils_process_t anomaly_proc;
    memset(&anomaly_proc, 0, sizeof(anomaly_proc));
    int anomaly_configured = 0;
    seL4_CPtr anomaly_event_slot = 0;   /* event EP slot in anomaly's CSpace */

    {
        int ev_err = vka_alloc_endpoint(&env.vka, &anomaly_event_ep_obj);
        if (ev_err != 0) {
            printf("[root] anomaly event EP alloc failed (err=%d) · A3-Phase-B disabled\n",
                   ev_err);
        } else {
            sel4utils_process_config_t anomaly_config = process_config_default_simple(
                &env.simple, "sotOs-anomaly", seL4_MaxPrio);
            anomaly_config = process_config_mcp(anomaly_config, seL4_MaxPrio);

            int sp_err = sel4utils_configure_process_custom(
                &anomaly_proc, &env.vka, &env.vspace, anomaly_config);
            if (sp_err != 0) {
                printf("[root] anomaly configure_process_custom failed (err=%d) · A3-Phase-B disabled\n",
                       sp_err);
            } else {
                /* Mint UNBADGED event EP into anomaly's CSpace.
                 * Anomaly seL4_Recvs on this slot. */
                cspacepath_t ev_path;
                vka_cspace_make_path(&env.vka, anomaly_event_ep_obj.cptr, &ev_path);
                anomaly_event_slot = sel4utils_mint_cap_to_process(
                    &anomaly_proc, ev_path, seL4_AllRights, 0 /* unbadged */);
                if (anomaly_event_slot != 0) {
                    anomaly_configured = 1;
                    printf("[root] anomaly configured · event_ep=%lu anomaly_event_slot=%lu\n",
                           (unsigned long)anomaly_event_ep_obj.cptr,
                           (unsigned long)anomaly_event_slot);
                } else {
                    printf("[root] anomaly event EP mint failed · A3-Phase-B disabled\n");
                }
            }
        }
    }

    /* sotNet-γ Phase 3-A Path D · Phase 1: allocate synth event EP + configure
     * synth process BEFORE spawning orch (same rationale as anomaly above). */
    vka_object_t synth_event_ep_obj;
    memset(&synth_event_ep_obj, 0, sizeof(synth_event_ep_obj));
    sel4utils_process_t synth_proc;
    memset(&synth_proc, 0, sizeof(synth_proc));
    int synth_configured = 0;
    seL4_CPtr synth_event_slot = 0;   /* event EP slot in synth's CSpace */

    {
        int ph_ev_err = vka_alloc_endpoint(&env.vka, &synth_event_ep_obj);
        if (ph_ev_err != 0) {
            printf("[root] synth event EP alloc failed (err=%d) · Phase 3-A disabled\n",
                   ph_ev_err);
        } else {
            sel4utils_process_config_t synth_config = process_config_default_simple(
                &env.simple, "sotOs-net-synth", seL4_MaxPrio);
            synth_config = process_config_mcp(synth_config, seL4_MaxPrio);

            int ph_sp_err = sel4utils_configure_process_custom(
                &synth_proc, &env.vka, &env.vspace, synth_config);
            if (ph_sp_err != 0) {
                printf("[root] synth configure_process_custom failed (err=%d) · Phase 3-A disabled\n",
                       ph_sp_err);
            } else {
                /* Copy UNBADGED event EP into synth's CSpace (slot 1 = initial EP).
                 * sotOs-net-synth seL4_Recvs on this slot. */
                cspacepath_t ph_ev_path;
                vka_cspace_make_path(&env.vka, synth_event_ep_obj.cptr, &ph_ev_path);
                synth_event_slot = sel4utils_mint_cap_to_process(
                    &synth_proc, ph_ev_path, seL4_AllRights, 0 /* unbadged */);
                if (synth_event_slot != 0) {
                    synth_configured = 1;
                    printf("[root] synth configured · event_ep=%lu synth_event_slot=%lu\n",
                           (unsigned long)synth_event_ep_obj.cptr,
                           (unsigned long)synth_event_slot);
                } else {
                    printf("[root] synth event EP mint failed · Phase 3-A disabled\n");
                }
            }
        }
    }

    /* procd Path D · Phase 1: allocate procd listen EP + configure procd
     * process BEFORE spawning orch. Same rationale as anomaly/synth:
     * root's allocman pool is fresh; procd is load-bearing once OP_SPAWN
     * migrates (see plan PR 5). procd's listen EP is the one clients
     * (orch, lucas, anomaly) seL4_Call for mutations.
     *
     * PR 4 · also allocate the event notification object here so procd
     * can seL4_Signal it after publishing to the SHM event ring, and
     * orch (Phase 2 below, once spawned) can seL4_Poll it on each main
     * loop pass.  Allocating up-front keeps cap layout deterministic.
     */
    vka_object_t procd_listen_ep_obj;
    memset(&procd_listen_ep_obj, 0, sizeof(procd_listen_ep_obj));
    vka_object_t procd_event_ntf_obj;
    memset(&procd_event_ntf_obj, 0, sizeof(procd_event_ntf_obj));
    sel4utils_process_t procd_proc;
    memset(&procd_proc, 0, sizeof(procd_proc));
    int procd_configured = 0;
    seL4_CPtr procd_listen_slot = 0;
    seL4_CPtr procd_ntf_slot_in_procd = 0;   /* set during Phase 1 */

    {
        int pd_ev_err = vka_alloc_endpoint(&env.vka, &procd_listen_ep_obj);
        if (pd_ev_err != 0) {
            printf("[root] procd listen EP alloc failed (err=%d) · procd disabled\n",
                   pd_ev_err);
        } else {
            sel4utils_process_config_t procd_config = process_config_default_simple(
                &env.simple, "sotOs-procd", seL4_MaxPrio);
            procd_config = process_config_mcp(procd_config, seL4_MaxPrio);

            int pd_sp_err = sel4utils_configure_process_custom(
                &procd_proc, &env.vka, &env.vspace, procd_config);
            if (pd_sp_err != 0) {
                printf("[root] procd configure_process_custom failed (err=%d)\n",
                       pd_sp_err);
            } else {
                cspacepath_t pd_ev_path;
                vka_cspace_make_path(&env.vka, procd_listen_ep_obj.cptr, &pd_ev_path);
                procd_listen_slot = sel4utils_mint_cap_to_process(
                    &procd_proc, pd_ev_path, seL4_AllRights, 0 /* unbadged */);
                if (procd_listen_slot != 0) {
                    procd_configured = 1;
                    printf("[root] procd configured · listen_ep=%lu procd_listen_slot=%lu\n",
                           (unsigned long)procd_listen_ep_obj.cptr,
                           (unsigned long)procd_listen_slot);
                } else {
                    printf("[root] procd listen EP mint failed\n");
                }

                /* PR 4 · allocate procd's event notification object and
                 * mint it into procd's CSpace with BADGE_PROCD_EVENT so
                 * subscribers can detect the signal via the notification
                 * word (seL4_Poll surfaces the badge in *sender).  Orch's
                 * Wait-side copy is minted in Phase 2 below, once
                 * orch_proc exists.  Failure here is non-fatal: procd
                 * still boots, just without the event channel. */
                if (procd_configured) {
                    int ntf_err = vka_alloc_notification(&env.vka, &procd_event_ntf_obj);
                    if (ntf_err != 0) {
                        printf("[root] procd NTF alloc failed (err=%d) · event channel disabled\n",
                               ntf_err);
                    } else {
                        cspacepath_t pd_ntf_path;
                        vka_cspace_make_path(&env.vka, procd_event_ntf_obj.cptr,
                                             &pd_ntf_path);
                        procd_ntf_slot_in_procd = sel4utils_mint_cap_to_process(
                            &procd_proc, pd_ntf_path, seL4_AllRights,
                            BADGE_PROCD_EVENT);
                        if (procd_ntf_slot_in_procd != 0) {
                            printf("[root] procd NTF minted · ntf=%lu procd_slot=%lu badge=0x%x\n",
                                   (unsigned long)procd_event_ntf_obj.cptr,
                                   (unsigned long)procd_ntf_slot_in_procd,
                                   (unsigned)BADGE_PROCD_EVENT);
                        } else {
                            printf("[root] procd NTF mint into procd failed · event channel disabled\n");
                        }
                    }
                }
            }
        }
    }

    /* PR 3 · procd unit test ELF · CONFIGURED HERE (Phase 1) while the
     * allocman pool is still fresh; spawned later (Phase 2) after orch
     * exists, so root has moved on by the time procd-unit starts running
     * its tests.  configure_process_custom maps ~2 MiB of writable BSS
     * for the test's static SHM scratch buffer; doing this AFTER orch's
     * delegation eats untypeds reliably failed silently in PR 3 testing.
     */
    sel4utils_process_t procd_unit_proc;
    memset(&procd_unit_proc, 0, sizeof(procd_unit_proc));
    int procd_unit_configured = 0;
    {
        sel4utils_process_config_t unit_cfg = process_config_default_simple(
            &env.simple, "sotOs-procd-unit", seL4_MaxPrio);
        unit_cfg = process_config_mcp(unit_cfg, seL4_MaxPrio);
        int unit_cfg_rc = sel4utils_configure_process_custom(
            &procd_unit_proc, &env.vka, &env.vspace, unit_cfg);
        if (unit_cfg_rc != 0) {
            printf("[root] procd-unit configure failed (rc=%d)\n", unit_cfg_rc);
        } else {
            procd_unit_configured = 1;
            printf("[root] procd-unit configured\n");
        }
    }

    /* PR 8 · WAL unit test ELF · configured here while the allocman
     * pool is fresh, spawned later (Phase 2) alongside procd-unit so
     * both tests print PASS/FAIL lines before orch's main demo starts.
     * Same rationale as procd-unit · configure_process_custom after
     * orch's untyped delegation has been failing silently in earlier
     * PRs, so we keep the "configure before delegate" pattern. */
    sel4utils_process_t wal_unit_proc;
    memset(&wal_unit_proc, 0, sizeof(wal_unit_proc));
    int wal_unit_configured = 0;
    {
        sel4utils_process_config_t wal_cfg = process_config_default_simple(
            &env.simple, "sotOs-wal-unit", seL4_MaxPrio);
        wal_cfg = process_config_mcp(wal_cfg, seL4_MaxPrio);
        int wal_cfg_rc = sel4utils_configure_process_custom(
            &wal_unit_proc, &env.vka, &env.vspace, wal_cfg);
        if (wal_cfg_rc != 0) {
            printf("[root] wal-unit configure failed (rc=%d)\n", wal_cfg_rc);
        } else {
            wal_unit_configured = 1;
            printf("[root] wal-unit configured\n");
        }
    }

    /* sotnano PR 2 · gap-buffer unit test ELF · configured here while the
     * allocman pool is fresh, spawned later (Phase 2) alongside the other
     * unit fixtures so all tests print PASS/FAIL lines before orch's main
     * demo starts.  Same "configure before delegate" rationale as the
     * procd/wal unit fixtures above. */
    sel4utils_process_t sotnano_unit_proc;
    memset(&sotnano_unit_proc, 0, sizeof(sotnano_unit_proc));
    int sotnano_unit_configured = 0;
    {
        sel4utils_process_config_t sn_cfg = process_config_default_simple(
            &env.simple, "sotOs-sotnano-unit", seL4_MaxPrio);
        sn_cfg = process_config_mcp(sn_cfg, seL4_MaxPrio);
        int sn_cfg_rc = sel4utils_configure_process_custom(
            &sotnano_unit_proc, &env.vka, &env.vspace, sn_cfg);
        if (sn_cfg_rc != 0) {
            printf("[root] sotnano-unit configure failed (rc=%d)\n", sn_cfg_rc);
        } else {
            sotnano_unit_configured = 1;
            printf("[root] sotnano-unit configured\n");
        }
    }

    /* sotinit Path D · Phase 1: allocate sotinit listen EP + configure
     * sotinit process BEFORE spawning orch · same allocman-pool-freshness
     * rationale as procd above.  sotinit is the systemd-style init
     * scheduler · sibling of orch / procd in the Path D layout.  PR 1
     * scaffold spawns the ELF with a single listen EP slot in argv[1];
     * subsequent PRs add unit file parsing, the procd OP_SPAWN client
     * path for service activation, and the operator query handlers.
     *
     * Spec: init-cron-scheduler-design §3.
     */
    vka_object_t sotinit_listen_ep_obj;
    memset(&sotinit_listen_ep_obj, 0, sizeof(sotinit_listen_ep_obj));
    sel4utils_process_t sotinit_proc;
    memset(&sotinit_proc, 0, sizeof(sotinit_proc));
    int sotinit_configured = 0;
    seL4_CPtr sotinit_listen_slot = 0;

    {
        int rc = vka_alloc_endpoint(&env.vka, &sotinit_listen_ep_obj);
        if (rc != 0) {
            printf("[root] sotinit listen EP alloc failed (err=%d) · sotinit disabled\n", rc);
        } else {
            sel4utils_process_config_t cfg = process_config_default_simple(
                &env.simple, "sotOs-sotinit", seL4_MaxPrio);
            cfg = process_config_mcp(cfg, seL4_MaxPrio);
            int cfg_rc = sel4utils_configure_process_custom(
                &sotinit_proc, &env.vka, &env.vspace, cfg);
            if (cfg_rc != 0) {
                printf("[root] sotinit configure_process_custom failed (err=%d)\n", cfg_rc);
            } else {
                cspacepath_t path;
                vka_cspace_make_path(&env.vka, sotinit_listen_ep_obj.cptr, &path);
                sotinit_listen_slot = sel4utils_mint_cap_to_process(
                    &sotinit_proc, path, seL4_AllRights, 0 /* unbadged */);
                if (sotinit_listen_slot != 0) {
                    sotinit_configured = 1;
                    printf("[root] sotinit configured · listen_ep=%lu slot=%lu\n",
                           (unsigned long)sotinit_listen_ep_obj.cptr,
                           (unsigned long)sotinit_listen_slot);
                } else {
                    printf("[root] sotinit listen EP mint failed\n");
                }
            }
        }
    }

    /* sotcron Path D · Phase 1: allocate sotcron listen EP + configure
     * sotcron process BEFORE spawning orch · same allocman-pool-freshness
     * rationale as sotinit above.  sotcron is the systemd-style timer
     * scheduler · sibling of sotinit / procd in the Path D layout.  PR 7
     * scaffold spawns the ELF with a single listen EP slot in argv[1];
     * subsequent PRs add OnCalendar / OnUnitActiveSec parsers, the fire
     * dispatch path into sotinit (SOTINIT_OP_ACTIVATE), and the operator
     * query handlers.
     *
     * Spec: init-cron-scheduler-design §4.
     */
    vka_object_t sotcron_listen_ep_obj;
    memset(&sotcron_listen_ep_obj, 0, sizeof(sotcron_listen_ep_obj));
    sel4utils_process_t sotcron_proc;
    memset(&sotcron_proc, 0, sizeof(sotcron_proc));
    int sotcron_configured = 0;
    seL4_CPtr sotcron_listen_slot = 0;

    {
        int rc = vka_alloc_endpoint(&env.vka, &sotcron_listen_ep_obj);
        if (rc != 0) {
            printf("[root] sotcron listen EP alloc failed (err=%d) · sotcron disabled\n", rc);
        } else {
            sel4utils_process_config_t cfg = process_config_default_simple(
                &env.simple, "sotOs-sotcron", seL4_MaxPrio);
            cfg = process_config_mcp(cfg, seL4_MaxPrio);
            int cfg_rc = sel4utils_configure_process_custom(
                &sotcron_proc, &env.vka, &env.vspace, cfg);
            if (cfg_rc != 0) {
                printf("[root] sotcron configure_process_custom failed (err=%d)\n", cfg_rc);
            } else {
                cspacepath_t path;
                vka_cspace_make_path(&env.vka, sotcron_listen_ep_obj.cptr, &path);
                sotcron_listen_slot = sel4utils_mint_cap_to_process(
                    &sotcron_proc, path, seL4_AllRights, 0 /* unbadged */);
                if (sotcron_listen_slot != 0) {
                    sotcron_configured = 1;
                    printf("[root] sotcron configured · listen_ep=%lu slot=%lu\n",
                           (unsigned long)sotcron_listen_ep_obj.cptr,
                           (unsigned long)sotcron_listen_slot);
                } else {
                    printf("[root] sotcron listen EP mint failed\n");
                }
            }
        }
    }

    /* L12-alpha · Wayland compositor Path-D scaffold.  Configure before orch
     * while root's allocman pool is fresh, matching the other Path-D siblings.
     * L12-beta will use the orch-visible listen EP slot to route the narrow
     * /run/user/1000/wayland-0 AF_UNIX special case. */
    vka_object_t wayland_listen_ep_obj;
    memset(&wayland_listen_ep_obj, 0, sizeof(wayland_listen_ep_obj));
    sel4utils_process_t wayland_proc;
    memset(&wayland_proc, 0, sizeof(wayland_proc));
    int wayland_configured = 0;
    seL4_CPtr wayland_listen_slot = 0;

    {
        int rc = vka_alloc_endpoint(&env.vka, &wayland_listen_ep_obj);
        if (rc != 0) {
            printf("[root] wayland listen EP alloc failed (err=%d) · wayland disabled\n", rc);
        } else {
            sel4utils_process_config_t cfg = process_config_default_simple(
                &env.simple, "sotOs-wl-compositor", seL4_MaxPrio);
            cfg = process_config_mcp(cfg, seL4_MaxPrio);
            int cfg_rc = sel4utils_configure_process_custom(
                &wayland_proc, &env.vka, &env.vspace, cfg);
            if (cfg_rc != 0) {
                printf("[root] wayland configure_process_custom failed (err=%d)\n", cfg_rc);
            } else {
                cspacepath_t path;
                vka_cspace_make_path(&env.vka, wayland_listen_ep_obj.cptr, &path);
                wayland_listen_slot = sel4utils_mint_cap_to_process(
                    &wayland_proc, path, seL4_AllRights, 0 /* unbadged */);
                if (wayland_listen_slot != 0) {
                    wayland_configured = 1;
                    printf("[root] wayland configured · listen_ep=%lu slot=%lu\n",
                           (unsigned long)wayland_listen_ep_obj.cptr,
                           (unsigned long)wayland_listen_slot);
                } else {
                    printf("[root] wayland listen EP mint failed\n");
                }
            }
        }
    }

    /* L14a-A1 · Wayland shadow compositor Path-D scaffold.  Configure before orch
     * while root's allocman pool is fresh, matching the other Path-D siblings.
     * A later task will route flagged-hostile clients here (away from the honest
     * compositor) by using the orch-visible listen EP slot. */
    vka_object_t canary_listen_ep_obj;
    memset(&canary_listen_ep_obj, 0, sizeof(canary_listen_ep_obj));
    sel4utils_process_t canary_proc;
    memset(&canary_proc, 0, sizeof(canary_proc));
    int canary_configured = 0;
    seL4_CPtr canary_listen_slot = 0;

    {
        int rc = vka_alloc_endpoint(&env.vka, &canary_listen_ep_obj);
        if (rc != 0) {
            printf("[root] shadow listen EP alloc failed (err=%d) · shadow disabled\n", rc);
        } else {
            sel4utils_process_config_t cfg = process_config_default_simple(
                &env.simple, "sotOs-wl-canary", seL4_MaxPrio);
            cfg = process_config_mcp(cfg, seL4_MaxPrio);
            int cfg_rc = sel4utils_configure_process_custom(
                &canary_proc, &env.vka, &env.vspace, cfg);
            if (cfg_rc != 0) {
                printf("[root] shadow configure_process_custom failed (err=%d)\n", cfg_rc);
            } else {
                cspacepath_t path;
                vka_cspace_make_path(&env.vka, canary_listen_ep_obj.cptr, &path);
                canary_listen_slot = sel4utils_mint_cap_to_process(
                    &canary_proc, path, seL4_AllRights, 0 /* unbadged */);
                if (canary_listen_slot != 0) {
                    canary_configured = 1;
                    printf("[root] shadow configured · listen_ep=%lu slot=%lu\n",
                           (unsigned long)canary_listen_ep_obj.cptr,
                           (unsigned long)canary_listen_slot);
                } else {
                    printf("[root] shadow listen EP mint failed\n");
                }
            }
        }
    }

    /* L3a-T3: spawn the lucas-orchestrator with a larger CNode (14 bits)
     * so delegated untyped caps can be copied into its CSpace. */
    sel4utils_process_t orch_proc;
    seL4_CPtr orch_ep = 0;
    int orch_rc = sotos_spawn_orch(&env, "sotOs-lucas-orch", "orch",
                                     &orch_proc, &orch_ep, 0xC0FFEE);
    if (orch_rc != 0 || orch_ep == 0) {
        printf("[root] failed to spawn lucas-orchestrator (rc=%d) · continuing degraded\n",
               orch_rc);
    } else {
        printf("[root] orchestrator EP=%lu\n", (unsigned long)orch_ep);
    }

    /* procd-authoritative-GC · cross-vspace SHM mapping (replaces the PR4
     * NTF-only deferral).  Allocate the 1 MiB SHM as explicit frames NOW,
     * while the allocman pool is fresh and before untyped delegation, then
     * map RW into procd + RO into orch.  procd is configured (Phase 1) but
     * not yet resumed, so it cannot touch the region before it is mapped;
     * orch is running but never dereferences it until BOOTSTRAP + a drain
     * signal.  The vaddrs are consumed below: rw → procd argv[4],
     * ro → bs.procd_shm_base. */
    uintptr_t procd_shm_rw_vaddr = 0;   /* procd's RW view  → argv[4]          */
    uintptr_t procd_shm_ro_vaddr = 0;   /* orch's RO view   → bs.procd_shm_base */
    if (procd_configured && orch_rc == 0 && orch_ep != 0) {
        int map_rc = root_map_procd_shm(&env, &procd_proc, &orch_proc,
                                        &procd_shm_rw_vaddr,
                                        &procd_shm_ro_vaddr);
        if (map_rc != 0) {
            printf("[root] procd SHM cross-map failed (rc=%d) · NTF-only fallback\n",
                   map_rc);
            procd_shm_rw_vaddr = 0;
            procd_shm_ro_vaddr = 0;
        }
    }

    /* sotNet γ-3-γ-1 · stand up the orch<->responder byte channel.  The
     * responder is configured (Phase 1) but resumed only in Phase 2 below, so
     * it cannot touch the region before it is mapped; orch is running but
     * never dereferences it until BOOTSTRAP sets bytepipe_ready.  On any
     * failure we leave the channel disabled and fall back to the
     * message-register path. */
    int bytepipe_ready = 0;
    if (synth_configured && orch_rc == 0 && orch_ep != 0) {
        if (root_map_bytepipe_shm(&env, &orch_proc, &synth_proc) == 0) {
            bytepipe_ready = 1;
        } else {
            printf("[root] bytepipe SHM map failed · message-register fallback\n");
        }
    }

    /* N2-T · inbound framed transport · a SECOND ring pair, mapped only if the
     * outbound pipe (and thus synth + orch) is already up. */
    int bytepipe2_ready = 0;
    if (bytepipe_ready) {
        if (root_map_bytepipe_shm2(&env, &orch_proc, &synth_proc) == 0)
            bytepipe2_ready = 1;
        else
            printf("[root] inbound bytepipe SHM map failed · inbound disabled\n");
    }

    /* SSH canary shell (Phase B) · a THIRD ring pair carrying the decrypted shell
     * stream, mapped only if the inbound pair (and thus synth + orch) is up. */
    int bytepipe3_ready = 0;
    if (bytepipe2_ready) {
        if (root_map_bytepipe_shm3(&env, &orch_proc, &synth_proc) == 0)
            bytepipe3_ready = 1;
        else
            printf("[root] shell bytepipe SHM map failed · SSH shell disabled\n");
    }

    /* T3: iterate untypeds, delegate non-device ones >= 2^18 (256 KiB) into
     * the orchestrator's CSpace, then send the BOOTSTRAP message with the
     * populated orch_bootstrap_info_t payload. */
    orch_bootstrap_info_t bs;
    memset(&bs, 0, sizeof(bs));
    bs.bytepipe_ready = (uint64_t)bytepipe_ready;
    bs.bytepipe2_ready = (uint64_t)bytepipe2_ready;
    bs.bytepipe3_ready = (uint64_t)bytepipe3_ready;

    if (orch_ep != 0) {
        int ut_total = simple_get_untyped_count(&env.simple);
        const size_t MIN_BITS = 18;   /* take untypeds >= 256 KiB so orch
                                          can carve several frames + TCBs */
        /* OBSD-η · also delegate the device untyped covering TPM MMIO
         * (0xFED40000-0xFED40FFF · TIS locality 0) so orch's userland
         * TPM driver can vka_alloc_frame_at that paddr.  We accept any
         * device untyped whose [paddr, paddr+(1<<size_bits)) interval
         * straddles 0xFED40000. */
        const uintptr_t TPM_TIS_PADDR = 0xFED40000UL;
        /* PCI MMIO BAR window (below the IOAPIC at 0xFEC00000): this is where
         * QEMU assigns virtio-gpu / virtio-keyboard BARs. We delegate device
         * untypeds overlapping it (so orch can map those BARs) PLUS the TPM TIS
         * frame — but NOT the ~20 tiny APIC/HPET device untypeds, which would
         * otherwise flood ORCH_MAX_DELEGATED_UNTYPEDS and crowd out the RAM
         * untypeds orch needs for its allocman + arena pool. */
        const uintptr_t PCI_MMIO_LO = 0x80000000UL;
        const uintptr_t PCI_MMIO_HI = 0xFEC00000UL;
        /* High 64-bit PCI MMIO hole.  Modern QEMU (10.x i440fx) assigns the
         * virtio-gpu / virtio-keyboard / virtio-tablet 64-bit prefetchable BAR4
         * up in the high PCI hole — observed at ~0xe0000008000 (~15 TiB) — far
         * above PCI_MMIO_HI.  seL4 covers that whole zone with ONE large device
         * untyped ([0x8000000000, 0x408000000000) · 64 TiB on this host), so a
         * single extra delegation lets orch vka_alloc_frame_at the high BARs.
         * Without it the virtio-gpu is invisible and the graphical console comes
         * up headless (older QEMU placed these BARs in the 32-bit window above,
         * so this path only triggers on newer hosts).  Bounded to the one big
         * untyped so it never floods ORCH_MAX_DELEGATED_UNTYPEDS. */
        const uintptr_t PCI_MMIO64_LO = 0x8000000000ULL;   /* 512 GiB */
        const uintptr_t PCI_MMIO64_HI = 0x408000000000ULL; /*  70 TiB */
        uint32_t taken = 0;
        /* Two passes so RAM untypeds are NEVER crowded out by device untypeds
         * (the device untypeds are enumerated first on QEMU; a single capped
         * loop filled all 32 slots with device untypeds → orch got 0 RAM → its
         * arena pool came up empty and bootstrap failed). Pass 0 = RAM,
         * Pass 1 = the selected device untypeds. Slots are allocated
         * sequentially by sel4utils_copy_cap_to_process, so the delegated caps
         * still land in consecutive orch CSpace slots from cnode_slot_first. */
        for (int pass = 0; pass < 2 && taken < ORCH_MAX_DELEGATED_UNTYPEDS; ++pass) {
            for (int i = 0; i < ut_total && taken < ORCH_MAX_DELEGATED_UNTYPEDS; ++i) {
                size_t   size_bits = 0;
                uintptr_t paddr    = 0;
                bool     is_device = false;
                seL4_CPtr ut = simple_get_nth_untyped(&env.simple, i,
                                                        &size_bits, &paddr,
                                                        &is_device);
                if (pass == 0) {
                    /* RAM untypeds (essential: orch's allocman + arena pool). */
                    if (is_device) continue;
                    if (size_bits < MIN_BITS) continue;
                } else {
                    /* Device untypeds: only the PCI MMIO BAR window + the TPM. */
                    if (!is_device) continue;
                    uintptr_t end = paddr + ((uintptr_t)1u << size_bits);
                    int in_pci   = (paddr < PCI_MMIO_HI)   && (end > PCI_MMIO_LO);
                    int in_pci64 = (paddr < PCI_MMIO64_HI) && (end > PCI_MMIO64_LO);
                    int is_tpm   = (paddr <= TPM_TIS_PADDR) && (TPM_TIS_PADDR < end);
                    if (!in_pci && !in_pci64 && !is_tpm) continue;
                }
                /* Copy the untyped cap into orch's CSpace.
                 * seL4_CNode_Copy calls deriveCap/ensureNoChildren on the source.
                 * If root's allocman has already retyped this untyped (to create
                 * frames for loading orch's ELF etc.), the copy will fail with
                 * seL4_RevokeFirst.  Skip such untypeds; only delegate clear ones
                 * that orch can actually retype from. */
                seL4_CPtr dst_slot = sel4utils_copy_cap_to_process(&orch_proc,
                                                                     &env.vka,
                                                                     ut);
                if (dst_slot == 0) {
                    /* already retyped (or CSpace full) — skip silently */
                    continue;
                }
                if (taken == 0) bs.cnode_slot_first = dst_slot;
                bs.ut_size_bits[taken] = (uint64_t)size_bits;
                bs.ut_paddr[taken]     = (uint64_t)paddr;
                bs.ut_is_device[taken] = is_device ? 1 : 0;
                if (is_device) {
                    printf("[root] delegating device untyped (PCI BAR/TPM) · paddr=0x%lx size_bits=%zu\n",
                           (unsigned long)paddr, size_bits);
                }
                ++taken;
            }
        }
        bs.untyped_count = taken;
        printf("[root] delegated %u untypeds to orchestrator (first slot=%lu)\n",
               taken, (unsigned long)bs.cnode_slot_first);
    }

    /* virtio-blk Phase 2b · delegate the x86 IOPort cap to orch so it
     * can enumerate PCI + drive virtio-blk via ports 0xCF8/0xCFC.
     * TODO: tighten to sub-range 0xCF8-0xCFF + virtio device own ports once
     *       BAR0 is known (Phase 2c).  For now we issue the full 0x0000-0xFFFF
     *       range so orch can probe all PCI config space without further minting.
     *
     * Implementation: simple_get_IOPort_cap calls seL4_X86_IOPortControl_Issue,
     * which mints a new IOPort cap into a CNode slot we specify.  We use
     * vka_cspace_alloc_path to get a correctly-formed cspacepath_t (with the
     * right root CNode address), issue the cap there, then copy it into orch's
     * CSpace via sel4utils_copy_cap_to_process.  The temp slot in root's CSpace
     * is intentionally not freed after the copy (freeing it would revoke the
     * derived copy in orch's CSpace). */
    if (orch_ep != 0) {
        cspacepath_t io_path;
        int io_alloc_err = vka_cspace_alloc_path(&env.vka, &io_path);
        if (io_alloc_err != 0) {
            printf("[root] vka_cspace_alloc_path for IOPort failed (err=%d) · skipping delegation\n",
                   io_alloc_err);
        } else {
            /* Issue a full-range IOPort cap (0x0000-0xFFFF) into the allocated slot.
             * simple_get_IOPort_cap(simple, start, end, cnode_root, slot, depth) */
            seL4_Error io_issue = (seL4_Error)simple_get_IOPort_cap(
                &env.simple, 0, 0xFFFF,
                io_path.root, io_path.capPtr, (seL4_Word)io_path.capDepth);
            if (io_issue != seL4_NoError) {
                printf("[root] simple_get_IOPort_cap failed (err=%d) · skipping delegation\n",
                       (int)io_issue);
                vka_cspace_free(&env.vka, io_path.capPtr);
            } else {
                seL4_CPtr dst_slot = sel4utils_copy_cap_to_process(&orch_proc,
                                                                     &env.vka,
                                                                     io_path.capPtr);
                if (dst_slot != 0) {
                    bs.io_port_slot = (uint64_t)dst_slot;
                    printf("[root] IOPort cap delegated to orch · slot=%lu\n",
                           (unsigned long)dst_slot);
                } else {
                    printf("[root] sel4utils_copy_cap_to_process IOPort failed · skipping delegation\n");
                }
                /* Program PIT (i8254) channel 0 for a periodic ~100 Hz tick (mode 2,
                 * rate generator).  Its IRQ (claimed below as GSI 2) gives the lwIP
                 * egress pump a periodic wake so raw_poll/complete_tx runs even with
                 * no RX IRQ.  cmd 0x34 = ch0, lo/hi access, mode 2, binary; divisor
                 * 11932 = 1193182/100 Hz.  Uses root's full-range IOPort cap. */
                (void)seL4_X86_IOPort_Out8(io_path.capPtr, 0x43, 0x34);
                (void)seL4_X86_IOPort_Out8(io_path.capPtr, 0x40, 0x9C); /* divisor lo */
                (void)seL4_X86_IOPort_Out8(io_path.capPtr, 0x40, 0x2E); /* divisor hi */
                printf("[root] PIT ch0 → ~100 Hz periodic (egress pump tick)\n");
            }
        }
    }

    /* Path D · Phase 2: now that orch is spawned (orch_proc + orch_ep are live),
     * complete anomaly wiring:
     *   (a) Mint event EP copy into orch's CSpace → bs.anomaly_event_ep_slot
     *   (b) Mint orch EP into anomaly's CSpace as callback (badged 0xA005)
     *   (c) Resume anomaly with argv = [name, event_slot, callback_slot]
     * anomaly_configured == 1 means Phase 1 succeeded. */
    if (orch_ep != 0 && anomaly_configured) {
        /* (a) Copy event EP into orch's CSpace.
         * sel4utils_copy_cap_to_process uses CNode_Copy (unbadged). */
        seL4_CPtr orch_event_slot = sel4utils_copy_cap_to_process(
            &orch_proc, &env.vka, anomaly_event_ep_obj.cptr);

        /* (b) Mint orch's listen EP into anomaly's CSpace with badge 0xA005.
         * Anomaly seL4_Calls this for ORCH_OP_PROMOTE_TIER callbacks. */
        cspacepath_t orch_ep_path;
        vka_cspace_make_path(&env.vka, orch_ep, &orch_ep_path);
        seL4_CPtr anomaly_callback_slot = sel4utils_mint_cap_to_process(
            &anomaly_proc, orch_ep_path, seL4_AllRights,
            BADGE_ANOMALY_ORCH_CALLBACK);

        /* (b') procd PR 10 · mint procd's listen EP into anomaly's CSpace
         * badged with BADGE_ANOMALY_OP_SET_TIER (0xA009).  Anomaly
         * seL4_Calls this for OP_SET_TIER + OP_REBIND_FUNCTOR; procd's
         * dispatcher reads the badge off seL4_Recv and only honours the
         * mutation when badge == 0xA009.  Non-fatal if procd never came
         * up · anomaly falls back to the legacy ORCH_OP_PROMOTE_TIER
         * path so the dual-write demo invariant still drives the
         * writes_silenced/is_isolated flag flip. */
        seL4_CPtr anomaly_procd_ep_slot = 0;
        if (procd_configured) {
            cspacepath_t procd_listen_path;
            vka_cspace_make_path(&env.vka, procd_listen_ep_obj.cptr,
                                 &procd_listen_path);
            anomaly_procd_ep_slot = sel4utils_mint_cap_to_process(
                &anomaly_proc, procd_listen_path, seL4_AllRights,
                BADGE_ANOMALY_OP_SET_TIER);
            if (anomaly_procd_ep_slot != 0) {
                printf("[root] procd EP minted into anomaly (badged 0x%x) · slot=%lu\n",
                       (unsigned)BADGE_ANOMALY_OP_SET_TIER,
                       (unsigned long)anomaly_procd_ep_slot);
            } else {
                printf("[root] procd EP mint into anomaly failed · OP_SET_TIER disabled (legacy path remains)\n");
            }
        }

        /* PR 4 · WAL IPC · mint an UNBADGED copy of orch's listen EP into
         * anomaly's CSpace.  anomaly uses this to seL4_Call
         * SOTFS_OP_WAL_LOG and mirror anomaly events into the sotfs
         * WAL.  Distinct from anomaly_callback_slot (badged 0xA005 for
         * ORCH_OP_PROMOTE_TIER) · the WAL op routes purely on the message
         * label so an unbadged cap is sufficient.  0 if mint fails ·
         * anomaly's g_wal_attached stays 0 and the writer hook is a no-op. */
        seL4_CPtr anomaly_wal_ep_slot = sel4utils_mint_cap_to_process(
            &anomaly_proc, orch_ep_path, seL4_AllRights,
            0 /* unbadged · op label routes the call */);
        if (anomaly_wal_ep_slot != 0) {
            printf("[root] anomaly WAL EP (orch listen) minted · anomaly_slot=%lu\n",
                   (unsigned long)anomaly_wal_ep_slot);
        } else {
            printf("[root] anomaly WAL EP mint failed · WAL IPC disabled\n");
        }

        if (orch_event_slot != 0 && anomaly_callback_slot != 0) {
            bs.anomaly_event_ep_slot = (uint64_t)orch_event_slot;

            /* (c) Resume anomaly with full argv.  PR 10 adds the optional
             * procd_ep slot as argv[3] · the anomaly binary reads it as
             * g_procd_ep and falls back to the legacy orch callback path
             * when 0 (procd not configured / mint failed).
             *
             * PR 4 · adds the WAL EP slot as argv[4] · the anomaly binary
             * reads it as g_sotfs_wal_ep and uses it to seL4_Call
             * SOTFS_OP_WAL_LOG.  Flips g_wal_attached = 1 once verified
             * non-zero so the sotguard_emit-side mirror starts logging. */
            char ev_slot_str[32], cb_slot_str[32], pd_slot_str[32];
            char wal_slot_str[32];
            snprintf(ev_slot_str, sizeof(ev_slot_str), "%lu",
                     (unsigned long)anomaly_event_slot);
            snprintf(cb_slot_str, sizeof(cb_slot_str), "%lu",
                     (unsigned long)anomaly_callback_slot);
            snprintf(pd_slot_str, sizeof(pd_slot_str), "%lu",
                     (unsigned long)anomaly_procd_ep_slot);
            snprintf(wal_slot_str, sizeof(wal_slot_str), "%lu",
                     (unsigned long)anomaly_wal_ep_slot);
            char *anomaly_argv[] = {
                "sotOs-anomaly",
                ev_slot_str,
                cb_slot_str,
                pd_slot_str,
                wal_slot_str,
                NULL
            };
            int launch_err = sel4utils_spawn_process_v(
                &anomaly_proc, &env.vka, &env.vspace,
                5, anomaly_argv, 1 /* resume */);
            if (launch_err != 0) {
                printf("[root] anomaly spawn_process_v failed (err=%d) · A3-Phase-B disabled\n",
                       launch_err);
                bs.anomaly_event_ep_slot = 0;
            } else {
                printf("[root] anomaly ready · orch_event_slot=%lu anomaly_event_slot=%lu callback_slot=%lu procd_ep_slot=%lu wal_ep_slot=%lu\n",
                       (unsigned long)orch_event_slot,
                       (unsigned long)anomaly_event_slot,
                       (unsigned long)anomaly_callback_slot,
                       (unsigned long)anomaly_procd_ep_slot,
                       (unsigned long)anomaly_wal_ep_slot);
            }
        } else {
            printf("[root] anomaly Phase 2 cap minting failed (orch_slot=%lu cb_slot=%lu) · A3-Phase-B disabled\n",
                   (unsigned long)orch_event_slot,
                   (unsigned long)anomaly_callback_slot);
        }
    } else if (anomaly_configured && orch_ep == 0) {
        printf("[root] anomaly configured but orch failed · A3-Phase-B disabled\n");
    }

    /* sotNet-γ Phase 3-A Path D · Phase 2: complete synth wiring now that orch is live.
     *   (a) Copy event EP into orch's CSpace → bs.synth_event_ep_slot
     *   (b) Mint orch's main EP into synth's CSpace as Phase 3-D callback EP
     *       (badged BADGE_SYNTH_RESPONSE_TO_ORCH=0xA007).  Synth seL4_Calls
     *       this with ORCH_OP_SYNTH_RESPONSE after response_profile_dispatch.
     *   (c) Resume synth with argv = [name, event_slot, callback_slot]
     * synth_configured == 1 means Phase 1 succeeded. */
    if (orch_ep != 0 && synth_configured) {
        /* (a) Copy event EP into orch's CSpace (unbadged). */
        seL4_CPtr orch_synth_slot = sel4utils_copy_cap_to_process(
            &orch_proc, &env.vka, synth_event_ep_obj.cptr);

        /* (b) Mint orch's listen EP into synth's CSpace with badge 0xA007.
         * Synth seL4_Calls this for ORCH_OP_SYNTH_RESPONSE callbacks
         * (closes the γ Phase 3-D synth→orch loop). */
        cspacepath_t orch_ep_path_ph;
        vka_cspace_make_path(&env.vka, orch_ep, &orch_ep_path_ph);
        seL4_CPtr synth_callback_slot = sel4utils_mint_cap_to_process(
            &synth_proc, orch_ep_path_ph, seL4_AllRights,
            BADGE_SYNTH_RESPONSE_TO_ORCH);

        if (orch_synth_slot != 0 && synth_callback_slot != 0) {
            bs.synth_event_ep_slot = (uint64_t)orch_synth_slot;

            /* (c) Resume synth with full argv (event_slot + callback_slot). */
            char ph_ev_slot_str[32], ph_cb_slot_str[32], ph_bp_str[8];
            char ph_bp2_str[8];   /* N2-T · inbound bytepipe ready flag (argv[4]) */
            char ph_bp3_str[8];   /* SSH canary shell · shell bytepipe ready (argv[5]) */
            snprintf(ph_ev_slot_str, sizeof(ph_ev_slot_str), "%lu",
                     (unsigned long)synth_event_slot);
            snprintf(ph_cb_slot_str, sizeof(ph_cb_slot_str), "%lu",
                     (unsigned long)synth_callback_slot);
            snprintf(ph_bp_str, sizeof(ph_bp_str), "%d", bytepipe_ready);
            snprintf(ph_bp2_str, sizeof(ph_bp2_str), "%d", bytepipe2_ready);
            snprintf(ph_bp3_str, sizeof(ph_bp3_str), "%d", bytepipe3_ready);
            char *synth_argv[] = {
                "sotOs-net-synth",
                ph_ev_slot_str,
                ph_cb_slot_str,
                ph_bp_str,
                ph_bp2_str,
                ph_bp3_str,
                NULL
            };
            int ph_launch_err = sel4utils_spawn_process_v(
                &synth_proc, &env.vka, &env.vspace,
                6, synth_argv, 1 /* resume */);
            if (ph_launch_err != 0) {
                printf("[root] synth spawn_process_v failed (err=%d) · Phase 3-A disabled\n",
                       ph_launch_err);
                bs.synth_event_ep_slot = 0;
            } else {
                printf("[root] synth ready · orch_synth_slot=%lu synth_event_slot=%lu callback_slot=%lu (Phase 3-D)\n",
                       (unsigned long)orch_synth_slot,
                       (unsigned long)synth_event_slot,
                       (unsigned long)synth_callback_slot);
            }
        } else {
            printf("[root] synth Phase 2 cap minting failed (orch_slot=%lu cb_slot=%lu) · Phase 3-A disabled\n",
                   (unsigned long)orch_synth_slot,
                   (unsigned long)synth_callback_slot);
        }
    } else if (synth_configured && orch_ep == 0) {
        printf("[root] synth configured but orch failed · Phase 3-A disabled\n");
    }

    /* procd Path D · Phase 2: now that orch is spawned and the rest of the
     * Path D siblings are configured, resume procd with argv = [name, listen_slot, ntf_slot].
     * PR 4 · also mint procd's event NTF into orch's CSpace so orch can
     * seL4_Poll for procd-publish-wakeups in its main loop.  The SHM
     * cross-vspace mapping (procd_shm_base) ships in PR 5 alongside the
     * OP_SPAWN migration; until then orch operates in NTF-only mode and
     * just prints '[orch] procd signaled' when the NTF fires. */
    if (procd_configured && procd_ntf_slot_in_procd != 0 && orch_ep != 0) {
        cspacepath_t pd_ntf_path_for_orch;
        vka_cspace_make_path(&env.vka, procd_event_ntf_obj.cptr,
                             &pd_ntf_path_for_orch);
        seL4_CPtr procd_ntf_slot_in_orch = sel4utils_mint_cap_to_process(
            &orch_proc, pd_ntf_path_for_orch, seL4_AllRights, 0 /* unbadged */);
        if (procd_ntf_slot_in_orch != 0) {
            bs.procd_event_ntf_slot = (uint64_t)procd_ntf_slot_in_orch;
            /* procd-authoritative-GC · hand orch the RO view of the
             * cross-mapped SHM (allocated + mapped right after orch spawn).
             * 0 if the mapping failed → orch stays in NTF-only mode. */
            bs.procd_shm_base       = (uint64_t)procd_shm_ro_vaddr;
            printf("[root] procd NTF minted into orch · orch_slot=%lu\n",
                   (unsigned long)procd_ntf_slot_in_orch);
        } else {
            printf("[root] procd NTF mint into orch failed · event channel half-wired\n");
        }

        /* procd PR 5 · CROSSING-OF-RUBICON · also mint the procd LISTEN
         * EP into orch's CSpace so orch_procd_spawn can seL4_Call procd
         * with OP_SPAWN payloads.  Unbadged because procd only has one
         * caller in PR 5 (orch); badging arrives when anomaly and
         * lucas start calling too (PR 10+). */
        cspacepath_t pd_listen_path_for_orch;
        vka_cspace_make_path(&env.vka, procd_listen_ep_obj.cptr,
                             &pd_listen_path_for_orch);
        seL4_CPtr procd_listen_slot_in_orch = sel4utils_mint_cap_to_process(
            &orch_proc, pd_listen_path_for_orch, seL4_AllRights, 0 /* unbadged */);
        if (procd_listen_slot_in_orch != 0) {
            bs.procd_listen_ep_slot = (uint64_t)procd_listen_slot_in_orch;
            printf("[root] procd listen EP minted into orch · orch_slot=%lu\n",
                   (unsigned long)procd_listen_slot_in_orch);
        } else {
            bs.procd_listen_ep_slot = 0;
            printf("[root] procd listen EP mint into orch failed · OP_SPAWN announce disabled\n");
        }

        /* procd PR 10 · BADGED procd listen EP for orch's CSpace.  Distinct
         * from the unbadged copy above · this one carries
         * BADGE_ANOMALY_OP_SET_TIER (0xA009) so the OP_SET_TIER /
         * OP_REBIND_FUNCTOR ops accept the call.  Used by
         * lucas_set_tier() (which runs inside orch's vspace) to mirror
         * every legacy tier flip into procd's authoritative proc_t state.
         * Without this orch's lucas_set_tier sites would have only the
         * unbadged cap and procd would reject the mutation with -EPERM.
         * The badge is shared with anomaly-ext's copy because procd
         * only checks the badge identity (not who minted what cap from
         * where) when deciding whether to honour OP_SET_TIER. */
        seL4_CPtr procd_set_tier_slot_in_orch = sel4utils_mint_cap_to_process(
            &orch_proc, pd_listen_path_for_orch, seL4_AllRights,
            BADGE_ANOMALY_OP_SET_TIER);
        if (procd_set_tier_slot_in_orch != 0) {
            bs.procd_set_tier_ep_slot = (uint64_t)procd_set_tier_slot_in_orch;
            printf("[root] procd badged EP minted into orch (0x%x) · orch_slot=%lu\n",
                   (unsigned)BADGE_ANOMALY_OP_SET_TIER,
                   (unsigned long)procd_set_tier_slot_in_orch);
        } else {
            bs.procd_set_tier_ep_slot = 0;
            printf("[root] procd badged EP mint into orch failed · OP_SET_TIER from lucas_set_tier disabled\n");
        }
    }

    /* β · PR 5 · mint sotinit's listen EP into orch's CSpace.  Orch then
     * forwards the same slot to sotShell on ORCH_OP_SPAWN_NATIVE so the
     * operator can drive `systemctl <action> <unit>` directly against
     * sotinit's operator-query IPC loop.  0 if sotinit was not
     * pre-spawned · the bootstrap field stays 0 and sotShell's
     * cmd_systemctl prints "sotinit EP not available". */
    if (sotinit_configured && orch_ep != 0) {
        cspacepath_t sotinit_path_for_orch;
        vka_cspace_make_path(&env.vka, sotinit_listen_ep_obj.cptr,
                             &sotinit_path_for_orch);
        seL4_CPtr sotinit_slot_in_orch = sel4utils_mint_cap_to_process(
            &orch_proc, sotinit_path_for_orch, seL4_AllRights, 0 /* unbadged */);
        if (sotinit_slot_in_orch != 0) {
            bs.sotinit_listen_ep_slot = (uint64_t)sotinit_slot_in_orch;
            printf("[root] sotinit listen EP minted into orch · orch_slot=%lu\n",
                   (unsigned long)sotinit_slot_in_orch);
        } else {
            bs.sotinit_listen_ep_slot = 0;
            printf("[root] sotinit listen EP mint into orch failed · systemctl disabled\n");
        }
    }

    /* β · PR 9 · mint sotcron's listen EP into orch's CSpace.  Orch then
     * forwards the same slot to sotShell on ORCH_OP_SPAWN_NATIVE so the
     * operator can drive `cron list` / `cron now <timer>` directly
     * against sotcron's non-blocking IPC drain.  0 if sotcron was not
     * pre-spawned · the bootstrap field stays 0 and sotShell's cmd_cron
     * prints "sotcron EP not available".  Minted UNBADGED into orch ·
     * orch re-mints it BADGED with BADGE_SOTCRON_OPERATOR when forwarding
     * to sotShell so sotcron's NBRecv drain can detect the empty-queue
     * vs message-arrived distinction via the badge register. */
    if (sotcron_configured && orch_ep != 0) {
        cspacepath_t sotcron_path_for_orch;
        vka_cspace_make_path(&env.vka, sotcron_listen_ep_obj.cptr,
                             &sotcron_path_for_orch);
        seL4_CPtr sotcron_slot_in_orch = sel4utils_mint_cap_to_process(
            &orch_proc, sotcron_path_for_orch, seL4_AllRights, 0 /* unbadged */);
        if (sotcron_slot_in_orch != 0) {
            bs.sotcron_listen_ep_slot = (uint64_t)sotcron_slot_in_orch;
            printf("[root] sotcron listen EP minted into orch · orch_slot=%lu\n",
                   (unsigned long)sotcron_slot_in_orch);
        } else {
            bs.sotcron_listen_ep_slot = 0;
            printf("[root] sotcron listen EP mint into orch failed · cron disabled\n");
        }
    }

    /* L12-alpha · mint the compositor listen EP into orch so L12-beta can
     * route the narrow wayland-0 AF_UNIX connect path without another root
     * bootstrap change. */
    if (wayland_configured && orch_ep != 0) {
        cspacepath_t wayland_path_for_orch;
        vka_cspace_make_path(&env.vka, wayland_listen_ep_obj.cptr,
                             &wayland_path_for_orch);
        seL4_CPtr wayland_slot_in_orch = sel4utils_mint_cap_to_process(
            &orch_proc, wayland_path_for_orch, seL4_AllRights, 0 /* unbadged */);
        if (wayland_slot_in_orch != 0) {
            bs.wayland_listen_ep_slot = (uint64_t)wayland_slot_in_orch;
            printf("[root] wayland listen EP minted into orch · orch_slot=%lu\n",
                   (unsigned long)wayland_slot_in_orch);
        } else {
            bs.wayland_listen_ep_slot = 0;
            printf("[root] wayland listen EP mint into orch failed · wayland-0 disabled\n");
        }

        /* L13-A1 · mint the compositor page-directory (PML4) cap into orch so
         * L13-A2 can call sel4utils_map_page to install shared SHM frames into
         * the compositor vspace.  Same condition as the listen-EP mint above:
         * wayland_proc.pd is valid whenever wayland_configured is set. */
        cspacepath_t wayland_pd_path_for_orch;
        vka_cspace_make_path(&env.vka, wayland_proc.pd.cptr,
                             &wayland_pd_path_for_orch);
        seL4_CPtr wayland_pd_slot_in_orch = sel4utils_mint_cap_to_process(
            &orch_proc, wayland_pd_path_for_orch, seL4_AllRights, 0 /* unbadged */);
        if (wayland_pd_slot_in_orch != 0) {
            bs.wayland_pd_slot = (uint64_t)wayland_pd_slot_in_orch;
            printf("[root] wayland PD minted to orch · slot=%lu\n",
                   (unsigned long)wayland_pd_slot_in_orch);
        } else {
            bs.wayland_pd_slot = 0;
            printf("[root] wayland PD mint into orch failed · L13 shm disabled\n");
        }
    }

    /* L14a-A1 · mint the shadow compositor listen EP into orch so a later
     * task can route flagged-hostile clients to the shadow.  Mirrors the
     * compositor listen-EP-to-orch mint (L12-alpha) exactly. */
    if (canary_configured && orch_ep != 0) {
        cspacepath_t canary_path_for_orch;
        vka_cspace_make_path(&env.vka, canary_listen_ep_obj.cptr,
                             &canary_path_for_orch);
        seL4_CPtr canary_slot_in_orch = sel4utils_mint_cap_to_process(
            &orch_proc, canary_path_for_orch, seL4_AllRights, 0 /* unbadged */);
        if (canary_slot_in_orch != 0) {
            bs.wayland_canary_ep_slot = (uint64_t)canary_slot_in_orch;
            printf("[root] wayland shadow EP minted to orch · slot=%lu\n",
                   (unsigned long)canary_slot_in_orch);
        } else {
            bs.wayland_canary_ep_slot = 0;
            printf("[root] wayland shadow EP mint into orch failed · L14a routing disabled\n");
        }
    }

    /* PR 4 · WAL IPC · mint orch's listen EP into procd's CSpace (unbadged)
     * so procd can seL4_Call SOTFS_OP_WAL_LOG to log proc_t mutations to
     * the sotfs WAL.  Orch hosts sotos-sotfs as a linked library; the WAL
     * EP is just orch's listen EP with a new op label.  0 if orch was not
     * spawned or the mint failed · procd's g_wal_attached stays 0 and the
     * PROCD_SEQLOCK_END_LOGGED macro degenerates to plain seqlock_end. */
    seL4_CPtr procd_wal_ep_slot = 0;
    if (procd_configured && orch_ep != 0) {
        cspacepath_t orch_ep_path_for_procd;
        vka_cspace_make_path(&env.vka, orch_ep, &orch_ep_path_for_procd);
        procd_wal_ep_slot = sel4utils_mint_cap_to_process(
            &procd_proc, orch_ep_path_for_procd, seL4_AllRights,
            0 /* unbadged · op label routes the call */);
        if (procd_wal_ep_slot != 0) {
            printf("[root] procd WAL EP (orch listen) minted · procd_slot=%lu\n",
                   (unsigned long)procd_wal_ep_slot);
        } else {
            printf("[root] procd WAL EP mint failed · WAL IPC disabled\n");
        }
    }

    if (procd_configured) {
        char procd_argv0[16];
        char procd_argv1[32];
        char procd_argv2[32];
        char procd_argv3[32];
        char procd_argv4[32];
        snprintf(procd_argv0, sizeof(procd_argv0), "sotOs-procd");
        snprintf(procd_argv1, sizeof(procd_argv1), "%lu",
                 (unsigned long)procd_listen_slot);
        snprintf(procd_argv2, sizeof(procd_argv2), "%lu",
                 (unsigned long)procd_ntf_slot_in_procd);
        snprintf(procd_argv3, sizeof(procd_argv3), "%lu",
                 (unsigned long)procd_wal_ep_slot);
        snprintf(procd_argv4, sizeof(procd_argv4), "%lu",
                 (unsigned long)procd_shm_rw_vaddr);
        char *procd_argv_ptrs[5] = { procd_argv0, procd_argv1, procd_argv2,
                                     procd_argv3, procd_argv4 };

        int pd_run_rc = sel4utils_spawn_process_v(
            &procd_proc, &env.vka, &env.vspace, 5, procd_argv_ptrs, 1 /* resume */);
        if (pd_run_rc != 0) {
            printf("[root] procd spawn failed (rc=%d)\n", pd_run_rc);
        } else {
            printf("[root] procd spawned · pid=%lu ntf_slot=%lu wal_ep_slot=%lu\n",
                   (unsigned long)procd_proc.thread.tcb.cptr,
                   (unsigned long)procd_ntf_slot_in_procd,
                   (unsigned long)procd_wal_ep_slot);
        }
    }

    /* PR 3 · Run procd unit tests at boot · the ELF prints PASS/FAIL
     * lines that scripts/smoke-procd.sh greps from the QEMU serial log.
     * Test ELF blocks forever after; that's fine, root has already moved
     * on to the orch BOOTSTRAP message + demo workload below.  The proc
     * was configured during Phase 1 above (allocman pool fresh).  We
     * just resume it here. */
    if (procd_unit_configured) {
        char *unit_argv[1] = { "sotOs-procd-unit" };
        int unit_run_rc = sel4utils_spawn_process_v(
            &procd_unit_proc, &env.vka, &env.vspace,
            1, unit_argv, 1 /* resume */);
        if (unit_run_rc == 0) {
            printf("[root] procd-unit spawned\n");
        } else {
            printf("[root] procd-unit spawn failed (rc=%d)\n", unit_run_rc);
        }
    }

    /* PR 8 · WAL unit test · prints [wal-unit] PASS lines + ALL PASS.
     * Spawned right after procd-unit so both tests fire before the
     * heavier L4-L11 demo workload below.  Blocks forever after via
     * seL4_Yield · that's fine, root has moved on. */
    if (wal_unit_configured) {
        char *wal_unit_argv[1] = { "sotOs-wal-unit" };
        int wal_run_rc = sel4utils_spawn_process_v(
            &wal_unit_proc, &env.vka, &env.vspace,
            1, wal_unit_argv, 1 /* resume */);
        if (wal_run_rc == 0) {
            printf("[root] wal-unit spawned\n");
        } else {
            printf("[root] wal-unit spawn failed (rc=%d)\n", wal_run_rc);
        }
    }

    /* sotnano PR 2 · gap-buffer unit test · prints [sotnano-unit] PASS
     * lines + ALL PASS.  Spawned alongside the other unit fixtures so all
     * tests fire before the heavier demo workload below.  Blocks forever
     * after via seL4_Yield · that's fine, root has moved on. */
    if (sotnano_unit_configured) {
        char *sotnano_unit_argv[1] = { "sotOs-sotnano-unit" };
        int sn_run_rc = sel4utils_spawn_process_v(
            &sotnano_unit_proc, &env.vka, &env.vspace,
            1, sotnano_unit_argv, 1 /* resume */);
        if (sn_run_rc == 0) {
            printf("[root] sotnano-unit spawned\n");
        } else {
            printf("[root] sotnano-unit spawn failed (rc=%d)\n", sn_run_rc);
        }
    }

    /* sotinit Path D · Phase 2: now that orch is spawned and procd is up,
     * resume sotinit with argv = [name, listen_slot].  PR 1 is scaffold-
     * only · the banner + idle yield is enough to verify the cascade.
     * Subsequent PRs add operator-driven IPC handlers + the procd
     * OP_SPAWN client path for activating services.
     *
     * Placed after procd's Phase 2 spawn so the boot order is:
     *   orch (Path D root) -> anomaly -> synth -> procd -> sotinit
     * which matches the dependency order: sotinit calls procd OP_SPAWN
     * for activated services (PR 3+), and procd needs orch alive for
     * the WAL EP. */
    if (sotinit_configured) {
        /* PR 3 · mint procd's listen EP into sotinit's CSpace so sotinit
         * can seL4_Call OP_SPAWN for each activated service.  Mirror
         * pattern used for orch above (line ~648) · unbadged copy is
         * sufficient because procd's dispatcher routes purely on the
         * op label for SPAWN (badge gating only applies to OP_SET_TIER /
         * OP_REBIND_FUNCTOR · PR 10).  Non-fatal if procd was not
         * configured · sotinit's activate_service falls back to marking
         * units FAILED + logging "procd EP unavailable". */
        seL4_CPtr procd_ep_in_sotinit = 0;
        if (procd_configured) {
            cspacepath_t pd_path;
            vka_cspace_make_path(&env.vka, procd_listen_ep_obj.cptr, &pd_path);
            procd_ep_in_sotinit = sel4utils_mint_cap_to_process(
                &sotinit_proc, pd_path, seL4_AllRights, 0 /* unbadged */);
            if (procd_ep_in_sotinit != 0) {
                printf("[root] procd EP minted into sotinit · slot=%lu\n",
                       (unsigned long)procd_ep_in_sotinit);
            } else {
                printf("[root] procd EP mint into sotinit failed · OP_SPAWN client disabled\n");
            }
        }

        /* γ · F_persistence PR 5 · mint orch's listen EP into sotinit's
         * CSpace.  sotinit's audit_ipc.c uses this EP to seL4_Call
         * ORCH_OP_AUDIT_APPEND so its audit events land in the same
         * anomaly-log ring sotShell queries.  Reuses orch's existing
         * listen EP · no new allocation (the dispatcher in orch/main.c
         * routes by op label).  Non-fatal if orch_ep == 0 · sotinit's
         * audit_emit falls back to printf-only (NO_EP marker). */
        seL4_CPtr orch_audit_ep_in_sotinit = 0;
        if (orch_ep != 0) {
            cspacepath_t orch_path;
            vka_cspace_make_path(&env.vka, orch_ep, &orch_path);
            orch_audit_ep_in_sotinit = sel4utils_mint_cap_to_process(
                &sotinit_proc, orch_path, seL4_AllRights, 0 /* unbadged */);
            if (orch_audit_ep_in_sotinit != 0) {
                printf("[root] orch audit EP minted into sotinit · slot=%lu\n",
                       (unsigned long)orch_audit_ep_in_sotinit);
            } else {
                printf("[root] orch audit EP mint into sotinit failed · "
                       "audit_emit falls back to printf-only\n");
            }
        }

        char sotinit_argv0[16];
        char sotinit_argv1[32];
        char sotinit_argv2[32];
        char sotinit_argv3[32];
        snprintf(sotinit_argv0, sizeof(sotinit_argv0), "sotOs-sotinit");
        snprintf(sotinit_argv1, sizeof(sotinit_argv1), "%lu",
                 (unsigned long)sotinit_listen_slot);
        snprintf(sotinit_argv2, sizeof(sotinit_argv2), "%lu",
                 (unsigned long)procd_ep_in_sotinit);
        snprintf(sotinit_argv3, sizeof(sotinit_argv3), "%lu",
                 (unsigned long)orch_audit_ep_in_sotinit);
        char *sotinit_argv_ptrs[4] = { sotinit_argv0, sotinit_argv1,
                                       sotinit_argv2, sotinit_argv3 };
        int rc = sel4utils_spawn_process_v(&sotinit_proc, &env.vka,
                                            &env.vspace, 4,
                                            sotinit_argv_ptrs, 1 /* resume */);
        if (rc == 0) {
            printf("[root] sotinit spawned · pid=%lu\n",
                   (unsigned long)sotinit_proc.thread.tcb.cptr);
        } else {
            printf("[root] sotinit spawn failed rc=%d\n", rc);
        }
    }

    /* sotcron Path D · Phase 2: resume sotcron with argv = [name, listen_slot,
     * sotinit_ep_slot].  PR 7 was scaffold-only (banner + TSC calibration +
     * idle polling loop); PR 8 adds the timer registry + fire dispatch into
     * sotinit via SOTINIT_OP_ACTIVATE, so sotcron now needs sotinit's listen
     * EP minted into its CSpace.
     *
     * Mirrors the orch -> sotinit and sotinit -> procd mint patterns used
     * above: unbadged copy because sotinit's dispatcher routes purely on the
     * op label (badge gating arrives if/when anomaly-driven ACTIVATE calls
     * land in a follow-up PR).  Non-fatal if sotinit was not configured ·
     * sotcron's process_timers detects g_sotinit_ep == 0 and emits a SKIPPED
     * log line so the per-tick walk still surfaces.
     *
     * Boot order:
     *   orch (Path D root) -> anomaly -> synth -> procd -> sotinit -> sotcron
     * PR 9 adds the operator query handlers (cron list / cron now).
     */
    if (sotcron_configured) {
        /* PR 8 · mint sotinit's listen EP into sotcron's CSpace so the
         * scheduler can seL4_Call SOTINIT_OP_ACTIVATE for every timer
         * fire.  Same unbadged pattern used for orch -> sotinit and
         * sotinit -> procd above. */
        seL4_CPtr sotinit_ep_in_sotcron = 0;
        if (sotinit_configured) {
            cspacepath_t si_path;
            vka_cspace_make_path(&env.vka, sotinit_listen_ep_obj.cptr,
                                 &si_path);
            sotinit_ep_in_sotcron = sel4utils_mint_cap_to_process(
                &sotcron_proc, si_path, seL4_AllRights, 0 /* unbadged */);
            if (sotinit_ep_in_sotcron != 0) {
                printf("[root] sotinit EP minted into sotcron · slot=%lu\n",
                       (unsigned long)sotinit_ep_in_sotcron);
            } else {
                printf("[root] sotinit EP mint into sotcron failed · "
                       "fire dispatch disabled\n");
            }
        }

        /* γ · F_persistence PR 5 · mint orch's listen EP into sotcron's
         * CSpace · same rationale as the sotinit mint above (audit_ipc.c
         * uses this EP to seL4_Call ORCH_OP_AUDIT_APPEND).  Non-fatal if
         * orch_ep == 0. */
        seL4_CPtr orch_audit_ep_in_sotcron = 0;
        if (orch_ep != 0) {
            cspacepath_t orch_path_c;
            vka_cspace_make_path(&env.vka, orch_ep, &orch_path_c);
            orch_audit_ep_in_sotcron = sel4utils_mint_cap_to_process(
                &sotcron_proc, orch_path_c, seL4_AllRights, 0 /* unbadged */);
            if (orch_audit_ep_in_sotcron != 0) {
                printf("[root] orch audit EP minted into sotcron · slot=%lu\n",
                       (unsigned long)orch_audit_ep_in_sotcron);
            } else {
                printf("[root] orch audit EP mint into sotcron failed · "
                       "audit_emit falls back to printf-only\n");
            }
        }

        char sotcron_argv0[16];
        char sotcron_argv1[32];
        char sotcron_argv2[32];
        char sotcron_argv3[32];
        snprintf(sotcron_argv0, sizeof(sotcron_argv0), "sotOs-sotcron");
        snprintf(sotcron_argv1, sizeof(sotcron_argv1), "%lu",
                 (unsigned long)sotcron_listen_slot);
        snprintf(sotcron_argv2, sizeof(sotcron_argv2), "%lu",
                 (unsigned long)sotinit_ep_in_sotcron);
        snprintf(sotcron_argv3, sizeof(sotcron_argv3), "%lu",
                 (unsigned long)orch_audit_ep_in_sotcron);
        char *sotcron_argv_ptrs[4] = { sotcron_argv0, sotcron_argv1,
                                       sotcron_argv2, sotcron_argv3 };
        int rc = sel4utils_spawn_process_v(&sotcron_proc, &env.vka,
                                            &env.vspace, 4,
                                            sotcron_argv_ptrs, 1 /* resume */);
        if (rc == 0) {
            printf("[root] sotcron spawned · pid=%lu\n",
                   (unsigned long)sotcron_proc.thread.tcb.cptr);
        } else {
            printf("[root] sotcron spawn failed rc=%d\n", rc);
        }
    }

    /* L12-alpha · resume the native Wayland compositor scaffold.  The process
     * is intentionally idle until L12-beta routes AF_UNIX wayland-0 connects
     * to its listen EP. */
    if (wayland_configured) {
        char wayland_argv0[24];
        char wayland_argv1[32];
        snprintf(wayland_argv0, sizeof(wayland_argv0), "sotOs-wl-compositor");
        snprintf(wayland_argv1, sizeof(wayland_argv1), "%lu",
                 (unsigned long)wayland_listen_slot);
        char *wayland_argv_ptrs[2] = { wayland_argv0, wayland_argv1 };
        int rc = sel4utils_spawn_process_v(&wayland_proc, &env.vka,
                                           &env.vspace, 2,
                                           wayland_argv_ptrs, 1 /* resume */);
        if (rc == 0) {
            printf("[root] wayland spawned · pid=%lu\n",
                   (unsigned long)wayland_proc.thread.tcb.cptr);
        } else {
            printf("[root] wayland spawn failed rc=%d\n", rc);
        }
    }

    /* L14a-A1 · resume the Wayland shadow compositor.  Idle until a later
     * task routes a flagged-hostile client's traffic here. */
    if (canary_configured) {
        char canary_argv0[20];
        char canary_argv1[32];
        snprintf(canary_argv0, sizeof(canary_argv0), "sotOs-wl-canary");
        snprintf(canary_argv1, sizeof(canary_argv1), "%lu",
                 (unsigned long)canary_listen_slot);
        char *canary_argv_ptrs[2] = { canary_argv0, canary_argv1 };
        int rc = sel4utils_spawn_process_v(&canary_proc, &env.vka,
                                           &env.vspace, 2,
                                           canary_argv_ptrs, 1 /* resume */);
        if (rc == 0) {
            printf("[root] shadow spawned · pid=%lu\n",
                   (unsigned long)canary_proc.thread.tcb.cptr);
        } else {
            printf("[root] shadow spawn failed rc=%d\n", rc);
        }
    }

    /* IRQ-driven virtio-net RX · claim the virtio-net IOAPIC IRQ and hand orch an
     * IRQHandler + Notification so it can block-and-wake on RX instead of
     * busy-polling (the throughput bottleneck on this uniprocessor build).
     * GSI 11 / PCI INTA / level-triggered active-low on QEMU i440fx (confirmed by
     * the driver's PCI 0x3C read).  seL4 GetIOAPIC: arg `pin`=GSI (programmed into
     * the IOAPIC redirection entry), arg `vector`=a logical user-irq index in
     * [0,107] (kernel maps it to irq=idx+16, IDT vector=irq+32); we reuse 11 for
     * both.  level=1, polarity=1 (PCI), NOT the simple_get_irq <16⇒ISA heuristic. */
    if (orch_ep != 0) {
        /* IRQ-driven virtio-net RX · the virtio-net PCI INTA routes to IOAPIC
         * GSI 11 (confirmed by a candidate sweep) · level-triggered active-low.
         * GetIOAPIC: arg `pin`=GSI=11; arg `vector`=user-irq index (kernel maps to
         * irq=idx+16, IDT vector=irq+32) — reuse 11.  Bind a BADGED notification
         * (badge MUST be non-zero so orch's seL4_Wait/Poll surfaces it; an unbadged
         * cap signals badge 0 → looks like "no event").  Hand orch the badged
         * Notification (to wait on) + the IRQHandler (to Ack/re-arm the level IRQ
         * after draining RX).  orch blocks on this in the RX wait instead of
         * busy-polling → the vCPU idles → QEMU's iothread gets the host CPU → the
         * inbound DMAs land promptly (the egress-throughput fix). */
        seL4_CPtr irq_ctrl = simple_get_irq_ctrl(&env.simple);
        vka_object_t vnet_ntf_obj;
        cspacepath_t irqh_path;
        if (irq_ctrl != 0 && vka_alloc_notification(&env.vka, &vnet_ntf_obj) == 0
            && vka_cspace_alloc_path(&env.vka, &irqh_path) == 0) {
            seL4_Error ire = seL4_IRQControl_GetIOAPIC(
                irq_ctrl, irqh_path.root, irqh_path.capPtr,
                (seL4_Uint8)irqh_path.capDepth,
                0 /*ioapic*/, 11 /*pin=GSI*/, 1 /*level*/, 1 /*active-low*/,
                11 /*user-irq index*/);
            if (ire != seL4_NoError) {
                printf("[root] virtio-net GetIOAPIC(GSI 11) failed err=%d · busy-poll fallback\n",
                       (int)ire);
            } else {
                /* badged copy of the notification (badge=VIRTIO_NET_IRQ_BADGE) */
                cspacepath_t base_ntf_path, badged_path;
                vka_cspace_make_path(&env.vka, vnet_ntf_obj.cptr, &base_ntf_path);
                if (vka_cspace_alloc_path(&env.vka, &badged_path) == 0
                    && vka_cnode_mint(&badged_path, &base_ntf_path, seL4_AllRights,
                                      (seL4_Word)VIRTIO_NET_IRQ_BADGE) == 0) {
                    (void)seL4_IRQHandler_SetNotification(irqh_path.capPtr,
                                                          badged_path.capPtr);
                    seL4_CPtr ntf_in_orch = sel4utils_mint_cap_to_process(
                        &orch_proc, base_ntf_path, seL4_AllRights, 0 /*unbadged view*/);
                    seL4_CPtr irqh_in_orch = sel4utils_copy_cap_to_process(
                        &orch_proc, &env.vka, irqh_path.capPtr);
                    bs.virtio_net_irq_ntf_slot     = (uint64_t)ntf_in_orch;
                    bs.virtio_net_irq_handler_slot = (uint64_t)irqh_in_orch;
                    printf("[root] virtio-net IRQ wired (GSI 11) · ntf_orch=%lu irqh_orch=%lu\n",
                           (unsigned long)ntf_in_orch, (unsigned long)irqh_in_orch);
                }
            }
        } else {
            printf("[root] no IRQControl/NTF · virtio-net stays busy-poll\n");
        }
    }

    /* Same machinery for the SECOND virtio-net — the lwIP egress NIC.  On QEMU
     * i440fx its PCI INTA routes to IOAPIC GSI 10 (confirmed by the driver's PCI
     * 0x3C read: "2nd virtio-net … IRQ line=10").  Without this the egress pump
     * busy-polls (the throughput bottleneck); with it orch blocks on the badged
     * Notification, the vCPU idles, QEMU's iothread runs, and inbound DMAs land. */
    if (orch_ep != 0) {
        seL4_CPtr irq_ctrl = simple_get_irq_ctrl(&env.simple);
        vka_object_t lnet_ntf_obj;
        cspacepath_t lirqh_path;
        if (irq_ctrl != 0 && vka_alloc_notification(&env.vka, &lnet_ntf_obj) == 0
            && vka_cspace_alloc_path(&env.vka, &lirqh_path) == 0) {
            seL4_Error ire = seL4_IRQControl_GetIOAPIC(
                irq_ctrl, lirqh_path.root, lirqh_path.capPtr,
                (seL4_Uint8)lirqh_path.capDepth,
                0 /*ioapic*/, 10 /*pin=GSI*/, 1 /*level*/, 1 /*active-low*/,
                10 /*user-irq index*/);
            if (ire != seL4_NoError) {
                printf("[root] lwIP-net GetIOAPIC(GSI 10) failed err=%d · busy-poll fallback\n",
                       (int)ire);
            } else {
                cspacepath_t lbase_ntf_path, lbadged_path;
                vka_cspace_make_path(&env.vka, lnet_ntf_obj.cptr, &lbase_ntf_path);
                if (vka_cspace_alloc_path(&env.vka, &lbadged_path) == 0
                    && vka_cnode_mint(&lbadged_path, &lbase_ntf_path, seL4_AllRights,
                                      (seL4_Word)LWIP_NET_IRQ_BADGE) == 0) {
                    (void)seL4_IRQHandler_SetNotification(lirqh_path.capPtr,
                                                          lbadged_path.capPtr);
                    seL4_CPtr ntf_in_orch = sel4utils_mint_cap_to_process(
                        &orch_proc, lbase_ntf_path, seL4_AllRights, 0 /*unbadged view*/);
                    seL4_CPtr irqh_in_orch = sel4utils_copy_cap_to_process(
                        &orch_proc, &env.vka, lirqh_path.capPtr);
                    bs.lwip_net_irq_ntf_slot     = (uint64_t)ntf_in_orch;
                    bs.lwip_net_irq_handler_slot = (uint64_t)irqh_in_orch;
                    printf("[root] lwIP-net IRQ wired (GSI 10) · ntf_orch=%lu irqh_orch=%lu\n",
                           (unsigned long)ntf_in_orch, (unsigned long)irqh_in_orch);

                    /* PIT periodic tick → SAME notification (different badge).  The
                     * i8254 (programmed ~100 Hz above) drives ISA IRQ 0, which the
                     * IOAPIC exposes as GSI 2 (ACPI ISA-IRQ-0→GSI-2 override on
                     * i440fx) · edge-triggered, active-high.  Binding it to
                     * lnet_ntf_obj makes orch's Wait wake on the RX IRQ OR this tick,
                     * so raw_poll/complete_tx runs regularly and the egress pump
                     * can't deadlock on a full TX ring. */
                    cspacepath_t pirqh_path, pit_badged;
                    if (vka_cspace_alloc_path(&env.vka, &pirqh_path) == 0) {
                        seL4_Error pire = seL4_IRQControl_GetIOAPIC(
                            irq_ctrl, pirqh_path.root, pirqh_path.capPtr,
                            (seL4_Uint8)pirqh_path.capDepth,
                            0 /*ioapic*/, 2 /*pin=GSI*/, 0 /*edge*/, 0 /*active-high*/,
                            2 /*user-irq index*/);
                        if (pire != seL4_NoError) {
                            printf("[root] PIT GetIOAPIC(GSI 2) failed err=%d · pump stays busy-poll\n",
                                   (int)pire);
                        } else if (vka_cspace_alloc_path(&env.vka, &pit_badged) == 0
                                   && vka_cnode_mint(&pit_badged, &lbase_ntf_path, seL4_AllRights,
                                                     (seL4_Word)LWIP_PIT_IRQ_BADGE) == 0) {
                            (void)seL4_IRQHandler_SetNotification(pirqh_path.capPtr,
                                                                  pit_badged.capPtr);
                            (void)seL4_IRQHandler_Ack(pirqh_path.capPtr);  /* arm the edge IRQ */
                            seL4_CPtr pith_in_orch = sel4utils_copy_cap_to_process(
                                &orch_proc, &env.vka, pirqh_path.capPtr);
                            bs.lwip_pit_irq_handler_slot = (uint64_t)pith_in_orch;
                            printf("[root] PIT tick IRQ wired (GSI 2) · pith_orch=%lu\n",
                                   (unsigned long)pith_in_orch);
                        }
                    }
                }
            }
        }
    }

    if (orch_ep != 0) {
        size_t nwords = sizeof(orch_bootstrap_info_t) / sizeof(seL4_Word);
        seL4_Word *src = (seL4_Word *)&bs;
        for (size_t i = 0; i < nwords; ++i) {
            seL4_SetMR(i, src[i]);
        }
        seL4_MessageInfo_t bs_info = seL4_MessageInfo_new(ORCH_OP_BOOTSTRAP,
                                                            0, 0, nwords);
        seL4_Call(orch_ep, bs_info);
        printf("[root] BOOTSTRAP delivered (%u untypeds, %zu words)\n",
               bs.untyped_count, nwords);
    }

    /* L3b-T6: Demo #1 · busybox sh -c "ls /etc | grep passwd"
     * L3c-T4: Demo #2 · busybox cat /proc/self/maps
     *
     * Both use the extended orch_spawn_msg_t payload (binname + argc + packed
     * argv pool).  orch_fault_loop returns when alive_count==0 between demos,
     * so orch's main loop iterates back to seL4_Recv and serves the next SPAWN.
     *
     * L4: sotShell (ORCH_OP_SPAWN_NATIVE) runs BEFORE the Linux demos so that
     * orch's 256 KiB allocman pool is still fresh when configure_process_custom
     * is called for sotOs-shell.  sotShell runs concurrently (seL4 round-robin),
     * calls ORCH_OP_QUERY_STATUS, and prints the sotinfo table.  Because it
     * fires before any Linux demo, the sotBox table is empty at query time —
     * which is valid L4 output and correctly demonstrates the asymmetry. */
    if (orch_ep != 0) {
        /* L4: spawn sotShell via orch (ORCH_OP_SPAWN_NATIVE) BEFORE Linux demos.
         * sotShell lives in orch's CPIO; orch spawns it using orch's own VKA.
         * Orch mints its EP into sotShell's CSpace (argv[1]) so sotShell can
         * send ORCH_OP_QUERY_STATUS and see the real sotBox table (asymmetry §4).
         * Running first ensures orch's pool has not yet been depleted by busybox. */
        {
            static orch_spawn_msg_t native_msg;
            memset(&native_msg, 0, sizeof(native_msg));
            strlcpy(native_msg.binname, "sotOs-shell", ORCH_SPAWN_BINNAME_BYTES);
            native_msg.argc = 0;

            size_t nwords_n = sizeof(native_msg) / sizeof(seL4_Word);
            seL4_Word *src_n = (seL4_Word *)&native_msg;
            for (size_t i = 0; i < nwords_n; ++i) seL4_SetMR(i, src_n[i]);

            seL4_MessageInfo_t info_n = seL4_MessageInfo_new(ORCH_OP_SPAWN_NATIVE,
                                                               0, 0, nwords_n);
            seL4_MessageInfo_t reply_n = seL4_Call(orch_ep, info_n);
            seL4_Word rc_n = seL4_MessageInfo_get_label(reply_n);
            if (rc_n != 0) {
                printf("[root] SPAWN_NATIVE sotOs-shell failed (rc=%lu) · demo skipped\n",
                       (unsigned long)rc_n);
            } else {
                printf("[root] sotShell spawned via orch · operator console active\n");
            }
        }

        /* sotFS-ε demo · same sh -c reads all three installed canary files (reads
         * are unaffected at Tier 2 in minimal ε) THEN attempts a write which
         * is silently dropped by the isolated-write path · logs [isolated] line +
         * shell reports "Permission denied".
         * Placed FIRST among Linux demos so the allocman pool is fresh. */
        {
            static orch_spawn_msg_t fs_msg;
            memset(&fs_msg, 0, sizeof(fs_msg));
            const char *binname = "busybox-static.bin";
            const char *fs_argv[] = {
                "busybox", "sh", "-c",
                "echo 1; echo 2; echo 3; echo 4; echo 5; echo 6; cat /tmp/welcome; cat /tmp/honey-aws-creds; echo CORRUPTED > /tmp/test-mirror"
            };
            const int fs_argc = 4;
            strlcpy(fs_msg.binname, binname, ORCH_SPAWN_BINNAME_BYTES);
            fs_msg.argc         = (uint32_t)fs_argc;
            fs_msg.profile      = 0;  /* ALPINE */
            fs_msg.initial_tier = 2;  /* sotFS-ε: Tier 2 isolated-write path */
            size_t fs_off = 0;
            for (int i = 0; i < fs_argc; ++i) {
                size_t l = strlen(fs_argv[i]) + 1;
                memcpy(fs_msg.argv_pool + fs_off, fs_argv[i], l);
                fs_off += l;
            }
            size_t nwords = sizeof(fs_msg) / sizeof(seL4_Word);
            seL4_Word *src = (seL4_Word *)&fs_msg;
            for (size_t i = 0; i < nwords; ++i) seL4_SetMR(i, src[i]);
            seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nwords);
            seL4_Call(orch_ep, info);
            printf("[root] sotFS-ε demo (sh -c cat 3 canary files + mirror write) completed\n");
        }

        /* L6 silenced demo: spawn echo at Tier 1 · 'SYNTH-OUTPUT-NEVER-SHOULD-APPEAR'
         * goes nowhere; the binary believes write() succeeded; operator sees
         * [silenced] log but NOT the actual string. */
        {
            static orch_spawn_msg_t silenced_msg;
            memset(&silenced_msg, 0, sizeof(silenced_msg));
            const char *binname = "busybox-static.bin";
            const char *silenced_argv[] = { "busybox", "echo", "SYNTH-OUTPUT-NEVER-SHOULD-APPEAR" };
            strlcpy(silenced_msg.binname, binname, ORCH_SPAWN_BINNAME_BYTES);
            silenced_msg.argc         = 3;
            silenced_msg.profile      = 0;  /* ALPINE */
            silenced_msg.initial_tier = 1;  /* Silenced Mode */
            size_t off = 0;
            for (int i = 0; i < 3; ++i) {
                size_t l = strlen(silenced_argv[i]) + 1;
                memcpy(silenced_msg.argv_pool + off, silenced_argv[i], l);
                off += l;
            }
            size_t nwords = sizeof(silenced_msg) / sizeof(seL4_Word);
            seL4_Word *src = (seL4_Word *)&silenced_msg;
            for (size_t i = 0; i < nwords; ++i) seL4_SetMR(i, src[i]);
            seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nwords);
            seL4_Call(orch_ep, info);
            printf("[root] L6 silenced demo (echo · Tier 1) completed\n");
        }

        /* L7 · Tier 2 isolated-write path · busybox reads /etc/passwd, sees canary.
         * Pool exhaustion consistently hits at the 3rd sotbox spawn; keeping
         * L7 at position 3 (after sotFS + silenced) still has pool budget.
         * L5 Ubuntu / L3c Alpine demos follow (may hit pool limit). */
        {
            static orch_spawn_msg_t t2_msg;
            memset(&t2_msg, 0, sizeof(t2_msg));
            const char *binname = "busybox-static.bin";
            const char *argv[] = { "busybox", "cat", "/etc/passwd" };
            strlcpy(t2_msg.binname, binname, ORCH_SPAWN_BINNAME_BYTES);
            t2_msg.argc         = 3;
            t2_msg.profile      = 0;  /* doesn't matter · tier 2 overrides */
            t2_msg.initial_tier = 2;  /* isolated-write path */
            size_t off = 0;
            for (int i = 0; i < 3; ++i) {
                size_t l = strlen(argv[i]) + 1;
                memcpy(t2_msg.argv_pool + off, argv[i], l);
                off += l;
            }
            size_t nwords = sizeof(t2_msg) / sizeof(seL4_Word);
            seL4_Word *src = (seL4_Word *)&t2_msg;
            for (size_t i = 0; i < nwords; ++i) seL4_SetMR(i, src[i]);
            seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nwords);
            seL4_Call(orch_ep, info);
            printf("[root] L7 demo (cat /etc/passwd · Tier 2 canary) completed\n");
        }

        /* sotNet-β-4 demo · udp_send.bin · tiny asm fixture that calls
         * socket(AF_INET, SOCK_DGRAM, 0) + sendto(10.0.2.2, 9999, "hi", 2).
         * Only ~4.5 KiB stripped (vs busybox 1.1 MB), needs ~10 frames total.
         * Placed at spawn 4 — the allocman pool budget is tight but sufficient
         * for this minimal ELF since each LOAD segment fits in one 4-KiB frame.
         * Triggers: lucas_sys_sendto → sotnet_send_udp → virtio_net_tx.
         * Smoke check: [sotnet-β] UDP send line → 32/32 PASS. */
        {
            static orch_spawn_msg_t udp_msg;
            memset(&udp_msg, 0, sizeof(udp_msg));
            const char *udp_argv[] = { "udp_send" };
            strlcpy(udp_msg.binname, "udp_send.bin", ORCH_SPAWN_BINNAME_BYTES);
            udp_msg.argc    = 1;
            udp_msg.profile = 0;
            udp_msg.initial_tier = 0;
            size_t udp_off = 0;
            for (int i = 0; i < 1; ++i) {
                size_t l = strlen(udp_argv[i]) + 1;
                if (udp_off + l >= ORCH_SPAWN_ARGV_BYTES) break;
                memcpy(udp_msg.argv_pool + udp_off, udp_argv[i], l);
                udp_off += l;
            }
            size_t nwords_udp = sizeof(udp_msg) / sizeof(seL4_Word);
            seL4_Word *src_udp = (seL4_Word *)&udp_msg;
            for (size_t i = 0; i < nwords_udp; ++i) seL4_SetMR(i, src_udp[i]);
            seL4_MessageInfo_t info_udp = seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nwords_udp);
            seL4_MessageInfo_t reply_udp = seL4_Call(orch_ep, info_udp);
            seL4_Word rc_udp = seL4_MessageInfo_get_label(reply_udp);
            if (rc_udp != 0) {
                printf("[root] sotNet-β-4 udp_send demo · SPAWN failed (rc=%lu)\n",
                       (unsigned long)rc_udp);
            } else {
                printf("[root] sotNet-β-4 udp_send.bin spawned · UDP sendto in flight\n");
            }
        }

        /* sotNet-γ Phase 3-D-1 · udp_send.bin at Tier 2 (isolated-write path).
         * Reuses the same tiny ~4.5 KiB asm fixture but with the shadow functor,
         * so sendto routes through synth_record_redirect → sotOs-net-synth →
         * response_profile_dispatch → orch ORCH_OP_SYNTH_RESPONSE.  This closes the
         * Phase 3-D synth→orch callback loop and emits the recognizable
         * '[orch] synth→sotbox response · pid=' evidence line.  Pool budget:
         * the binary's frames are already cached from the Tier 0 spawn above,
         * so the marginal cost is ~1 CSpace + TCB + VSpace per process. */
        {
            static orch_spawn_msg_t udp_t2_msg;
            memset(&udp_t2_msg, 0, sizeof(udp_t2_msg));
            const char *udp_t2_argv[] = { "udp_send" };
            strlcpy(udp_t2_msg.binname, "udp_send.bin", ORCH_SPAWN_BINNAME_BYTES);
            udp_t2_msg.argc         = 1;
            udp_t2_msg.profile      = 0;
            udp_t2_msg.initial_tier = 2;  /* isolated-write path · shadow functor */
            size_t udp_t2_off = 0;
            for (int i = 0; i < 1; ++i) {
                size_t l = strlen(udp_t2_argv[i]) + 1;
                if (udp_t2_off + l >= ORCH_SPAWN_ARGV_BYTES) break;
                memcpy(udp_t2_msg.argv_pool + udp_t2_off, udp_t2_argv[i], l);
                udp_t2_off += l;
            }
            size_t nwords_udp_t2 = sizeof(udp_t2_msg) / sizeof(seL4_Word);
            seL4_Word *src_udp_t2 = (seL4_Word *)&udp_t2_msg;
            for (size_t i = 0; i < nwords_udp_t2; ++i) seL4_SetMR(i, src_udp_t2[i]);
            seL4_MessageInfo_t info_udp_t2 = seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nwords_udp_t2);
            seL4_MessageInfo_t reply_udp_t2 = seL4_Call(orch_ep, info_udp_t2);
            seL4_Word rc_udp_t2 = seL4_MessageInfo_get_label(reply_udp_t2);
            if (rc_udp_t2 != 0) {
                printf("[root] γ Phase 3-D-1 Tier 2 udp_send · SPAWN failed (rc=%lu)\n",
                       (unsigned long)rc_udp_t2);
            } else {
                printf("[root] γ Phase 3-D-1 Tier 2 udp_send.bin spawned · synth loop active\n");
            }
        }

        /* MS-M2 verification · pthread test fixture · exercises
         * clone(CLONE_VM|CLONE_THREAD|CLONE_SETTLS) + futex WAIT/WAKE on a
         * shared global.  Tiny ~1 KiB static ELF · negligible pool cost.
         * Triggers the [clone] thread create + [futex] WAIT/WAKE log lines
         * that serve as M2 E2E evidence. */
        {
            static orch_spawn_msg_t pt_msg;
            memset(&pt_msg, 0, sizeof(pt_msg));
            const char *pt_argv[] = { "pthread_test" };
            strlcpy(pt_msg.binname, "pthread_test.bin", ORCH_SPAWN_BINNAME_BYTES);
            pt_msg.argc = 1; pt_msg.profile = 0; pt_msg.initial_tier = 0;
            size_t off = 0;
            size_t l = strlen(pt_argv[0]) + 1;
            memcpy(pt_msg.argv_pool + off, pt_argv[0], l);
            size_t nw = sizeof(pt_msg) / sizeof(seL4_Word);
            seL4_Word *src = (seL4_Word *)&pt_msg;
            for (size_t i = 0; i < nw; ++i) seL4_SetMR(i, src[i]);
            seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nw);
            seL4_MessageInfo_t reply = seL4_Call(orch_ep, info);
            seL4_Word rc = seL4_MessageInfo_get_label(reply);
            printf("[root] MS-M2 · pthread_test.bin spawn rc=%lu\n", (unsigned long)rc);
        }

        /* PROCD PR 6/7 · fork/exit/wait4 smoke fixture.  Tiny static
         * Linux ELF that forks once, the child exits 42, the parent
         * wait4s and exits 0.  PR 7 dropped the PROCD_TAKEOVER_SPAWN
         * gate · the shadow-announce path is now unconditional and
         * always lights up four log lines that scripts/smoke-procd.sh
         * greps for:
         *   - [orch] procd fork announced
         *   - [procd] fork slot=
         *   - [procd] exit slot=
         *   - [procd] EV_SIGCHLD
         * The [fork-test] marker lines independently confirm the
         * fixture itself ran end to end. */
        {
            static orch_spawn_msg_t pft_msg;
            memset(&pft_msg, 0, sizeof(pft_msg));
            const char *pft_argv[] = { "procd_fork_test" };
            strlcpy(pft_msg.binname, "procd_fork_test.bin",
                    ORCH_SPAWN_BINNAME_BYTES);
            pft_msg.argc         = 1;
            pft_msg.profile      = 0;
            pft_msg.initial_tier = 0;
            size_t pft_off = 0;
            size_t pft_l = strlen(pft_argv[0]) + 1;
            memcpy(pft_msg.argv_pool + pft_off, pft_argv[0], pft_l);
            size_t nwords_pft = sizeof(pft_msg) / sizeof(seL4_Word);
            seL4_Word *src_pft = (seL4_Word *)&pft_msg;
            for (size_t i = 0; i < nwords_pft; ++i)
                seL4_SetMR(i, src_pft[i]);
            seL4_MessageInfo_t info_pft = seL4_MessageInfo_new(
                ORCH_OP_SPAWN, 0, 0, nwords_pft);
            printf("[root] procd PR 6 · spawning procd_fork_test.bin (fork+wait4 smoke)\n");
            seL4_MessageInfo_t reply_pft = seL4_Call(orch_ep, info_pft);
            seL4_Word rc_pft = seL4_MessageInfo_get_label(reply_pft);
            printf("[root] procd PR 6 · procd_fork_test.bin spawn rc=%lu\n",
                   (unsigned long)rc_pft);
        }

        /* PY4 · arch_prctl minimal reproducer.  Tiny static ELF that
         * issues `arch_prctl(ARCH_SET_FS, 0xdeadbeef)` immediately
         * followed by `ret` — the exact `syscall ; ret` pattern that
         * CPython's musl __set_thread_area crashes on at `entry+2`.
         *
         * Outcomes:
         *   • "AP-PASS" in serial log → syscall+ret works in isolation;
         *     bug is Python-specific (code layout, surrounding data, etc.).
         *   • Fault at the fixture's ret with the same signature as
         *     Python (rip_post+2, RSP unchanged, RAX corrupted) → bug
         *     is general; isolated from the 24 MiB CPython binary into
         *     a ~100-byte one.
         *
         * Spawned AFTER busybox demos / pthread_test, BEFORE Python so
         * the orch pool is still warm.  See src/test/lucas_arch_prctl. */
        {
            static orch_spawn_msg_t ap_msg;
            memset(&ap_msg, 0, sizeof(ap_msg));
            const char *ap_argv[] = { "arch_prctl_test" };
            strlcpy(ap_msg.binname, "arch_prctl_test.bin", ORCH_SPAWN_BINNAME_BYTES);
            ap_msg.argc         = 1;
            ap_msg.profile      = 0;
            ap_msg.initial_tier = 0;
            size_t ap_off = 0;
            size_t ap_l = strlen(ap_argv[0]) + 1;
            memcpy(ap_msg.argv_pool + ap_off, ap_argv[0], ap_l);
            size_t nwords_ap = sizeof(ap_msg) / sizeof(seL4_Word);
            seL4_Word *src_ap = (seL4_Word *)&ap_msg;
            for (size_t i = 0; i < nwords_ap; ++i) seL4_SetMR(i, src_ap[i]);
            seL4_MessageInfo_t info_ap = seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nwords_ap);
            printf("[root] PY4 · spawning arch_prctl_test.bin (syscall+ret isolator · expect 'AP-PASS')\n");
            seL4_MessageInfo_t reply_ap = seL4_Call(orch_ep, info_ap);
            seL4_Word rc_ap = seL4_MessageInfo_get_label(reply_ap);
            printf("[root] PY4 · arch_prctl_test.bin spawn rc=%lu\n", (unsigned long)rc_ap);
        }

        /* L11-β-2 · CPython 3.12 hello-world attempt (now L11-γ exercise).
         * 24 MiB static binary, ~30 MiB of LOAD segments.  With L11-γ
         * stdlib infra landed (orch budget bump + sotfs-backed stdlib),
         * we now expect Python to actually print the confirmation message
         * rather than fail in the allocator.  argv carries the new
         * "stdlib loaded" banner the operator will look for in QEMU. */
        {
            static orch_spawn_msg_t py_msg;
            memset(&py_msg, 0, sizeof(py_msg));
            const char *py_argv[] = { "python3", "-c", "print('hello from python on sotOs · L11-γ stdlib loaded')" };
            strlcpy(py_msg.binname, "python3.12-static", ORCH_SPAWN_BINNAME_BYTES);
            py_msg.argc    = 3;
            py_msg.profile = 0;
            py_msg.initial_tier = 0;
            size_t py_off = 0;
            for (int i = 0; i < 3; ++i) {
                size_t l = strlen(py_argv[i]) + 1;
                if (py_off + l >= ORCH_SPAWN_ARGV_BYTES) break;
                memcpy(py_msg.argv_pool + py_off, py_argv[i], l);
                py_off += l;
            }
            size_t nwords_py = sizeof(py_msg) / sizeof(seL4_Word);
            seL4_Word *src_py = (seL4_Word *)&py_msg;
            for (size_t i = 0; i < nwords_py; ++i) seL4_SetMR(i, src_py[i]);
            seL4_MessageInfo_t info_py = seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nwords_py);
            printf("[root] L11-γ attempt · spawning python3.12-static (24 MiB ELF · expect 'stdlib loaded' banner with γ infra)\n");
            seL4_MessageInfo_t reply_py = seL4_Call(orch_ep, info_py);
            seL4_Word rc_py = seL4_MessageInfo_get_label(reply_py);
            if (rc_py != 0) {
                printf("[root] L11-γ · SPAWN failed (rc=%lu) · γ infra incomplete · diagnostic captured\n",
                       (unsigned long)rc_py);
            } else {
                printf("[root] L11-γ · python3.12-static SPAWNED · stdlib-loaded banner incoming?\n");
            }
        }

        /* Demo #1 · L5 · cat /etc/os-release with Ubuntu profile. */
        {
            static orch_spawn_msg_t spawn_msg;
            memset(&spawn_msg, 0, sizeof(spawn_msg));

            const char *binname     = "busybox-static.bin";
            const char *osrel_argv[] = { "busybox", "cat", "/etc/os-release" };
            const int   sh_argc     = 3;  /* re-using var name from old #1 */
            const char *const *sh_argv = osrel_argv;

            strlcpy(spawn_msg.binname, binname, ORCH_SPAWN_BINNAME_BYTES);
            spawn_msg.argc    = (uint32_t)sh_argc;
            spawn_msg.profile = 1;  /* UBUNTU */

            size_t pool_off = 0;
            for (int i = 0; i < sh_argc; ++i) {
                size_t l = strlen(sh_argv[i]) + 1;
                if (pool_off + l >= ORCH_SPAWN_ARGV_BYTES) break;
                memcpy(spawn_msg.argv_pool + pool_off, sh_argv[i], l);
                pool_off += l;
            }

            size_t nwords = sizeof(spawn_msg) / sizeof(seL4_Word);
            seL4_Word *src = (seL4_Word *)&spawn_msg;
            for (size_t i = 0; i < nwords; ++i) seL4_SetMR(i, src[i]);

            seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nwords);
            seL4_Call(orch_ep, info);
            printf("[root] L5 demo (cat /etc/os-release · Ubuntu) completed\n");
        }

        /* Demo #2 · L3c · cat /proc/self/maps (Alpine profile). */
        {
            static orch_spawn_msg_t spawn_msg2;
            memset(&spawn_msg2, 0, sizeof(spawn_msg2));

            const char *binname    = "busybox-static.bin";
            const char *maps_argv[] = { "busybox", "cat", "/proc/self/maps" };
            const int   maps_argc   = 3;

            strlcpy(spawn_msg2.binname, binname, ORCH_SPAWN_BINNAME_BYTES);
            spawn_msg2.argc    = (uint32_t)maps_argc;
            spawn_msg2.profile = 0;  /* ALPINE */

            size_t pool_off = 0;
            for (int i = 0; i < maps_argc; ++i) {
                size_t l = strlen(maps_argv[i]) + 1;
                if (pool_off + l >= ORCH_SPAWN_ARGV_BYTES) break;
                memcpy(spawn_msg2.argv_pool + pool_off, maps_argv[i], l);
                pool_off += l;
            }

            size_t nwords = sizeof(spawn_msg2) / sizeof(seL4_Word);
            seL4_Word *src = (seL4_Word *)&spawn_msg2;
            for (size_t i = 0; i < nwords; ++i) seL4_SetMR(i, src[i]);

            seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nwords);
            seL4_Call(orch_ep, info);
            printf("[root] L3c demo (cat /proc/self/maps · Alpine) completed\n");
        }

        /* Demo #3 · A3-Z anomaly stress · sequential echo writes at Tier 0.
         * anomaly_on_write() forwards ANOMALY_EV_WRITE to anomaly-ext for
         * each write syscall.  After ANOMALY_EXT_WRITE_THRESHOLD writes the
         * external anomaly (threshold > 50 · S-THRESH) fires
         * ORCH_OP_PROMOTE_TIER for the REAL sotbox pid · replacing the C2-B
         * synthetic trigger (pid=7) with an organic round-trip driven by
         * real Linux sotbox writes.  The shell uses a POSIX `while` loop
         * (no `seq` dependency) so the inline command stays inside the
         * argv_pool budget while still producing enough writes to cross
         * the threshold.  Uses the same allocman slot as old Demo #3 (no
         * new pool pressure). */
        {
            static orch_spawn_msg_t spawn_msg3;
            memset(&spawn_msg3, 0, sizeof(spawn_msg3));

            const char *binname = "busybox-static.bin";
            /* S-THRESH · 60 echo writes (threshold=50, margin=10).  A
             * POSIX `while` loop with `$((i+1))` arithmetic produces the
             * required volume without depending on an external `seq`
             * applet (busybox builds vary).  The inline shell command
             * stays under 60 chars so it fits comfortably in the
             * argv_pool (368 bytes total). */
            const char *stress_argv[] = {
                "busybox", "sh", "-c",
                "i=1; while [ $i -le 60 ]; do echo $i; i=$((i+1)); done"
            };
            const int   stress_argc = 4;

            strlcpy(spawn_msg3.binname, binname, ORCH_SPAWN_BINNAME_BYTES);
            spawn_msg3.argc         = (uint32_t)stress_argc;
            spawn_msg3.profile      = 0;  /* ALPINE · Tier 0 writes visible to anomaly */
            spawn_msg3.initial_tier = 0;  /* Tier 0 · anomaly counts writes */

            size_t pool_off = 0;
            for (int i = 0; i < stress_argc; ++i) {
                size_t l = strlen(stress_argv[i]) + 1;
                if (pool_off + l >= ORCH_SPAWN_ARGV_BYTES) break;
                memcpy(spawn_msg3.argv_pool + pool_off, stress_argv[i], l);
                pool_off += l;
            }

            size_t nwords = sizeof(spawn_msg3) / sizeof(seL4_Word);
            seL4_Word *src = (seL4_Word *)&spawn_msg3;
            for (size_t i = 0; i < nwords; ++i) seL4_SetMR(i, src[i]);

            seL4_MessageInfo_t info = seL4_MessageInfo_new(ORCH_OP_SPAWN, 0, 0, nwords);
            seL4_Call(orch_ep, info);
            printf("[root] A3-Z anomaly stress (60 echo writes · Tier 0) completed\n");
        }

    }

    /* L4: STO demo deferred — root's untyped budget covers orch + 2 Linux demos.
     * The STO demos run standalone via the dedicated STO image. */

    printf("[root] entering wait loop\n");
    while (1) {
        seL4_Yield();
    }
    return 0;
}
