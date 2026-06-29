# sotinit · bundled demo units (PR 2 + PR 4 · β)

These files are the canonical text for the demo systemd unit fragments
that ship inside the sotinit ELF as `.rodata` blobs (see `src/sotinit/scan.c`).
They exist on disk for:

- Editor / reviewer ergonomics · syntax highlighting + diffs.
- Documentation · the in-source blobs include comments referencing this
  directory so the reader knows where the canonical source lives.
- Future packing · when sotfs gains an IPC channel for sotinit (PR 3 / PR 5)
  these files become the seed data for the on-disk `/etc/systemd/system/`
  directory, and the `.rodata` embedding in `scan.c` collapses to a
  fallback / first-boot path.

Inventory:

- `multi-user.target` · PR 2 · the default boot target (Description-only).
- `demo-noop.service` · PR 2 · the canonical activation smoke fixture
  (Type=simple, ExecStart=/bin/true).
- `demo-a.service` + `demo-b.service` · PR 4 · the topological-sort
  fixture · `demo-b` declares `After=demo-a.service`, and `g_bundled[]`
  in `scan.c` inserts B before A so the smoke gate proves Kahn's
  algorithm flipped the activation order at boot.

All files must be kept in sync with the string literals in
`src/sotinit/scan.c::g_bundled[]`.  A later PR introduces a build-time
check that fails the build on drift (out of scope for PR 2 / PR 4).
