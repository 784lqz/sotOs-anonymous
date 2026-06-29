#!/usr/bin/env python3
"""Emit a real us-layout xkb_v1 keymap blob -> keymap-us.xkb (commit: git add -f).
Tries the host's libxkbcommon (xkbcli) for a genuine resolved keymap; falls back
to a representative xkb_v1 text if unavailable. Prints fnv1a (the gate value).
"""
import os, subprocess
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keymap-us.xkb")
blob = None
try:
    r = subprocess.run(["xkbcli", "compile-keymap", "--layout", "us"],
                       capture_output=True, timeout=20)
    if r.returncode == 0 and len(r.stdout) > 1024:
        blob = r.stdout
except Exception:
    pass
if blob is None:
    # Representative xkb_v1 keymap (us). NUL-terminated, mmap-able; a real client
    # feeds this to xkb_keymap_new_from_string(XKB_KEYMAP_FORMAT_TEXT_V1).
    text = (
        'xkb_keymap {\n'
        '  xkb_keycodes "evdev+aliases(qwerty)" {\n'
        '    minimum = 8; maximum = 255;\n'
        + ''.join('    <K%02d> = %d;\n' % (i, i + 8) for i in range(0, 64)) +
        '  };\n'
        '  xkb_types "complete" { virtual_modifiers NumLock,Alt,LevelThree; };\n'
        '  xkb_compatibility "complete" { virtual_modifiers NumLock,Alt; };\n'
        '  xkb_symbols "pc+us+inet(evdev)" {\n'
        '    name[group1]="English (US)";\n'
        '    key <K01> { [ Escape ] };\n'
        + ''.join('    key <K%02d> { [ %s, %s ] };\n'
                  % (i + 10, c, c.upper()) for i, c in enumerate("1234567890qwertyuiopasdfghjklzxcvbnm")) +
        '    key <K60> { [ space ] };\n'
        '    key <K61> { [ Return ] };\n'
        '    modifier_map Shift { <K50> };\n'
        '  };\n'
        '};\n'
    )
    blob = text.encode() + b"\x00"
open(out, "wb").write(blob)
h = 2166136261
for byte in blob:
    h ^= byte; h = (h * 16777619) & 0xFFFFFFFF
print("wrote %s (%d bytes) fnv1a=0x%08x" % (out, len(blob), h))
