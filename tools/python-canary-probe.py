#!/usr/bin/env python3
"""Type a python command into the bbsh canary shell over the virtio-keyboard (QMP)
and let the orch idle-loop spawn real CPython (heavy arena).  Boot is launched
separately.  Richer keymap than abi-shell-probe (parens/quotes/+ for code).

Usage: python-canary-probe.py <qmp.sock> <serial.log> <cmd1> [cmd2] ...
"""
import json, socket, sys, time

QMP, SERIAL = sys.argv[1], sys.argv[2]
CMDS = sys.argv[3:]

QC = {c: c for c in "abcdefghijklmnopqrstuvwxyz0123456789"}
QC.update({" ": "spc", "\n": "ret", "-": "minus", "/": "slash", ".": "dot",
           "_": "shift+minus", "=": "equal",
           "(": "shift+9", ")": "shift+0", "+": "shift+equal",
           "*": "shift+8", ",": "comma", ":": "shift+semicolon",
           "'": "apostrophe", '"': "shift+apostrophe"})


def wait_marker(path, marker, timeout):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            if marker.encode() in open(path, "rb").read():
                return True
        except FileNotFoundError:
            pass
        time.sleep(0.5)
    return False


class Qmp:
    def __init__(self, path):
        for _ in range(60):
            try:
                self.s = socket.socket(socket.AF_UNIX); self.s.connect(path); break
            except (FileNotFoundError, ConnectionRefusedError):
                time.sleep(0.5)
        else:
            raise SystemExit("qmp connect timeout")
        self.f = self.s.makefile("rwb", buffering=0)
        self.f.readline()
        self.cmd("qmp_capabilities")

    def cmd(self, ex, **a):
        m = {"execute": ex}
        if a:
            m["arguments"] = a
        self.f.write((json.dumps(m) + "\n").encode())
        while True:
            r = json.loads(self.f.readline())
            if "return" in r or "error" in r:
                return r

    def key(self, qc):
        keys = qc.split("+")
        for k in keys:
            self.cmd("input-send-event", events=[{"type": "key", "data":
                     {"down": True, "key": {"type": "qcode", "data": k}}}])
        for k in reversed(keys):
            self.cmd("input-send-event", events=[{"type": "key", "data":
                     {"down": False, "key": {"type": "qcode", "data": k}}}])
        time.sleep(0.03)

    def typ(self, s):
        for ch in s:
            qc = QC.get(ch)
            if qc:
                self.key(qc)
                time.sleep(0.07)


def main():
    if not wait_marker(SERIAL, "bbsh: entering fault loop", 120):
        raise SystemExit("terminal not ready")
    time.sleep(3)
    q = Qmp(QMP)
    for c in CMDS:
        time.sleep(1.5)
        print(f"[py-probe] typing: {c}")
        q.typ(c + "\n")
        time.sleep(6)              # CPython spawn + heavy-arena + import is slow
    time.sleep(4)
    print("[py-probe] done")


main()
