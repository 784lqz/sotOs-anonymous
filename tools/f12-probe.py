#!/usr/bin/env python3
"""F12 toggle probe: drive the GTK-window shell switch over QMP.

Sequence:
  1. wait for the canary shell (bbsh) prompt
  2. press F12  → expect orch to hand the window to the operator console
  3. type `list` + Enter → an operator-only command (runs in sotShell)
  4. press F12 again → expect a fresh canary shell
  5. screendump at the end for an eyeball

Usage: f12-probe.py <qmp.sock> <serial.log> <screendump.ppm>
"""
import json, socket, sys, time

QMP, SERIAL, SHOT = sys.argv[1], sys.argv[2], sys.argv[3]

QC = {c: c for c in "abcdefghijklmnopqrstuvwxyz0123456789"}
QC.update({" ": "spc", "\n": "ret", "-": "minus", "/": "slash", ".": "dot"})


def wait_marker(path, marker, timeout, after=0):
    """Wait until `marker` appears in the file at/after byte offset `after`."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            data = open(path, "rb").read()
            if marker.encode() in data[after:]:
                return True
        except FileNotFoundError:
            pass
        time.sleep(0.4)
    return False


class Qmp:
    def __init__(self, path):
        for _ in range(80):
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
        time.sleep(0.05)

    def typ(self, s):
        for ch in s:
            qc = QC.get(ch)
            if qc:
                self.key(qc); time.sleep(0.08)

    def screendump(self, path):
        self.cmd("screendump", filename=path)


def main():
    if not wait_marker(SERIAL, "bbsh: entering fault loop", 120):
        raise SystemExit("canary shell not ready")
    time.sleep(3)
    q = Qmp(QMP)
    sz = lambda: len(open(SERIAL, "rb").read())

    # 1. F12 in the canary shell → operator console
    m1 = sz()
    print("[f12-probe] F12 #1 (canary shell → operator console)")
    q.key("f12")
    wait_marker(SERIAL, "OPERATOR CONSOLE", 15, after=m1)
    time.sleep(2)

    # 2. an operator-only command
    print("[f12-probe] typing operator command: list")
    q.typ("list\n")
    time.sleep(3)
    q.screendump(SHOT + ".operator.ppm")   # eyeball: the truth view
    time.sleep(1)

    # 3. F12 in the operator console → back to a fresh canary shell
    m2 = sz()
    print("[f12-probe] F12 #2 (operator console → canary shell)")
    q.key("f12")
    wait_marker(SERIAL, "bbsh: entering fault loop", 15, after=m2)
    time.sleep(2)

    q.screendump(SHOT)
    time.sleep(1)
    print("[f12-probe] done")


main()
