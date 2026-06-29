#!/usr/bin/env python3
"""Autonomous interactive-console probe.

Boots are launched separately; this connects to a QEMU QMP unix socket, waits
for a serial-log marker, types a string via virtio-keyboard (input-send-event),
waits for a second marker, then screendumps the virtio-gpu scanout.

Usage: interactive-qmp-probe.py <qmp.sock> <serial.log> <out.ppm> [post_qcodes]
  post_qcodes: comma-separated QEMU qcodes to send (with delays) AFTER frames
               start, before the screendump (e.g. "esc,down,down,ret").
"""
import json, socket, sys, time, os

QMP, SERIAL, OUT = sys.argv[1], sys.argv[2], sys.argv[3]

# char -> QEMU qcode
QCODE = {c: c for c in "abcdefghijklmnopqrstuvwxyz0123456789"}
QCODE[" "] = "spc"
QCODE["\n"] = "ret"
QCODE["-"] = "minus"


def wait_marker(path, marker, timeout, after=0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with open(path, "rb") as f:
                f.seek(after)
                data = f.read()
            if marker.encode() in data:
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
            raise SystemExit("qmp: connect timeout")
        self.f = self.s.makefile("rwb", buffering=0)
        self.f.readline()  # greeting
        self.cmd("qmp_capabilities")

    def cmd(self, ex, **args):
        m = {"execute": ex}
        if args:
            m["arguments"] = args
        self.f.write((json.dumps(m) + "\n").encode())
        while True:
            line = self.f.readline()
            if not line:
                raise SystemExit("qmp: closed")
            r = json.loads(line)
            if "return" in r or "error" in r:
                return r

    def key(self, qcode):
        for down in (True, False):
            self.cmd("input-send-event", events=[
                {"type": "key", "data": {"down": down,
                 "key": {"type": "qcode", "data": qcode}}}])
            time.sleep(0.02)

    def mouse_abs(self, x, y):
        self.cmd("input-send-event", events=[
            {"type": "abs", "data": {"axis": "x", "value": x}},
            {"type": "abs", "data": {"axis": "y", "value": y}}])

    def mouse_btn(self, down, button="left"):
        self.cmd("input-send-event", events=[
            {"type": "btn", "data": {"down": down, "button": button}}])

    def type_str(self, s):
        for ch in s:
            qc = QCODE.get(ch)
            if not qc:
                continue
            self.key(qc)
            time.sleep(0.08)


def main():
    print("[probe] waiting for terminal-ready marker…")
    if not wait_marker(SERIAL, "bbsh: entering fault loop", 120):
        raise SystemExit("[probe] terminal not ready")
    time.sleep(3)  # let the prompt + DSR settle
    pos = os.path.getsize(SERIAL)
    q = Qmp(QMP)
    print("[probe] typing 'doom'…")
    q.type_str("doom\n")
    print("[probe] waiting for Chocolate frames…")
    if not wait_marker(SERIAL, "[doom] frame=", 90, after=pos):
        # retry once — the shell line-edit + DSR dance can drop a keystroke
        print("[probe] no frames yet · retrying 'doom'")
        q.type_str("doom\n")
        if not wait_marker(SERIAL, "[doom] frame=", 90, after=pos):
            raise SystemExit("[probe] no doom frames")
    print("[probe] frames flowing · letting it render…")
    time.sleep(5)
    if len(sys.argv) > 4 and sys.argv[4]:
        seq = [s for s in sys.argv[4].split(",") if s]
        print(f"[probe] sending post-launch keys: {seq}")
        for qc in seq:
            q.key(qc)
            time.sleep(0.4)
        time.sleep(2)
    # optional mouse-fire test: argv[5]=="fire" → screendump before, hold left
    # button (fire), screendump during, release.  OUT2 = OUT + "_fire".
    if len(sys.argv) > 5 and sys.argv[5] == "fire":
        out2 = OUT.rsplit(".", 1)[0] + "_fire." + OUT.rsplit(".", 1)[1]
        q.mouse_abs(16384, 16384)   # seed tablet position (center)
        time.sleep(0.4)
        q.cmd("screendump", filename=OUT)     # before fire
        print(f"[probe] screendump (pre-fire) → {OUT}")
        print("[probe] holding LEFT mouse button (fire)…")
        q.mouse_btn(True)
        time.sleep(1.6)
        q.cmd("screendump", filename=out2)    # during fire
        q.mouse_btn(False)
        print(f"[probe] screendump (firing) → {out2}")
        time.sleep(1)
        return
    q.cmd("screendump", filename=OUT)
    time.sleep(1)
    print(f"[probe] screendump → {OUT}")


main()
