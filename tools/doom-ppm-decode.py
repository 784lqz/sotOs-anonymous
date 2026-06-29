#!/usr/bin/env python3
# Decode the [doom-ppm-begin] WxH … [doom-ppm-end] base64 block (RGB rows) from a
# serial log into a PPM (header built from the WxH marker). Usage: SERIAL_LOG OUT.ppm
import sys, base64, re
log, out = sys.argv[1], sys.argv[2]
data = open(log, 'rb').read().decode('latin-1')
m = re.search(r'\[doom-ppm-begin\]\s*(\d+)x(\d+)\s*\n(.*?)\[doom-ppm-end\]', data, re.S)
if not m:
    sys.exit("no PPM block in serial")
w, h = int(m.group(1)), int(m.group(2))
b64 = ''.join(l.strip() for l in m.group(3).splitlines()
              if re.fullmatch(r'[A-Za-z0-9+/=]+', l.strip()))
rgb = base64.b64decode(b64)
hdr = ("P6\n%d %d\n255\n" % (w, h)).encode()
open(out, 'wb').write(hdr + rgb)
print(f"wrote {out} ({w}x{h}, {len(rgb)} RGB bytes)")
