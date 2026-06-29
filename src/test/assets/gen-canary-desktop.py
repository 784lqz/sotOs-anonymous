#!/usr/bin/env python3
"""Generate the L14a Canary Screenshot asset: a GNOME Shell + Files (Nautilus)
corporate-desktop scene, 1280x720, raw BGRA (== wl_shm XRGB8888 LE: a u32
0xFFrrggbb on LE is bytes [B,G,R,X]). Reproducible from PIL alone (no browser).
Run on the host:  python3 gen-canary-desktop.py  ->  canary-desktop.rgba  (commit: git add -f).
"""
from PIL import Image, ImageDraw, ImageFont
import os

W, H = 1280, 720

# subtle desktop wallpaper gradient (top darker -> bottom slightly blue-grey)
im = Image.new("RGBA", (W, H), (32, 34, 38, 255))
px = im.load()
for y in range(H):
    t = y / H
    r = int(30 + 14 * t); g = int(33 + 16 * t); b = int(40 + 26 * t)
    for x in range(0, W, 1):
        px[x, y] = (r, g, b, 255)
d = ImageDraw.Draw(im)

def font(sz):
    for p in ("/usr/share/fonts/dejavu/DejaVuSans.ttf",
              "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
              "/usr/share/fonts/dejavu-sans-fonts/DejaVuSans.ttf"):
        if os.path.exists(p):
            return ImageFont.truetype(p, sz)
    return ImageFont.load_default()

f_bar, f_title, f_item, f_small = font(15), font(15), font(16), font(13)

# --- GNOME top bar (black, 28px) ---
d.rectangle([0, 0, W, 28], fill=(0, 0, 0, 255))
d.text((14, 6), "Activities", font=f_bar, fill=(225, 225, 225, 255))
d.text((W // 2 - 52, 6), "Tue 08:47", font=f_bar, fill=(245, 245, 245, 255))
d.text((W - 120, 6), "EN  ●  ▰  ▾", font=f_bar, fill=(205, 205, 205, 255))

# --- Nautilus (Files) window, centred CSD ---
wx, wy, ww, wh = 180, 90, 920, 520
d.rounded_rectangle([wx, wy, wx + ww, wy + wh], radius=12, fill=(43, 43, 43, 255))
# header bar
d.rounded_rectangle([wx, wy, wx + ww, wy + 44], radius=12, fill=(53, 53, 53, 255))
d.rectangle([wx, wy + 22, wx + ww, wy + 44], fill=(53, 53, 53, 255))
d.text((wx + 16, wy + 13), "◀  ▶", font=f_title, fill=(200, 200, 200, 255))
d.text((wx + ww // 2 - 92, wy + 13), "CORP-FS01 — File Manager", font=f_title, fill=(235, 235, 235, 255))
d.text((wx + ww - 78, wy + 13), "–  □  ✕", font=f_title, fill=(200, 200, 200, 255))
# sidebar
d.rectangle([wx, wy + 44, wx + 180, wy + wh], fill=(48, 48, 48, 255))
for i, name in enumerate(["⭐ Starred", "\U0001F553 Recent", "\U0001F3E0 Home",
                          "\U0001F4C4 Documents", "⬇ Downloads", "\U0001F5A5 CORP-FS01"]):
    d.text((wx + 14, wy + 60 + i * 30), name, font=f_small, fill=(210, 210, 210, 255))
# bait file grid (3 cols x 3 rows) in the content area
baits = ["\U0001F4C1 HR_Confidential", "\U0001F4C1 Payroll_2026", "\U0001F4C1 Contracts",
         "\U0001F511 vpn_credentials.txt", "\U0001F511 aws_keys.csv", "\U0001F4C4 passwords.kdbx",
         "\U0001F4C1 M&A_DueDiligence", "\U0001F4CA Q4_Financials.xlsx", "\U0001F510 root_backup.gpg"]
cx0, cy0 = wx + 200, wy + 60
for i, name in enumerate(baits):
    col, row = i % 3, i // 3
    bx, by = cx0 + col * 230, cy0 + row * 150
    d.rounded_rectangle([bx, by, bx + 210, by + 130], radius=8, fill=(60, 60, 60, 255))
    d.text((bx + 78, by + 40), "\U0001F4C1" if "\U0001F4C1" in name else "\U0001F511",
           font=font(40), fill=(180, 190, 210, 255))
    d.text((bx + 12, by + 100), name.split(" ", 1)[1], font=f_small, fill=(225, 225, 225, 255))

# --- GNOME dash (bottom, translucent pill) ---
dw = 320
d.rounded_rectangle([W // 2 - dw // 2, H - 64, W // 2 + dw // 2, H - 12], radius=16, fill=(0, 0, 0, 150))
d.text((W // 2 - dw // 2 + 24, H - 54), "\U0001F98A   \U0001F4C1   \U0001F4E7   \U0001F5A5   ⚙",
       font=font(28), fill=(235, 235, 235, 255))

# --- mouse cursor (white arrow) so the scene reads as live ---
cxp, cyp = 760, 430
d.polygon([(cxp, cyp), (cxp, cyp + 18), (cxp + 5, cyp + 13), (cxp + 9, cyp + 21),
           (cxp + 12, cyp + 19), (cxp + 8, cyp + 11), (cxp + 14, cyp + 11)],
          fill=(255, 255, 255, 255), outline=(0, 0, 0, 255))

# --- pack BGRA (B,G,R,X) == XRGB8888 LE ---
b = bytearray()
for r, g, bl, a in im.getdata():
    b += bytes((bl, g, r, 0xFF))
assert len(b) == W * H * 4, len(b)
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "canary-desktop.rgba")
open(out, "wb").write(bytes(b))

h = 2166136261
for byte in b:
    h ^= byte; h = (h * 16777619) & 0xFFFFFFFF
print("wrote %s (%d bytes) %dx%d fnv1a=0x%08x" % (out, len(b), W, H, h))
