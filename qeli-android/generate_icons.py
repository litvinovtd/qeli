#!/usr/bin/env python3
"""Generate Android icons from the polished Windows app icon (qeli.ico) directly,
so the Q (and its green tail) look exactly like the original and never get
redrawn/clipped.

- drawable-nodpi/ic_logo.png : full art for the in-app header (no masking).
- mipmap legacy ic_launcher* : full art (+ circle-masked round variant). No
  adaptive icon: the adaptive parallax-zoom pushed the Q tail past the launcher
  mask, so the launcher uses the plain full-bleed art instead (MIUI just rounds
  the corners), matching the in-app logo.
"""
from PIL import Image, ImageDraw
import os

ICO = r"C:\Users\litvi\OneDrive\Documents\OpenCode\VPN_CLAUDE\qeli-win\QeliWin\Assets\qeli.ico"
RES = r"C:\Users\litvi\OneDrive\Documents\OpenCode\VPN_CLAUDE\qeli-android\app\src\main\res"

ico = Image.open(ICO); ico.size = (256, 256)
art = ico.convert("RGBA")

def circle(im):
    w, h = im.size
    m = Image.new("L", (w, h), 0)
    ImageDraw.Draw(m).ellipse([0, 0, w - 1, h - 1], fill=255)
    out = im.copy(); out.putalpha(m); return out

LEGACY = {"mdpi": 48, "hdpi": 72, "xhdpi": 96, "xxhdpi": 144, "xxxhdpi": 192}

for dens, px in LEGACY.items():
    d = os.path.join(RES, f"mipmap-{dens}"); os.makedirs(d, exist_ok=True)
    sq = art.resize((px, px), Image.LANCZOS)
    sq.save(os.path.join(d, "ic_launcher.png"))
    circle(sq).save(os.path.join(d, "ic_launcher_round.png"))

# in-app header logo (full art, never masked)
nod = os.path.join(RES, "drawable-nodpi"); os.makedirs(nod, exist_ok=True)
art.resize((192, 192), Image.LANCZOS).save(os.path.join(nod, "ic_logo.png"))

print("icons regenerated from original win art (header logo + launcher)")
