"""Renders the Hubris app icon to PNG with real alpha, stdlib only (no SVG rasteriser on a stock Mac).

    python3 build/render-icon.py out.png [size]

Geometry mirrors brand/hubris-icon.svg: rounded 1024 tile (r=236) with a vertical luminance gradient and a
hairline rim, plus the sheared disc (two half discs, r=262, shifted +-50, 28 px gap). Signed-distance fields
with analytic anti-aliasing: one sample per pixel is enough for clean edges at every size.
"""
import math, struct, sys, zlib

out = sys.argv[1]
size = int(sys.argv[2]) if len(sys.argv) > 2 else 1024
S = size / 1024.0  # 1024-space -> pixel

def lerp(a, b, t): return a + (b - a) * t
def cov(d): return min(1.0, max(0.0, 0.5 - d))  # d in pixels, negative = inside

def sd_round_rect(x, y, cx, cy, hw, hh, r):
    qx, qy = abs(x - cx) - hw + r, abs(y - cy) - hh + r
    return math.hypot(max(qx, 0), max(qy, 0)) + min(max(qx, qy), 0) - r

def sd_half_disc(x, y, cx, cy, r, left):
    d = math.hypot(x - cx, y - cy) - r
    plane = (x - cx) if left else (cx - x)  # inside when <= 0
    return max(d, plane)

TILE_TOP, TILE_BOT = (0x1A, 0x1C, 0x22), (0x0A, 0x0B, 0x0D)
GLYPH_TOP, GLYPH_BOT = (0xFF, 0xFF, 0xFF), (0xB4, 0xB9, 0xC3)
RIM = (0x2A, 0x2E, 0x36)

rows = []
for py in range(size):
    y = (py + 0.5) / S
    row = bytearray([0])
    tt = y / 1024.0
    tile_rgb = [lerp(TILE_TOP[k], TILE_BOT[k], tt) for k in range(3)]
    gt = min(1.0, max(0.0, (y - 200.0) / 624.0))
    glyph_rgb = [lerp(GLYPH_TOP[k], GLYPH_BOT[k], gt) for k in range(3)]
    for px in range(size):
        x = (px + 0.5) / S
        d_tile = sd_round_rect(x, y, 512, 512, 512, 512, 236) * S
        a_tile = cov(d_tile)
        if a_tile <= 0:
            row += b"\x00\x00\x00\x00"
            continue
        # rim: a 3px (1024-space) stroke just inside the edge
        rim = cov(abs(d_tile + 1.5 * S) - 1.5 * S) if size >= 64 else 0.0
        rgb = [lerp(tile_rgb[k], RIM[k], rim * 0.9) for k in range(3)]
        d_g = min(sd_half_disc(x, y, 498, 562, 262, True), sd_half_disc(x, y, 526, 462, 262, False)) * S
        a_g = cov(d_g)
        if a_g > 0:
            rgb = [lerp(rgb[k], glyph_rgb[k], a_g) for k in range(3)]
        row += bytes((int(round(rgb[0])), int(round(rgb[1])), int(round(rgb[2])), int(round(a_tile * 255))))
    rows.append(bytes(row))

def chunk(tag, data):
    return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
png += chunk(b"IDAT", zlib.compress(b"".join(rows), 9)) + chunk(b"IEND", b"")
open(out, "wb").write(png)
