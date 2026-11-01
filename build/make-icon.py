"""Writes a placeholder app icon (rounded dark square with a light 'H') as PNG using only the stdlib."""
import struct, sys, zlib

size = int(sys.argv[2]) if len(sys.argv) > 2 else 1024
out = sys.argv[1]
bg, fg, corner = (28, 31, 38), (188, 140, 255), size // 5

def inside_rounded(x, y):
    r = corner
    cx = min(max(x, r), size - 1 - r)
    cy = min(max(y, r), size - 1 - r)
    return (x - cx) ** 2 + (y - cy) ** 2 <= r * r

def inside_h(x, y):
    stem = size * 0.13
    left, right = size * 0.24, size * 0.76 - stem
    top, bottom = size * 0.24, size * 0.76
    bar_t, bar_b = size * 0.455, size * 0.545
    if not (top <= y < bottom):
        return False
    return left <= x < left + stem or right <= x < right + stem or (left <= x < right + stem and bar_t <= y < bar_b)

rows = []
for y in range(size):
    row = bytearray([0])  # filter type 0
    for x in range(size):
        if not inside_rounded(x, y):
            row += b"\x00\x00\x00\x00"
        else:
            row += bytes(fg if inside_h(x, y) else bg) + b"\xff"
    rows.append(bytes(row))

def chunk(tag, data):
    return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
png += chunk(b"IDAT", zlib.compress(b"".join(rows), 9)) + chunk(b"IEND", b"")
open(out, "wb").write(png)
