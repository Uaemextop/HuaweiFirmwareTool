"""
SVG and icon assets for the HuaweiFlash.

Generates the application logo and provides icon data for UI elements.
All icons are base64-encoded PNG data generated from PIL drawings.
"""

import base64
import io
import math
from typing import Tuple

try:
    from PIL import Image, ImageDraw, ImageFont, ImageFilter
    HAS_PIL = True
except ImportError:
    HAS_PIL = False


BRAND_BLUE = "#2563EB"
BRAND_CYAN = "#06B6D4"
BRAND_DARK = "#0F172A"
BRAND_LIGHT = "#F8FAFC"
ACCENT_GREEN = "#10B981"
ACCENT_RED = "#EF4444"
ACCENT_ORANGE = "#F59E0B"
ACCENT_PURPLE = "#8B5CF6"


def generate_logo(size: int = 128) -> bytes:
    """Generate the HuaweiFlash logo as PNG bytes.

    Creates a modern gradient logo with a circuit/firmware motif.
    """
    if not HAS_PIL:
        return b""

    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    center = size // 2
    radius = size // 2 - 4

    # Outer glow
    glow = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    glow_draw = ImageDraw.Draw(glow)
    for i in range(8, 0, -1):
        alpha = int(30 * (1 - i / 8))
        glow_draw.ellipse(
            [center - radius - i, center - radius - i, center + radius + i, center + radius + i],
            fill=(37, 99, 235, alpha),
        )
    img = Image.alpha_composite(img, glow)
    draw = ImageDraw.Draw(img)

    # Gradient background circle
    for r in range(radius, 0, -1):
        progress = 1 - r / radius
        red = int(15 + progress * 22)
        green = int(23 + progress * 80)
        blue = int(42 + progress * 193)
        draw.ellipse(
            [center - r, center - r, center + r, center + r],
            fill=(red, green, blue, 255),
        )

    # Inner highlight
    highlight_r = int(radius * 0.85)
    for r in range(highlight_r, int(highlight_r * 0.3), -1):
        progress = 1 - (r - highlight_r * 0.3) / (highlight_r * 0.7)
        alpha = int(40 * progress)
        draw.ellipse(
            [center - r, center - r - int(radius * 0.1), center + r, center + r - int(radius * 0.1)],
            fill=(255, 255, 255, alpha),
        )

    # Circuit lines
    line_color = (6, 182, 212, 180)
    line_w = max(2, size // 40)

    # Horizontal circuit traces
    y1 = center - size // 6
    y2 = center + size // 6
    draw.line([(center - radius // 2, y1), (center + radius // 3, y1)], fill=line_color, width=line_w)
    draw.line([(center - radius // 3, y2), (center + radius // 2, y2)], fill=line_color, width=line_w)

    # Vertical connection
    draw.line([(center, y1), (center, y2)], fill=line_color, width=line_w)

    # Circuit nodes
    node_r = max(3, size // 25)
    for x, y in [(center - radius // 2, y1), (center + radius // 3, y1),
                 (center - radius // 3, y2), (center + radius // 2, y2),
                 (center, center)]:
        draw.ellipse([x - node_r, y - node_r, x + node_r, y + node_r], fill=(6, 182, 212, 255))
        inner = node_r - max(1, node_r // 3)
        draw.ellipse([x - inner, y - inner, x + inner, y + inner], fill=(255, 255, 255, 200))

    # Arrow/flash symbol in center
    flash_size = size // 5
    cx, cy = center, center
    points = [
        (cx - flash_size // 3, cy - flash_size // 2),
        (cx + flash_size // 6, cy - flash_size // 8),
        (cx - flash_size // 8, cy - flash_size // 8),
        (cx + flash_size // 3, cy + flash_size // 2),
        (cx - flash_size // 6, cy + flash_size // 8),
        (cx + flash_size // 8, cy + flash_size // 8),
    ]
    draw.polygon(points, fill=(255, 255, 255, 230))

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def generate_icon(name: str, size: int = 20, color: str = "#FFFFFF") -> bytes:
    """Generate a simple icon as PNG bytes.

    Supported icons: flash, folder, play, stop, settings, terminal,
    shield, info, log, save, refresh, connect, disconnect, search,
    key, lock, unlock, download, upload, trash, copy, check, x, warning.
    """
    if not HAS_PIL:
        return b""

    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    r, g, b = _hex_to_rgb(color)
    fill = (r, g, b, 255)
    lw = max(1, size // 10)

    if name == "flash":
        _draw_flash(draw, size, fill)
    elif name == "folder":
        _draw_folder(draw, size, fill)
    elif name == "play":
        _draw_play(draw, size, fill)
    elif name == "stop":
        m = size // 4
        draw.rectangle([m, m, size - m, size - m], fill=fill)
    elif name == "settings":
        _draw_gear(draw, size, fill)
    elif name == "terminal":
        m = size // 5
        draw.rectangle([m, m, size - m, size - m], outline=fill, width=lw)
        draw.text((m + 2, m + 1), ">_", fill=fill)
    elif name == "shield":
        _draw_shield(draw, size, fill)
    elif name == "info":
        c = size // 2
        r2 = size // 3
        draw.ellipse([c - r2, c - r2, c + r2, c + r2], outline=fill, width=lw)
        draw.text((c - 2, c - r2 // 2), "i", fill=fill)
    elif name == "refresh":
        _draw_refresh(draw, size, fill, lw)
    elif name == "connect":
        draw.ellipse([size // 3, size // 3, 2 * size // 3, 2 * size // 3], fill=(16, 185, 129, 255))
    elif name == "disconnect":
        draw.ellipse([size // 3, size // 3, 2 * size // 3, 2 * size // 3], fill=(239, 68, 68, 255))
    elif name == "check":
        pts = [(size // 5, size // 2), (size * 2 // 5, size * 3 // 4), (size * 4 // 5, size // 4)]
        draw.line(pts, fill=fill, width=lw + 1)
    elif name == "warning":
        draw.polygon([(size // 2, size // 6), (size // 6, size * 5 // 6), (size * 5 // 6, size * 5 // 6)], outline=fill, width=lw)
        draw.text((size // 2 - 2, size // 2), "!", fill=fill)
    elif name == "save":
        _draw_save(draw, size, fill, lw)
    elif name == "log":
        _draw_log(draw, size, fill, lw)
    elif name == "trash":
        _draw_trash(draw, size, fill, lw)
    elif name == "copy":
        _draw_copy(draw, size, fill, lw)
    elif name == "x":
        _draw_x(draw, size, fill, lw)
    elif name == "upload":
        _draw_upload(draw, size, fill, lw)
    elif name == "download":
        _draw_download(draw, size, fill, lw)
    elif name == "key":
        _draw_key(draw, size, fill, lw)
    elif name == "lock":
        _draw_lock(draw, size, fill, lw, locked=True)
    elif name == "unlock":
        _draw_lock(draw, size, fill, lw, locked=False)
    elif name == "search":
        _draw_search(draw, size, fill, lw)
    else:
        # Default: filled circle
        m = size // 4
        draw.ellipse([m, m, size - m, size - m], fill=fill)

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def generate_ico(path: str, sizes: tuple = (16, 32, 48, 64, 128, 256)) -> bool:
    """Generate a multi-size ICO file for the application.

    Returns True on success, False if PIL is unavailable.
    """
    if not HAS_PIL:
        return False

    images = []
    for size in sizes:
        png_data = generate_logo(size)
        if png_data:
            images.append(Image.open(io.BytesIO(png_data)))

    if not images:
        return False

    images[0].save(path, format="ICO", sizes=[(s, s) for s in sizes], append_images=images[1:])
    return True


def logo_to_base64(size: int = 64) -> str:
    """Return logo as base64 string for embedding."""
    data = generate_logo(size)
    if data:
        return base64.b64encode(data).decode("ascii")
    return ""




def _hex_to_rgb(hex_color: str) -> Tuple[int, int, int]:
    """Convert hex color string to RGB tuple."""
    hex_color = hex_color.lstrip("#")
    return tuple(int(hex_color[i : i + 2], 16) for i in (0, 2, 4))


def _draw_flash(draw: "ImageDraw.Draw", size: int, fill: tuple):
    s = size
    points = [
        (s * 3 // 8, s // 8),
        (s * 5 // 8, s * 3 // 8),
        (s // 2, s * 3 // 8),
        (s * 5 // 8, s * 7 // 8),
        (s * 3 // 8, s * 5 // 8),
        (s // 2, s * 5 // 8),
    ]
    draw.polygon(points, fill=fill)


def _draw_folder(draw: "ImageDraw.Draw", size: int, fill: tuple):
    m = size // 5
    draw.rectangle([m, m + size // 8, size - m, size - m], outline=fill, width=max(1, size // 12))
    draw.rectangle([m, m, m + size // 3, m + size // 6], fill=fill)


def _draw_play(draw: "ImageDraw.Draw", size: int, fill: tuple):
    m = size // 4
    draw.polygon([(m, m), (m, size - m), (size - m, size // 2)], fill=fill)


def _draw_gear(draw: "ImageDraw.Draw", size: int, fill: tuple):
    c = size // 2
    outer = size // 3
    inner = size // 5
    draw.ellipse([c - outer, c - outer, c + outer, c + outer], outline=fill, width=max(1, size // 10))
    draw.ellipse([c - inner, c - inner, c + inner, c + inner], fill=fill)


def _draw_shield(draw: "ImageDraw.Draw", size: int, fill: tuple):
    m = size // 5
    mid = size // 2
    pts = [(mid, m), (size - m, m + size // 6), (size - m, size // 2),
           (mid, size - m), (m, size // 2), (m, m + size // 6)]
    draw.polygon(pts, outline=fill, width=max(1, size // 10))


def _draw_refresh(draw: "ImageDraw.Draw", size: int, fill: tuple, lw: int):
    c = size // 2
    r = size // 3
    draw.arc([c - r, c - r, c + r, c + r], 30, 330, fill=fill, width=lw)
    # Arrow head
    ax = c + int(r * math.cos(math.radians(330)))
    ay = c - int(r * math.sin(math.radians(330)))
    draw.polygon([(ax, ay), (ax - 3, ay - 5), (ax + 3, ay - 2)], fill=fill)


def _draw_save(draw: "ImageDraw.Draw", size: int, fill: tuple, lw: int):
    """Floppy disk save icon."""
    m = size // 6
    # Outer rectangle
    draw.rectangle([m, m, size - m, size - m], outline=fill, width=lw)
    # Top slot (label area)
    draw.rectangle([m + lw, m + lw, size - m - lw, m + size // 3], fill=fill)
    # Bottom data area
    inner = size // 4
    draw.rectangle([m + inner, size // 2, size - m - inner, size - m - lw],
                   outline=fill, width=lw)


def _draw_log(draw: "ImageDraw.Draw", size: int, fill: tuple, lw: int):
    """Lines-of-text log icon."""
    m = size // 5
    gap = (size - 2 * m) // 4
    for i in range(4):
        y = m + i * gap + gap // 2
        end_x = size - m if i % 2 == 0 else size - m - size // 5
        draw.line([(m, y), (end_x, y)], fill=fill, width=lw)


def _draw_trash(draw: "ImageDraw.Draw", size: int, fill: tuple, lw: int):
    """Trash can icon."""
    m = size // 5
    top = size // 4
    # Can body
    draw.rectangle([m, top, size - m, size - m // 2], outline=fill, width=lw)
    # Lid
    draw.line([(m - lw, top), (size - m + lw, top)], fill=fill, width=lw)
    # Handle
    hx1, hx2 = size // 2 - size // 8, size // 2 + size // 8
    draw.line([(hx1, top), (hx1, m)], fill=fill, width=lw)
    draw.line([(hx2, top), (hx2, m)], fill=fill, width=lw)
    draw.line([(hx1, m), (hx2, m)], fill=fill, width=lw)


def _draw_copy(draw: "ImageDraw.Draw", size: int, fill: tuple, lw: int):
    """Two overlapping rectangles copy icon."""
    off = size // 5
    # Back rectangle
    draw.rectangle([off, off, size - off // 2, size - off // 2],
                   outline=fill, width=lw)
    # Front rectangle (offset)
    draw.rectangle([off // 2, off // 2, size - off, size - off],
                   outline=fill, width=lw)


def _draw_x(draw: "ImageDraw.Draw", size: int, fill: tuple, lw: int):
    """X (close) icon."""
    m = size // 4
    draw.line([(m, m), (size - m, size - m)], fill=fill, width=lw + 1)
    draw.line([(size - m, m), (m, size - m)], fill=fill, width=lw + 1)


def _draw_upload(draw: "ImageDraw.Draw", size: int, fill: tuple, lw: int):
    """Upload arrow (pointing up) icon."""
    cx = size // 2
    m = size // 5
    tip = m
    base = size - m
    # Arrow shaft
    draw.line([(cx, tip + size // 5), (cx, base)], fill=fill, width=lw)
    # Arrow head
    draw.polygon([(cx, tip), (cx - size // 5, tip + size // 5),
                  (cx + size // 5, tip + size // 5)], fill=fill)
    # Base line
    draw.line([(m, base), (size - m, base)], fill=fill, width=lw)


def _draw_download(draw: "ImageDraw.Draw", size: int, fill: tuple, lw: int):
    """Download arrow (pointing down) icon."""
    cx = size // 2
    m = size // 5
    tip = size - m
    top = m
    # Arrow shaft
    draw.line([(cx, top), (cx, tip - size // 5)], fill=fill, width=lw)
    # Arrow head
    draw.polygon([(cx, tip), (cx - size // 5, tip - size // 5),
                  (cx + size // 5, tip - size // 5)], fill=fill)
    # Base line
    draw.line([(m, tip), (size - m, tip)], fill=fill, width=lw)


def _draw_key(draw: "ImageDraw.Draw", size: int, fill: tuple, lw: int):
    """Key icon."""
    # Key ring (circle on left)
    kr = size // 4
    kx, ky = size // 3, size // 2
    draw.ellipse([kx - kr, ky - kr, kx + kr, ky + kr], outline=fill, width=lw)
    # Key shaft
    draw.line([(kx + kr, ky), (size - size // 5, ky)], fill=fill, width=lw)
    # Teeth
    tx = kx + kr + size // 5
    draw.line([(tx, ky), (tx, ky + size // 6)], fill=fill, width=lw)
    tx2 = tx + size // 8
    draw.line([(tx2, ky), (tx2, ky + size // 8)], fill=fill, width=lw)


def _draw_lock(draw: "ImageDraw.Draw", size: int, fill: tuple, lw: int,
               locked: bool = True):
    """Padlock icon (locked or unlocked)."""
    m = size // 5
    body_top = size // 2
    # Lock body
    draw.rectangle([m, body_top, size - m, size - m], outline=fill, width=lw)
    # Shackle (arc)
    arc_left = m + size // 8
    arc_right = size - m - size // 8
    arc_top = m
    arc_bottom = body_top + lw
    if locked:
        draw.arc([arc_left, arc_top, arc_right, arc_bottom],
                 180, 0, fill=fill, width=lw)
    else:
        # Open: arc on left side only, shifted up
        draw.arc([arc_left, arc_top - size // 8, arc_right, arc_bottom - size // 8],
                 180, 90, fill=fill, width=lw)


def _draw_search(draw: "ImageDraw.Draw", size: int, fill: tuple, lw: int):
    """Magnifying glass search icon."""
    cr = size // 3
    cx, cy = size // 2 - size // 10, size // 2 - size // 10
    # Circle
    draw.ellipse([cx - cr, cy - cr, cx + cr, cy + cr], outline=fill, width=lw)
    # Handle
    handle_start_x = cx + int(cr * math.cos(math.radians(45)))
    handle_start_y = cy + int(cr * math.sin(math.radians(45)))
    handle_end_x = handle_start_x + size // 4
    handle_end_y = handle_start_y + size // 4
    draw.line([(handle_start_x, handle_start_y), (handle_end_x, handle_end_y)],
              fill=fill, width=lw + 1)
