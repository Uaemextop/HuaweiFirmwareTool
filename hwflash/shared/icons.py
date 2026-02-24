"""
SVG and icon assets for the OBSC Firmware Tool.

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
    """Generate the OBSC Firmware Tool logo as PNG bytes.

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
    else:
        # Default: filled circle
        m = size // 4
        draw.ellipse([m, m, size - m, size - m], fill=fill)

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


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
