"""
Assets package for OBSC Firmware Tool.

Provides programmatically generated images (logo, icons) so the application
has no binary asset files in the repository.  All images are drawn at runtime
via Pillow when available, or fall back to a minimal tkinter-drawn variant.
"""

from __future__ import annotations

import io
import math
import os
from typing import Optional

# --------------------------------------------------------------------------- #
#  Public API
# --------------------------------------------------------------------------- #

def get_logo_png(size: int = 256) -> Optional[bytes]:
    """Return the application logo as raw PNG bytes.

    Uses Pillow when installed; returns *None* if it is not available so that
    callers can fall back gracefully.

    Args:
        size: Side length of the square PNG in pixels.

    Returns:
        PNG bytes, or ``None`` if Pillow is not installed.
    """
    try:
        return _render_logo(size)
    except Exception:
        return None


def get_logo_photo(size: int = 64, root=None):
    """Return a ``tkinter.PhotoImage`` (or ``ImageTk.PhotoImage``) for use
    directly in Tk labels / canvas items.

    Args:
        size: Side length in pixels.
        root: Tk root window (required for plain ``tk.PhotoImage``).

    Returns:
        A PhotoImage-compatible object, or ``None`` on failure.
    """
    data = get_logo_png(size)
    if data is None:
        return None
    try:
        from PIL import ImageTk, Image
        img = Image.open(io.BytesIO(data))
        return ImageTk.PhotoImage(img)
    except Exception:
        pass
    # Fallback: tkinter built-in (only supports GIF/PGM natively)
    try:
        import tkinter as tk
        import base64
        b64 = base64.b64encode(data).decode()
        return tk.PhotoImage(data=b64, master=root)
    except Exception:
        return None


# --------------------------------------------------------------------------- #
#  Internal renderer
# --------------------------------------------------------------------------- #

def _render_logo(size: int = 256) -> bytes:
    """Draw the OBSC logo using Pillow and return PNG bytes."""
    from PIL import Image, ImageDraw, ImageFilter, ImageFont  # noqa: PLC0415

    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    cx = cy = size // 2

    # ── Radial gradient background circle ──────────────────────────────────
    r_outer = int(size * 0.47)
    for i in range(r_outer, 0, -1):
        t = i / r_outer  # 1.0 at edge → 0.0 at center
        rc = int(10 + 40 * (1 - t))
        gc = int(15 + 50 * (1 - t))
        bc = int(60 + 90 * (1 - t))
        draw.ellipse([cx - i, cy - i, cx + i, cy + i], fill=(rc, gc, bc, 255))

    # ── Outer glowing ring ─────────────────────────────────────────────────
    for w in range(4, 0, -1):
        alpha = int(80 + 50 * (w / 4))
        draw.ellipse(
            [cx - r_outer + w, cy - r_outer + w, cx + r_outer - w, cy + r_outer - w],
            outline=(96, 205, 255, alpha),
            width=1,
        )

    # ── WiFi / signal arcs ─────────────────────────────────────────────────
    arc_fracs = [0.36, 0.27, 0.18]
    for idx, frac in enumerate(arc_fracs):
        wr = int(size * frac)
        alpha = 220 - idx * 50
        lw = 3 - idx
        # Top-right arc (main signal lobe)
        draw.arc(
            [cx - wr, cy - wr, cx + wr, cy + wr],
            start=210, end=330,
            fill=(96, 205, 255, alpha),
            width=lw,
        )

    # ── Router body (rounded rectangle) ───────────────────────────────────
    rw = int(size * 0.14)
    rh = int(size * 0.065)
    draw.rounded_rectangle(
        [cx - rw, cy - rh, cx + rw, cy + rh],
        radius=4,
        fill=(96, 205, 255, 255),
    )

    # Antenna stubs above body
    for dx in (-int(rw * 0.6), 0, int(rw * 0.6)):
        draw.line(
            [cx + dx, cy - rh, cx + dx, cy - rh - int(size * 0.065)],
            fill=(96, 205, 255, 200),
            width=2,
        )

    # ── Glow pass ─────────────────────────────────────────────────────────
    glow = img.filter(ImageFilter.GaussianBlur(2))
    img = Image.alpha_composite(glow, img)

    # ── 'OBSC' text ────────────────────────────────────────────────────────
    draw2 = ImageDraw.Draw(img)
    font_size = max(14, size // 9)
    font = _load_font(font_size)
    txt = "OBSC"
    bb = draw2.textbbox((0, 0), txt, font=font)
    tw, th = bb[2] - bb[0], bb[3] - bb[1]
    ty = cy + int(r_outer * 0.52)
    draw2.text((cx - tw // 2, ty - th // 2), txt, fill=(255, 255, 255, 255), font=font)

    # ── Encode ────────────────────────────────────────────────────────────
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _load_font(size: int):
    """Load a bold system font; fall back to PIL default."""
    from PIL import ImageFont  # noqa: PLC0415

    candidates = [
        # Windows
        "arialbd.ttf",
        "Arial Bold.ttf",
        # Linux
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/freefont/FreeSansBold.ttf",
        "/usr/share/fonts/liberation/LiberationSans-Bold.ttf",
        # macOS
        "/Library/Fonts/Arial Bold.ttf",
        "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
    ]
    for path in candidates:
        try:
            return ImageFont.truetype(path, size)
        except (OSError, IOError):
            continue
    return ImageFont.load_default()
