"""Logo and icon generator for OBSC Firmware Tool."""

from pathlib import Path
from typing import Tuple


def generate_logo_svg(width: int = 256, height: int = 256) -> str:
    """
    Generate SVG logo for OBSC Firmware Tool.

    Modern design with:
    - Circuit board pattern
    - Gradient background
    - Clean typography

    Args:
        width: Logo width
        height: Logo height

    Returns:
        SVG markup as string
    """
    svg = f'''<?xml version="1.0" encoding="UTF-8"?>
<svg width="{width}" height="{height}" viewBox="0 0 256 256" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="bgGradient" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#0078D4;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#00B7C3;stop-opacity:1" />
    </linearGradient>
    <linearGradient id="chipGradient" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#FFFFFF;stop-opacity:0.9" />
      <stop offset="100%" style="stop-color:#E1E1E1;stop-opacity:0.9" />
    </linearGradient>
  </defs>

  <!-- Background circle with gradient -->
  <circle cx="128" cy="128" r="120" fill="url(#bgGradient)" />

  <!-- Circuit board pattern -->
  <g opacity="0.15" stroke="#FFFFFF" stroke-width="2" fill="none">
    <!-- Horizontal lines -->
    <line x1="40" y1="80" x2="216" y2="80" />
    <line x1="40" y1="128" x2="216" y2="128" />
    <line x1="40" y1="176" x2="216" y2="176" />

    <!-- Vertical lines -->
    <line x1="80" y1="40" x2="80" y2="216" />
    <line x1="128" y1="40" x2="128" y2="216" />
    <line x1="176" y1="40" x2="176" y2="216" />

    <!-- Connection nodes -->
    <circle cx="80" cy="80" r="4" fill="#FFFFFF" />
    <circle cx="176" cy="80" r="4" fill="#FFFFFF" />
    <circle cx="80" cy="176" r="4" fill="#FFFFFF" />
    <circle cx="176" cy="176" r="4" fill="#FFFFFF" />
    <circle cx="128" cy="128" r="4" fill="#FFFFFF" />
  </g>

  <!-- Main chip icon -->
  <g>
    <!-- Chip body -->
    <rect x="88" y="88" width="80" height="80" rx="8" fill="url(#chipGradient)"
          stroke="#FFFFFF" stroke-width="3" />

    <!-- Chip pins (left) -->
    <rect x="68" y="100" width="20" height="6" fill="#FFFFFF" />
    <rect x="68" y="125" width="20" height="6" fill="#FFFFFF" />
    <rect x="68" y="150" width="20" height="6" fill="#FFFFFF" />

    <!-- Chip pins (right) -->
    <rect x="168" y="100" width="20" height="6" fill="#FFFFFF" />
    <rect x="168" y="125" width="20" height="6" fill="#FFFFFF" />
    <rect x="168" y="150" width="20" height="6" fill="#FFFFFF" />

    <!-- Chip pins (top) -->
    <rect x="100" y="68" width="6" height="20" fill="#FFFFFF" />
    <rect x="125" y="68" width="6" height="20" fill="#FFFFFF" />
    <rect x="150" y="68" width="6" height="20" fill="#FFFFFF" />

    <!-- Chip pins (bottom) -->
    <rect x="100" y="168" width="6" height="20" fill="#FFFFFF" />
    <rect x="125" y="168" width="6" height="20" fill="#FFFFFF" />
    <rect x="150" y="168" width="6" height="20" fill="#FFFFFF" />

    <!-- Chip center detail -->
    <circle cx="128" cy="128" r="15" fill="#0078D4" opacity="0.5" />
    <circle cx="128" cy="128" r="8" fill="#FFFFFF" />
  </g>

  <!-- Text: OBSC -->
  <text x="128" y="235" font-family="Segoe UI, Arial, sans-serif" font-size="24"
        font-weight="bold" fill="#FFFFFF" text-anchor="middle">OBSC</text>
</svg>'''
    return svg


def generate_icon_svg(icon_type: str, size: int = 64) -> str:
    """
    Generate icon SVG.

    Args:
        icon_type: Icon type (upload, download, settings, refresh, etc.)
        size: Icon size

    Returns:
        SVG markup as string
    """
    icons = {
        'upload': _generate_upload_icon(size),
        'download': _generate_download_icon(size),
        'settings': _generate_settings_icon(size),
        'refresh': _generate_refresh_icon(size),
        'network': _generate_network_icon(size),
        'folder': _generate_folder_icon(size),
    }

    return icons.get(icon_type, '')


def _generate_upload_icon(size: int) -> str:
    """Generate upload icon."""
    return f'''<svg width="{size}" height="{size}" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg">
  <path d="M32 8 L22 18 L28 18 L28 40 L36 40 L36 18 L42 18 Z" fill="#0078D4" />
  <path d="M16 48 L16 54 L48 54 L48 48" stroke="#0078D4" stroke-width="3" fill="none" />
</svg>'''


def _generate_download_icon(size: int) -> str:
    """Generate download icon."""
    return f'''<svg width="{size}" height="{size}" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg">
  <path d="M32 8 L32 40 L26 34 L32 40 L38 34" stroke="#0078D4" stroke-width="3" fill="none" />
  <path d="M22 40 L32 50 L42 40" fill="#0078D4" />
  <path d="M16 48 L16 54 L48 54 L48 48" stroke="#0078D4" stroke-width="3" fill="none" />
</svg>'''


def _generate_settings_icon(size: int) -> str:
    """Generate settings icon."""
    return f'''<svg width="{size}" height="{size}" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg">
  <circle cx="32" cy="32" r="8" fill="#0078D4" />
  <path d="M32 12 L34 20 L42 18 L40 26 L48 28 L46 36 L54 38 L52 46 L44 44 L42 52 L34 50 L32 58 L30 50 L22 52 L24 44 L16 42 L18 34 L10 32 L12 24 L20 26 L22 18 L30 20 Z"
        stroke="#0078D4" stroke-width="2" fill="none" />
</svg>'''


def _generate_refresh_icon(size: int) -> str:
    """Generate refresh icon."""
    return f'''<svg width="{size}" height="{size}" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg">
  <path d="M32 8 A24 24 0 1 1 8 32 L12 32 A20 20 0 1 0 32 12"
        stroke="#0078D4" stroke-width="3" fill="none" />
  <path d="M8 24 L8 32 L16 32 Z" fill="#0078D4" />
</svg>'''


def _generate_network_icon(size: int) -> str:
    """Generate network icon."""
    return f'''<svg width="{size}" height="{size}" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg">
  <circle cx="32" cy="12" r="4" fill="#0078D4" />
  <circle cx="16" cy="52" r="4" fill="#0078D4" />
  <circle cx="32" cy="52" r="4" fill="#0078D4" />
  <circle cx="48" cy="52" r="4" fill="#0078D4" />
  <line x1="32" y1="16" x2="16" y2="48" stroke="#0078D4" stroke-width="2" />
  <line x1="32" y1="16" x2="32" y2="48" stroke="#0078D4" stroke-width="2" />
  <line x1="32" y1="16" x2="48" y2="48" stroke="#0078D4" stroke-width="2" />
</svg>'''


def _generate_folder_icon(size: int) -> str:
    """Generate folder icon."""
    return f'''<svg width="{size}" height="{size}" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg">
  <path d="M8 16 L8 48 C8 50 10 52 12 52 L52 52 C54 52 56 50 56 48 L56 24 C56 22 54 20 52 20 L32 20 L28 16 Z"
        fill="#0078D4" />
</svg>'''


def save_logo(output_path: Path):
    """
    Save logo to file.

    Args:
        output_path: Output file path (supports .svg)
    """
    svg_content = generate_logo_svg()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(svg_content)


def save_icon(icon_type: str, output_path: Path, size: int = 64):
    """
    Save icon to file.

    Args:
        icon_type: Icon type
        output_path: Output file path (supports .svg)
        size: Icon size
    """
    svg_content = generate_icon_svg(icon_type, size)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(svg_content)


def save_all_icons(output_dir: Path, size: int = 64):
    """
    Save all icons to directory.

    Args:
        output_dir: Output directory
        size: Icon size
    """
    icon_types = ['upload', 'download', 'settings', 'refresh', 'network', 'folder']

    for icon_type in icon_types:
        output_path = output_dir / f'{icon_type}.svg'
        save_icon(icon_type, output_path, size)


if __name__ == '__main__':
    # Generate logo and icons when run directly
    base_dir = Path(__file__).parent

    # Save logo
    logo_path = base_dir / 'logos' / 'logo.svg'
    save_logo(logo_path)
    print(f"Logo saved to: {logo_path}")

    # Save all icons
    icons_dir = base_dir / 'icons'
    save_all_icons(icons_dir)
    print(f"Icons saved to: {icons_dir}")
