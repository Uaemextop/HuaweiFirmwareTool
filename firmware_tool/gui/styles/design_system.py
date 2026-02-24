"""
Modern design system for OBSC Firmware Tool.

This module provides a comprehensive design system including:
- Color palette
- Typography
- Spacing system
- Animation utilities
- Shadow effects
- Gradient generators
"""

import tkinter as tk
from tkinter import ttk
from typing import Dict, Tuple


# Color Palette - Modern, professional colors
class Colors:
    """Modern color palette with light and dark theme support."""

    # Primary colors
    PRIMARY = "#0078D4"  # Microsoft Blue
    PRIMARY_LIGHT = "#4A9EE0"
    PRIMARY_DARK = "#005A9E"

    # Secondary colors
    SECONDARY = "#00B7C3"  # Cyan
    SECONDARY_LIGHT = "#4DD4DB"
    SECONDARY_DARK = "#008B95"

    # Accent colors
    ACCENT = "#8961FF"  # Purple
    SUCCESS = "#107C10"  # Green
    WARNING = "#F7630C"  # Orange
    ERROR = "#D83B01"  # Red
    INFO = "#0078D4"  # Blue

    # Neutral colors - Light theme
    BG_LIGHT = "#FFFFFF"
    BG_LIGHT_SECONDARY = "#F3F3F3"
    BG_LIGHT_TERTIARY = "#E1E1E1"
    TEXT_LIGHT = "#201F1E"
    TEXT_LIGHT_SECONDARY = "#605E5C"
    TEXT_LIGHT_TERTIARY = "#8A8886"
    BORDER_LIGHT = "#D1D1D1"

    # Neutral colors - Dark theme
    BG_DARK = "#1E1E1E"
    BG_DARK_SECONDARY = "#2D2D2D"
    BG_DARK_TERTIARY = "#3D3D3D"
    TEXT_DARK = "#FFFFFF"
    TEXT_DARK_SECONDARY = "#D1D1D1"
    TEXT_DARK_TERTIARY = "#A1A1A1"
    BORDER_DARK = "#3D3D3D"

    # Status colors
    ONLINE = "#107C10"
    OFFLINE = "#D13438"
    PENDING = "#F7630C"

    @classmethod
    def get_theme_colors(cls, theme: str = "light") -> Dict[str, str]:
        """Get colors for specified theme."""
        if theme == "dark":
            return {
                'bg': cls.BG_DARK,
                'bg_secondary': cls.BG_DARK_SECONDARY,
                'bg_tertiary': cls.BG_DARK_TERTIARY,
                'text': cls.TEXT_DARK,
                'text_secondary': cls.TEXT_DARK_SECONDARY,
                'text_tertiary': cls.TEXT_DARK_TERTIARY,
                'border': cls.BORDER_DARK,
            }
        return {
            'bg': cls.BG_LIGHT,
            'bg_secondary': cls.BG_LIGHT_SECONDARY,
            'bg_tertiary': cls.BG_LIGHT_TERTIARY,
            'text': cls.TEXT_LIGHT,
            'text_secondary': cls.TEXT_LIGHT_SECONDARY,
            'text_tertiary': cls.TEXT_LIGHT_TERTIARY,
            'border': cls.BORDER_LIGHT,
        }


# Typography
class Fonts:
    """Font definitions for consistent typography."""

    FAMILY = "Segoe UI"
    FAMILY_MONO = "Consolas"

    # Sizes
    SIZE_HUGE = 24
    SIZE_XL = 18
    SIZE_LARGE = 14
    SIZE_NORMAL = 11
    SIZE_SMALL = 9
    SIZE_TINY = 8

    @staticmethod
    def get(size: int = 11, weight: str = 'normal', family: str = None) -> Tuple:
        """Get font tuple."""
        return (family or Fonts.FAMILY, size, weight)


# Spacing System
class Spacing:
    """Consistent spacing values."""

    NONE = 0
    XS = 2
    SM = 5
    MD = 10
    LG = 15
    XL = 20
    XXL = 30


# Border Radius
class Radius:
    """Border radius values."""

    NONE = 0
    SM = 3
    MD = 5
    LG = 10
    XL = 15
    ROUND = 999


# Shadow Effects
class Shadows:
    """CSS-like shadow definitions (for custom canv as elements)."""

    NONE = "0 0 0 0"
    SM = "0 1px 3px rgba(0,0,0,0.12)"
    MD = "0 3px 6px rgba(0,0,0,0.16)"
    LG = "0 10px 20px rgba(0,0,0,0.19)"
    XL = "0 15px 30px rgba(0,0,0,0.25)"


# Animation Durations
class Duration:
    """Animation duration values in milliseconds."""

    INSTANT = 0
    FAST = 150
    NORMAL = 300
    SLOW = 500
    SLOWER = 1000


class Animations:
    """Animation utilities for smooth transitions."""

    @staticmethod
    def fade_in(widget, duration: int = Duration.NORMAL):
        """Fade in animation (placeholder - needs custom implementation)."""
        # Note: Tkinter doesn't natively support opacity
        # This would require platform-specific implementations or PIL
        pass

    @staticmethod
    def slide_in(widget, direction: str = "left", duration: int = Duration.NORMAL):
        """Slide in animation."""
        # Implementation would use place() with animated coordinates
        pass

    @staticmethod
    def ease_in_out(t: float) -> float:
        """
        Ease in-out timing function.

        Args:
            t: Progress value (0.0 to 1.0)

        Returns:
            Eased value
        """
        if t < 0.5:
            return 2 * t * t
        return 1 - pow(-2 * t + 2, 2) / 2


class Gradients:
    """Gradient color generators."""

    @staticmethod
    def hex_to_rgb(hex_color: str) -> Tuple[int, int, int]:
        """Convert hex color to RGB tuple."""
        hex_color = hex_color.lstrip('#')
        return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))

    @staticmethod
    def rgb_to_hex(rgb: Tuple[int, int, int]) -> str:
        """Convert RGB tuple to hex color."""
        return '#{:02x}{:02x}{:02x}'.format(*rgb)

    @staticmethod
    def interpolate_color(color1: str, color2: str, factor: float) -> str:
        """
        Interpolate between two colors.

        Args:
            color1: Start color (hex)
            color2: End color (hex)
            factor: Interpolation factor (0.0 to 1.0)

        Returns:
            Interpolated color (hex)
        """
        rgb1 = Gradients.hex_to_rgb(color1)
        rgb2 = Gradients.hex_to_rgb(color2)

        rgb = tuple(
            int(rgb1[i] + (rgb2[i] - rgb1[i]) * factor)
            for i in range(3)
        )

        return Gradients.rgb_to_hex(rgb)

    @staticmethod
    def generate_gradient(color1: str, color2: str, steps: int) -> list:
        """
        Generate gradient colors.

        Args:
            color1: Start color (hex)
            color2: End color (hex)
            steps: Number of steps

        Returns:
            List of hex colors
        """
        if steps < 2:
            return [color1]

        gradient = []
        for i in range(steps):
            factor = i / (steps - 1)
            color = Gradients.interpolate_color(color1, color2, factor)
            gradient.append(color)

        return gradient


class Icons:
    """Unicode icons for UI elements."""

    # Navigation
    ARROW_LEFT = "◀"
    ARROW_RIGHT = "▶"
    ARROW_UP = "▲"
    ARROW_DOWN = "▼"

    # Actions
    CHECK = "✓"
    CROSS = "✗"
    PLUS = "+"
    MINUS = "-"
    REFRESH = "⟳"
    SETTINGS = "⚙"

    # File operations
    FOLDER = "📁"
    FILE = "📄"
    SAVE = "💾"
    DOWNLOAD = "⬇"
    UPLOAD = "⬆"

    # Status
    SUCCESS = "✓"
    ERROR = "✗"
    WARNING = "⚠"
    INFO = "ℹ"

    # Network
    NETWORK = "🌐"
    WIFI = "📶"
    ETHERNET = "🔌"

    # Device
    DEVICE = "📱"
    COMPUTER = "💻"
    SERVER = "🖥"


def apply_modern_style(root: tk.Tk, theme: str = "light"):
    """
    Apply modern styling to the application.

    Args:
        root: Root Tk window
        theme: Theme name ("light" or "dark")
    """
    style = ttk.Style(root)
    colors = Colors.get_theme_colors(theme)

    # Try to use modern theme
    try:
        if theme == "dark":
            style.theme_use('azure-dark')
        else:
            style.theme_use('azure')
    except:
        # Fallback to default with custom styling
        style.theme_use('clam')

    # Configure common widget styles
    style.configure('.',
        background=colors['bg'],
        foreground=colors['text'],
        bordercolor=colors['border'],
        font=Fonts.get()
    )

    # Button styling with accent color
    style.configure('Accent.TButton',
        background=Colors.PRIMARY,
        foreground='white',
        borderwidth=0,
        font=Fonts.get(weight='bold')
    )

    style.map('Accent.TButton',
        background=[('active', Colors.PRIMARY_LIGHT), ('pressed', Colors.PRIMARY_DARK)]
    )

    # Frame styling
    style.configure('TFrame', background=colors['bg'])
    style.configure('Card.TFrame',
        background=colors['bg'],
        borderwidth=1,
        relief='solid'
    )

    # Label styling
    style.configure('TLabel',
        background=colors['bg'],
        foreground=colors['text']
    )

    style.configure('Title.TLabel',
        font=Fonts.get(Fonts.SIZE_LARGE, 'bold')
    )

    style.configure('Subtitle.TLabel',
        font=Fonts.get(Fonts.SIZE_NORMAL),
        foreground=colors['text_secondary']
    )

    # Entry styling
    style.configure('TEntry',
        fieldbackground=colors['bg_secondary'],
        foreground=colors['text'],
        bordercolor=colors['border']
    )

    return style
