"""Theme switching — now handled entirely by ThemeEngine.

This module is kept for backward compatibility. The ThemeEngine in
styles.py handles all widget theme updates via its reactive
registration system. Only a thin ``toggle_theme`` helper is provided.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hwflash.shared.styles import ThemeEngine


def toggle_theme(engine: "ThemeEngine") -> None:
    """Toggle between dark and light themes.

    This is a convenience wrapper. Callers can also use
    ``engine.toggle()`` directly.
    """
    engine.toggle()
