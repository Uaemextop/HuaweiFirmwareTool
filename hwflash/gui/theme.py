"""
Theme management for OBSC Firmware Tool.

Provides the ``ThemeMixin`` class that handles dark/light toggling,
ttk style configuration, and animation helpers (fade-in on focus,
hover glow on buttons, smooth status-text transitions).
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Optional

try:
    import ttkbootstrap as ttkb  # type: ignore[import]
    HAS_TTKB = True
except ImportError:
    HAS_TTKB = False

from hwflash.gui.colors import THEMES, TTKB_DARK, TTKB_LIGHT


class ThemeMixin:
    """Mixin providing theme management and visual enhancement methods."""

    # ── Theme application ────────────────────────────────────────────────────

    def _apply_theme(self):
        """Apply the current theme to all ttk / tk widgets."""
        colors = THEMES[self.current_theme]

        if HAS_TTKB:
            theme = TTKB_DARK if self.current_theme == "dark" else TTKB_LIGHT
            try:
                ttkb.Style().theme_use(theme)
            except Exception:
                pass
            # ttkbootstrap handles most styling; we only override a few extras.
            self._configure_ttkb_extras(colors)
            return

        # ── Plain ttk styling ────────────────────────────────────────────────
        try:
            self.style.theme_use("clam")
        except tk.TclError:
            pass

        self.style.configure(
            ".",
            background=colors["bg"],
            foreground=colors["fg"],
            bordercolor=colors["border"],
            focuscolor=colors["accent"],
            font=("Segoe UI", 10),
        )
        self.style.configure("TFrame", background=colors["bg"])
        self.style.configure("TLabel",
                             background=colors["bg"],
                             foreground=colors["fg"])
        self.style.configure("TLabelframe",
                             background=colors["bg"],
                             foreground=colors["fg"])
        self.style.configure(
            "TLabelframe.Label",
            background=colors["bg"],
            foreground=colors["accent"],
            font=("Segoe UI", 10, "bold"),
        )
        self._configure_button_style(colors)
        self._configure_entry_style(colors)
        self._configure_combobox_style(colors)
        self._configure_notebook_style(colors)
        self._configure_treeview_style(colors)
        self._configure_progress_style(colors)
        self._configure_scrollbar_style(colors)

    # ── ttkbootstrap extras ──────────────────────────────────────────────────

    def _configure_ttkb_extras(self, colors: dict):
        """Additional styling applied on top of a ttkbootstrap theme."""
        try:
            s = ttkb.Style()
            s.configure(
                "TLabelframe.Label",
                font=("Segoe UI", 10, "bold"),
            )
            s.configure(
                "Custom.Horizontal.TProgressbar",
                troughcolor=colors["progress_bg"],
                background=colors["progress_fg"],
                thickness=12,
                borderwidth=0,
            )
        except Exception:
            pass

    # ── Individual widget styles ─────────────────────────────────────────────

    def _configure_button_style(self, colors: dict):
        self.style.configure(
            "TButton",
            background=colors["surface_alt"],
            foreground=colors["fg"],
            bordercolor=colors["border"],
            relief="flat",
            padding=(10, 5),
        )
        self.style.map(
            "TButton",
            background=[
                ("active", colors["accent"]),
                ("pressed", colors["accent_hover"]),
            ],
            foreground=[
                ("active", "#FFFFFF"),
                ("pressed", "#FFFFFF"),
            ],
            relief=[("pressed", "flat")],
        )

    def _configure_entry_style(self, colors: dict):
        self.style.configure(
            "TEntry",
            fieldbackground=colors["surface"],
            foreground=colors["fg"],
            bordercolor=colors["border"],
            insertcolor=colors["fg"],
            padding=(4, 2),
        )
        self.style.map(
            "TEntry",
            fieldbackground=[("focus", colors["surface_alt"])],
            bordercolor=[("focus", colors["accent"])],
        )

    def _configure_combobox_style(self, colors: dict):
        self.style.configure(
            "TCombobox",
            fieldbackground=colors["surface"],
            foreground=colors["fg"],
            background=colors["surface_alt"],
            bordercolor=colors["border"],
            arrowcolor=colors["accent"],
            selectbackground=colors["accent"],
            selectforeground="#FFFFFF",
        )

    def _configure_notebook_style(self, colors: dict):
        self.style.configure(
            "TNotebook",
            background=colors["bg"],
            bordercolor=colors["border"],
            tabmargins=(2, 4, 0, 0),
        )
        self.style.configure(
            "TNotebook.Tab",
            background=colors["surface"],
            foreground=colors["fg"],
            bordercolor=colors["border"],
            padding=(12, 6),
            font=("Segoe UI", 9),
        )
        self.style.map(
            "TNotebook.Tab",
            background=[
                ("selected", colors["accent"]),
                ("active", colors["surface_alt"]),
            ],
            foreground=[
                ("selected", "#FFFFFF"),
                ("active", colors["accent"]),
            ],
        )

    def _configure_treeview_style(self, colors: dict):
        self.style.configure(
            "Treeview",
            background=colors["surface"],
            foreground=colors["fg"],
            fieldbackground=colors["surface"],
            bordercolor=colors["border"],
            rowheight=24,
        )
        self.style.configure(
            "Treeview.Heading",
            background=colors["surface_alt"],
            foreground=colors["accent"],
            bordercolor=colors["border"],
            font=("Segoe UI", 9, "bold"),
        )
        self.style.map(
            "Treeview",
            background=[("selected", colors["accent"])],
            foreground=[("selected", "#FFFFFF")],
        )

    def _configure_progress_style(self, colors: dict):
        self.style.configure(
            "Horizontal.TProgressbar",
            troughcolor=colors["progress_bg"],
            background=colors["progress_fg"],
            thickness=12,
            borderwidth=0,
        )

    def _configure_scrollbar_style(self, colors: dict):
        self.style.configure(
            "TScrollbar",
            background=colors["surface_alt"],
            troughcolor=colors["surface"],
            bordercolor=colors["border"],
            arrowcolor=colors["accent"],
        )
        self.style.map(
            "TScrollbar",
            background=[("active", colors["accent"])],
        )

    # ── Theme toggle ─────────────────────────────────────────────────────────

    def _toggle_theme(self):
        """Switch between dark and light themes with a smooth update."""
        self.current_theme = "light" if self.current_theme == "dark" else "dark"
        self._apply_theme()
        # Update header
        if hasattr(self, "_header"):
            self._header._draw()
        # Update theme button label
        btn_text = "🌙 Dark" if self.current_theme == "light" else "☀️ Light"
        self.theme_btn.configure(text=btn_text)
        # Update root / content backgrounds
        colors = THEMES[self.current_theme]
        try:
            self.root.configure(bg=colors["bg"])
        except Exception:
            pass
        self._log(f"Theme switched to {self.current_theme}")

    # ── Status text animation ────────────────────────────────────────────────

    def _animate_status(self, widget, text: str, steps: int = 8, delay: int = 30):
        """Fade-in a status text change by cycling through brightness.

        Uses the log text widget's foreground colour or falls back to a
        direct ``textvariable`` update.

        Args:
            widget: The ``tk.Label`` or ``ttk.Label`` to animate.
            text: New text to show.
            steps: Number of animation frames.
            delay: Milliseconds between frames.
        """
        colors = THEMES[self.current_theme]
        target_fg = colors["fg"]

        def _set_alpha(step: int):
            if step >= steps:
                try:
                    widget.configure(text=text, foreground=target_fg)
                except tk.TclError:
                    pass
                return
            # Interpolate opacity via grey shading
            t = step / steps
            r = int(t * 255)
            col = f"#{r:02x}{r:02x}{r:02x}"
            try:
                widget.configure(foreground=col)
            except tk.TclError:
                pass
            widget.after(delay, lambda: _set_alpha(step + 1))

        try:
            widget.configure(text=text, foreground="#000000")
            widget.after(1, lambda: _set_alpha(0))
        except tk.TclError:
            pass
