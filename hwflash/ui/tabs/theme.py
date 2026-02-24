"""Theme switching mixin for HuaweiFlash."""

import tkinter as tk
from tkinter import ttk

try:
    import ttkbootstrap as ttkb
    HAS_TTKB = True
except ImportError:
    HAS_TTKB = False

from hwflash.shared.styles import TAB_THEMES as THEMES
from hwflash.shared.styles import TTKB_DARK, TTKB_LIGHT, get_theme


class ThemeMixin:
    """Mixin providing theme management methods."""

    def _apply_theme(self):
        colors = THEMES[self.current_theme]

        if HAS_TTKB:
            theme = TTKB_DARK if self.current_theme == 'dark' else TTKB_LIGHT
            try:
                ttkb.Style().theme_use(theme)
            except Exception:
                pass
            return

        try:
            self.style.theme_use('clam')
        except tk.TclError:
            pass

        self.style.configure('.',
                             background=colors['bg'],
                             foreground=colors['fg'],
                             bordercolor=colors['border'],
                             focuscolor=colors['accent'],
                             )

        self.style.configure('TFrame', background=colors['bg'])
        self.style.configure('TLabel', background=colors['bg'], foreground=colors['fg'])
        self.style.configure('TLabelframe', background=colors['bg'],
                             foreground=colors['fg'])
        self.style.configure('TLabelframe.Label', background=colors['bg'],
                             foreground=colors['accent'],
                             font=('Segoe UI', 10, 'bold'))

        self.style.configure('TButton',
                             background=colors['surface_alt'],
                             foreground=colors['fg'],
                             bordercolor=colors['border'],
                             padding=(8, 4))
        self.style.map('TButton',
                        background=[('active', colors['accent']),
                                    ('pressed', colors['accent_hover'])],
                        foreground=[('active', '#FFFFFF'),
                                    ('pressed', '#FFFFFF')])

        self.style.configure('TEntry',
                             fieldbackground=colors['surface'],
                             foreground=colors['fg'],
                             bordercolor=colors['border'])

        self.style.configure('TCombobox',
                             fieldbackground=colors['surface'],
                             foreground=colors['fg'],
                             bordercolor=colors['border'])

        self.style.configure('TCheckbutton',
                             background=colors['bg'],
                             foreground=colors['fg'])

        self.style.configure('TNotebook',
                             background=colors['bg'],
                             bordercolor=colors['border'])
        self.style.configure('TNotebook.Tab',
                             background=colors['surface_alt'],
                             foreground=colors['fg'],
                             padding=(12, 6))
        self.style.map('TNotebook.Tab',
                        background=[('selected', colors['surface'])],
                        foreground=[('selected', colors['accent'])])

        self.style.configure('Horizontal.TProgressbar',
                             background=colors['progress_fg'],
                             troughcolor=colors['progress_bg'],
                             bordercolor=colors['border'])

    def _toggle_theme(self):
        self.current_theme = 'light' if self.current_theme == 'dark' else 'dark'
        next_label = "☀️ Light Mode" if self.current_theme == 'dark' else "🌙 Dark Mode"
        self.theme_btn.configure(text=next_label)
        self._apply_theme()

        if not HAS_TTKB:
            self.root.configure(bg=THEMES[self.current_theme]['bg'])

        # Update all text widgets with theme colors
        colors = THEMES[self.current_theme]
        theme = get_theme(self.current_theme)
        for text_widget in [self.log_text, self.preset_details_text,
                            self.cfg_text, self.dump_output, self.fw_detail_text]:
            text_widget.configure(
                bg=colors['log_bg'],
                fg=colors['log_fg'],
                insertbackground=colors['fg'],
            )

        # Terminal uses its own distinct colors
        self.term_output.configure(
            bg=theme['terminal_bg'],
            fg=theme['terminal_fg'],
            insertbackground=theme['terminal_fg'],
        )
