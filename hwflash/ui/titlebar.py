"""Custom window titlebar with logo, title, and window controls."""

import tkinter as tk
import io

from hwflash.shared.styles import FONT_FAMILY
from hwflash.shared.icons import generate_logo

try:
    from PIL import Image, ImageTk
    HAS_PIL = True
except ImportError:
    HAS_PIL = False


class CustomTitlebar(tk.Frame):
    """Frameless custom titlebar with drag, minimize, maximize, close."""

    def __init__(self, parent, root, title="HuaweiFlash", theme=None, **kwargs):
        colors = theme or {}
        bg = colors.get("titlebar", "#0F172A")
        fg = colors.get("fg", "#F8FAFC")
        fg_muted = colors.get("fg_muted", "#64748B")

        super().__init__(parent, bg=bg, height=36, **kwargs)
        self.pack_propagate(False)
        self._root = root
        self._drag_x = 0
        self._drag_y = 0
        self._maximized = False
        self._prev_geo = None

        left = tk.Frame(self, bg=bg)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(8, 0))

        self._logo_ref = None
        if HAS_PIL:
            try:
                data = generate_logo(22)
                if data:
                    img = Image.open(io.BytesIO(data))
                    self._logo_ref = ImageTk.PhotoImage(img)
                    logo = tk.Label(left, image=self._logo_ref, bg=bg)
                    logo.pack(side=tk.LEFT, padx=(0, 6))
                    logo.bind("<Button-1>", self._start_drag)
                    logo.bind("<B1-Motion>", self._on_drag)
                    logo.bind("<Double-Button-1>", self._toggle_max)
            except Exception:
                pass

        self._title = tk.Label(
            left, text=title,
            font=(FONT_FAMILY, 10, "bold"),
            bg=bg, fg=fg,
        )
        self._title.pack(side=tk.LEFT, padx=(0, 4))
        self._title.bind("<Button-1>", self._start_drag)
        self._title.bind("<B1-Motion>", self._on_drag)
        self._title.bind("<Double-Button-1>", self._toggle_max)

        btns = tk.Frame(self, bg=bg)
        btns.pack(side=tk.RIGHT, fill=tk.Y)

        btn_cfg = {"font": (FONT_FAMILY, 12), "bd": 0, "width": 4, "cursor": "hand2"}

        self._close_btn = tk.Button(
            btns, text="✕", bg=bg, fg=fg_muted,
            activebackground="#EF4444", activeforeground="#FFFFFF",
            command=self._on_close, **btn_cfg,
        )
        self._close_btn.pack(side=tk.RIGHT, fill=tk.Y)

        self._max_btn = tk.Button(
            btns, text="□", bg=bg, fg=fg_muted,
            activebackground=colors.get("bg_hover", "#334155"),
            activeforeground=fg,
            command=self._toggle_max, **btn_cfg,
        )
        self._max_btn.pack(side=tk.RIGHT, fill=tk.Y)

        self._min_btn = tk.Button(
            btns, text="─", bg=bg, fg=fg_muted,
            activebackground=colors.get("bg_hover", "#334155"),
            activeforeground=fg,
            command=self._on_minimize, **btn_cfg,
        )
        self._min_btn.pack(side=tk.RIGHT, fill=tk.Y)

        for btn in (self._close_btn, self._max_btn, self._min_btn):
            btn.bind("<Enter>", lambda e, b=btn: b.configure(
                bg=b.cget("activebackground")))
            btn.bind("<Leave>", lambda e, b=btn: b.configure(bg=bg))

        self.bind("<Button-1>", self._start_drag)
        self.bind("<B1-Motion>", self._on_drag)
        self.bind("<Double-Button-1>", self._toggle_max)

    def _start_drag(self, event):
        self._drag_x = event.x_root - self._root.winfo_x()
        self._drag_y = event.y_root - self._root.winfo_y()

    def _on_drag(self, event):
        if self._maximized:
            return
        x = event.x_root - self._drag_x
        y = event.y_root - self._drag_y
        self._root.geometry(f"+{x}+{y}")

    def _toggle_max(self, event=None):
        if self._maximized:
            self._root.geometry(self._prev_geo)
            self._maximized = False
            self._max_btn.configure(text="□")
        else:
            self._prev_geo = self._root.geometry()
            sw = self._root.winfo_screenwidth()
            sh = self._root.winfo_screenheight()
            self._root.geometry(f"{sw}x{sh}+0+0")
            self._maximized = True
            self._max_btn.configure(text="❐")

    def _on_minimize(self):
        self._root.iconify()

    def _on_close(self):
        self._root.event_generate("<<AppClose>>")

    def update_theme(self, theme):
        bg = theme.get("titlebar", "#0F172A")
        fg = theme.get("fg", "#F8FAFC")
        fg_muted = theme.get("fg_muted", "#64748B")
        self.configure(bg=bg)
        self._title.configure(bg=bg, fg=fg)
        for btn in (self._close_btn, self._max_btn, self._min_btn):
            btn.configure(bg=bg, fg=fg_muted)
