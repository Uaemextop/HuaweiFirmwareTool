"""Log tab — application log viewer."""

from __future__ import annotations

import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog
from typing import TYPE_CHECKING

from hwflash.ui.components.cards import GradientBar
from hwflash.ui.components.factory import ActionSpec

if TYPE_CHECKING:
    from hwflash.ui.state import AppState, AppController
    from hwflash.shared.styles import ThemeEngine


class LogTab(ttk.Frame):
    """Log viewer tab."""

    def __init__(self, parent, state: AppState, ctrl: AppController,
                 engine: ThemeEngine, **kwargs):
        super().__init__(parent, padding=6, **kwargs)
        self.s = state
        self.ctrl = ctrl
        self.engine = engine
        self.widgets = ctrl.get_engine("widgets")
        self._build()
        # Register a proper callable callback — NOT the widget itself
        ctrl.bind_log_widget(self._append_log_entry)
        # Flush any log entries that were queued before the widget existed
        self._flush_existing_entries()

    def _build(self):
        accent_start, accent_end = self.engine.gradient("accent")
        GradientBar(self, height=2, color_start=accent_start, color_end=accent_end).pack(fill=tk.X, pady=(0, 6))

        controls = ttk.Frame(self)
        controls.pack(fill=tk.X, pady=(0, 4))

        if self.widgets:
            self.widgets.actions(
                controls,
                [
                    ActionSpec("Clear Log", self._clear_log, width=10),
                    ActionSpec("Export Log", self._export_log, width=10, padx=(4, 0)),
                ],
                pady=(0, 0),
            )
        else:
            ttk.Button(controls, text="Clear Log", command=self._clear_log, width=10).pack(side=tk.LEFT)
            ttk.Button(controls, text="Export Log", command=self._export_log, width=10).pack(side=tk.LEFT, padx=4)

        self.log_text = scrolledtext.ScrolledText(
            self, wrap=tk.WORD,
            font=('Consolas', 9),
            state='disabled',
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)

        self.engine.register(self.log_text,
                             {"bg": "log_bg", "fg": "log_fg",
                              "insertbackground": "fg"})
        self.engine.attach_hover(self.log_text, bg="log_bg", hover="surface_alt")

    def _flush_existing_entries(self):
        """Write any log entries that were queued before this widget existed."""
        if self.s.log_entries:
            try:
                self.log_text.configure(state='normal')
                self.log_text.insert(tk.END, '\n'.join(self.s.log_entries))
                self.log_text.see(tk.END)
                self.log_text.configure(state='disabled')
            except (tk.TclError, Exception):
                pass

    def _append_log_entry(self, entry: str):
        """Append a log entry to the ScrolledText widget (thread-safe via root.after)."""
        try:
            self.log_text.configure(state='normal')
            if self.log_text.index('end-1c') != '1.0':
                self.log_text.insert(tk.END, '\n')
            self.log_text.insert(tk.END, entry)
            self.log_text.see(tk.END)
            self.log_text.configure(state='disabled')
        except (tk.TclError, Exception):
            pass

    def _clear_log(self):
        self.s.log_entries.clear()
        self.log_text.configure(state='normal')
        self.log_text.delete('1.0', tk.END)
        self.log_text.configure(state='disabled')

    def _export_log(self):
        path = filedialog.asksaveasfilename(
            title="Export Log",
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt")],
            initialfile=f"hwflash_{datetime.datetime.now().strftime('%Y-%m-%d_%H')}.log",
        )
        if path:
            with open(path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(self.s.log_entries))
            self.ctrl.log(f"Log exported to {path}")

    def browse_log_dir(self):
        """Browse for log directory — called from Settings tab."""
        path = filedialog.askdirectory(title="Select Log Directory")
        if path:
            self.s.log_dir_var.set(path)
