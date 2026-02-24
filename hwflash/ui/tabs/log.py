"""Log tab mixin for HuaweiFlash."""

import os
import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog


class LogTabMixin:
    """Mixin providing the Log tab and related methods."""

    def _build_log_tab(self):
        """Build the log viewer tab."""
        tab = self.tab_log

        # Log controls
        controls = ttk.Frame(tab)
        controls.pack(fill=tk.X, pady=(0, 5))

        ttk.Button(controls, text="Clear Log", command=self._clear_log, width=12).pack(side=tk.LEFT)
        ttk.Button(controls, text="Export Log", command=self._export_log, width=12).pack(side=tk.LEFT, padx=5)

        # Log text
        self.log_text = scrolledtext.ScrolledText(
            tab, wrap=tk.WORD,
            font=('Consolas', 9),
            state='disabled',
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)

    # ── Logging ──────────────────────────────────────────────────

    def _log(self, message):
        """Add a timestamped message to the log."""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] {message}"
        self.log_entries.append(entry)

        self.log_text.configure(state='normal')
        self.log_text.insert(tk.END, entry + "\n")
        self.log_text.see(tk.END)
        self.log_text.configure(state='disabled')

    def _clear_log(self):
        """Clear the log panel."""
        self.log_entries.clear()
        self.log_text.configure(state='normal')
        self.log_text.delete('1.0', tk.END)
        self.log_text.configure(state='disabled')

    def _export_log(self):
        """Export log to file."""
        # Log filename matches original Huawei tool format (OSBC_LOG_*)
        path = filedialog.asksaveasfilename(
            title="Export Log",
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt")],
            initialfile=f"hwflash_{datetime.datetime.now().strftime('%Y-%m-%d_%H')}.log",
        )
        if path:
            with open(path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(self.log_entries))
            self._log(f"Log exported to {path}")

    def _auto_save_log(self):
        """Auto-save log after upgrade."""
        try:
            log_dir = self.log_dir_var.get()
            os.makedirs(log_dir, exist_ok=True)
            filename = f"hwflash_{datetime.datetime.now().strftime('%Y-%m-%d_%H')}.log"
            path = os.path.join(log_dir, filename)
            with open(path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(self.log_entries))
            self._log(f"Log auto-saved to {path}")
        except OSError as e:
            self._log(f"Failed to auto-save log: {e}")

    def _browse_log_dir(self):
        """Browse for log directory."""
        path = filedialog.askdirectory(title="Select Log Directory")
        if path:
            self.log_dir_var.set(path)
