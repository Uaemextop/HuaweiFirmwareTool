"""Firmware Dump tab — read MTD partitions via terminal."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hwflash.ui.state import AppState, AppController
    from hwflash.shared.styles import ThemeEngine


class DumpTab(ttk.Frame):
    """Firmware dump tab."""

    def __init__(self, parent, state: "AppState", ctrl: "AppController",
                 engine: "ThemeEngine", **kwargs):
        super().__init__(parent, padding=6, **kwargs)
        self.s = state
        self.ctrl = ctrl
        self.engine = engine
        self._build()

    def _build(self):
        # Info
        info_frame = ttk.LabelFrame(self, text="Firmware Dump (via Telnet)", padding=6)
        info_frame.pack(fill=tk.X, pady=(0, 6))

        ttk.Label(info_frame,
                  text="Requires active Telnet to the ONT. Enable Telnet first "
                       "(flash 1-TELNET.bin), connect via Terminal tab, then dump here.",
                  font=('Segoe UI', 9), justify=tk.LEFT, wraplength=700,
                  ).pack(fill=tk.X)

        # Partition list
        part_frame = ttk.LabelFrame(self, text="MTD Partitions", padding=6)
        part_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 6))

        btn_row = ttk.Frame(part_frame)
        btn_row.pack(fill=tk.X, pady=(0, 4))
        ttk.Button(btn_row, text="\U0001f50d Read Partitions",
                   command=self._dump_read_partitions, width=16).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(btn_row, text="\U0001f4be Dump Selected",
                   command=self._dump_selected, width=14).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(btn_row, text="\U0001f4be Dump All",
                   command=self._dump_all, width=10).pack(side=tk.LEFT)

        ttk.Label(btn_row, textvariable=self.s.dump_status_var,
                  font=('Segoe UI', 9)).pack(side=tk.LEFT, padx=8)

        columns = ('id', 'name', 'size', 'erasesize')
        self.dump_tree = ttk.Treeview(
            part_frame, columns=columns, show='headings', height=8)
        self.dump_tree.heading('id', text='MTD #')
        self.dump_tree.heading('name', text='Partition Name')
        self.dump_tree.heading('size', text='Size')
        self.dump_tree.heading('erasesize', text='Erase Size')
        self.dump_tree.column('id', width=60)
        self.dump_tree.column('name', width=200)
        self.dump_tree.column('size', width=120)
        self.dump_tree.column('erasesize', width=120)
        self.dump_tree.pack(fill=tk.BOTH, expand=True)

        # Dump output
        out_frame = ttk.LabelFrame(self, text="Dump Output", padding=4)
        out_frame.pack(fill=tk.X, pady=(0, 4))

        self.dump_output = scrolledtext.ScrolledText(
            out_frame, wrap=tk.WORD,
            font=('Consolas', 9),
            state='disabled', height=5,
        )
        self.dump_output.pack(fill=tk.BOTH, expand=True)

        self.engine.register(self.dump_output,
                             {"bg": "log_bg", "fg": "log_fg",
                              "insertbackground": "fg"})

    # ── Handlers ─────────────────────────────────────────────────

    def _dump_read_partitions(self):
        if not self.s.firmware_dumper:
            messagebox.showwarning("Not Connected",
                                   "Connect to the device via the Terminal tab first.")
            return
        self.s.dump_status_var.set("Reading partitions...")
        self._dump_log("Sending: cat /proc/mtd\n")
        self.s.firmware_dumper.get_mtd_partitions(callback=self._dump_partitions_loaded)

    def _dump_partitions_loaded(self, partitions):
        def _update():
            for item in self.dump_tree.get_children():
                self.dump_tree.delete(item)
            for p in partitions:
                size_str = f"{p['size']:,} bytes ({p['size'] / 1024 / 1024:.1f} MB)"
                erase_str = f"{p['erasesize']:,} bytes"
                self.dump_tree.insert('', tk.END, values=(
                    f"mtd{p['id']}", p['name'], size_str, erase_str))
            self.s.dump_status_var.set(f"Found {len(partitions)} partition(s)")
            self._dump_log(f"Found {len(partitions)} MTD partitions\n")
        self.s.root.after(0, _update)

    def _dump_selected(self):
        if not self.s.firmware_dumper:
            messagebox.showwarning("Not Connected",
                                   "Connect to the device via the Terminal tab first.")
            return
        selected = self.dump_tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Select a partition to dump.")
            return
        for item in selected:
            values = self.dump_tree.item(item, 'values')
            mtd_id = int(values[0].replace('mtd', ''))
            name = values[1]
            self._dump_log(f"Dumping mtd{mtd_id} ({name}) to /tmp/mtd{mtd_id}.bin...\n")
            self.s.firmware_dumper.dump_partition(mtd_id)
            self.ctrl.log(f"Firmware dump: mtd{mtd_id} ({name})")

    def _dump_all(self):
        if not self.s.firmware_dumper:
            messagebox.showwarning("Not Connected",
                                   "Connect to the device via the Terminal tab first.")
            return
        if not self.s.firmware_dumper.partitions:
            messagebox.showwarning("No Partitions", "Read partitions first.")
            return
        if not messagebox.askyesno("Dump All",
                                    f"Dump all {len(self.s.firmware_dumper.partitions)} "
                                    f"partitions to /tmp on the device?"):
            return
        self._dump_log(f"Dumping all {len(self.s.firmware_dumper.partitions)} partitions...\n")
        self.s.firmware_dumper.dump_all_partitions()
        self.ctrl.log("Firmware dump: all partitions")

    def _dump_log(self, text):
        self.dump_output.configure(state='normal')
        self.dump_output.insert(tk.END, text)
        self.dump_output.see(tk.END)
        self.dump_output.configure(state='disabled')
