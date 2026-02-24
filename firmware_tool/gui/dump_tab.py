"""Firmware Dump tab mixin for OBSC Firmware Tool."""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox


class DumpTabMixin:
    """Mixin providing the Firmware Dump tab and related methods."""

    def _build_dump_tab(self):
        """Build the firmware dump tab."""
        tab = self.tab_dump

        # ── Info ─────────────────────────────────────────────────
        info_frame = ttk.LabelFrame(tab, text="Firmware Dump (via Telnet)", padding=10)
        info_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(info_frame,
                  text="Firmware dump requires an active Telnet connection to the ONT device.\n"
                       "The device must have Telnet enabled (flash 1-TELNET.bin first).\n"
                       "Connect via the Terminal tab, then use the controls below to dump partitions.",
                  font=('Segoe UI', 9), justify=tk.LEFT,
                  ).pack(fill=tk.X)

        # ── Partition List ───────────────────────────────────────
        part_frame = ttk.LabelFrame(tab, text="MTD Partitions", padding=10)
        part_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        btn_row = ttk.Frame(part_frame)
        btn_row.pack(fill=tk.X, pady=(0, 5))
        ttk.Button(btn_row, text="🔍 Read Partitions",
                   command=self._dump_read_partitions, width=18).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_row, text="💾 Dump Selected",
                   command=self._dump_selected, width=15).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_row, text="💾 Dump All",
                   command=self._dump_all, width=12).pack(side=tk.LEFT)

        self.dump_status_var = tk.StringVar(value="Connect via Terminal tab first")
        ttk.Label(btn_row, textvariable=self.dump_status_var,
                  font=('Segoe UI', 9)).pack(side=tk.LEFT, padx=10)

        # Partition table
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

        # ── Dump Output ──────────────────────────────────────────
        out_frame = ttk.LabelFrame(tab, text="Dump Output", padding=5)
        out_frame.pack(fill=tk.X, pady=(0, 5))

        self.dump_output = scrolledtext.ScrolledText(
            out_frame, wrap=tk.WORD,
            font=('Consolas', 9),
            state='disabled', height=6,
        )
        self.dump_output.pack(fill=tk.BOTH, expand=True)

    # ── Firmware Dump Handlers ───────────────────────────────────

    def _dump_read_partitions(self):
        """Read MTD partition table from connected device."""
        if not self.firmware_dumper:
            messagebox.showwarning("Not Connected",
                                   "Connect to the device via the Terminal tab first.")
            return
        self.dump_status_var.set("Reading partitions...")
        self._dump_log("Sending: cat /proc/mtd\n")
        self.firmware_dumper.get_mtd_partitions(callback=self._dump_partitions_loaded)

    def _dump_partitions_loaded(self, partitions):
        """Callback when partitions have been read."""
        def _update():
            # Clear existing items
            for item in self.dump_tree.get_children():
                self.dump_tree.delete(item)
            # Add partitions
            for p in partitions:
                size_str = f"{p['size']:,} bytes ({p['size'] / 1024 / 1024:.1f} MB)"
                erase_str = f"{p['erasesize']:,} bytes"
                self.dump_tree.insert('', tk.END, values=(
                    f"mtd{p['id']}", p['name'], size_str, erase_str))
            self.dump_status_var.set(f"Found {len(partitions)} partition(s)")
            self._dump_log(f"Found {len(partitions)} MTD partitions\n")
        self.root.after(0, _update)

    def _dump_selected(self):
        """Dump the selected partition."""
        if not self.firmware_dumper:
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
            self.firmware_dumper.dump_partition(mtd_id)
            self._log(f"Firmware dump: mtd{mtd_id} ({name})")

    def _dump_all(self):
        """Dump all partitions."""
        if not self.firmware_dumper:
            messagebox.showwarning("Not Connected",
                                   "Connect to the device via the Terminal tab first.")
            return
        if not self.firmware_dumper.partitions:
            messagebox.showwarning("No Partitions",
                                   "Read partitions first.")
            return
        if not messagebox.askyesno("Dump All",
                                    f"Dump all {len(self.firmware_dumper.partitions)} "
                                    f"partitions to /tmp on the device?"):
            return
        self._dump_log(f"Dumping all {len(self.firmware_dumper.partitions)} partitions...\n")
        self.firmware_dumper.dump_all_partitions()
        self._log("Firmware dump: all partitions")

    def _dump_log(self, text):
        """Append text to dump output."""
        self.dump_output.configure(state='normal')
        self.dump_output.insert(tk.END, text)
        self.dump_output.see(tk.END)
        self.dump_output.configure(state='disabled')
