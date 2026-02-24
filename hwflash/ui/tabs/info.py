"""Firmware Editor tab — browse, inspect, export, import, replace, repack & sign."""

from __future__ import annotations

import os
import struct
import zlib
import hashlib
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import TYPE_CHECKING

from hwflash.shared.styles import FONT_FAMILY

if TYPE_CHECKING:
    from hwflash.ui.state import AppState, AppController
    from hwflash.shared.styles import ThemeEngine


# ── Helpers ──────────────────────────────────────────────────────

def _human_size(size: int) -> str:
    """Format a byte count into a human-readable string."""
    n = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024:
            return f"{n:,.1f} {unit}" if unit != "B" else f"{int(n):,} {unit}"
        n /= 1024
    return f"{n:,.1f} TB"


def _short_hash(data: bytes, algo: str = "sha256") -> str:
    h = hashlib.new(algo, data)
    return h.hexdigest()


# ── Tab ──────────────────────────────────────────────────────────

class InfoTab(ttk.Frame):
    """Firmware editor: explore, export, import, replace, repack, and sign."""

    def __init__(self, parent, state: "AppState", ctrl: "AppController",
                 engine: "ThemeEngine", **kwargs):
        super().__init__(parent, padding=0, **kwargs)
        self.s = state
        self.ctrl = ctrl
        self.engine = engine
        self._selected_item_idx = None
        self._build()

    # ─────────────────────────────────────────────────────────────
    # Build
    # ─────────────────────────────────────────────────────────────

    def _build(self):
        # ── Top toolbar ──────────────────────────────────────────
        toolbar = ttk.Frame(self, padding=(8, 4))
        toolbar.pack(fill=tk.X)

        # Row 1: File I/O and item editing
        row1 = ttk.Frame(toolbar)
        row1.pack(fill=tk.X, pady=(0, 3))

        ttk.Button(row1, text="Load Firmware", bootstyle="primary",
                   command=self._load_firmware, width=14).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(row1, text="Refresh",
                   command=self._refresh_fw_info, width=8).pack(side=tk.LEFT, padx=(0, 2))

        ttk.Separator(row1, orient=tk.VERTICAL).pack(
            side=tk.LEFT, fill=tk.Y, padx=6, pady=2)

        ttk.Button(row1, text="Export",
                   command=self._export_selected, width=8).pack(side=tk.LEFT, padx=(0, 2))
        ttk.Button(row1, text="Replace",
                   command=self._import_replace, width=8).pack(side=tk.LEFT, padx=(0, 2))
        ttk.Button(row1, text="Remove", bootstyle="danger-outline",
                   command=self._remove_item, width=8).pack(side=tk.LEFT, padx=(0, 2))
        ttk.Button(row1, text="Add",
                   command=self._add_item, width=6).pack(side=tk.LEFT, padx=(0, 2))

        ttk.Separator(row1, orient=tk.VERTICAL).pack(
            side=tk.LEFT, fill=tk.Y, padx=6, pady=2)

        ttk.Button(row1, text="Unpack All",
                   command=self._unpack_all, width=10).pack(side=tk.LEFT, padx=(0, 2))
        ttk.Button(row1, text="Pack Dir",
                   command=self._pack_from_dir, width=8).pack(side=tk.LEFT, padx=(0, 2))

        # Row 2: Verification, signing, repack
        row2 = ttk.Frame(toolbar)
        row2.pack(fill=tk.X)

        ttk.Button(row2, text="Verify CRC",
                   command=self._verify_crc, width=10).pack(side=tk.LEFT, padx=(0, 2))
        ttk.Button(row2, text="Verify Sig",
                   command=self._verify_signature, width=10).pack(side=tk.LEFT, padx=(0, 2))
        ttk.Button(row2, text="Sign",
                   command=self._sign_firmware, width=6).pack(side=tk.LEFT, padx=(0, 2))

        ttk.Separator(row2, orient=tk.VERTICAL).pack(
            side=tk.LEFT, fill=tk.Y, padx=6, pady=2)

        ttk.Button(row2, text="Repack & Save", bootstyle="success",
                   command=self._repack_save, width=14).pack(side=tk.LEFT, padx=(0, 4))

        self._status_lbl = ttk.Label(row2, textvariable=self.s.fw_info_status_var,
                                     font=(FONT_FAMILY, 8, "italic"))
        self._status_lbl.pack(side=tk.RIGHT, padx=6)

        # Separator below toolbar
        ttk.Separator(self, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=(0, 2))

        # ── Main paned area ──────────────────────────────────────
        paned = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=6, pady=(2, 6))

        # ── Left: File explorer tree ─────────────────────────────
        left = ttk.Frame(paned)
        paned.add(left, weight=2)

        tree_toolbar = ttk.Frame(left)
        tree_toolbar.pack(fill=tk.X, pady=(0, 2))
        ttk.Label(tree_toolbar, text="Explorer",
                  font=(FONT_FAMILY, 10, "bold")).pack(side=tk.LEFT)

        self._search_var = tk.StringVar()
        search_entry = ttk.Entry(tree_toolbar, textvariable=self._search_var, width=18)
        search_entry.pack(side=tk.RIGHT, padx=(4, 0))
        search_entry.bind('<Return>', lambda e: self._filter_tree())
        ttk.Label(tree_toolbar, text="Search:").pack(side=tk.RIGHT)

        # Sub-frame for treeview + scrollbars (avoids pack/grid conflict)
        tree_frame = ttk.Frame(left)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        # Treeview with columns
        cols = ("type", "size", "crc32", "version")
        self.fw_tree = ttk.Treeview(tree_frame, columns=cols, show="tree headings",
                                    selectmode="browse")
        self.fw_tree.heading("#0", text="Path", anchor="w")
        self.fw_tree.heading("type", text="Section", anchor="w")
        self.fw_tree.heading("size", text="Size", anchor="e")
        self.fw_tree.heading("crc32", text="CRC32", anchor="w")
        self.fw_tree.heading("version", text="Version", anchor="w")

        self.fw_tree.column("#0", width=260, minwidth=140)
        self.fw_tree.column("type", width=80, minwidth=50)
        self.fw_tree.column("size", width=90, minwidth=60, anchor="e")
        self.fw_tree.column("crc32", width=100, minwidth=70)
        self.fw_tree.column("version", width=80, minwidth=50)

        vsb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.fw_tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.fw_tree.xview)
        self.fw_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.fw_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        self.fw_tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self.fw_tree.bind("<Double-1>", self._on_tree_double)

        # Context menu
        self._ctx_menu = tk.Menu(self.fw_tree, tearoff=0)
        self._ctx_menu.add_command(label="Export item ...", command=self._export_selected)
        self._ctx_menu.add_command(label="Replace data ...", command=self._import_replace)
        self._ctx_menu.add_command(label="Remove item", command=self._remove_item)
        self._ctx_menu.add_separator()
        self._ctx_menu.add_command(label="Copy SHA256", command=self._copy_sha256)
        self._ctx_menu.add_command(label="Copy CRC32", command=self._copy_crc32)
        self.fw_tree.bind("<Button-3>", self._show_ctx_menu)

        # ── Right: Detail panel ──────────────────────────────────
        right = ttk.Frame(paned)
        paned.add(right, weight=3)

        # Detail notebook for Properties / Hex / Text tabs
        self._detail_nb = ttk.Notebook(right)
        self._detail_nb.pack(fill=tk.BOTH, expand=True)

        # -- Properties tab
        prop_frame = ttk.Frame(self._detail_nb, padding=6)
        self._detail_nb.add(prop_frame, text="Properties")

        self._prop_tree = ttk.Treeview(prop_frame, columns=("value",),
                                       show="tree headings", selectmode="browse")
        self._prop_tree.heading("#0", text="Property", anchor="w")
        self._prop_tree.heading("value", text="Value", anchor="w")
        self._prop_tree.column("#0", width=180, minwidth=120)
        self._prop_tree.column("value", width=400, minwidth=200)
        prop_scroll = ttk.Scrollbar(prop_frame, orient=tk.VERTICAL,
                                    command=self._prop_tree.yview)
        self._prop_tree.configure(yscrollcommand=prop_scroll.set)
        self._prop_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        prop_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # -- Hex preview tab
        hex_frame = ttk.Frame(self._detail_nb, padding=6)
        self._detail_nb.add(hex_frame, text="Hex View")

        self._hex_text = tk.Text(hex_frame, wrap=tk.NONE, font=("Consolas", 9),
                                 state="disabled", width=80, height=24)
        hex_yscroll = ttk.Scrollbar(hex_frame, orient=tk.VERTICAL,
                                    command=self._hex_text.yview)
        hex_xscroll = ttk.Scrollbar(hex_frame, orient=tk.HORIZONTAL,
                                    command=self._hex_text.xview)
        self._hex_text.configure(yscrollcommand=hex_yscroll.set,
                                 xscrollcommand=hex_xscroll.set)
        self._hex_text.grid(row=0, column=0, sticky="nsew")
        hex_yscroll.grid(row=0, column=1, sticky="ns")
        hex_xscroll.grid(row=1, column=0, sticky="ew")
        hex_frame.rowconfigure(0, weight=1)
        hex_frame.columnconfigure(0, weight=1)

        # -- Text preview tab
        txt_frame = ttk.Frame(self._detail_nb, padding=6)
        self._detail_nb.add(txt_frame, text="Text View")

        self._txt_text = tk.Text(txt_frame, wrap=tk.WORD, font=("Consolas", 9),
                                 state="disabled")
        txt_scroll = ttk.Scrollbar(txt_frame, orient=tk.VERTICAL,
                                   command=self._txt_text.yview)
        self._txt_text.configure(yscrollcommand=txt_scroll.set)
        self._txt_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        txt_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Register theme-able widgets
        self.engine.register(self._hex_text, updater=self._update_hex_theme)
        self.engine.register(self._txt_text, updater=self._update_txt_theme)

    # ── Theme helpers ────────────────────────────────────────────

    def _update_hex_theme(self, colors):
        self._hex_text.configure(bg=colors["log_bg"], fg=colors["log_fg"],
                                 insertbackground=colors["fg"])

    def _update_txt_theme(self, colors):
        self._txt_text.configure(bg=colors["log_bg"], fg=colors["log_fg"],
                                 insertbackground=colors["fg"])

    # ─────────────────────────────────────────────────────────────
    # Tree / explorer logic
    # ─────────────────────────────────────────────────────────────

    def _refresh_fw_info(self):
        """Rebuild the tree from the currently loaded firmware."""
        fw = self.s.firmware
        if not fw:
            messagebox.showinfo("No Firmware",
                                "Load a firmware file first (use the Load button or Upgrade tab).")
            return

        for child in self.fw_tree.get_children():
            self.fw_tree.delete(child)

        # Header node
        hdr_node = self.fw_tree.insert(
            "", "end", text="Firmware Header",
            values=("HEADER", _human_size(len(fw.raw_data)),
                    f"0x{fw.raw_crc32:08X}", ""),
            tags=("header",))

        # Product list node
        prod_text = fw.product_list[:60] + ("..." if len(fw.product_list) > 60 else "")
        self.fw_tree.insert(
            "", "end", text="Product List",
            values=("PRODUCTS", f"{fw.prod_list_size} B", "", prod_text),
            tags=("products",))

        # Items root
        items_node = self.fw_tree.insert(
            "", "end",
            text=f"Items ({fw.item_count})",
            values=("", _human_size(fw.get_total_data_size()), "", ""),
            tags=("items_root",))

        # Group items by section
        sections: dict = {}
        for item in fw.items:
            sec = item.section or "UNKNOWN"
            sections.setdefault(sec, []).append(item)

        for sec_name, sec_items in sections.items():
            sec_size = sum(it.data_size for it in sec_items)
            sec_node = self.fw_tree.insert(
                items_node, "end",
                text=f"{sec_name} ({len(sec_items)})",
                values=(sec_name, _human_size(sec_size), "", ""),
                tags=("section",))

            for item in sec_items:
                colon_pos = item.item_path.find(':')
                display = item.item_path[colon_pos + 1:] if colon_pos >= 0 else item.item_path
                fname = os.path.basename(display) or display
                icon = self._icon_for_path(display)

                self.fw_tree.insert(
                    sec_node, "end",
                    text=f"{icon} {fname}",
                    values=(item.section,
                            _human_size(item.data_size),
                            f"0x{item.crc32:08X}",
                            item.version or "-"),
                    tags=(f"item:{item.index}",))

        # Expand all
        for child in self.fw_tree.get_children():
            self.fw_tree.item(child, open=True)
            for sub in self.fw_tree.get_children(child):
                self.fw_tree.item(sub, open=True)

        self.fw_tree.selection_set(hdr_node)
        self._show_header_props()

        info = fw.get_info()
        self.s.fw_info_status_var.set(
            f"Loaded: {info['file']} | {info['items']} items | "
            f"{info['size']:,} bytes")

    @staticmethod
    def _icon_for_path(path: str) -> str:
        ext = os.path.splitext(path)[1].lower()
        icons = {
            ".xml": "X", ".sh": "S", ".txt": "T", ".cfg": "C",
            ".bin": "B", ".img": "I", ".gz": "Z", ".tar": "A",
        }
        return f"[{icons.get(ext, 'F')}]"

    def _filter_tree(self):
        """Filter tree to show only items matching the search term."""
        term = self._search_var.get().lower().strip()
        if not term:
            self._refresh_fw_info()
            return

        fw = self.s.firmware
        if not fw:
            return

        for child in self.fw_tree.get_children():
            self.fw_tree.delete(child)

        for item in fw.items:
            path_lower = item.item_path.lower()
            sec_lower = item.section.lower()
            if term in path_lower or term in sec_lower:
                colon_pos = item.item_path.find(':')
                display = item.item_path[colon_pos + 1:] if colon_pos >= 0 else item.item_path
                fname = os.path.basename(display) or display
                icon = self._icon_for_path(display)

                self.fw_tree.insert(
                    "", "end",
                    text=f"{icon} {fname}  ({item.item_path})",
                    values=(item.section,
                            _human_size(item.data_size),
                            f"0x{item.crc32:08X}",
                            item.version or "-"),
                    tags=(f"item:{item.index}",))

    def _get_selected_item(self):
        """Return the selected HWNPItem or None."""
        fw = self.s.firmware
        if not fw:
            return None
        sel = self.fw_tree.selection()
        if not sel:
            return None
        tags = self.fw_tree.item(sel[0], "tags")
        for t in tags:
            if isinstance(t, str) and t.startswith("item:"):
                try:
                    idx = int(t.split(":")[1])
                    return next((it for it in fw.items if it.index == idx), None)
                except (ValueError, StopIteration):
                    pass
        return None

    def _on_tree_select(self, event):
        sel = self.fw_tree.selection()
        if not sel:
            return
        tags = self.fw_tree.item(sel[0], "tags")

        for t in tags:
            if not isinstance(t, str):
                continue
            if t == "header":
                self._show_header_props()
                return
            if t == "products":
                self._show_products_props()
                return
            if t.startswith("item:"):
                try:
                    idx = int(t.split(":")[1])
                    self._show_item_props(idx)
                except ValueError:
                    pass
                return
            if t in ("items_root", "section"):
                self._show_summary_props()
                return

    def _on_tree_double(self, event):
        item = self._get_selected_item()
        if item:
            self._export_selected()

    def _show_ctx_menu(self, event):
        sel = self.fw_tree.identify_row(event.y)
        if sel:
            self.fw_tree.selection_set(sel)
        try:
            self._ctx_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self._ctx_menu.grab_release()

    # ─────────────────────────────────────────────────────────────
    # Detail panels
    # ─────────────────────────────────────────────────────────────

    def _clear_props(self):
        for child in self._prop_tree.get_children():
            self._prop_tree.delete(child)
        self._hex_text.configure(state="normal")
        self._hex_text.delete("1.0", tk.END)
        self._hex_text.configure(state="disabled")
        self._txt_text.configure(state="normal")
        self._txt_text.delete("1.0", tk.END)
        self._txt_text.configure(state="disabled")

    def _add_prop(self, parent, name, value):
        return self._prop_tree.insert(parent, "end", text=name,
                                      values=(str(value),))

    def _show_header_props(self):
        fw = self.s.firmware
        if not fw:
            return
        self._clear_props()
        self._selected_item_idx = None

        hdr = self._prop_tree.insert("", "end", text="Firmware Header", values=("",))
        self._add_prop(hdr, "Magic", f"0x{fw.magic:08X}  (HWNP)")
        self._add_prop(hdr, "File Size", f"{len(fw.raw_data):,} bytes")
        self._add_prop(hdr, "Raw Size (header)", f"{fw.raw_size:,}")
        self._add_prop(hdr, "Header Size", f"{fw.header_size:,}")
        self._add_prop(hdr, "Raw CRC32", f"0x{fw.raw_crc32:08X}")
        self._add_prop(hdr, "Header CRC32", f"0x{fw.header_crc32:08X}")
        self._add_prop(hdr, "Item Count", str(fw.item_count))
        self._add_prop(hdr, "Product List Size", str(fw.prod_list_size))
        self._add_prop(hdr, "Item Header Size", str(fw.item_header_size))
        self._add_prop(hdr, "Header Layout", fw.header_layout)
        self._add_prop(hdr, "Header Offset", f"0x{fw.header_offset:X}")

        crc_node = self._prop_tree.insert("", "end", text="CRC32 Status", values=("",))
        hdr_ok, data_ok = fw.validate_crc32()
        self._add_prop(crc_node, "Header CRC32",
                       "PASS" if hdr_ok else "FAIL")
        self._add_prop(crc_node, "Data CRC32",
                       "PASS" if data_ok else "FAIL")

        for child in self._prop_tree.get_children():
            self._prop_tree.item(child, open=True)

        self._show_hex(fw.raw_data[:512])
        self._show_text("")

    def _show_products_props(self):
        fw = self.s.firmware
        if not fw:
            return
        self._clear_props()
        self._selected_item_idx = None

        node = self._prop_tree.insert("", "end", text="Product List", values=("",))
        self._add_prop(node, "Size", f"{fw.prod_list_size} bytes")

        if fw.product_list:
            for i, prod in enumerate(fw.product_list.split('\n')):
                prod = prod.strip()
                if prod:
                    self._add_prop(node, f"Product #{i + 1}", prod)
        else:
            self._add_prop(node, "Content", "(empty)")

        self._prop_tree.item(node, open=True)
        self._show_hex(fw.product_list.encode('ascii', errors='replace'))
        self._show_text(fw.product_list)

    def _show_summary_props(self):
        fw = self.s.firmware
        if not fw:
            return
        self._clear_props()
        self._selected_item_idx = None

        node = self._prop_tree.insert("", "end", text="Items Summary", values=("",))
        self._add_prop(node, "Total Items", str(fw.item_count))
        self._add_prop(node, "Total Data Size", _human_size(fw.get_total_data_size()))

        sections: dict = {}
        for item in fw.items:
            sec = item.section or "UNKNOWN"
            sections[sec] = sections.get(sec, 0) + 1

        sec_node = self._prop_tree.insert("", "end", text="Sections", values=("",))
        for sec, cnt in sections.items():
            self._add_prop(sec_node, sec, f"{cnt} item(s)")

        for child in self._prop_tree.get_children():
            self._prop_tree.item(child, open=True)

        lines = [f"{'#':>3}  {'Section':<14}  {'Size':>12}  {'CRC32':<12}  Path"]
        lines.append("-" * 80)
        for item in fw.items:
            lines.append(
                f"{item.index:3d}  {item.section:<14}  "
                f"{item.data_size:>10,}  0x{item.crc32:08X}  {item.item_path}")
        self._show_text('\n'.join(lines))
        self._show_hex(b'')

    def _show_item_props(self, idx: int):
        fw = self.s.firmware
        if not fw:
            return
        item = next((it for it in fw.items if it.index == idx), None)
        if not item:
            return

        self._clear_props()
        self._selected_item_idx = idx

        node = self._prop_tree.insert("", "end",
                                      text=f"Item #{item.index}", values=("",))
        self._add_prop(node, "Full Path", item.item_path)

        colon_pos = item.item_path.find(':')
        if colon_pos >= 0:
            self._add_prop(node, "Prefix", item.item_path[:colon_pos])
            self._add_prop(node, "FS Path", item.item_path[colon_pos + 1:])

        self._add_prop(node, "Section", item.section)
        self._add_prop(node, "Version", item.version or "-")
        self._add_prop(node, "CRC32", f"0x{item.crc32:08X}")
        self._add_prop(node, "Data Offset", f"0x{item.data_offset:08X}")
        self._add_prop(node, "Data Size",
                       f"{item.data_size:,} bytes ({_human_size(item.data_size)})")
        self._add_prop(node, "Policy", f"0x{item.policy:08X}")

        if item.data:
            sha = _short_hash(item.data, "sha256")
            md5 = _short_hash(item.data, "md5")
            hash_node = self._prop_tree.insert("", "end",
                                               text="Hashes", values=("",))
            self._add_prop(hash_node, "SHA256", sha)
            self._add_prop(hash_node, "MD5", md5)

            calc_crc = zlib.crc32(item.data) & 0xFFFFFFFF
            crc_match = calc_crc == item.crc32
            self._add_prop(hash_node, "CRC32 Verify",
                           f"{'PASS' if crc_match else 'FAIL'} "
                           f"(calc=0x{calc_crc:08X})")

            # Sub-magic detection
            if len(item.data) >= 4:
                sub_magic = struct.unpack_from('<I', item.data, 0)[0]
                magic_node = self._prop_tree.insert("", "end",
                                                    text="Sub-Header", values=("",))
                self._add_prop(magic_node, "Magic Bytes",
                               f"0x{sub_magic:08X}")
                if sub_magic == 0x68776877:
                    self._add_prop(magic_node, "Type",
                                   "Huawei Sub-Image (whwh)")
                    if len(item.data) >= 80:
                        sub_ver = item.data[4:68].split(b'\x00')[0].decode(
                            'ascii', errors='replace')
                        self._add_prop(magic_node, "Sub-Version", sub_ver)
                elif sub_magic == 0x56190527:
                    self._add_prop(magic_node, "Type", "U-Boot Image")
                elif item.data[:2] == b'\x1f\x8b':
                    self._add_prop(magic_node, "Type", "GZIP compressed")
                elif item.data[:4] == b'hsqs':
                    self._add_prop(magic_node, "Type", "SquashFS")
                elif item.data[:7] == b'<?xml v':
                    self._add_prop(magic_node, "Type", "XML document")

                self._prop_tree.item(magic_node, open=True)

        for child in self._prop_tree.get_children():
            self._prop_tree.item(child, open=True)

        if item.data:
            self._show_hex(item.data[:1024])
            preview = fw.get_item_text_preview(item)
            if preview.get('is_text'):
                self._show_text(preview.get('text', ''))
            else:
                self._show_text(
                    f"(Binary data - {preview.get('reason', 'not text')})")
        else:
            self._show_hex(b'')
            self._show_text("(No data)")

    # ── Hex / text helpers ───────────────────────────────────────

    def _show_hex(self, data: bytes):
        self._hex_text.configure(state="normal")
        self._hex_text.delete("1.0", tk.END)
        if not data:
            self._hex_text.configure(state="disabled")
            return

        lines = []
        for off in range(0, len(data), 16):
            chunk = data[off:off + 16]
            hex_part = ' '.join(f"{b:02X}" for b in chunk)
            ascii_part = ''.join(
                chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(f"{off:08X}  {hex_part:<48s}  |{ascii_part}|")

        self._hex_text.insert("1.0", '\n'.join(lines))
        self._hex_text.configure(state="disabled")

    def _show_text(self, text: str):
        self._txt_text.configure(state="normal")
        self._txt_text.delete("1.0", tk.END)
        if text:
            self._txt_text.insert("1.0", text)
        self._txt_text.configure(state="disabled")

    # ─────────────────────────────────────────────────────────────
    # Actions
    # ─────────────────────────────────────────────────────────────

    def _load_firmware(self):
        path = filedialog.askopenfilename(
            title="Open Firmware File",
            filetypes=[("Firmware files", "*.bin"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            from hwflash.core.firmware import HWNPFirmware
            fw = HWNPFirmware()
            fw.load(path)
            self.s.firmware = fw
            self.s.firmware_path = path
            self.s.fw_path_var.set(os.path.basename(path))
            self._refresh_fw_info()
            self.ctrl.log(f"Firmware loaded: {path}")
        except Exception as e:
            messagebox.showerror("Load Error", str(e))
            self.ctrl.log(f"Firmware load failed: {e}")

    def _export_selected(self):
        item = self._get_selected_item()
        if not item:
            messagebox.showinfo("No Selection",
                                "Select an item in the explorer to export.")
            return
        if not item.data:
            messagebox.showwarning("No Data", "This item has no data to export.")
            return

        colon_pos = item.item_path.find(':')
        if colon_pos >= 0:
            default_name = os.path.basename(item.item_path[colon_pos + 1:])
        else:
            default_name = f"item_{item.index}.bin"

        path = filedialog.asksaveasfilename(
            title=f"Export Item #{item.index} ({item.section})",
            initialfile=default_name,
            filetypes=[("All files", "*.*"), ("Binary files", "*.bin")],
        )
        if path:
            with open(path, 'wb') as f:
                f.write(item.data)
            self.ctrl.log(f"Exported item #{item.index} -> {path}")
            self.s.fw_info_status_var.set(
                f"Exported: {os.path.basename(path)} ({item.data_size:,} bytes)")

    def _import_replace(self):
        item = self._get_selected_item()
        if not item:
            messagebox.showinfo("No Selection",
                                "Select an item in the explorer to replace its data.")
            return

        path = filedialog.askopenfilename(
            title=f"Replace Item #{item.index} ({item.section})",
            filetypes=[("All files", "*.*"), ("Binary files", "*.bin")],
        )
        if not path:
            return

        with open(path, 'rb') as f:
            new_data = f.read()

        old_size = item.data_size
        fw = self.s.firmware
        fw.replace_item_data(item.index, new_data)

        self.ctrl.log(
            f"Replaced item #{item.index} ({item.section}): "
            f"{old_size:,} -> {len(new_data):,} bytes")
        self.s.fw_info_status_var.set(
            f"Replaced item #{item.index} with {os.path.basename(path)}")
        self._refresh_fw_info()

    def _remove_item(self):
        item = self._get_selected_item()
        if not item:
            messagebox.showinfo("No Selection", "Select an item to remove.")
            return

        if not messagebox.askyesno(
                "Confirm Remove",
                f"Remove item #{item.index} ({item.section}: "
                f"{item.item_path})?\n\nThis cannot be undone."):
            return

        fw = self.s.firmware
        fw.remove_item(item.index)
        self.ctrl.log(f"Removed item #{item.index} ({item.section})")
        self._refresh_fw_info()

    def _add_item(self):
        fw = self.s.firmware
        if not fw:
            messagebox.showinfo("No Firmware", "Load a firmware file first.")
            return

        path = filedialog.askopenfilename(
            title="Select file to add as item",
            filetypes=[("All files", "*.*")],
        )
        if not path:
            return

        dlg = tk.Toplevel(self)
        dlg.title("Add Item")
        dlg.geometry("420x260")
        dlg.resizable(False, False)
        dlg.transient(self.winfo_toplevel())
        dlg.grab_set()

        ttk.Label(dlg, text="Add New Firmware Item",
                  font=(FONT_FAMILY, 11, "bold")).pack(pady=(10, 6))

        fields = ttk.Frame(dlg, padding=10)
        fields.pack(fill=tk.X)

        ttk.Label(fields, text="Item Path:").grid(
            row=0, column=0, sticky="w", pady=3)
        item_path_var = tk.StringVar(value=f"file:{os.path.basename(path)}")
        ttk.Entry(fields, textvariable=item_path_var, width=36).grid(
            row=0, column=1, padx=(6, 0), pady=3)

        ttk.Label(fields, text="Section:").grid(
            row=1, column=0, sticky="w", pady=3)
        section_var = tk.StringVar(value="FILE")
        ttk.Combobox(fields, textvariable=section_var, width=33,
                     values=["FILE", "KERN", "ROOT", "ROOTB", "CFG",
                             "TEST", "ENRG", "WEB", "FS"]).grid(
            row=1, column=1, padx=(6, 0), pady=3)

        ttk.Label(fields, text="Version:").grid(
            row=2, column=0, sticky="w", pady=3)
        version_var = tk.StringVar(value="V1.0")
        ttk.Entry(fields, textvariable=version_var, width=36).grid(
            row=2, column=1, padx=(6, 0), pady=3)

        ttk.Label(fields, text="Policy:").grid(
            row=3, column=0, sticky="w", pady=3)
        policy_var = tk.StringVar(value="0")
        ttk.Entry(fields, textvariable=policy_var, width=36).grid(
            row=3, column=1, padx=(6, 0), pady=3)

        def on_ok():
            with open(path, 'rb') as f:
                data = f.read()
            try:
                pol = int(policy_var.get(), 0)
            except ValueError:
                pol = 0
            fw.add_item(item_path_var.get(), section_var.get(),
                        version_var.get(), data, pol)
            self.ctrl.log(
                f"Added item '{item_path_var.get()}' ({len(data):,} bytes)")
            dlg.destroy()
            self._refresh_fw_info()

        btn_frame = ttk.Frame(dlg)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Add", command=on_ok, width=10).pack(
            side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="Cancel", command=dlg.destroy,
                   width=10).pack(side=tk.LEFT, padx=4)

    def _unpack_all(self):
        fw = self.s.firmware
        if not fw:
            messagebox.showinfo("No Firmware", "Load a firmware file first.")
            return

        out_dir = filedialog.askdirectory(title="Unpack to Directory")
        if not out_dir:
            return

        try:
            fw.unpack_to_dir(out_dir)
            self.ctrl.log(f"Unpacked {fw.item_count} items -> {out_dir}")
            self.s.fw_info_status_var.set(
                f"Unpacked to {out_dir} ({fw.item_count} items)")
            messagebox.showinfo(
                "Unpack Complete",
                f"Unpacked {fw.item_count} items to:\n{out_dir}")
        except Exception as e:
            messagebox.showerror("Unpack Error", str(e))
            self.ctrl.log(f"Unpack failed: {e}")

    def _pack_from_dir(self):
        in_dir = filedialog.askdirectory(
            title="Select Unpacked Directory")
        if not in_dir:
            return

        out_path = filedialog.asksaveasfilename(
            title="Save Repacked Firmware",
            initialfile="firmware_repacked.bin",
            filetypes=[("Firmware files", "*.bin"), ("All files", "*.*")],
        )
        if not out_path:
            return

        try:
            from hwflash.core.firmware import HWNPFirmware
            fw = HWNPFirmware()
            firmware_data = fw.pack_from_dir(in_dir)

            with open(out_path, 'wb') as f:
                f.write(firmware_data)

            self.s.firmware = fw
            self.s.firmware_path = out_path
            self.s.fw_path_var.set(os.path.basename(out_path))
            self._refresh_fw_info()
            self.ctrl.log(
                f"Packed firmware from {in_dir} -> {out_path} "
                f"({len(firmware_data):,} bytes)")
            messagebox.showinfo(
                "Pack Complete",
                f"Firmware packed: {out_path}\n"
                f"Size: {len(firmware_data):,} bytes\n"
                f"Items: {fw.item_count}")
        except Exception as e:
            messagebox.showerror("Pack Error", str(e))
            self.ctrl.log(f"Pack from dir failed: {e}")

    def _repack_save(self):
        fw = self.s.firmware
        if not fw:
            messagebox.showinfo("No Firmware", "Load a firmware file first.")
            return

        out_path = filedialog.asksaveasfilename(
            title="Save Repacked Firmware",
            initialfile="firmware_repacked.bin",
            filetypes=[("Firmware files", "*.bin"), ("All files", "*.*")],
        )
        if not out_path:
            return

        try:
            firmware_data = fw.repack()

            with open(out_path, 'wb') as f:
                f.write(firmware_data)

            self.s.firmware_path = out_path
            self.s.fw_path_var.set(os.path.basename(out_path))
            self._refresh_fw_info()

            self.ctrl.log(
                f"Repacked firmware -> {out_path} "
                f"({len(firmware_data):,} bytes)")
            self.s.fw_info_status_var.set(
                f"Saved: {os.path.basename(out_path)} "
                f"({len(firmware_data):,} bytes)")
            messagebox.showinfo(
                "Repack Complete",
                f"Firmware saved: {out_path}\n"
                f"Size: {len(firmware_data):,} bytes")
        except Exception as e:
            messagebox.showerror("Repack Error", str(e))
            self.ctrl.log(f"Repack failed: {e}")

    def _verify_crc(self):
        fw = self.s.firmware
        if not fw:
            messagebox.showinfo("No Firmware", "Load a firmware file first.")
            return

        hdr_ok, data_ok = fw.validate_crc32()
        lines = []
        lines.append(
            f"Header CRC32:  {'PASS' if hdr_ok else 'FAIL'}")
        lines.append(
            f"Data CRC32:    {'PASS' if data_ok else 'FAIL'}")
        lines.append("")

        for item in fw.items:
            if item.data:
                calc = zlib.crc32(item.data) & 0xFFFFFFFF
                ok = calc == item.crc32
                lines.append(
                    f"  Item #{item.index:2d} ({item.section:14s}): "
                    f"{'OK' if ok else 'FAIL'}  "
                    f"calc=0x{calc:08X}  hdr=0x{item.crc32:08X}")

        msg = '\n'.join(lines)
        self.s.fw_info_status_var.set(
            f"CRC32: Header {'OK' if hdr_ok else 'FAIL'}, "
            f"Data {'OK' if data_ok else 'FAIL'}")
        messagebox.showinfo("CRC32 Verification", msg)

    def _verify_signature(self):
        fw = self.s.firmware
        if not fw:
            messagebox.showinfo("No Firmware", "Load a firmware file first.")
            return

        sig_path = filedialog.askopenfilename(
            title="Select Signature File",
            filetypes=[("Signature files", "*signature*;*sig*"),
                       ("All files", "*.*")],
        )
        if not sig_path:
            return

        pubkey_path = filedialog.askopenfilename(
            title="Select Public Key (PEM)",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")],
        )
        if not pubkey_path:
            return

        try:
            result = fw.verify_signature(sig_path, pubkey_path)
            lines = ["SHA256 Verification:"]
            for r in result['sha256_results']:
                status = "OK" if r['match'] else "FAIL"
                lines.append(f"  [{status}] {r['path']}")
                if not r['match']:
                    lines.append(f"      expected: {r['expected']}")
                    lines.append(f"      actual:   {r['actual']}")

            lines.append("")
            sig_ok = result['signature_valid']
            lines.append(
                f"RSA Signature: {'VALID' if sig_ok else 'INVALID'}")

            messagebox.showinfo("Signature Verification", '\n'.join(lines))
            self.ctrl.log(
                f"Signature verification: RSA="
                f"{'valid' if sig_ok else 'invalid'}")
            self.s.fw_info_status_var.set(
                f"Signature: {'VALID' if sig_ok else 'INVALID'}")
        except ImportError as e:
            messagebox.showerror("Missing Dependency", str(e))
        except Exception as e:
            messagebox.showerror("Verification Error", str(e))
            self.ctrl.log(f"Signature verify failed: {e}")

    def _sign_firmware(self):
        fw = self.s.firmware
        if not fw:
            messagebox.showinfo("No Firmware", "Load a firmware file first.")
            return

        privkey_path = filedialog.askopenfilename(
            title="Select Private Key (PEM, no password)",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")],
        )
        if not privkey_path:
            return

        out_path = filedialog.asksaveasfilename(
            title="Save Signature File",
            initialfile="signature",
            filetypes=[("All files", "*.*")],
        )
        if not out_path:
            return

        try:
            fw.sign_firmware(privkey_path, out_path)
            self.ctrl.log(f"Firmware signed -> {out_path}")
            self.s.fw_info_status_var.set(
                f"Signed: {os.path.basename(out_path)}")
            messagebox.showinfo(
                "Signing Complete",
                f"Signature written to:\n{out_path}\n\n"
                f"Items signed: {fw.item_count}")
        except ImportError as e:
            messagebox.showerror("Missing Dependency", str(e))
        except Exception as e:
            messagebox.showerror("Signing Error", str(e))
            self.ctrl.log(f"Signing failed: {e}")

    # ── Clipboard helpers ────────────────────────────────────────

    def _copy_sha256(self):
        item = self._get_selected_item()
        if item and item.data:
            sha = _short_hash(item.data, "sha256")
            self.clipboard_clear()
            self.clipboard_append(sha)
            self.s.fw_info_status_var.set(f"SHA256 copied: {sha[:16]}...")

    def _copy_crc32(self):
        item = self._get_selected_item()
        if item:
            crc = f"0x{item.crc32:08X}"
            self.clipboard_clear()
            self.clipboard_append(crc)
            self.s.fw_info_status_var.set(f"CRC32 copied: {crc}")
