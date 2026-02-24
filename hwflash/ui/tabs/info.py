"""Firmware Info tab mixin for HuaweiFlash."""

import os
import struct
import zlib
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox


class InfoTabMixin:
    """Mixin providing the Firmware Info tab and related methods."""

    def _build_info_tab(self):
        """Build the firmware information tab (HWFW_GUI style).

        Adapted from csersoft/HWFW_GUI: tree view showing firmware
        structure with header, product list, and item details.
        Supports item export and product list viewing.
        """
        tab = self.tab_info

        # ── Toolbar ──────────────────────────────────────────────
        toolbar = ttk.Frame(tab)
        toolbar.pack(fill=tk.X, pady=(0, 5))
        ttk.Button(toolbar, text="📋 Refresh Info",
                   command=self._refresh_fw_info, width=14).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(toolbar, text="💾 Export Item",
                   command=self._export_fw_item, width=14).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(toolbar, text="✅ Verify CRC32",
                   command=self._verify_fw_crc, width=14).pack(side=tk.LEFT, padx=(0, 5))

        self.fw_info_status_var = tk.StringVar(value="Load a firmware file first")
        ttk.Label(toolbar, textvariable=self.fw_info_status_var,
                  font=('Segoe UI', 9)).pack(side=tk.LEFT, padx=10)

        # ── Paned window: tree + details ─────────────────────────
        paned = ttk.PanedWindow(tab, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        # Left: Tree view (like HWFW_GUI's TreeView)
        tree_frame = ttk.Frame(paned)
        paned.add(tree_frame, weight=1)

        self.fw_tree = ttk.Treeview(tree_frame, show='tree', selectmode='browse')
        fw_tree_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL,
                                       command=self.fw_tree.yview)
        self.fw_tree.configure(yscrollcommand=fw_tree_scroll.set)
        self.fw_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        fw_tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.fw_tree.bind('<<TreeviewSelect>>', self._on_fw_tree_select)

        # Right: Details (like HWFW_GUI's ListView)
        detail_frame = ttk.Frame(paned)
        paned.add(detail_frame, weight=2)

        self.fw_detail_text = scrolledtext.ScrolledText(
            detail_frame, wrap=tk.WORD,
            font=('Consolas', 9),
            state='disabled',
        )
        self.fw_detail_text.pack(fill=tk.BOTH, expand=True)

    # ── Firmware Info Handlers (HWFW_GUI style) ──────────────────

    def _refresh_fw_info(self):
        """Refresh the firmware info tree view."""
        if not self.firmware:
            messagebox.showinfo("No Firmware", "Load a firmware file first (Upgrade tab).")
            return

        # Clear tree
        for item in self.fw_tree.get_children():
            self.fw_tree.delete(item)

        fw = self.firmware
        info = fw.get_info()

        # Root nodes (like HWFW_GUI's TreeView: Header, Products, Items)
        hdr_node = self.fw_tree.insert('', 'end', text='📄 Firmware Header',
                                       values=('header',), tags=('header',))
        prod_node = self.fw_tree.insert('', 'end', text='📦 Product List',
                                        values=('products',), tags=('products',))
        items_node = self.fw_tree.insert('', 'end', text='📋 Items',
                                         values=('items',), tags=('items',))

        # Add individual items as children (like HWFW_GUI item entries)
        # HW_ItemType_Text from HWFW_GUI: UPGRDCHECK, MODULE, KERNEL, ROOTFS, etc.
        for item in fw.items:
            label = f"[{item.index}] {item.section} — {item.item_path}"
            self.fw_tree.insert(items_node, 'end', text=label,
                                values=(f'item:{item.index}',),
                                tags=('item',))

        # Expand all nodes
        self.fw_tree.item(hdr_node, open=True)
        self.fw_tree.item(prod_node, open=True)
        self.fw_tree.item(items_node, open=True)

        # Select header by default
        self.fw_tree.selection_set(hdr_node)
        self._on_fw_tree_select(None)

        self.fw_info_status_var.set(
            f"Loaded: {info['file']} | {info['items']} items | "
            f"{info['size']:,} bytes")

    def _on_fw_tree_select(self, event):
        """Handle tree selection to show details in the right panel."""
        if not self.firmware:
            return
        sel = self.fw_tree.selection()
        if not sel:
            return

        fw = self.firmware
        node_text = self.fw_tree.item(sel[0], 'text')
        node_tags = self.fw_tree.item(sel[0], 'tags')

        lines = []
        if 'header' in node_tags:
            lines.append("═══════ Firmware Header ═══════")
            lines.append(f"  Magic:         0x{fw.magic:08X}  (HWNP)")
            lines.append(f"  File Size:     {len(fw.raw_data):,} bytes")
            lines.append(f"  Raw Size:      {fw.raw_size:,}")
            lines.append(f"  Header Size:   {fw.header_size}")
            lines.append(f"  Raw CRC32:     0x{fw.raw_crc32:08X}")
            lines.append(f"  Header CRC32:  0x{fw.header_crc32:08X}")
            lines.append(f"  Item Count:    {fw.item_count}")
            lines.append(f"  Prod List Size:{fw.prod_list_size}")
            lines.append(f"  Item Hdr Size: {fw.item_header_size}")

        elif 'products' in node_tags:
            lines.append("═══════ Product Compatibility List ═══════")
            if fw.product_list:
                for prod in fw.product_list.split('\n'):
                    prod = prod.strip()
                    if prod:
                        lines.append(f"  ✓ {prod}")
            else:
                lines.append("  (empty)")

        elif 'item' in node_tags:
            # Find the item by index
            vals = self.fw_tree.item(sel[0], 'values')
            if vals:
                idx_str = vals[0].replace('item:', '')
                try:
                    idx = int(idx_str)
                except ValueError:
                    idx = -1
                item = next((it for it in fw.items if it.index == idx), None)
                if item:
                    lines.append(f"═══════ Item #{item.index} ═══════")
                    lines.append(f"  Path:      {item.item_path}")
                    lines.append(f"  Type:      {item.section}")
                    lines.append(f"  Version:   {item.version}")
                    lines.append(f"  CRC32:     0x{item.crc32:08X}")
                    lines.append(f"  Offset:    0x{item.data_offset:08X}")
                    lines.append(f"  Size:      {item.data_size:,} bytes")
                    lines.append(f"  Policy:    0x{item.policy:08X}")
                    # Check for whwh sub-header (like HWFW_GUI IDT_WHWH)
                    if item.data and len(item.data) >= 4:
                        sub_magic = struct.unpack_from('<I', item.data, 0)[0]
                        if sub_magic == 0x68776877:  # 'whwh'
                            lines.append(f"  Sub-Magic: 0x{sub_magic:08X} (whwh)")
                            if len(item.data) >= 80:
                                sub_ver = item.data[4:68].split(b'\x00')[0].decode('ascii', errors='replace')
                                lines.append(f"  Sub-Ver:   {sub_ver}")

        elif 'items' in node_tags:
            lines.append("═══════ All Items Summary ═══════")
            lines.append(f"  Total items: {fw.item_count}")
            lines.append(f"  Total data:  {fw.get_total_data_size():,} bytes")
            lines.append("")
            lines.append(f"  {'#':>3}  {'Type':<14}  {'Size':>12}  {'CRC32':<12}  Path")
            lines.append("  " + "─" * 70)
            for item in fw.items:
                lines.append(
                    f"  {item.index:3d}  {item.section:<14}  "
                    f"{item.data_size:>10,}  0x{item.crc32:08X}  {item.item_path}")

        self.fw_detail_text.configure(state='normal')
        self.fw_detail_text.delete('1.0', tk.END)
        self.fw_detail_text.insert('1.0', '\n'.join(lines))
        self.fw_detail_text.configure(state='disabled')

    def _export_fw_item(self):
        """Export the selected firmware item data to a file."""
        if not self.firmware:
            messagebox.showinfo("No Firmware", "Load a firmware file first.")
            return

        sel = self.fw_tree.selection()
        if not sel:
            messagebox.showinfo("No Selection", "Select an item in the tree to export.")
            return

        tags = self.fw_tree.item(sel[0], 'tags')
        if 'item' not in tags:
            messagebox.showinfo("Select Item", "Select a specific item (not header/products) to export.")
            return

        vals = self.fw_tree.item(sel[0], 'values')
        if not vals:
            return
        try:
            idx = int(vals[0].replace('item:', ''))
        except ValueError:
            return

        item = next((it for it in self.firmware.items if it.index == idx), None)
        if not item or not item.data:
            messagebox.showwarning("No Data", "This item has no data to export.")
            return

        path = filedialog.asksaveasfilename(
            title=f"Export Item #{item.index} ({item.section})",
            initialfile=f"item_{item.index}_{item.section}.bin",
            filetypes=[("Binary files", "*.bin"), ("All files", "*.*")],
        )
        if path:
            with open(path, 'wb') as f:
                f.write(item.data)
            self._log(f"Exported item #{item.index} ({item.section}) -> {path}")
            self.fw_info_status_var.set(f"Exported: {os.path.basename(path)} ({item.data_size:,} bytes)")

    def _verify_fw_crc(self):
        """Verify firmware CRC32 checksums."""
        if not self.firmware:
            messagebox.showinfo("No Firmware", "Load a firmware file first.")
            return

        hdr_ok, data_ok = self.firmware.validate_crc32()

        results = []
        results.append(f"Header CRC32: {'✅ PASS' if hdr_ok else '❌ FAIL'}")
        results.append(f"Data CRC32:   {'✅ PASS' if data_ok else '❌ FAIL'}")

        # Check individual items
        for item in self.firmware.items:
            if item.data:
                calc = zlib.crc32(item.data) & 0xFFFFFFFF
                ok = (calc == item.crc32)
                results.append(f"  Item #{item.index} ({item.section}): "
                              f"{'✅' if ok else '❌'} "
                              f"calc=0x{calc:08X} hdr=0x{item.crc32:08X}")

        msg = '\n'.join(results)
        self.fw_info_status_var.set(
            f"CRC32: Header {'OK' if hdr_ok else 'FAIL'}, "
            f"Data {'OK' if data_ok else 'FAIL'}")
        messagebox.showinfo("CRC32 Verification", msg)
        self._log(f"CRC32 verification: header={'ok' if hdr_ok else 'fail'}, data={'ok' if data_ok else 'fail'}")
