"""Firmware Editor v2 — full rewrite with text-first editing workflow."""

from __future__ import annotations

import os
import zlib
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import TYPE_CHECKING, Optional

from hwflash.core.firmware import HWNPFirmware
from hwflash.shared.styles import FONT_FAMILY

if TYPE_CHECKING:
    from hwflash.ui.state import AppState, AppController
    from hwflash.shared.styles import ThemeEngine
    from hwflash.core.firmware import HWNPItem


_TEXT_ENCODINGS = ("utf-8", "utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "latin-1")


def _human_size(value: int) -> str:
    num = float(value)
    for unit in ("B", "KB", "MB", "GB"):
        if num < 1024 or unit == "GB":
            if unit == "B":
                return f"{int(num)} {unit}"
            return f"{num:.1f} {unit}"
        num /= 1024
    return f"{num:.1f} TB"


class FirmwareEditorTab(ttk.Frame):
    """Completely rebuilt firmware explorer/editor tab."""

    def __init__(self, parent, state: "AppState", ctrl: "AppController", engine: "ThemeEngine", **kwargs):
        super().__init__(parent, padding=0, **kwargs)
        self.s = state
        self.ctrl = ctrl
        self.engine = engine

        self._selected_item_index: Optional[int] = None
        self._selected_item_iid: Optional[str] = None
        self._tree_item_lookup: dict[str, int] = {}
        self._current_encoding = tk.StringVar(value="utf-8")
        self._search_var = tk.StringVar()
        self._nav_mode_var = tk.StringVar(value="By Section")
        self._status_var = tk.StringVar(value="Load firmware to start")

        self._item_path_var = tk.StringVar()
        self._item_section_var = tk.StringVar()
        self._item_version_var = tk.StringVar()
        self._item_policy_var = tk.StringVar(value="0")
        self._item_crc_var = tk.StringVar(value="-")
        self._item_size_var = tk.StringVar(value="-")

        self._product_id_var = tk.StringVar()
        self._soc_id_var = tk.StringVar()
        self._board_id_var = tk.StringVar()
        self._hw_ver_var = tk.StringVar()
        self._sw_ver_var = tk.StringVar()
        self._build_date_var = tk.StringVar()
        self._prod_size_var = tk.StringVar(value="0")

        self._signature_path_var = tk.StringVar()
        self._signature_tail = b""

        self._original_items: dict[int, bytes] = {}

        self._build_ui()

    def _build_ui(self):
        top = ttk.Frame(self, padding=(8, 8, 8, 4))
        top.pack(fill=tk.X)

        self._build_action_menus(top)

        ttk.Separator(self, orient=tk.HORIZONTAL).pack(fill=tk.X)

        content = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        content.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        left = ttk.Frame(content)
        right = ttk.Frame(content)
        content.add(left, weight=2)
        content.add(right, weight=5)

        self._build_tree_panel(left)
        self._build_editor_panel(right)

        status = ttk.Frame(self, padding=(8, 0, 8, 8))
        status.pack(fill=tk.X)
        ttk.Label(status, textvariable=self._status_var, font=(FONT_FAMILY, 9, "italic")).pack(side=tk.LEFT)

        self.engine.register(self._text_editor, {"bg": "bg_input", "fg": "fg", "insertbackground": "fg"})
        self.engine.register(self._product_text, {"bg": "bg_input", "fg": "fg", "insertbackground": "fg"})
        self.engine.register(self._signature_text, {"bg": "bg_input", "fg": "fg", "insertbackground": "fg"})
        self.engine.register(self._item_details_text, {"bg": "bg_input", "fg": "fg", "insertbackground": "fg"})

    def _build_action_menus(self, parent):
        wrap = ttk.Frame(parent)
        wrap.pack(fill=tk.X)

        file_btn = ttk.Menubutton(wrap, text="File", width=12)
        file_btn.pack(side=tk.LEFT, padx=(0, 6))
        file_menu = tk.Menu(file_btn, tearoff=0)
        file_menu.add_command(label="Open Firmware", command=self._load_firmware_dialog)
        file_menu.add_command(label="Save Firmware As", command=self._save_firmware_as)
        file_menu.add_command(label="Repack In Memory", command=self._repack_in_memory)
        file_menu.add_separator()
        file_menu.add_command(label="Unpack To Directory", command=self._unpack_all)
        file_menu.add_command(label="Pack From Directory", command=self._pack_from_dir)
        file_menu.add_separator()
        file_menu.add_command(label="Refresh View", command=self._refresh_fw_info)
        file_btn.configure(menu=file_menu)

        item_btn = ttk.Menubutton(wrap, text="Item", width=12)
        item_btn.pack(side=tk.LEFT, padx=(0, 6))
        item_menu = tk.Menu(item_btn, tearoff=0)
        item_menu.add_command(label="Add Item", command=self._add_item)
        item_menu.add_command(label="Remove Item", command=self._remove_item)
        item_menu.add_separator()
        item_menu.add_command(label="Import Binary", command=self._replace_item_binary)
        item_menu.add_command(label="Export Binary", command=self._export_item_binary)
        item_menu.add_command(label="Revert Selected Item", command=self._revert_selected_item)
        item_btn.configure(menu=item_menu)

        meta_btn = ttk.Menubutton(wrap, text="Metadata", width=12)
        meta_btn.pack(side=tk.LEFT, padx=(0, 6))
        meta_menu = tk.Menu(meta_btn, tearoff=0)
        meta_menu.add_command(label="Apply Product Fields", command=self._apply_product_metadata)
        meta_menu.add_command(label="Apply Item Fields", command=self._apply_item_fields)
        meta_menu.add_command(label="Copy Item Path", command=self._copy_item_path)
        meta_btn.configure(menu=meta_menu)

        sig_btn = ttk.Menubutton(wrap, text="Signature", width=12)
        sig_btn.pack(side=tk.LEFT, padx=(0, 6))
        sig_menu = tk.Menu(sig_btn, tearoff=0)
        sig_menu.add_command(label="Open Signature", command=self._open_signature_file)
        sig_menu.add_command(label="Save Signature", command=self._save_signature_file)
        sig_menu.add_separator()
        sig_menu.add_command(label="Verify Signature", command=self._verify_signature)
        sig_menu.add_command(label="Sign Firmware", command=self._sign_firmware)
        sig_btn.configure(menu=sig_menu)

        tools_btn = ttk.Menubutton(wrap, text="Tools", width=12)
        tools_btn.pack(side=tk.LEFT, padx=(0, 6))
        tools_menu = tk.Menu(tools_btn, tearoff=0)
        tools_menu.add_command(label="Verify CRC", command=self._verify_crc)
        tools_menu.add_command(label="Find Text", command=self._find_in_editor)
        tools_btn.configure(menu=tools_menu)

        ttk.Button(wrap, text="Apply Text", bootstyle="primary", command=self._apply_text_edit).pack(side=tk.RIGHT)
        ttk.Button(wrap, text="Save As", command=self._save_firmware_as).pack(side=tk.RIGHT, padx=(0, 6))
        ttk.Button(wrap, text="Repack", command=self._repack_in_memory).pack(side=tk.RIGHT, padx=(0, 6))

    def _build_tree_panel(self, parent):
        search_row = ttk.Frame(parent)
        search_row.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(search_row, text="Navigator", font=(FONT_FAMILY, 10, "bold")).pack(side=tk.LEFT)
        ttk.Combobox(
            search_row,
            textvariable=self._nav_mode_var,
            values=["By Section", "Flat List", "Textual First"],
            width=12,
            state="readonly",
        ).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(search_row, text="Rebuild", width=8, command=self._refresh_fw_info).pack(side=tk.LEFT, padx=(4, 8))
        ttk.Entry(search_row, textvariable=self._search_var, width=18).pack(side=tk.RIGHT)
        ttk.Button(search_row, text="Clear", width=8, command=self._clear_filter).pack(side=tk.RIGHT, padx=(0, 4))
        ttk.Button(search_row, text="Filter", width=8, command=self._filter_tree).pack(side=tk.RIGHT, padx=(0, 4))

        tree_wrap = ttk.Frame(parent)
        tree_wrap.pack(fill=tk.BOTH, expand=True)

        self.fw_tree = ttk.Treeview(tree_wrap, columns=("section", "size", "crc"), show="tree headings", selectmode="browse")
        self.fw_tree.heading("#0", text="Path", anchor="w")
        self.fw_tree.heading("section", text="Section", anchor="w")
        self.fw_tree.heading("size", text="Size", anchor="e")
        self.fw_tree.heading("crc", text="CRC32", anchor="w")
        self.fw_tree.column("#0", width=280, minwidth=150)
        self.fw_tree.column("section", width=90, minwidth=70)
        self.fw_tree.column("size", width=90, minwidth=80, anchor="e")
        self.fw_tree.column("crc", width=110, minwidth=100)

        sy = ttk.Scrollbar(tree_wrap, orient=tk.VERTICAL, command=self.fw_tree.yview)
        sx = ttk.Scrollbar(tree_wrap, orient=tk.HORIZONTAL, command=self.fw_tree.xview)
        self.fw_tree.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)

        self.fw_tree.grid(row=0, column=0, sticky="nsew")
        sy.grid(row=0, column=1, sticky="ns")
        sx.grid(row=1, column=0, sticky="ew")
        tree_wrap.rowconfigure(0, weight=1)
        tree_wrap.columnconfigure(0, weight=1)

        self.fw_tree.bind("<<TreeviewSelect>>", self._on_tree_select)

        self._tree_menu = tk.Menu(self.fw_tree, tearoff=0)
        self._tree_menu.add_command(label="Apply Text", command=self._apply_text_edit)
        self._tree_menu.add_command(label="Export Binary", command=self._export_item_binary)
        self._tree_menu.add_command(label="Import Binary", command=self._replace_item_binary)
        self._tree_menu.add_separator()
        self._tree_menu.add_command(label="Remove Item", command=self._remove_item)
        self._tree_menu.add_command(label="Copy Item Path", command=self._copy_item_path)
        self.fw_tree.bind("<Button-3>", self._show_tree_menu)

    def _build_editor_panel(self, parent):
        self._nb = ttk.Notebook(parent)
        self._nb.pack(fill=tk.BOTH, expand=True)

        text_tab = ttk.Frame(self._nb, padding=8)
        meta_tab = ttk.Frame(self._nb, padding=8)
        item_tab = ttk.Frame(self._nb, padding=8)
        sig_tab = ttk.Frame(self._nb, padding=8)

        self._nb.add(text_tab, text="Text Editor")
        self._nb.add(meta_tab, text="Metadata")
        self._nb.add(item_tab, text="Item Fields")
        self._nb.add(sig_tab, text="Signature")

        self._build_text_tab(text_tab)
        self._build_metadata_tab(meta_tab)
        self._build_item_tab(item_tab)
        self._build_signature_tab(sig_tab)

    def _build_text_tab(self, parent):
        top = ttk.Frame(parent)
        top.pack(fill=tk.X, pady=(0, 6))

        ttk.Label(top, text="Encoding:").pack(side=tk.LEFT)
        enc_combo = ttk.Combobox(top, textvariable=self._current_encoding, values=list(_TEXT_ENCODINGS), width=12, state="readonly")
        enc_combo.pack(side=tk.LEFT, padx=(6, 8))

        ttk.Button(top, text="Reload", width=9, command=self._load_selected_item_text).pack(side=tk.RIGHT)
        ttk.Button(top, text="Find", width=8, command=self._find_in_editor).pack(side=tk.RIGHT, padx=(0, 4))

        wrap = ttk.Frame(parent)
        wrap.pack(fill=tk.BOTH, expand=True)

        self._text_editor = tk.Text(wrap, wrap=tk.NONE, font=("Consolas", 10))
        sy = ttk.Scrollbar(wrap, orient=tk.VERTICAL, command=self._text_editor.yview)
        sx = ttk.Scrollbar(wrap, orient=tk.HORIZONTAL, command=self._text_editor.xview)
        self._text_editor.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)

        self._text_editor.grid(row=0, column=0, sticky="nsew")
        sy.grid(row=0, column=1, sticky="ns")
        sx.grid(row=1, column=0, sticky="ew")
        wrap.rowconfigure(0, weight=1)
        wrap.columnconfigure(0, weight=1)

    def _build_metadata_tab(self, parent):
        grid = ttk.Frame(parent)
        grid.pack(fill=tk.X)

        fields = [
            ("Product ID", self._product_id_var),
            ("Soft ID (SOC_ID)", self._soc_id_var),
            ("Board ID", self._board_id_var),
            ("HW Ver", self._hw_ver_var),
            ("SW Ver", self._sw_ver_var),
            ("Build Date", self._build_date_var),
            ("Declared Product Size", self._prod_size_var),
        ]

        for row, (label, var) in enumerate(fields):
            ttk.Label(grid, text=f"{label}:").grid(row=row, column=0, sticky="w", pady=3)
            ttk.Entry(grid, textvariable=var).grid(row=row, column=1, sticky="ew", pady=3, padx=(8, 0))

        grid.columnconfigure(1, weight=1)

        ttk.Label(parent, text="Product List Text (editable)", font=(FONT_FAMILY, 9, "bold")).pack(anchor="w", pady=(10, 4))

        wrap = ttk.Frame(parent)
        wrap.pack(fill=tk.BOTH, expand=True)
        self._product_text = tk.Text(wrap, wrap=tk.WORD, height=10, font=("Consolas", 9))
        sy = ttk.Scrollbar(wrap, orient=tk.VERTICAL, command=self._product_text.yview)
        self._product_text.configure(yscrollcommand=sy.set)
        self._product_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sy.pack(side=tk.RIGHT, fill=tk.Y)

        ttk.Button(parent, text="Apply Product Metadata", bootstyle="primary", command=self._apply_product_metadata).pack(anchor="e", pady=(8, 0))

    def _build_item_tab(self, parent):
        grid = ttk.Frame(parent)
        grid.pack(fill=tk.X)

        fields = [
            ("Item Path", self._item_path_var),
            ("Section", self._item_section_var),
            ("Version", self._item_version_var),
            ("Policy", self._item_policy_var),
            ("Size", self._item_size_var),
            ("CRC32", self._item_crc_var),
        ]

        for row, (label, var) in enumerate(fields):
            ttk.Label(grid, text=f"{label}:").grid(row=row, column=0, sticky="w", pady=3)
            state = "normal"
            if label in ("Size", "CRC32"):
                state = "readonly"
            ttk.Entry(grid, textvariable=var, state=state).grid(row=row, column=1, sticky="ew", pady=3, padx=(8, 0))

        grid.columnconfigure(1, weight=1)

        ttk.Button(parent, text="Apply Item Fields", bootstyle="primary", command=self._apply_item_fields).pack(anchor="e", pady=(8, 8))

        ttk.Label(parent, text="Selected Item Summary", font=(FONT_FAMILY, 9, "bold")).pack(anchor="w")
        self._item_details_text = tk.Text(parent, wrap=tk.WORD, height=10, font=("Consolas", 9), state="disabled")
        self._item_details_text.pack(fill=tk.BOTH, expand=True, pady=(4, 0))

    def _build_signature_tab(self, parent):
        row = ttk.Frame(parent)
        row.pack(fill=tk.X)

        ttk.Label(row, text="Signature file:").pack(side=tk.LEFT)
        ttk.Entry(row, textvariable=self._signature_path_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6)
        ttk.Button(row, text="Open", width=9, command=self._open_signature_file).pack(side=tk.LEFT)

        row2 = ttk.Frame(parent)
        row2.pack(fill=tk.X, pady=(6, 6))
        ttk.Button(row2, text="Save Signature", command=self._save_signature_file).pack(side=tk.LEFT)
        ttk.Button(row2, text="Verify", command=self._verify_signature).pack(side=tk.LEFT, padx=(6, 0))
        ttk.Button(row2, text="Sign", bootstyle="primary", command=self._sign_firmware).pack(side=tk.LEFT, padx=(6, 0))

        self._signature_text = tk.Text(parent, wrap=tk.NONE, font=("Consolas", 9))
        self._signature_text.pack(fill=tk.BOTH, expand=True)

    def _set_status(self, text: str):
        self._status_var.set(text)
        self.s.fw_info_status_var.set(text)

    def _mark_dirty(self, *, signature_dirty: bool = True):
        self.s.firmware_dirty = True
        if signature_dirty:
            self.s.firmware_signature_dirty = True

    def _mark_clean(self):
        self.s.firmware_dirty = False

    def _set_loaded_firmware(self, fw: HWNPFirmware, path: str):
        self._normalize_item_indices(fw)
        self.s.firmware = fw
        self.s.firmware_path = path
        self.s.fw_path_var.set(path)
        self._original_items = {item.index: bytes(item.data or b"") for item in fw.items}
        self._mark_clean()
        self.s.firmware_signature_dirty = False
        self._refresh_fw_info()

    def _load_firmware_dialog(self):
        path = filedialog.askopenfilename(
            title="Open Firmware",
            filetypes=[("Firmware files", "*.bin"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            fw = HWNPFirmware()
            fw.load(path)
            self._set_loaded_firmware(fw, path)
            self.ctrl.log(f"Firmware loaded: {path}")
            self._set_status(f"Loaded firmware: {os.path.basename(path)}")
        except Exception as exc:
            messagebox.showerror("Load Error", str(exc))
            self.ctrl.log(f"Firmware load failed: {exc}")

    def _refresh_fw_info(self):
        fw = self.s.firmware
        self._tree_item_lookup.clear()
        self._selected_item_iid = None

        roots = self.fw_tree.get_children("")
        if roots:
            self.fw_tree.delete(*roots)

        if not fw:
            self.s.fw_info_var.set("No firmware loaded")
            self._set_status("Load firmware to start")
            return

        self._normalize_item_indices(fw)

        root_meta = self.fw_tree.insert("", "end", iid="meta", text="[Metadata]", values=("-", "-", "-"))
        self.fw_tree.insert(root_meta, "end", iid="meta:product", text="Product List", values=("META", str(fw.prod_list_size), "-"))
        self.fw_tree.insert("", "end", iid="signature", text="[Signature]", values=("SIG", "-", "-"))

        mode = self._nav_mode_var.get()
        if mode == "By Section":
            section_nodes: dict[str, str] = {}
            for pos, item in enumerate(fw.items):
                section = (item.section or "UNKNOWN").strip() or "UNKNOWN"
                if section not in section_nodes:
                    sec_iid = f"sec:{section}:{len(section_nodes)}"
                    section_nodes[section] = self.fw_tree.insert(
                        "",
                        "end",
                        iid=sec_iid,
                        text=f"[{section}]",
                        values=("group", "-", "-"),
                    )
                self._insert_item_node(section_nodes[section], item, pos)
            for sec_iid in section_nodes.values():
                self.fw_tree.item(sec_iid, open=True)
        elif mode == "Textual First":
            txt_root = self.fw_tree.insert("", "end", iid="group:text", text="[Text-like Items]", values=("group", "-", "-"))
            bin_root = self.fw_tree.insert("", "end", iid="group:bin", text="[Binary-like Items]", values=("group", "-", "-"))
            for pos, item in enumerate(fw.items):
                preview = fw.get_item_text_preview(item)
                parent = txt_root if preview.get("is_text") else bin_root
                self._insert_item_node(parent, item, pos)
            self.fw_tree.item(txt_root, open=True)
            self.fw_tree.item(bin_root, open=True)
        else:
            for pos, item in enumerate(fw.items):
                self._insert_item_node("", item, pos)

        self.fw_tree.item(root_meta, open=True)

        dirty_tag = " *modified" if getattr(self.s, "firmware_dirty", False) else ""
        self.s.fw_info_var.set(
            f"HWNP | {fw.item_count} items | {_human_size(len(fw.raw_data))} | Products: {fw.product_list[:60]}{dirty_tag}"
        )

        if self._selected_item_index is not None and any(it.index == self._selected_item_index for it in fw.items):
            self._select_item_by_index(self._selected_item_index)
        elif fw.items:
            self._select_item_by_index(0)

    def _insert_item_node(self, parent: str, item: "HWNPItem", position: int):
        display = self._display_item_path(item.item_path)
        iid = f"itm:{position}:{item.index}"
        self.fw_tree.insert(
            parent,
            "end",
            iid=iid,
            text=display,
            values=(item.section, _human_size(item.data_size), f"0x{item.crc32:08X}"),
        )
        self._tree_item_lookup[iid] = item.index

    def _clear_filter(self):
        self._search_var.set("")
        self._refresh_fw_info()

    def _filter_tree(self):
        fw = self.s.firmware
        term = self._search_var.get().strip().lower()
        if not fw:
            return
        if not term:
            self._refresh_fw_info()
            return

        self._normalize_item_indices(fw)
        self._tree_item_lookup.clear()
        self._selected_item_iid = None

        roots = self.fw_tree.get_children("")
        if roots:
            self.fw_tree.delete(*roots)

        for pos, item in enumerate(fw.items):
            hay = f"{item.item_path} {item.section} {item.version}".lower()
            if term not in hay:
                continue
            self._insert_item_node("", item, pos)

        if self._tree_item_lookup:
            first_iid = next(iter(self._tree_item_lookup.keys()))
            self.fw_tree.selection_set(first_iid)
            self.fw_tree.see(first_iid)
        self._set_status(f"Filter active: {term}")

    def _on_tree_select(self, _event=None):
        selected = self.fw_tree.selection()
        if not selected:
            return

        iid = selected[0]
        if iid in self._tree_item_lookup:
            self._selected_item_iid = iid
            self._selected_item_index = self._tree_item_lookup[iid]
            self._load_selected_item_text()
            self._load_item_fields()
            self._nb.select(0)
            return

        if iid.startswith("meta"):
            self._load_metadata()
            self._nb.select(1)
            return

        if iid == "signature":
            self._nb.select(3)

    def _display_item_path(self, item_path: str) -> str:
        if ":" in item_path:
            return item_path.split(":", 1)[1] or item_path
        return item_path

    def _get_selected_item(self) -> Optional["HWNPItem"]:
        fw = self.s.firmware
        if not fw:
            return None
        if self._selected_item_iid and self._selected_item_iid in self._tree_item_lookup:
            self._selected_item_index = self._tree_item_lookup[self._selected_item_iid]
        if self._selected_item_index is None:
            return None
        return next((item for item in fw.items if item.index == self._selected_item_index), None)

    def _normalize_item_indices(self, fw: "HWNPFirmware"):
        for idx, item in enumerate(fw.items):
            item.index = idx
        fw.item_count = len(fw.items)

    def _select_item_by_index(self, index: int) -> bool:
        for iid, item_index in self._tree_item_lookup.items():
            if item_index == index:
                self.fw_tree.selection_set(iid)
                self.fw_tree.see(iid)
                self._selected_item_iid = iid
                self._selected_item_index = index
                return True
        return False

    def _decode_payload(self, data: bytes) -> tuple[str, str]:
        if not data:
            return "", "utf-8"

        for enc in _TEXT_ENCODINGS:
            try:
                text = data.decode(enc)
            except UnicodeDecodeError:
                continue
            printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text)
            ratio = printable / max(1, len(text))
            if ratio >= 0.55 or "\n" in text or "\r" in text:
                return text, enc

        return data.decode("latin-1", errors="replace"), "latin-1"

    def _load_selected_item_text(self):
        item = self._get_selected_item()
        if not item:
            return
        text, enc = self._decode_payload(item.data or b"")
        self._current_encoding.set(enc)
        self._text_editor.delete("1.0", tk.END)
        self._text_editor.insert("1.0", text)
        self._set_status(f"Loaded item #{item.index} text view ({enc})")

    def _apply_text_edit(self):
        fw = self.s.firmware
        item = self._get_selected_item()
        if not fw or not item:
            messagebox.showinfo("No Item", "Select an item first.")
            return

        encoding = self._current_encoding.get().strip() or "utf-8"
        text = self._text_editor.get("1.0", tk.END).rstrip("\n")

        try:
            payload = text.encode(encoding, errors="replace")
        except LookupError:
            payload = text.encode("utf-8", errors="replace")
            self._current_encoding.set("utf-8")

        fw.replace_item_data(item.index, payload)
        self._mark_dirty(signature_dirty=True)
        self._load_item_fields()
        self._refresh_fw_info()
        self._select_item_by_index(item.index)
        self.ctrl.log(f"Updated text payload: item #{item.index} ({len(payload)} bytes)")
        self._set_status(f"Applied text edits to item #{item.index}; repack before flashing")

    def _load_item_fields(self):
        item = self._get_selected_item()
        if not item:
            return
        self._item_path_var.set(item.item_path)
        self._item_section_var.set(item.section)
        self._item_version_var.set(item.version)
        self._item_policy_var.set(str(item.policy))
        self._item_size_var.set(f"{item.data_size} bytes")
        self._item_crc_var.set(f"0x{item.crc32:08X}")

        calc_crc = zlib.crc32(item.data or b"") & 0xFFFFFFFF
        details = [
            f"Index      : {item.index}",
            f"Path       : {item.item_path}",
            f"Section    : {item.section}",
            f"Version    : {item.version or '-'}",
            f"Policy     : {item.policy}",
            f"Data Size  : {item.data_size:,} bytes",
            f"CRC Header : 0x{item.crc32:08X}",
            f"CRC Actual : 0x{calc_crc:08X}",
        ]

        self._item_details_text.configure(state="normal")
        self._item_details_text.delete("1.0", tk.END)
        self._item_details_text.insert("1.0", "\n".join(details))
        self._item_details_text.configure(state="disabled")

    def _apply_item_fields(self):
        item = self._get_selected_item()
        fw = self.s.firmware
        if not fw or not item:
            messagebox.showinfo("No Item", "Select an item first.")
            return

        item.item_path = self._item_path_var.get().strip() or item.item_path
        item.section = self._item_section_var.get().strip() or item.section
        item.version = self._item_version_var.get().strip()

        try:
            item.policy = int(self._item_policy_var.get().strip() or "0", 0)
        except ValueError:
            messagebox.showerror("Invalid Policy", "Policy must be an integer value.")
            return

        self._mark_dirty(signature_dirty=True)
        self._refresh_fw_info()
        self._select_item_by_index(item.index)
        self._set_status(f"Updated item fields for item #{item.index}")

    def _parse_product_kv(self, text: str) -> dict[str, str]:
        out: dict[str, str] = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or "=" not in line:
                continue
            key, value = line.split("=", 1)
            out[key.strip().upper()] = value.strip()
        return out

    def _merge_product_kv(self, base_text: str, updates: dict[str, str]) -> str:
        lines = base_text.splitlines() if base_text else []
        used = {key: False for key in updates}
        merged: list[str] = []

        for line in lines:
            if "=" not in line:
                merged.append(line)
                continue
            key, _ = line.split("=", 1)
            key_u = key.strip().upper()
            if key_u in updates:
                value = updates[key_u].strip()
                if value:
                    merged.append(f"{key_u}={value}")
                used[key_u] = True
            else:
                merged.append(line)

        for key, value in updates.items():
            if value.strip() and not used[key]:
                merged.append(f"{key}={value.strip()}")

        return "\n".join(merged).strip()

    def _load_metadata(self):
        fw = self.s.firmware
        if not fw:
            return

        self._product_text.delete("1.0", tk.END)
        self._product_text.insert("1.0", fw.product_list)

        kv = self._parse_product_kv(fw.product_list)
        self._product_id_var.set(kv.get("PRODUCT_ID", ""))
        self._soc_id_var.set(kv.get("SOC_ID", ""))
        self._board_id_var.set(kv.get("BOARD_ID", ""))
        self._hw_ver_var.set(kv.get("HW_VER", ""))
        self._sw_ver_var.set(kv.get("SW_VER", ""))
        self._build_date_var.set(kv.get("BUILD_DATE", ""))
        self._prod_size_var.set(str(fw.prod_list_size))

    def _apply_product_metadata(self):
        fw = self.s.firmware
        if not fw:
            messagebox.showinfo("No Firmware", "Load firmware first.")
            return

        base_text = self._product_text.get("1.0", tk.END).rstrip("\n")
        updates = {
            "PRODUCT_ID": self._product_id_var.get(),
            "SOC_ID": self._soc_id_var.get(),
            "BOARD_ID": self._board_id_var.get(),
            "HW_VER": self._hw_ver_var.get(),
            "SW_VER": self._sw_ver_var.get(),
            "BUILD_DATE": self._build_date_var.get(),
        }

        merged = self._merge_product_kv(base_text, updates)
        fw.product_list = merged

        try:
            declared = int(self._prod_size_var.get().strip() or "0", 0)
        except ValueError:
            declared = 0

        min_size = len(merged.encode("ascii", errors="replace")) + 1
        fw.prod_list_size = max(min_size, declared)

        self._product_text.delete("1.0", tk.END)
        self._product_text.insert("1.0", merged)

        self._mark_dirty(signature_dirty=True)
        self._refresh_fw_info()
        self._set_status("Applied product metadata changes; repack before flashing")

    def _repack_in_memory(self):
        fw = self.s.firmware
        if not fw:
            messagebox.showinfo("No Firmware", "Load firmware first.")
            return

        try:
            fw.repack()
            self._mark_clean()
            self._refresh_fw_info()
            self._set_status("Firmware repacked in memory (CRC fields updated)")
            self.ctrl.log("Firmware repacked in memory")
        except Exception as exc:
            messagebox.showerror("Repack Error", str(exc))
            self.ctrl.log(f"Repack failed: {exc}")

    def _save_firmware_as(self):
        fw = self.s.firmware
        if not fw:
            messagebox.showinfo("No Firmware", "Load firmware first.")
            return

        if getattr(self.s, "firmware_dirty", False):
            should_repack = messagebox.askyesno(
                "Repack Required",
                "Firmware has unsaved structural changes. Repack now before save?",
            )
            if not should_repack:
                return
            self._repack_in_memory()

        out_path = filedialog.asksaveasfilename(
            title="Save Firmware",
            filetypes=[("Firmware files", "*.bin"), ("All files", "*.*")],
            defaultextension=".bin",
            initialfile="firmware_edited.bin",
        )
        if not out_path:
            return

        try:
            with open(out_path, "wb") as handle:
                handle.write(fw.raw_data)
            self.s.firmware_path = out_path
            self.s.fw_path_var.set(out_path)
            self.ctrl.log(f"Saved firmware: {out_path}")
            self._set_status(f"Firmware saved: {os.path.basename(out_path)}")
        except OSError as exc:
            messagebox.showerror("Save Error", str(exc))

    def _unpack_all(self):
        fw = self.s.firmware
        if not fw:
            messagebox.showinfo("No Firmware", "Load firmware first.")
            return

        out_dir = filedialog.askdirectory(title="Select output directory")
        if not out_dir:
            return

        try:
            fw.unpack_to_dir(out_dir)
            self.ctrl.log(f"Unpacked firmware to: {out_dir}")
            self._set_status(f"Unpacked to {out_dir}")
        except Exception as exc:
            messagebox.showerror("Unpack Error", str(exc))

    def _pack_from_dir(self):
        in_dir = filedialog.askdirectory(title="Select unpacked directory")
        if not in_dir:
            return

        out_path = filedialog.asksaveasfilename(
            title="Save packed firmware",
            filetypes=[("Firmware files", "*.bin"), ("All files", "*.*")],
            defaultextension=".bin",
            initialfile="firmware_packed.bin",
        )
        if not out_path:
            return

        try:
            fw = HWNPFirmware()
            packed = fw.pack_from_dir(in_dir)
            with open(out_path, "wb") as handle:
                handle.write(packed)
            self._set_loaded_firmware(fw, out_path)
            self.ctrl.log(f"Packed firmware from {in_dir} to {out_path}")
            self._set_status(f"Packed firmware saved: {os.path.basename(out_path)}")
        except Exception as exc:
            messagebox.showerror("Pack Error", str(exc))

    def _export_item_binary(self):
        item = self._get_selected_item()
        if not item:
            messagebox.showinfo("No Item", "Select an item first.")
            return

        default_name = os.path.basename(self._display_item_path(item.item_path)) or f"item_{item.index}.bin"
        out_path = filedialog.asksaveasfilename(
            title="Export item",
            initialfile=default_name,
            filetypes=[("All files", "*.*")],
        )
        if not out_path:
            return

        with open(out_path, "wb") as handle:
            handle.write(item.data or b"")
        self._set_status(f"Exported item #{item.index}")

    def _replace_item_binary(self):
        fw = self.s.firmware
        item = self._get_selected_item()
        if not fw or not item:
            messagebox.showinfo("No Item", "Select an item first.")
            return

        in_path = filedialog.askopenfilename(title="Select replacement payload", filetypes=[("All files", "*.*")])
        if not in_path:
            return

        with open(in_path, "rb") as handle:
            payload = handle.read()

        fw.replace_item_data(item.index, payload)
        self._mark_dirty(signature_dirty=True)
        self._refresh_fw_info()
        self._select_item_by_index(item.index)
        self._load_selected_item_text()
        self._load_item_fields()
        self._set_status(f"Replaced item #{item.index} binary payload")

    def _remove_item(self):
        fw = self.s.firmware
        item = self._get_selected_item()
        if not fw or not item:
            messagebox.showinfo("No Item", "Select an item first.")
            return

        if not messagebox.askyesno("Remove Item", f"Remove item #{item.index}? This action cannot be undone."):
            return

        fw.remove_item(item.index)
        self._selected_item_index = None
        self._mark_dirty(signature_dirty=True)
        self._refresh_fw_info()
        self._set_status("Item removed")

    def _add_item(self):
        fw = self.s.firmware
        if not fw:
            messagebox.showinfo("No Firmware", "Load firmware first.")
            return

        payload_path = filedialog.askopenfilename(title="Select payload file", filetypes=[("All files", "*.*")])
        if not payload_path:
            return

        dialog = tk.Toplevel(self)
        dialog.title("Add Item")
        dialog.geometry("500x260")
        dialog.transient(self.winfo_toplevel())
        dialog.grab_set()

        body = ttk.Frame(dialog, padding=10)
        body.pack(fill=tk.BOTH, expand=True)

        item_path_var = tk.StringVar(value=f"file:/{os.path.basename(payload_path)}")
        section_var = tk.StringVar(value="FILE")
        version_var = tk.StringVar(value="V1.0")
        policy_var = tk.StringVar(value="0")

        ttk.Label(body, text="Path:").grid(row=0, column=0, sticky="w", pady=4)
        ttk.Entry(body, textvariable=item_path_var).grid(row=0, column=1, sticky="ew", pady=4)
        ttk.Label(body, text="Section:").grid(row=1, column=0, sticky="w", pady=4)
        ttk.Combobox(body, textvariable=section_var, values=["FILE", "CFG", "KERN", "ROOT", "ROOTB", "WEB", "FS"], state="readonly").grid(row=1, column=1, sticky="ew", pady=4)
        ttk.Label(body, text="Version:").grid(row=2, column=0, sticky="w", pady=4)
        ttk.Entry(body, textvariable=version_var).grid(row=2, column=1, sticky="ew", pady=4)
        ttk.Label(body, text="Policy:").grid(row=3, column=0, sticky="w", pady=4)
        ttk.Entry(body, textvariable=policy_var).grid(row=3, column=1, sticky="ew", pady=4)
        body.columnconfigure(1, weight=1)

        def on_confirm():
            try:
                with open(payload_path, "rb") as handle:
                    payload = handle.read()
                policy = int(policy_var.get().strip() or "0", 0)
                fw.add_item(item_path_var.get().strip(), section_var.get().strip(), version_var.get().strip(), payload, policy)
                self._normalize_item_indices(fw)
                self._original_items[fw.items[-1].index] = bytes(payload)
                self._mark_dirty(signature_dirty=True)
                self._refresh_fw_info()
                self._select_item_by_index(fw.items[-1].index)
                self._set_status(f"Added item #{fw.items[-1].index}")
                dialog.destroy()
            except Exception as exc:
                messagebox.showerror("Add Item Error", str(exc))

        action = ttk.Frame(body)
        action.grid(row=4, column=0, columnspan=2, sticky="e", pady=(10, 0))
        ttk.Button(action, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT)
        ttk.Button(action, text="Add", bootstyle="primary", command=on_confirm).pack(side=tk.RIGHT, padx=(0, 6))

    def _revert_selected_item(self):
        fw = self.s.firmware
        item = self._get_selected_item()
        if not fw or not item:
            messagebox.showinfo("No Item", "Select an item first.")
            return

        original = self._original_items.get(item.index)
        if original is None:
            messagebox.showwarning("Revert Unavailable", "No original payload snapshot for this item.")
            return

        fw.replace_item_data(item.index, bytes(original))
        self._mark_dirty(signature_dirty=True)
        self._refresh_fw_info()
        self._select_item_by_index(item.index)
        self._load_selected_item_text()
        self._set_status(f"Reverted item #{item.index}")

    def _verify_crc(self):
        fw = self.s.firmware
        if not fw:
            messagebox.showinfo("No Firmware", "Load firmware first.")
            return

        hdr_ok, data_ok = fw.validate_crc32()
        msg = (
            f"Header CRC32: {'PASS' if hdr_ok else 'FAIL'}\n"
            f"Data CRC32: {'PASS' if data_ok else 'FAIL'}"
        )
        messagebox.showinfo("CRC Verification", msg)
        self._set_status(f"CRC verify: header={'OK' if hdr_ok else 'FAIL'} data={'OK' if data_ok else 'FAIL'}")

    def _open_signature_file(self):
        path = filedialog.askopenfilename(
            title="Open Signature File",
            filetypes=[("Signature files", "*signature*;*sig*"), ("All files", "*.*")],
        )
        if not path:
            return

        try:
            with open(path, "rb") as handle:
                raw = handle.read()

            if len(raw) > 256:
                text_raw = raw[:-256]
                self._signature_tail = raw[-256:]
            else:
                text_raw = raw
                self._signature_tail = b""

            text = text_raw.decode("utf-8", errors="replace")
            self._signature_text.delete("1.0", tk.END)
            self._signature_text.insert("1.0", text)
            self._signature_path_var.set(path)
            self._set_status(f"Loaded signature: {os.path.basename(path)}")
        except Exception as exc:
            messagebox.showerror("Signature Error", str(exc))

    def _save_signature_file(self):
        path = self._signature_path_var.get().strip()
        if not path:
            path = filedialog.asksaveasfilename(
                title="Save Signature File",
                filetypes=[("All files", "*.*")],
                initialfile="signature",
            )
            if not path:
                return

        text = self._signature_text.get("1.0", tk.END).rstrip("\n") + "\n"
        raw = text.encode("utf-8", errors="replace") + self._signature_tail

        try:
            with open(path, "wb") as handle:
                handle.write(raw)
            self._signature_path_var.set(path)
            self._set_status(f"Signature file saved: {os.path.basename(path)}")
        except Exception as exc:
            messagebox.showerror("Save Signature Error", str(exc))

    def _verify_signature(self):
        fw = self.s.firmware
        if not fw:
            messagebox.showinfo("No Firmware", "Load firmware first.")
            return

        sig_path = self._signature_path_var.get().strip()
        if not sig_path:
            messagebox.showwarning("No Signature", "Open or set a signature file first.")
            return

        pubkey_path = filedialog.askopenfilename(
            title="Select public key",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")],
        )
        if not pubkey_path:
            return

        try:
            result = fw.verify_signature(sig_path, pubkey_path)
            valid = result.get("signature_valid", False)
            self._set_status(f"Signature verify: {'VALID' if valid else 'INVALID'}")
            messagebox.showinfo("Verify Signature", f"RSA signature is {'VALID' if valid else 'INVALID'}")
        except ImportError as exc:
            messagebox.showerror("Missing Dependency", str(exc))
        except Exception as exc:
            messagebox.showerror("Verify Error", str(exc))

    def _sign_firmware(self):
        fw = self.s.firmware
        if not fw:
            messagebox.showinfo("No Firmware", "Load firmware first.")
            return

        privkey = filedialog.askopenfilename(
            title="Select private key",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")],
        )
        if not privkey:
            return

        out_path = filedialog.asksaveasfilename(
            title="Save signature",
            filetypes=[("All files", "*.*")],
            initialfile="signature",
        )
        if not out_path:
            return

        try:
            fw.sign_firmware(privkey, out_path)
            self._signature_path_var.set(out_path)
            self._open_signature_file_from_path(out_path)
            self.s.firmware_signature_dirty = False
            self._set_status(f"Firmware signed: {os.path.basename(out_path)}")
        except ImportError as exc:
            messagebox.showerror("Missing Dependency", str(exc))
        except Exception as exc:
            messagebox.showerror("Sign Error", str(exc))

    def _open_signature_file_from_path(self, path: str):
        try:
            with open(path, "rb") as handle:
                raw = handle.read()
            if len(raw) > 256:
                text_raw = raw[:-256]
                self._signature_tail = raw[-256:]
            else:
                text_raw = raw
                self._signature_tail = b""
            self._signature_text.delete("1.0", tk.END)
            self._signature_text.insert("1.0", text_raw.decode("utf-8", errors="replace"))
        except Exception:
            pass

    def _show_tree_menu(self, event):
        row = self.fw_tree.identify_row(event.y)
        if row:
            self.fw_tree.selection_set(row)
            self._tree_menu.tk_popup(event.x_root, event.y_root)

    def _copy_item_path(self):
        item = self._get_selected_item()
        if not item:
            return
        self.clipboard_clear()
        self.clipboard_append(item.item_path)
        self._set_status("Item path copied")

    def _find_in_editor(self):
        needle = self._search_var.get().strip()
        if not needle:
            return
        self._text_editor.tag_remove("find", "1.0", tk.END)
        start = "1.0"
        while True:
            pos = self._text_editor.search(needle, start, stopindex=tk.END, nocase=True)
            if not pos:
                break
            end = f"{pos}+{len(needle)}c"
            self._text_editor.tag_add("find", pos, end)
            start = end
        colors = self.engine.colors
        self._text_editor.tag_configure("find", background=colors["warning"], foreground=colors["fg"])

