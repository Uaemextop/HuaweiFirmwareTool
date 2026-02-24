"""Config Crypto tab — encrypt / decrypt Huawei config files."""

from __future__ import annotations

import os
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from typing import TYPE_CHECKING

from hwflash.core.crypto import (
    encrypt_config, decrypt_config, try_decrypt_all_keys,
    CfgFileParser, KNOWN_CHIP_IDS,
)

if TYPE_CHECKING:
    from hwflash.ui.state import AppState, AppController
    from hwflash.shared.styles import ThemeEngine


class CryptoTab(ttk.Frame):
    """Config file encryption / decryption tab."""

    def __init__(self, parent, state: "AppState", ctrl: "AppController",
                 engine: "ThemeEngine", **kwargs):
        super().__init__(parent, padding=6, **kwargs)
        self.s = state
        self.ctrl = ctrl
        self.engine = engine
        self._build()

    def _build(self):
        s = self.s

        # Encrypt / Decrypt
        op_frame = ttk.LabelFrame(self, text="Config File Encryption (aescrypt2)", padding=6)
        op_frame.pack(fill=tk.X, pady=(0, 6))

        row = ttk.Frame(op_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Input File:", width=12).pack(side=tk.LEFT)
        ttk.Entry(row, textvariable=s.crypto_input_var, width=42).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(row, text="Browse", command=self._browse_crypto_input, width=8).pack(side=tk.LEFT)

        row = ttk.Frame(op_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Output File:", width=12).pack(side=tk.LEFT)
        ttk.Entry(row, textvariable=s.crypto_output_var, width=42).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(row, text="Browse", command=self._browse_crypto_output, width=8).pack(side=tk.LEFT)

        row = ttk.Frame(op_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Chip ID:", width=12).pack(side=tk.LEFT)
        self.crypto_chip_combo = ttk.Combobox(
            row, textvariable=s.crypto_chip_var,
            values=["Auto"] + KNOWN_CHIP_IDS + ["Custom"],
            state='readonly', width=14,
        )
        self.crypto_chip_combo.pack(side=tk.LEFT, padx=(0, 4))
        self.crypto_chip_combo.bind('<<ComboboxSelected>>', self._on_crypto_chip_changed)
        ttk.Label(row, text="Key: Df7!ui%s9(lmV1L8", font=('Segoe UI', 8)).pack(side=tk.LEFT)

        self.crypto_custom_row = ttk.Frame(op_frame)
        ttk.Label(self.crypto_custom_row, text="Custom Chip:", width=12).pack(side=tk.LEFT)
        ttk.Entry(self.crypto_custom_row, textvariable=s.crypto_custom_chip_var, width=18).pack(side=tk.LEFT)
        self._on_crypto_chip_changed()

        btn_row = ttk.Frame(op_frame)
        btn_row.pack(fill=tk.X, pady=(6, 0))
        ttk.Button(btn_row, text="\U0001f513 Decrypt", command=self._crypto_decrypt, width=12).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(btn_row, text="\U0001f512 Encrypt", command=self._crypto_encrypt, width=12).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(btn_row, text="\U0001f50d Auto-Detect Key", command=self._crypto_auto_detect, width=16).pack(side=tk.LEFT)

        # Config editor
        edit_frame = ttk.LabelFrame(self, text="Config Editor (cfgtool)", padding=6)
        edit_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 4))

        search_row = ttk.Frame(edit_frame)
        search_row.pack(fill=tk.X, pady=(0, 4))
        ttk.Label(search_row, text="Search:").pack(side=tk.LEFT)
        self.cfg_search_var = tk.StringVar()
        ttk.Entry(search_row, textvariable=self.cfg_search_var, width=28).pack(side=tk.LEFT, padx=4)
        ttk.Button(search_row, text="Search", command=self._cfg_search, width=8).pack(side=tk.LEFT)
        ttk.Button(search_row, text="Load File", command=self._cfg_load, width=10).pack(side=tk.LEFT, padx=4)

        self.cfg_text = scrolledtext.ScrolledText(
            edit_frame, wrap=tk.WORD,
            font=('Consolas', 9),
            height=10,
        )
        self.cfg_text.pack(fill=tk.BOTH, expand=True)

        self.engine.register(self.cfg_text,
                             {"bg": "log_bg", "fg": "log_fg",
                              "insertbackground": "fg"})

    def _on_crypto_chip_changed(self, event=None):
        if self.s.crypto_chip_var.get() == "Custom":
            self.crypto_custom_row.pack(fill=tk.X, pady=2)
        else:
            self.crypto_custom_row.pack_forget()

    # ── Helpers ───────────────────────────────────────────────────

    def _get_chip_id(self):
        chip = self.s.crypto_chip_var.get()
        if chip == "Auto":
            return None
        if chip == "Custom":
            custom = self.s.crypto_custom_chip_var.get().strip()
            if not custom:
                messagebox.showwarning("No Chip ID", "Enter a custom chip ID.")
                return None
            return custom
        return chip

    def _browse_crypto_input(self):
        path = filedialog.askopenfilename(
            title="Select Config File",
            filetypes=[("XML files", "*.xml"), ("Binary files", "*.bin"), ("All files", "*.*")],
        )
        if path:
            self.s.crypto_input_var.set(path)
            base, ext = os.path.splitext(path)
            self.s.crypto_output_var.set(base + "_out" + ext)

    def _browse_crypto_output(self):
        path = filedialog.asksaveasfilename(
            title="Save Decrypted/Encrypted File",
            filetypes=[("XML files", "*.xml"), ("Binary files", "*.bin"), ("All files", "*.*")],
        )
        if path:
            self.s.crypto_output_var.set(path)

    def _crypto_decrypt(self):
        in_path = self.s.crypto_input_var.get().strip()
        out_path = self.s.crypto_output_var.get().strip()
        if not in_path or not out_path:
            messagebox.showwarning("Missing Path", "Select input and output files.")
            return
        chip_id = self._get_chip_id()
        if chip_id is None:
            self._crypto_auto_detect_and_save(in_path, out_path)
            return
        try:
            with open(in_path, 'rb') as f:
                encrypted_data = f.read()
            decrypted = decrypt_config(encrypted_data, chip_id)
            with open(out_path, 'wb') as f:
                f.write(decrypted)
            try:
                text = decrypted.decode('utf-8', errors='replace')
                self.cfg_text.delete('1.0', tk.END)
                self.cfg_text.insert('1.0', text)
            except Exception:
                pass
            self.ctrl.log(f"Decrypted {in_path} -> {out_path} (chip: {chip_id})")
            messagebox.showinfo("Success",
                                f"Decrypted successfully.\n"
                                f"Key: Df7!ui{chip_id}9(lmV1L8\n"
                                f"Output: {out_path}")
        except Exception as e:
            messagebox.showerror("Decrypt Error", str(e))
            self.ctrl.log(f"Decrypt error: {e}")

    def _crypto_encrypt(self):
        in_path = self.s.crypto_input_var.get().strip()
        out_path = self.s.crypto_output_var.get().strip()
        if not in_path or not out_path:
            messagebox.showwarning("Missing Path", "Select input and output files.")
            return
        chip_id = self._get_chip_id()
        if chip_id is None:
            messagebox.showwarning("Select Chip ID",
                                   "Auto-detect is only available for decryption.\n"
                                   "Please select a specific chip ID for encryption.")
            return
        try:
            with open(in_path, 'rb') as f:
                plain_data = f.read()
            encrypted = encrypt_config(plain_data, chip_id)
            with open(out_path, 'wb') as f:
                f.write(encrypted)
            self.ctrl.log(f"Encrypted {in_path} -> {out_path} (chip: {chip_id})")
            messagebox.showinfo("Success",
                                f"Encrypted successfully.\n"
                                f"Key: Df7!ui{chip_id}9(lmV1L8\n"
                                f"Output: {out_path}")
        except Exception as e:
            messagebox.showerror("Encrypt Error", str(e))
            self.ctrl.log(f"Encrypt error: {e}")

    def _crypto_auto_detect(self):
        in_path = self.s.crypto_input_var.get().strip()
        if not in_path:
            messagebox.showwarning("No File", "Select an encrypted config file first.")
            return
        try:
            with open(in_path, 'rb') as f:
                data = f.read()
            results = try_decrypt_all_keys(data)
            if results:
                chip_id, decrypted = results[0]
                self.s.crypto_chip_var.set(chip_id)
                text = decrypted.decode('utf-8', errors='replace')
                self.cfg_text.delete('1.0', tk.END)
                self.cfg_text.insert('1.0', text)
                self.ctrl.log(f"Auto-detected key: {chip_id} for {in_path}")
                messagebox.showinfo("Key Detected",
                                    f"Detected chip ID: {chip_id}\n"
                                    f"Key: Df7!ui{chip_id}9(lmV1L8\n"
                                    f"Config loaded in editor.")
            else:
                messagebox.showwarning("No Match",
                                       "Could not decrypt with any known chip ID.\n"
                                       "Try entering a custom chip ID.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _crypto_auto_detect_and_save(self, in_path, out_path):
        try:
            with open(in_path, 'rb') as f:
                data = f.read()
            results = try_decrypt_all_keys(data)
            if results:
                chip_id, decrypted = results[0]
                self.s.crypto_chip_var.set(chip_id)
                with open(out_path, 'wb') as f:
                    f.write(decrypted)
                try:
                    text = decrypted.decode('utf-8', errors='replace')
                    self.cfg_text.delete('1.0', tk.END)
                    self.cfg_text.insert('1.0', text)
                except Exception:
                    pass
                self.ctrl.log(f"Auto-detected chip: {chip_id}, decrypted {in_path} -> {out_path}")
                messagebox.showinfo("Auto-Detect Success",
                                    f"Detected chip ID: {chip_id}\n"
                                    f"Key: Df7!ui{chip_id}9(lmV1L8\n"
                                    f"Output: {out_path}")
            else:
                messagebox.showwarning("No Match",
                                       "Could not decrypt with any known chip ID.\n"
                                       "Try entering a custom chip ID.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _cfg_load(self):
        path = filedialog.askopenfilename(
            title="Load Config File",
            filetypes=[("XML files", "*.xml"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            parser = CfgFileParser()
            chip_id = self._get_chip_id()
            parser.load(path, chip_id=chip_id)
            self.cfg_text.delete('1.0', tk.END)
            self.cfg_text.insert('1.0', parser.text_content)
            if parser.is_encrypted:
                self.s.crypto_chip_var.set(parser.chip_id)
                self.ctrl.log(f"Loaded encrypted config: {path} (chip: {parser.chip_id})")
            else:
                self.ctrl.log(f"Loaded plaintext config: {path}")
        except Exception as e:
            messagebox.showerror("Load Error", str(e))

    def _cfg_search(self):
        query = self.cfg_search_var.get().strip()
        if not query:
            return
        self.cfg_text.tag_remove('search', '1.0', tk.END)
        start = '1.0'
        count = 0
        while True:
            pos = self.cfg_text.search(query, start, stopindex=tk.END, nocase=True)
            if not pos:
                break
            end = f"{pos}+{len(query)}c"
            self.cfg_text.tag_add('search', pos, end)
            start = end
            count += 1
        self.cfg_text.tag_configure('search', background='#3B82F6', foreground='#FFFFFF')
        if count > 0:
            self.cfg_text.see(self.cfg_text.tag_ranges('search')[0])
        self.ctrl.log(f"Config search '{query}': {count} match(es)")
