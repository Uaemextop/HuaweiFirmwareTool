"""Verification tab — pre-flash checks UI."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk, filedialog
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hwflash.ui.state import AppState, AppController
    from hwflash.shared.styles import ThemeEngine


class VerifyTab(ttk.Frame):
    """Pre-flash verification options."""

    def __init__(self, parent, state: AppState, ctrl: AppController,
                 engine: ThemeEngine, **kwargs):
        super().__init__(parent, padding=6, **kwargs)
        self.s = state
        self.ctrl = ctrl
        self.engine = engine
        self._build()

    def _build(self):
        s = self.s

        # CRC32
        crc_frame = ttk.LabelFrame(self, text="CRC32 Integrity Verification", padding=6)
        crc_frame.pack(fill=tk.X, pady=(0, 6))

        ttk.Checkbutton(
            crc_frame, text="Verify CRC32 checksums before flashing",
            variable=s.verify_crc32_var,
        ).pack(fill=tk.X, pady=2)

        ttk.Label(crc_frame,
                  text="Validates HWNP header and data CRC32 before transfer. "
                       "Disable only for modified/custom firmware.",
                  font=('Segoe UI', 8), justify=tk.LEFT, wraplength=700,
                  ).pack(fill=tk.X, pady=(2, 0))

        # Signature
        sig_frame = ttk.LabelFrame(self, text="HWNP Signature Verification", padding=6)
        sig_frame.pack(fill=tk.X, pady=(0, 6))

        ttk.Checkbutton(
            sig_frame, text="Verify RSA signature before flashing",
            variable=s.verify_signature_var,
        ).pack(fill=tk.X, pady=2)

        row = ttk.Frame(sig_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Public Key File:", width=14).pack(side=tk.LEFT)
        ttk.Entry(row, textvariable=s.pubkey_path_var, width=38).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(row, text="Browse", command=self._browse_pubkey, width=8).pack(side=tk.LEFT)

        ttk.Label(sig_frame,
                  text="HWNP firmware may include an RSA signature (SIGNINFO). "
                       "If you have the public key, enable this to verify authenticity.",
                  font=('Segoe UI', 8), justify=tk.LEFT, wraplength=700,
                  ).pack(fill=tk.X, pady=(2, 0))

        # Product compatibility
        prod_frame = ttk.LabelFrame(self, text="Product Compatibility Check", padding=6)
        prod_frame.pack(fill=tk.X, pady=(0, 6))

        ttk.Checkbutton(
            prod_frame, text="Skip product compatibility check (dangerous)",
            variable=s.skip_product_check_var,
        ).pack(fill=tk.X, pady=2)

        ttk.Label(prod_frame,
                  text="Firmware includes a product list of compatible hardware. "
                       "Skipping allows flashing to potentially incompatible devices.",
                  font=('Segoe UI', 8), justify=tk.LEFT, wraplength=700,
                  ).pack(fill=tk.X, pady=(2, 0))

        # Pre-flash
        preflash_frame = ttk.LabelFrame(self, text="Pre-Flash Verification", padding=6)
        preflash_frame.pack(fill=tk.X, pady=(0, 6))

        ttk.Checkbutton(
            preflash_frame, text="Verify individual item CRC32 checksums",
            variable=s.verify_item_crc_var,
        ).pack(fill=tk.X, pady=2)

        ttk.Checkbutton(
            preflash_frame, text="Verify firmware file size matches header",
            variable=s.verify_size_var,
        ).pack(fill=tk.X, pady=2)

        ttk.Checkbutton(
            preflash_frame, text="Dry run mode (validate only, do not flash)",
            variable=s.dry_run_var,
        ).pack(fill=tk.X, pady=2)

        ttk.Label(preflash_frame,
                  text="Additional checks before transfer. Dry run performs all "
                       "steps except sending data — useful for testing configuration.",
                  font=('Segoe UI', 8), justify=tk.LEFT, wraplength=700,
                  ).pack(fill=tk.X, pady=(2, 0))

    def _browse_pubkey(self):
        path = filedialog.askopenfilename(
            title="Select Public Key File",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")],
        )
        if path:
            self.s.pubkey_path_var.set(path)
