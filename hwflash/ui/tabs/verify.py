"""Verification tab mixin for HuaweiFlash."""

import tkinter as tk
from tkinter import ttk, filedialog


class VerificationTabMixin:
    """Mixin providing the Verification tab and related methods."""

    def _build_verification_tab(self):
        tab = self.tab_verify

        # CRC32
        crc_frame = ttk.LabelFrame(tab, text="CRC32 Integrity Verification", padding=6)
        crc_frame.pack(fill=tk.X, pady=(0, 6))

        self.verify_crc32_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            crc_frame, text="Verify CRC32 checksums before flashing",
            variable=self.verify_crc32_var,
        ).pack(fill=tk.X, pady=2)

        ttk.Label(crc_frame,
                  text="Validates HWNP header and data CRC32 before transfer. "
                       "Disable only for modified/custom firmware.",
                  font=('Segoe UI', 8), justify=tk.LEFT, wraplength=700,
                  ).pack(fill=tk.X, pady=(2, 0))

        # Signature
        sig_frame = ttk.LabelFrame(tab, text="HWNP Signature Verification", padding=6)
        sig_frame.pack(fill=tk.X, pady=(0, 6))

        self.verify_signature_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            sig_frame, text="Verify RSA signature before flashing",
            variable=self.verify_signature_var,
        ).pack(fill=tk.X, pady=2)

        row = ttk.Frame(sig_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Public Key File:", width=14).pack(side=tk.LEFT)
        self.pubkey_path_var = tk.StringVar(value="")
        ttk.Entry(row, textvariable=self.pubkey_path_var, width=38).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(row, text="Browse", command=self._browse_pubkey, width=8).pack(side=tk.LEFT)

        ttk.Label(sig_frame,
                  text="HWNP firmware may include an RSA signature (SIGNINFO). "
                       "If you have the public key, enable this to verify authenticity.",
                  font=('Segoe UI', 8), justify=tk.LEFT, wraplength=700,
                  ).pack(fill=tk.X, pady=(2, 0))

        # Product compatibility
        prod_frame = ttk.LabelFrame(tab, text="Product Compatibility Check", padding=6)
        prod_frame.pack(fill=tk.X, pady=(0, 6))

        self.skip_product_check_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            prod_frame, text="Skip product compatibility check (dangerous)",
            variable=self.skip_product_check_var,
        ).pack(fill=tk.X, pady=2)

        ttk.Label(prod_frame,
                  text="Firmware includes a product list of compatible hardware. "
                       "Skipping allows flashing to potentially incompatible devices.",
                  font=('Segoe UI', 8), justify=tk.LEFT, wraplength=700,
                  ).pack(fill=tk.X, pady=(2, 0))

        # Pre-flash
        preflash_frame = ttk.LabelFrame(tab, text="Pre-Flash Verification", padding=6)
        preflash_frame.pack(fill=tk.X, pady=(0, 6))

        self.verify_item_crc_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            preflash_frame, text="Verify individual item CRC32 checksums",
            variable=self.verify_item_crc_var,
        ).pack(fill=tk.X, pady=2)

        self.verify_size_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            preflash_frame, text="Verify firmware file size matches header",
            variable=self.verify_size_var,
        ).pack(fill=tk.X, pady=2)

        self.dry_run_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            preflash_frame, text="Dry run mode (validate only, do not flash)",
            variable=self.dry_run_var,
        ).pack(fill=tk.X, pady=2)

        ttk.Label(preflash_frame,
                  text="Additional checks before transfer. Dry run performs all "
                       "steps except sending data — useful for testing configuration.",
                  font=('Segoe UI', 8), justify=tk.LEFT, wraplength=700,
                  ).pack(fill=tk.X, pady=(2, 0))

    # ── Verification Helpers ─────────────────────────────────────

    def _browse_pubkey(self):
        """Browse for RSA public key file."""
        path = filedialog.askopenfilename(
            title="Select Public Key File",
            filetypes=[
                ("PEM files", "*.pem"),
                ("All files", "*.*"),
            ],
        )
        if path:
            self.pubkey_path_var.set(path)
