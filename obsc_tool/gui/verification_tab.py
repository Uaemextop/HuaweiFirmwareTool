"""Verification tab mixin for OBSC Firmware Tool."""

import tkinter as tk
from tkinter import ttk, filedialog


class VerificationTabMixin:
    """Mixin providing the Verification tab and related methods."""

    def _build_verification_tab(self):
        """Build the signature and verification configuration tab."""
        tab = self.tab_verify

        # ── CRC32 Verification ───────────────────────────────────
        crc_frame = ttk.LabelFrame(tab, text="CRC32 Integrity Verification", padding=10)
        crc_frame.pack(fill=tk.X, pady=(0, 10))

        self.verify_crc32_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            crc_frame, text="Verify CRC32 checksums before flashing",
            variable=self.verify_crc32_var,
        ).pack(fill=tk.X, pady=2)

        ttk.Label(crc_frame,
                  text="When enabled, the tool validates the HWNP header and data CRC32\n"
                       "checksums before starting the transfer. Disable only if you are\n"
                       "working with modified/custom firmware packages.",
                  font=('Segoe UI', 8), justify=tk.LEFT,
                  ).pack(fill=tk.X, pady=(2, 0))

        # ── HWNP Signature Verification ──────────────────────────
        sig_frame = ttk.LabelFrame(tab, text="HWNP Signature Verification", padding=10)
        sig_frame.pack(fill=tk.X, pady=(0, 10))

        self.verify_signature_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            sig_frame, text="Verify RSA signature before flashing",
            variable=self.verify_signature_var,
        ).pack(fill=tk.X, pady=2)

        row = ttk.Frame(sig_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Public Key File:", width=16).pack(side=tk.LEFT)
        self.pubkey_path_var = tk.StringVar(value="")
        ttk.Entry(row, textvariable=self.pubkey_path_var, width=40).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(row, text="Browse", command=self._browse_pubkey, width=8).pack(side=tk.LEFT)

        ttk.Label(sig_frame,
                  text="Huawei HWNP firmware packages may include an RSA signature\n"
                       "(SIGNINFO section). If you have the public key, enable this to\n"
                       "verify the firmware authenticity before flashing.",
                  font=('Segoe UI', 8), justify=tk.LEFT,
                  ).pack(fill=tk.X, pady=(2, 0))

        # ── Product Compatibility Check ──────────────────────────
        prod_frame = ttk.LabelFrame(tab, text="Product Compatibility Check", padding=10)
        prod_frame.pack(fill=tk.X, pady=(0, 10))

        self.skip_product_check_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            prod_frame, text="Skip product compatibility check (dangerous)",
            variable=self.skip_product_check_var,
        ).pack(fill=tk.X, pady=2)

        ttk.Label(prod_frame,
                  text="HWNP firmware includes a product list specifying compatible\n"
                       "hardware. Skipping this check allows flashing firmware to\n"
                       "potentially incompatible devices. Use with extreme caution.",
                  font=('Segoe UI', 8), justify=tk.LEFT,
                  ).pack(fill=tk.X, pady=(2, 0))

        # ── Pre-Flash Verification ───────────────────────────────
        preflash_frame = ttk.LabelFrame(tab, text="Pre-Flash Verification", padding=10)
        preflash_frame.pack(fill=tk.X, pady=(0, 10))

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
                  text="These options run additional checks on the firmware before\n"
                       "starting the transfer. Dry run mode performs all steps except\n"
                       "actually sending data, useful for testing configuration.",
                  font=('Segoe UI', 8), justify=tk.LEFT,
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
