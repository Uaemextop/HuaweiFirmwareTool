"""Presets tab mixin for HuaweiFlash."""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

from hwflash.shared.helpers import safe_int as _safe_int
from hwflash.core.presets import PRESET_TEMPLATE
from hwflash.core.protocol import OBSC_SEND_PORT, OBSC_RECV_PORT


class PresetsTabMixin:
    """Mixin providing the Presets tab and related methods."""

    NEW_PRESET_LABEL = "\u2795 New Preset..."

    def _build_presets_tab(self):
        """Build the router presets management tab."""
        tab = self.tab_presets

        # ── Preset Selection ─────────────────────────────────────
        select_frame = ttk.LabelFrame(tab, text="Router Presets", padding=10)
        select_frame.pack(fill=tk.X, pady=(0, 10))
        self.preset_select_frame = select_frame  # Store ref for pack(after=) in siblings

        row = ttk.Frame(select_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Select Preset:", width=16).pack(side=tk.LEFT)
        self.preset_var = tk.StringVar()
        self.preset_combo = ttk.Combobox(
            row, textvariable=self.preset_var,
            state='readonly', width=35,
        )
        self.preset_combo.pack(side=tk.LEFT, padx=(0, 5))
        self.preset_load_btn = ttk.Button(row, text="Load", command=self._load_preset, width=8)
        self.preset_load_btn.pack(side=tk.LEFT, padx=2)
        self.preset_edit_btn = ttk.Button(row, text="Load to Editor", command=self._load_preset_into_editor, width=14)
        self.preset_edit_btn.pack(side=tk.LEFT, padx=2)
        self.preset_delete_btn = ttk.Button(row, text="Delete", command=self._delete_preset, width=8)
        self.preset_delete_btn.pack(side=tk.LEFT, padx=2)

        # Preset description
        self.preset_desc_var = tk.StringVar(value="Select a preset to see its description")
        ttk.Label(select_frame, textvariable=self.preset_desc_var,
                  font=('Segoe UI', 9), wraplength=600).pack(fill=tk.X, pady=(5, 0))

        self.preset_combo.bind('<<ComboboxSelected>>', self._on_preset_selected)

        # ── Create / Edit Preset (hidden by default) ─────────────
        self.preset_create_frame = ttk.LabelFrame(tab, text="Create / Edit Preset", padding=10)
        # NOT packed yet — shown only when "New Preset..." is selected

        # --- Row: Name + Model ---
        row = ttk.Frame(self.preset_create_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Preset Name:", width=16).pack(side=tk.LEFT)
        self.new_preset_name_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.new_preset_name_var, width=24).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Label(row, text="Router Model:", width=14).pack(side=tk.LEFT)
        self.new_preset_model_var = tk.StringVar(value="HG8145V5")
        ttk.Combobox(
            row, textvariable=self.new_preset_model_var,
            values=["HG8145V5", "HG8245H", "HG8546M", "HG8245Q2",
                     "HG8045Q", "EG8145V5", "HN8245Q", "Custom"],
            width=14,
        ).pack(side=tk.LEFT)

        # --- Row: Description ---
        row = ttk.Frame(self.preset_create_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Description:", width=16).pack(side=tk.LEFT)
        self.new_preset_desc_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.new_preset_desc_var, width=60).pack(side=tk.LEFT, fill=tk.X, expand=True)

        # --- Transfer Settings ---
        tsf = ttk.LabelFrame(self.preset_create_frame, text="Transfer Settings", padding=4)
        tsf.pack(fill=tk.X, pady=(4, 2))

        r1 = ttk.Frame(tsf)
        r1.pack(fill=tk.X, pady=1)
        ttk.Label(r1, text="Frame Size:", width=14).pack(side=tk.LEFT)
        self.np_frame_size_var = tk.StringVar(value="1400")
        ttk.Combobox(r1, textvariable=self.np_frame_size_var,
                     values=["1200", "1400", "1472", "4096", "8192"],
                     state='readonly', width=8).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(r1, text="Interval (ms):", width=12).pack(side=tk.LEFT)
        self.np_frame_interval_var = tk.StringVar(value="5")
        ttk.Combobox(r1, textvariable=self.np_frame_interval_var,
                     values=["1", "2", "5", "10", "20", "50"],
                     state='readonly', width=6).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(r1, text="Flash Mode:", width=10).pack(side=tk.LEFT)
        self.np_flash_mode_var = tk.StringVar(value="Normal")
        ttk.Combobox(r1, textvariable=self.np_flash_mode_var,
                     values=["Normal", "Forced"], state='readonly',
                     width=8).pack(side=tk.LEFT)

        r2 = ttk.Frame(tsf)
        r2.pack(fill=tk.X, pady=1)
        ttk.Label(r2, text="Upgrade Type:", width=14).pack(side=tk.LEFT)
        self.np_upgrade_type_var = tk.StringVar(value="Standard")
        ttk.Combobox(r2, textvariable=self.np_upgrade_type_var,
                     values=["Standard", "Equipment", "Equipment WC"],
                     state='readonly', width=14).pack(side=tk.LEFT, padx=(0, 10))
        self.np_delete_cfg_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(r2, text="Delete existing config",
                        variable=self.np_delete_cfg_var).pack(side=tk.LEFT)

        # --- Network Settings ---
        nsf = ttk.LabelFrame(self.preset_create_frame, text="Network Settings", padding=4)
        nsf.pack(fill=tk.X, pady=(2, 2))

        r3 = ttk.Frame(nsf)
        r3.pack(fill=tk.X, pady=1)
        ttk.Label(r3, text="Send Port:", width=14).pack(side=tk.LEFT)
        self.np_send_port_var = tk.StringVar(value="50000")
        ttk.Combobox(r3, textvariable=self.np_send_port_var,
                     values=["50000", "50002", "50010"],
                     width=8).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(r3, text="Recv Port:", width=10).pack(side=tk.LEFT)
        self.np_recv_port_var = tk.StringVar(value="50001")
        ttk.Combobox(r3, textvariable=self.np_recv_port_var,
                     values=["50001", "50003", "50011"],
                     width=8).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(r3, text="Broadcast:", width=10).pack(side=tk.LEFT)
        self.np_broadcast_var = tk.StringVar(value="auto")
        ttk.Combobox(r3, textvariable=self.np_broadcast_var,
                     values=["auto", "255.255.255.255", "192.168.100.255"],
                     width=16).pack(side=tk.LEFT)

        r4 = ttk.Frame(nsf)
        r4.pack(fill=tk.X, pady=1)
        ttk.Label(r4, text="Timeout (s):", width=14).pack(side=tk.LEFT)
        self.np_timeout_var = tk.StringVar(value="600")
        ttk.Combobox(r4, textvariable=self.np_timeout_var,
                     values=["300", "600", "900", "1200", "1800"],
                     width=8).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(r4, text="Machine Filter:", width=12).pack(side=tk.LEFT)
        self.np_machine_filter_var = tk.StringVar(value="")
        ttk.Entry(r4, textvariable=self.np_machine_filter_var, width=18).pack(side=tk.LEFT)

        # --- Advanced Settings ---
        asf = ttk.LabelFrame(self.preset_create_frame, text="Advanced / Verification", padding=4)
        asf.pack(fill=tk.X, pady=(2, 2))

        r5 = ttk.Frame(asf)
        r5.pack(fill=tk.X, pady=1)
        ttk.Label(r5, text="Discovery (s):", width=14).pack(side=tk.LEFT)
        self.np_discovery_var = tk.StringVar(value="10")
        ttk.Combobox(r5, textvariable=self.np_discovery_var,
                     values=["5", "10", "15", "20", "30", "60"],
                     state='readonly', width=6).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(r5, text="Ctrl Retries:", width=10).pack(side=tk.LEFT)
        self.np_ctrl_retries_var = tk.StringVar(value="3")
        ttk.Combobox(r5, textvariable=self.np_ctrl_retries_var,
                     values=["1", "2", "3", "5", "10"],
                     state='readonly', width=5).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(r5, text="Data Retries:", width=10).pack(side=tk.LEFT)
        self.np_data_retries_var = tk.StringVar(value="0")
        ttk.Combobox(r5, textvariable=self.np_data_retries_var,
                     values=["0", "1", "2", "3"],
                     state='readonly', width=5).pack(side=tk.LEFT)

        r6 = ttk.Frame(asf)
        r6.pack(fill=tk.X, pady=1)
        self.np_verify_crc_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(r6, text="Verify CRC32", variable=self.np_verify_crc_var).pack(side=tk.LEFT, padx=(0, 12))
        self.np_verify_sig_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(r6, text="Verify Signature", variable=self.np_verify_sig_var).pack(side=tk.LEFT, padx=(0, 12))
        self.np_skip_product_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(r6, text="Skip Product Check", variable=self.np_skip_product_var).pack(side=tk.LEFT)

        r7 = ttk.Frame(asf)
        r7.pack(fill=tk.X, pady=1)
        ttk.Label(r7, text="Check Policy:", width=16).pack(side=tk.LEFT)
        self.np_check_policy_var = tk.StringVar(value="")
        ttk.Entry(r7, textvariable=self.np_check_policy_var, width=16).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Label(r7, text="BOM Code:", width=12).pack(side=tk.LEFT)
        self.np_bom_code_var = tk.StringVar(value="")
        ttk.Entry(r7, textvariable=self.np_bom_code_var, width=16).pack(side=tk.LEFT)

        # --- Action Buttons ---
        btn_row = ttk.Frame(self.preset_create_frame)
        btn_row.pack(fill=tk.X, pady=(8, 0))
        ttk.Button(btn_row, text="💾 Save Preset",
                   command=self._save_preset, width=16).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_row, text="📋 Copy Current Settings",
                   command=self._copy_current_to_preset_editor, width=22).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_row, text="🔄 Reset Fields",
                   command=self._reset_preset_editor, width=14).pack(side=tk.LEFT)

        # ── Preset Details (shown when an existing preset is selected) ──
        self.preset_details_frame = ttk.LabelFrame(tab, text="Preset Details", padding=10)
        self.preset_details_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))

        self.preset_details_text = scrolledtext.ScrolledText(
            self.preset_details_frame, wrap=tk.WORD,
            font=('Consolas', 9),
            state='disabled', height=10,
        )
        self.preset_details_text.pack(fill=tk.BOTH, expand=True)

        # Populate preset list (must be after all widgets are created)
        self._refresh_preset_list()

    # ── Preset Management ────────────────────────────────────────

    def _refresh_preset_list(self):
        """Refresh the preset combobox values with New Preset option."""
        names = [self.NEW_PRESET_LABEL] + self.preset_manager.list_presets()
        self.preset_combo['values'] = names
        if len(names) > 1:
            self.preset_combo.current(1)
            self._on_preset_selected(None)
        else:
            self.preset_combo.current(0)
            self._on_preset_selected(None)

    def _on_preset_selected(self, event):
        """Handle preset selection — show editor or details panel."""
        name = self.preset_var.get()

        if name == self.NEW_PRESET_LABEL:
            # Show create/edit form, hide details panel
            self.preset_create_frame.pack(fill=tk.X, pady=(0, 10),
                                          after=self.preset_select_frame)
            self.preset_details_frame.pack_forget()
            self.preset_load_btn.configure(state='disabled')
            self.preset_edit_btn.configure(state='disabled')
            self.preset_delete_btn.configure(state='disabled')
            self.preset_desc_var.set("Fill in the fields below to create a new preset")
            self._reset_preset_editor()
            return

        # Existing preset selected — hide editor, show details
        self.preset_create_frame.pack_forget()
        self.preset_details_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        self.preset_load_btn.configure(state='normal')
        self.preset_edit_btn.configure(state='normal')
        builtin = self.preset_manager.is_builtin(name)
        self.preset_delete_btn.configure(state='disabled' if builtin else 'normal')

        preset = self.preset_manager.get_preset(name)
        if preset:
            self.preset_desc_var.set(preset.get('description', 'No description'))
            lines = []
            for key, val in sorted(preset.items()):
                if key.startswith('_'):
                    continue
                lines.append(f"  {key:25s} = {val}")
            self.preset_details_text.configure(state='normal')
            self.preset_details_text.delete('1.0', tk.END)
            self.preset_details_text.insert('1.0', f"Preset: {name}\n{'=' * 50}\n" + '\n'.join(lines))
            self.preset_details_text.configure(state='disabled')

    def _load_preset(self):
        """Load the selected preset into the current settings."""
        name = self.preset_var.get()
        if not name or name == self.NEW_PRESET_LABEL:
            messagebox.showwarning("No Preset", "Please select a preset first.")
            return

        preset = self.preset_manager.get_preset(name)
        if not preset:
            return

        # Apply preset to all settings
        self.frame_size_var.set(str(preset.get('frame_size', 1400)))
        self.frame_interval_var.set(str(preset.get('frame_interval_ms', 5)))
        self.flash_mode_var.set(preset.get('flash_mode', 'Normal'))
        self.delete_cfg_var.set(preset.get('delete_cfg', False))
        self.upgrade_type_var.set(preset.get('upgrade_type', 'Standard'))
        self.send_port_var.set(str(preset.get('send_port', OBSC_SEND_PORT)))
        self.recv_port_var.set(str(preset.get('recv_port', OBSC_RECV_PORT)))
        self.timeout_var.set(str(preset.get('timeout', 600)))
        self.machine_filter_var.set(preset.get('machine_filter', ''))
        self.broadcast_var.set(preset.get('broadcast_address', 'auto'))
        self.verify_crc32_var.set(preset.get('verify_crc32', True))
        self.verify_signature_var.set(preset.get('verify_signature', False))
        self.skip_product_check_var.set(preset.get('skip_product_check', False))
        self.discovery_duration_var.set(str(preset.get('discovery_duration', 10)))
        self.ctrl_retries_var.set(str(preset.get('ctrl_retries', 3)))
        self.data_retries_var.set(str(preset.get('data_retries', 0)))
        self.check_policy_var.set(preset.get('check_policy', ''))
        self.bom_code_var.set(preset.get('bom_code', ''))

        self._log(f"Loaded preset: {name}")
        messagebox.showinfo("Preset Loaded", f"Loaded preset: {name}")

    def _save_preset(self):
        """Save the preset editor fields as a new preset."""
        name = self.new_preset_name_var.get().strip()
        if not name:
            messagebox.showwarning("No Name", "Please enter a preset name.")
            return

        if self.preset_manager.is_builtin(name):
            messagebox.showwarning("Built-in Preset",
                                   "Cannot overwrite a built-in preset. Choose a different name.")
            return

        model = self.new_preset_model_var.get() or "Custom"
        description = self.new_preset_desc_var.get() or f"Custom preset for {model}"
        preset_data = {
            'model': model,
            'description': description,
            'frame_size': _safe_int(self.np_frame_size_var.get(), 1400),
            'frame_interval_ms': _safe_int(self.np_frame_interval_var.get(), 5),
            'flash_mode': self.np_flash_mode_var.get(),
            'delete_cfg': self.np_delete_cfg_var.get(),
            'upgrade_type': self.np_upgrade_type_var.get(),
            'send_port': _safe_int(self.np_send_port_var.get(), 50000),
            'recv_port': _safe_int(self.np_recv_port_var.get(), 50001),
            'timeout': _safe_int(self.np_timeout_var.get(), 600),
            'machine_filter': self.np_machine_filter_var.get(),
            'broadcast_address': self.np_broadcast_var.get(),
            'verify_crc32': self.np_verify_crc_var.get(),
            'verify_signature': self.np_verify_sig_var.get(),
            'skip_product_check': self.np_skip_product_var.get(),
            'discovery_duration': _safe_int(self.np_discovery_var.get(), 10),
            'ctrl_retries': _safe_int(self.np_ctrl_retries_var.get(), 3),
            'data_retries': _safe_int(self.np_data_retries_var.get(), 0),
            'check_policy': self.np_check_policy_var.get(),
            'bom_code': self.np_bom_code_var.get(),
        }

        self.preset_manager.save_preset(name, preset_data)
        self._refresh_preset_list()
        # Select the newly saved preset and show its details
        try:
            idx = list(self.preset_combo['values']).index(name)
            self.preset_combo.current(idx)
            self._on_preset_selected(None)
        except ValueError:
            pass
        self._log(f"Saved preset: {name}")
        messagebox.showinfo("Preset Saved", f"Preset '{name}' saved successfully.")

    def _delete_preset(self):
        """Delete the selected preset."""
        name = self.preset_var.get()
        if not name:
            return

        if self.preset_manager.is_builtin(name):
            messagebox.showwarning("Built-in Preset",
                                   "Cannot delete built-in presets.")
            return

        if messagebox.askyesno("Delete Preset", f"Delete preset '{name}'?"):
            if self.preset_manager.delete_preset(name):
                self._refresh_preset_list()
                self._log(f"Deleted preset: {name}")

    def _copy_current_to_preset_editor(self):
        """Copy the current Upgrade/Settings values into the preset editor fields."""
        self.np_frame_size_var.set(self.frame_size_var.get())
        self.np_frame_interval_var.set(self.frame_interval_var.get())
        self.np_flash_mode_var.set(self.flash_mode_var.get())
        self.np_delete_cfg_var.set(self.delete_cfg_var.get())
        self.np_upgrade_type_var.set(self.upgrade_type_var.get())
        self.np_send_port_var.set(self.send_port_var.get())
        self.np_recv_port_var.set(self.recv_port_var.get())
        self.np_timeout_var.set(self.timeout_var.get())
        self.np_machine_filter_var.set(self.machine_filter_var.get())
        self.np_broadcast_var.set(self.broadcast_var.get())
        self.np_verify_crc_var.set(self.verify_crc32_var.get())
        self.np_verify_sig_var.set(self.verify_signature_var.get())
        self.np_skip_product_var.set(self.skip_product_check_var.get())
        self.np_discovery_var.set(self.discovery_duration_var.get())
        self.np_ctrl_retries_var.set(self.ctrl_retries_var.get())
        self.np_data_retries_var.set(self.data_retries_var.get())
        self.np_check_policy_var.set(self.check_policy_var.get())
        self.np_bom_code_var.set(self.bom_code_var.get())
        self._log("Copied current settings to preset editor")

    def _reset_preset_editor(self):
        """Reset the preset editor fields to default values."""
        tmpl = PRESET_TEMPLATE
        self.new_preset_name_var.set("")
        self.new_preset_model_var.set("HG8145V5")
        self.new_preset_desc_var.set("")
        self.np_frame_size_var.set(str(tmpl['frame_size']))
        self.np_frame_interval_var.set(str(tmpl['frame_interval_ms']))
        self.np_flash_mode_var.set(tmpl['flash_mode'])
        self.np_delete_cfg_var.set(tmpl['delete_cfg'])
        self.np_upgrade_type_var.set(tmpl['upgrade_type'])
        self.np_send_port_var.set(str(tmpl['send_port']))
        self.np_recv_port_var.set(str(tmpl['recv_port']))
        self.np_timeout_var.set(str(tmpl['timeout']))
        self.np_machine_filter_var.set(tmpl['machine_filter'])
        self.np_broadcast_var.set(tmpl['broadcast_address'])
        self.np_verify_crc_var.set(tmpl['verify_crc32'])
        self.np_verify_sig_var.set(tmpl['verify_signature'])
        self.np_skip_product_var.set(tmpl['skip_product_check'])
        self.np_discovery_var.set(str(tmpl['discovery_duration']))
        self.np_ctrl_retries_var.set(str(tmpl['ctrl_retries']))
        self.np_data_retries_var.set(str(tmpl['data_retries']))
        self.np_check_policy_var.set(tmpl['check_policy'])
        self.np_bom_code_var.set(tmpl['bom_code'])

    def _load_preset_into_editor(self):
        """Load the selected preset into the preset editor for editing."""
        name = self.preset_var.get()
        if not name or name == self.NEW_PRESET_LABEL:
            return
        preset = self.preset_manager.get_preset(name)
        if not preset:
            return
        # Show the editor frame
        self.preset_create_frame.pack(fill=tk.X, pady=(0, 10),
                                      after=self.preset_select_frame)
        self.preset_details_frame.pack_forget()
        # Don't overwrite name for built-ins (user should rename)
        if not self.preset_manager.is_builtin(name):
            self.new_preset_name_var.set(name)
        else:
            self.new_preset_name_var.set(name + " (copy)")
        self.new_preset_model_var.set(preset.get('model', 'Custom'))
        self.new_preset_desc_var.set(preset.get('description', ''))
        self.np_frame_size_var.set(str(preset.get('frame_size', 1400)))
        self.np_frame_interval_var.set(str(preset.get('frame_interval_ms', 5)))
        self.np_flash_mode_var.set(preset.get('flash_mode', 'Normal'))
        self.np_delete_cfg_var.set(preset.get('delete_cfg', False))
        self.np_upgrade_type_var.set(preset.get('upgrade_type', 'Standard'))
        self.np_send_port_var.set(str(preset.get('send_port', 50000)))
        self.np_recv_port_var.set(str(preset.get('recv_port', 50001)))
        self.np_timeout_var.set(str(preset.get('timeout', 600)))
        self.np_machine_filter_var.set(preset.get('machine_filter', ''))
        self.np_broadcast_var.set(preset.get('broadcast_address', 'auto'))
        self.np_verify_crc_var.set(preset.get('verify_crc32', True))
        self.np_verify_sig_var.set(preset.get('verify_signature', False))
        self.np_skip_product_var.set(preset.get('skip_product_check', False))
        self.np_discovery_var.set(str(preset.get('discovery_duration', 10)))
        self.np_ctrl_retries_var.set(str(preset.get('ctrl_retries', 3)))
        self.np_data_retries_var.set(str(preset.get('data_retries', 0)))
        self.np_check_policy_var.set(preset.get('check_policy', ''))
        self.np_bom_code_var.set(preset.get('bom_code', ''))
        self._log(f"Loaded preset '{name}' into editor")

    def _gather_current_settings(self):
        """Gather all current settings into a dict."""
        return {
            'frame_size': _safe_int(self.frame_size_var.get(), 1400),
            'frame_interval_ms': _safe_int(self.frame_interval_var.get(), 5),
            'flash_mode': self.flash_mode_var.get(),
            'delete_cfg': self.delete_cfg_var.get(),
            'upgrade_type': self.upgrade_type_var.get(),
            'send_port': _safe_int(self.send_port_var.get(), 50000),
            'recv_port': _safe_int(self.recv_port_var.get(), 50001),
            'timeout': _safe_int(self.timeout_var.get(), 600),
            'machine_filter': self.machine_filter_var.get(),
            'broadcast_address': self.broadcast_var.get(),
            'verify_crc32': self.verify_crc32_var.get(),
            'verify_signature': self.verify_signature_var.get(),
            'skip_product_check': self.skip_product_check_var.get(),
            'discovery_duration': _safe_int(self.discovery_duration_var.get(), 10),
            'ctrl_retries': _safe_int(self.ctrl_retries_var.get(), 3),
            'data_retries': _safe_int(self.data_retries_var.get(), 0),
            'check_policy': self.check_policy_var.get(),
            'bom_code': self.bom_code_var.get(),
        }
