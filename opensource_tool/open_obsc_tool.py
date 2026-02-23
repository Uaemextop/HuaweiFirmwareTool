"""
Open OBSC Tool — Open-source ONT firmware flashing tool.

A graphical application for managing and flashing firmware on Huawei ONT
(Optical Network Terminal) devices. Replicates and extends the functionality
of the original OBSCTool.exe and OntSoftwareBroadcaster.exe.

Features:
  - Load and inspect HWNP firmware packages
  - Build custom firmware packages with configurable items
  - Discover ONT devices on the local network via UDP broadcast
  - Flash firmware to individual or all discovered devices
  - Configurable network parameters (port, chunk size, retry interval)
  - Customizable UpgradeCheck.xml hardware validation
  - Firmware item editor (add, remove, modify items)
  - Operation logging with timestamps

Requirements:
  - Python 3.8+
  - tkinter (included with Python on Windows)
  - No external dependencies required

Usage:
  python open_obsc_tool.py
"""

import os
import sys
import json
import time
import struct
import hashlib
import logging
import threading
import tkinter as tk
import tkinter.simpledialog
from tkinter import ttk, filedialog, messagebox, scrolledtext
from pathlib import Path
from datetime import datetime
from typing import Optional

# Import local modules
from hwnp import HwnpFirmware, HwnpItem, create_upgrade_check_xml, HWNP_MAGIC
from obsc_protocol import (
    ObscBroadcaster,
    OntDevice,
    UpgradeProgress,
    DEFAULT_BROADCAST_PORT,
    DEFAULT_CHUNK_SIZE,
    DEFAULT_RETRY_INTERVAL_MS,
)

APP_NAME = "Open OBSC Tool"
APP_VERSION = "1.0.0"
CONFIG_FILE = "open_obsc_config.json"

logger = logging.getLogger(__name__)


class FirmwareInfoFrame(ttk.LabelFrame):
    """Frame displaying firmware package information."""

    def __init__(self, parent):
        super().__init__(parent, text="Firmware Package", padding=5)
        self.firmware: Optional[HwnpFirmware] = None
        self._setup_ui()

    def _setup_ui(self):
        # Info labels
        info_frame = ttk.Frame(self)
        info_frame.pack(fill=tk.X, padx=2, pady=2)

        self.lbl_file = ttk.Label(info_frame, text="No firmware loaded")
        self.lbl_file.pack(anchor=tk.W)

        self.lbl_info = ttk.Label(info_frame, text="")
        self.lbl_info.pack(anchor=tk.W)

        # Items tree
        columns = ("item", "section", "size", "policy", "version")
        self.tree = ttk.Treeview(
            self, columns=columns, show="headings", height=8
        )
        self.tree.heading("item", text="Item Path")
        self.tree.heading("section", text="Section")
        self.tree.heading("size", text="Size")
        self.tree.heading("policy", text="Policy")
        self.tree.heading("version", text="Version")

        self.tree.column("item", width=280)
        self.tree.column("section", width=100)
        self.tree.column("size", width=80, anchor=tk.E)
        self.tree.column("policy", width=60, anchor=tk.CENTER)
        self.tree.column("version", width=160)

        scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(2, 0), pady=2)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 2), pady=2)

    def load_firmware(self, firmware: HwnpFirmware, filename: str = ""):
        """Display firmware information."""
        self.firmware = firmware

        # Clear tree
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Update labels
        self.lbl_file.config(text=f"File: {filename}")
        board_info = firmware.prod_list or "(universal — no board restriction)"
        self.lbl_info.config(
            text=f"Items: {firmware.item_counts} | "
            f"Boards: {board_info}"
        )

        # Populate tree
        for i, item in enumerate(firmware.items):
            policy_str = "Auto-exec" if item.policy == 2 else str(item.policy)
            size_str = self._format_size(len(item.data))
            self.tree.insert(
                "",
                tk.END,
                values=(
                    item.item,
                    item.section,
                    size_str,
                    policy_str,
                    item.version or "—",
                ),
            )

    def clear(self):
        """Clear firmware display."""
        self.firmware = None
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.lbl_file.config(text="No firmware loaded")
        self.lbl_info.config(text="")

    @staticmethod
    def _format_size(size: int) -> str:
        if size >= 1024 * 1024:
            return f"{size / 1024 / 1024:.1f} MB"
        if size >= 1024:
            return f"{size / 1024:.1f} KB"
        return f"{size} B"


class DevicesFrame(ttk.LabelFrame):
    """Frame displaying discovered ONT devices."""

    def __init__(self, parent):
        super().__init__(parent, text="Discovered Devices", padding=5)
        self._setup_ui()

    def _setup_ui(self):
        columns = ("sn", "mac", "ip", "status")
        self.tree = ttk.Treeview(
            self, columns=columns, show="headings", height=5
        )
        self.tree.heading("sn", text="Board SN")
        self.tree.heading("mac", text="MAC Address")
        self.tree.heading("ip", text="IP Address")
        self.tree.heading("status", text="Status")

        self.tree.column("sn", width=200)
        self.tree.column("mac", width=140)
        self.tree.column("ip", width=120)
        self.tree.column("status", width=120)

        scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(2, 0), pady=2)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 2), pady=2)

    def add_device(self, device: OntDevice):
        """Add or update a device in the list."""
        # Check if device already exists
        for child in self.tree.get_children():
            values = self.tree.item(child, "values")
            if values and values[0] == device.board_sn:
                self.tree.item(
                    child,
                    values=(
                        device.board_sn,
                        device.mac,
                        device.ip_address,
                        "Online",
                    ),
                )
                return

        self.tree.insert(
            "",
            tk.END,
            values=(
                device.board_sn,
                device.mac,
                device.ip_address,
                "Online",
            ),
        )

    def get_selected_device(self) -> Optional[str]:
        """Get the IP of the selected device, or None."""
        sel = self.tree.selection()
        if sel:
            values = self.tree.item(sel[0], "values")
            if values:
                return values[2]  # IP address
        return None

    def clear(self):
        for item in self.tree.get_children():
            self.tree.delete(item)


class SettingsFrame(ttk.LabelFrame):
    """Frame for network and upgrade settings."""

    def __init__(self, parent):
        super().__init__(parent, text="Settings", padding=5)
        self._setup_ui()

    def _setup_ui(self):
        row = 0

        # Port
        ttk.Label(self, text="Broadcast Port:").grid(
            row=row, column=0, sticky=tk.W, padx=2, pady=2
        )
        self.var_port = tk.StringVar(value=str(DEFAULT_BROADCAST_PORT))
        self.ent_port = ttk.Entry(self, textvariable=self.var_port, width=8)
        self.ent_port.grid(row=row, column=1, sticky=tk.W, padx=2, pady=2)

        # Chunk size
        ttk.Label(self, text="Chunk Size:").grid(
            row=row, column=2, sticky=tk.W, padx=(10, 2), pady=2
        )
        self.var_chunk = tk.StringVar(value=str(DEFAULT_CHUNK_SIZE))
        self.ent_chunk = ttk.Entry(self, textvariable=self.var_chunk, width=8)
        self.ent_chunk.grid(row=row, column=3, sticky=tk.W, padx=2, pady=2)

        row += 1

        # Retry interval
        ttk.Label(self, text="Retry Interval (ms):").grid(
            row=row, column=0, sticky=tk.W, padx=2, pady=2
        )
        self.var_interval = tk.StringVar(value=str(DEFAULT_RETRY_INTERVAL_MS))
        self.ent_interval = ttk.Entry(self, textvariable=self.var_interval, width=8)
        self.ent_interval.grid(row=row, column=1, sticky=tk.W, padx=2, pady=2)

        # Network interface
        ttk.Label(self, text="Interface:").grid(
            row=row, column=2, sticky=tk.W, padx=(10, 2), pady=2
        )
        self.var_interface = tk.StringVar(value="0.0.0.0")
        interfaces = ObscBroadcaster.get_network_interfaces()
        iface_names = [i["name"] for i in interfaces]
        self.cmb_interface = ttk.Combobox(
            self,
            textvariable=self.var_interface,
            values=iface_names,
            width=25,
            state="readonly",
        )
        self.cmb_interface.grid(row=row, column=3, sticky=tk.W, padx=2, pady=2)
        if iface_names:
            self.cmb_interface.current(0)

        row += 1

        # Board filter
        ttk.Label(self, text="Board Filter:").grid(
            row=row, column=0, sticky=tk.W, padx=2, pady=2
        )
        self.var_board_filter = tk.StringVar(value="")
        self.ent_board_filter = ttk.Entry(
            self, textvariable=self.var_board_filter, width=40
        )
        self.ent_board_filter.grid(
            row=row, column=1, columnspan=3, sticky=tk.EW, padx=2, pady=2
        )

        row += 1

        # UpgradeCheck bypass
        self.var_bypass_checks = tk.BooleanVar(value=True)
        self.chk_bypass = ttk.Checkbutton(
            self,
            text="Bypass all hardware checks (UpgradeCheck.xml)",
            variable=self.var_bypass_checks,
        )
        self.chk_bypass.grid(
            row=row, column=0, columnspan=4, sticky=tk.W, padx=2, pady=2
        )

        self.columnconfigure(3, weight=1)

    def get_port(self) -> int:
        try:
            return int(self.var_port.get())
        except ValueError:
            return DEFAULT_BROADCAST_PORT

    def get_chunk_size(self) -> int:
        try:
            return int(self.var_chunk.get())
        except ValueError:
            return DEFAULT_CHUNK_SIZE

    def get_interval(self) -> int:
        try:
            return int(self.var_interval.get())
        except ValueError:
            return DEFAULT_RETRY_INTERVAL_MS

    def get_interface(self) -> str:
        val = self.var_interface.get()
        # Extract IP from display name if needed
        interfaces = ObscBroadcaster.get_network_interfaces()
        for iface in interfaces:
            if iface["name"] == val:
                return iface["address"]
        return val

    def get_config(self) -> dict:
        return {
            "port": self.get_port(),
            "chunk_size": self.get_chunk_size(),
            "interval": self.get_interval(),
            "interface": self.get_interface(),
            "board_filter": self.var_board_filter.get(),
            "bypass_checks": self.var_bypass_checks.get(),
        }

    def set_config(self, config: dict):
        if "port" in config:
            self.var_port.set(str(config["port"]))
        if "chunk_size" in config:
            self.var_chunk.set(str(config["chunk_size"]))
        if "interval" in config:
            self.var_interval.set(str(config["interval"]))
        if "board_filter" in config:
            self.var_board_filter.set(config["board_filter"])
        if "bypass_checks" in config:
            self.var_bypass_checks.set(config["bypass_checks"])


class OpenObscTool(tk.Tk):
    """Main application window."""

    def __init__(self):
        super().__init__()

        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry("900x750")
        self.minsize(700, 550)

        self.firmware: Optional[HwnpFirmware] = None
        self.firmware_data: Optional[bytes] = None
        self.firmware_path: str = ""
        self.broadcaster: Optional[ObscBroadcaster] = None
        self.current_progress: Optional[UpgradeProgress] = None

        self._setup_ui()
        self._setup_menu()
        self._load_config()
        self._update_button_states()

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _setup_ui(self):
        # Main container
        main = ttk.Frame(self, padding=5)
        main.pack(fill=tk.BOTH, expand=True)

        # Top: Toolbar
        toolbar = ttk.Frame(main)
        toolbar.pack(fill=tk.X, pady=(0, 5))

        self.btn_load = ttk.Button(
            toolbar, text="📂 Load Firmware", command=self._on_load_firmware
        )
        self.btn_load.pack(side=tk.LEFT, padx=2)

        self.btn_build = ttk.Button(
            toolbar, text="🔨 Build Package", command=self._on_build_package
        )
        self.btn_build.pack(side=tk.LEFT, padx=2)

        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(
            side=tk.LEFT, fill=tk.Y, padx=5, pady=2
        )

        self.btn_discover = ttk.Button(
            toolbar, text="🔍 Discover Devices", command=self._on_toggle_discovery
        )
        self.btn_discover.pack(side=tk.LEFT, padx=2)

        self.btn_flash = ttk.Button(
            toolbar, text="⚡ Flash Firmware", command=self._on_flash_firmware
        )
        self.btn_flash.pack(side=tk.LEFT, padx=2)

        self.btn_stop = ttk.Button(
            toolbar, text="⏹ Stop", command=self._on_stop
        )
        self.btn_stop.pack(side=tk.LEFT, padx=2)

        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(
            side=tk.LEFT, fill=tk.Y, padx=5, pady=2
        )

        self.btn_inspect = ttk.Button(
            toolbar, text="🔎 Inspect File", command=self._on_inspect_firmware
        )
        self.btn_inspect.pack(side=tk.LEFT, padx=2)

        self.btn_extract = ttk.Button(
            toolbar, text="📦 Extract Items", command=self._on_extract_items
        )
        self.btn_extract.pack(side=tk.LEFT, padx=2)

        # Middle: Paned window
        paned = ttk.PanedWindow(main, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True)

        # Top pane: Firmware + Settings
        top_frame = ttk.Frame(paned)
        paned.add(top_frame, weight=3)

        # Firmware info
        self.firmware_frame = FirmwareInfoFrame(top_frame)
        self.firmware_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 3))

        # Settings
        self.settings_frame = SettingsFrame(top_frame)
        self.settings_frame.pack(fill=tk.X, pady=(0, 3))

        # Devices
        self.devices_frame = DevicesFrame(top_frame)
        self.devices_frame.pack(fill=tk.BOTH, expand=True)

        # Bottom pane: Log + Progress
        bottom_frame = ttk.Frame(paned)
        paned.add(bottom_frame, weight=2)

        # Progress bar
        progress_frame = ttk.Frame(bottom_frame)
        progress_frame.pack(fill=tk.X, padx=2, pady=2)

        self.lbl_status = ttk.Label(progress_frame, text="Ready")
        self.lbl_status.pack(side=tk.LEFT, padx=2)

        self.progress_bar = ttk.Progressbar(
            progress_frame, mode="determinate", length=200
        )
        self.progress_bar.pack(side=tk.RIGHT, padx=2)

        # Log
        log_frame = ttk.LabelFrame(bottom_frame, text="Log", padding=3)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        self.log_text = scrolledtext.ScrolledText(
            log_frame, height=8, wrap=tk.WORD, state=tk.DISABLED,
            font=("Consolas", 9)
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)

    def _setup_menu(self):
        menubar = tk.Menu(self)
        self.config(menu=menubar)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(
            label="Load Firmware...", command=self._on_load_firmware
        )
        file_menu.add_command(
            label="Build Package...", command=self._on_build_package
        )
        file_menu.add_separator()
        file_menu.add_command(
            label="Inspect Firmware...", command=self._on_inspect_firmware
        )
        file_menu.add_command(
            label="Extract Items...", command=self._on_extract_items
        )
        file_menu.add_separator()
        file_menu.add_command(label="Save Settings", command=self._save_config)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._on_close)

        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(
            label="Generate UpgradeCheck.xml...",
            command=self._on_generate_upgrade_check,
        )
        tools_menu.add_command(
            label="Calculate SHA-256...", command=self._on_calculate_hash
        )

        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self._on_about)

    def _log(self, message: str):
        """Add a timestamped message to the log."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def _update_button_states(self):
        """Update button enabled/disabled states."""
        has_firmware = self.firmware is not None
        is_discovering = self.broadcaster is not None and self.broadcaster._running

        self.btn_flash.config(
            state=tk.NORMAL if has_firmware else tk.DISABLED
        )
        self.btn_extract.config(
            state=tk.NORMAL if has_firmware else tk.DISABLED
        )
        self.btn_discover.config(
            text="⏹ Stop Discovery" if is_discovering else "🔍 Discover Devices"
        )

    def _on_load_firmware(self):
        """Load a HWNP firmware file."""
        path = filedialog.askopenfilename(
            title="Load Firmware Package",
            filetypes=[
                ("Firmware files", "*.bin *.hwnp"),
                ("All files", "*.*"),
            ],
        )
        if not path:
            return

        try:
            with open(path, "rb") as f:
                self.firmware_data = f.read()

            self.firmware = HwnpFirmware.from_bytes(self.firmware_data)
            self.firmware_path = path

            self.firmware_frame.load_firmware(
                self.firmware, os.path.basename(path)
            )

            sha256 = hashlib.sha256(self.firmware_data).hexdigest()
            self._log(
                f"Loaded: {os.path.basename(path)} "
                f"({len(self.firmware_data)} bytes, "
                f"{self.firmware.item_counts} items)"
            )
            self._log(f"SHA-256: {sha256}")
            self._update_button_states()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to load firmware:\n{e}")
            self._log(f"Error loading firmware: {e}")

    def _on_build_package(self):
        """Open the package builder dialog."""
        BuildPackageDialog(self)

    def _on_inspect_firmware(self):
        """Inspect a firmware file without loading it for flashing."""
        path = filedialog.askopenfilename(
            title="Inspect Firmware File",
            filetypes=[
                ("Firmware files", "*.bin *.hwnp *.exe"),
                ("All files", "*.*"),
            ],
        )
        if not path:
            return

        try:
            fw = HwnpFirmware.from_file(path)
            info = fw.summary()
            sha256 = hashlib.sha256(open(path, "rb").read()).hexdigest()
            info += f"\n\nSHA-256: {sha256}"
            info += f"\nFile size: {os.path.getsize(path)} bytes"

            # Show in a dialog
            dialog = tk.Toplevel(self)
            dialog.title(f"Firmware Info — {os.path.basename(path)}")
            dialog.geometry("600x400")

            text = scrolledtext.ScrolledText(
                dialog, wrap=tk.WORD, font=("Consolas", 10)
            )
            text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            text.insert(tk.END, info)
            text.config(state=tk.DISABLED)

            self._log(f"Inspected: {os.path.basename(path)}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to inspect file:\n{e}")

    def _on_extract_items(self):
        """Extract items from loaded firmware to a directory."""
        if not self.firmware:
            messagebox.showwarning("Warning", "No firmware loaded")
            return

        out_dir = filedialog.askdirectory(title="Select Output Directory")
        if not out_dir:
            return

        try:
            for i, item in enumerate(self.firmware.items):
                # Convert firmware path to local path
                name = item.item.replace(":", "_").replace("/", os.sep)
                if name.startswith(os.sep):
                    name = name[1:]
                item_path = os.path.join(out_dir, name)

                os.makedirs(os.path.dirname(item_path), exist_ok=True)
                with open(item_path, "wb") as f:
                    f.write(item.data)

                self._log(
                    f"Extracted [{i}]: {item.item} "
                    f"({len(item.data)} bytes)"
                )

            self._log(
                f"Extracted {len(self.firmware.items)} items to {out_dir}"
            )
            messagebox.showinfo(
                "Success",
                f"Extracted {len(self.firmware.items)} items to:\n{out_dir}",
            )

        except Exception as e:
            messagebox.showerror("Error", f"Failed to extract items:\n{e}")

    def _on_toggle_discovery(self):
        """Toggle device discovery on/off."""
        if self.broadcaster and self.broadcaster._running:
            self.broadcaster.stop()
            self.broadcaster = None
            self._log("Device discovery stopped")
        else:
            config = self.settings_frame.get_config()
            self.broadcaster = ObscBroadcaster(
                broadcast_port=config["port"],
                chunk_size=config["chunk_size"],
                retry_interval_ms=config["interval"],
                bind_address=config["interface"],
            )
            self.broadcaster.set_callbacks(
                on_device_found=self._on_device_found_callback,
                on_log=self._on_log_callback,
            )
            self.broadcaster.start_discovery()
            self._log(
                f"Discovery started on port {config['port']} "
                f"({config['interface']})"
            )

        self._update_button_states()

    def _on_device_found_callback(self, device: OntDevice):
        """Callback when a device is found (from background thread)."""
        self.after(0, self.devices_frame.add_device, device)

    def _on_log_callback(self, message: str):
        """Callback for log messages (from background thread)."""
        self.after(0, self._log, message)

    def _on_progress_callback(self, progress: UpgradeProgress):
        """Callback for progress updates (from background thread)."""
        def update():
            self.progress_bar["value"] = progress.progress_percent
            self.lbl_status.config(
                text=f"{progress.status} — "
                f"{progress.progress_percent:.0f}% "
                f"({progress.elapsed_seconds:.1f}s)"
            )
            if progress.status in ("Complete", "Error"):
                self._update_button_states()

        self.after(0, update)

    def _on_flash_firmware(self):
        """Flash loaded firmware to device(s)."""
        if not self.firmware_data:
            messagebox.showwarning("Warning", "No firmware loaded")
            return

        config = self.settings_frame.get_config()

        # Get target
        selected_ip = self.devices_frame.get_selected_device()
        target = selected_ip or "<broadcast>"

        if target == "<broadcast>":
            if not messagebox.askyesno(
                "Confirm Broadcast",
                "No device selected. Flash firmware to ALL devices "
                "on the network via broadcast?\n\n"
                "This will send the firmware to every ONT device "
                "that can hear the broadcast.",
            ):
                return

        # Create broadcaster if needed
        if not self.broadcaster:
            self.broadcaster = ObscBroadcaster(
                broadcast_port=config["port"],
                chunk_size=config["chunk_size"],
                retry_interval_ms=config["interval"],
                bind_address=config["interface"],
            )
            self.broadcaster.set_callbacks(
                on_log=self._on_log_callback,
                on_progress=self._on_progress_callback,
            )

        self._log(
            f"Flashing firmware ({len(self.firmware_data)} bytes) "
            f"to {target}..."
        )
        self.lbl_status.config(text="Flashing...")
        self.progress_bar["value"] = 0

        self.current_progress = self.broadcaster.send_firmware(
            self.firmware_data, target_address=target
        )

    def _on_stop(self):
        """Stop all operations."""
        if self.broadcaster:
            self.broadcaster.stop()
            self.broadcaster = None
        self.progress_bar["value"] = 0
        self.lbl_status.config(text="Stopped")
        self._log("Operations stopped")
        self._update_button_states()

    def _on_generate_upgrade_check(self):
        """Generate a custom UpgradeCheck.xml."""
        path = filedialog.asksaveasfilename(
            title="Save UpgradeCheck.xml",
            defaultextension=".xml",
            filetypes=[("XML files", "*.xml"), ("All files", "*.*")],
            initialfile="UpgradeCheck.xml",
        )
        if not path:
            return

        xml_data = create_upgrade_check_xml()
        with open(path, "wb") as f:
            f.write(xml_data)

        self._log(f"Generated UpgradeCheck.xml → {path}")
        messagebox.showinfo("Success", f"Saved to:\n{path}")

    def _on_calculate_hash(self):
        """Calculate SHA-256 of a file."""
        path = filedialog.askopenfilename(
            title="Select File",
            filetypes=[("All files", "*.*")],
        )
        if not path:
            return

        with open(path, "rb") as f:
            sha256 = hashlib.sha256(f.read()).hexdigest()

        self._log(f"SHA-256 of {os.path.basename(path)}: {sha256}")
        messagebox.showinfo(
            "SHA-256",
            f"File: {os.path.basename(path)}\n\n"
            f"SHA-256:\n{sha256}",
        )

    def _on_about(self):
        """Show about dialog."""
        messagebox.showinfo(
            "About",
            f"{APP_NAME} v{APP_VERSION}\n\n"
            "Open-source ONT firmware flashing tool.\n\n"
            "Replaces the proprietary OBSCTool.exe and\n"
            "OntSoftwareBroadcaster.exe with an open,\n"
            "configurable alternative.\n\n"
            "Features:\n"
            "• Load/inspect HWNP firmware packages\n"
            "• Build custom firmware packages\n"
            "• Discover ONT devices via UDP broadcast\n"
            "• Flash firmware with configurable parameters\n"
            "• Extract firmware items\n\n"
            "License: Unlicense (Public Domain)",
        )

    def _save_config(self):
        """Save current settings to config file."""
        config = self.settings_frame.get_config()
        try:
            config_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), CONFIG_FILE
            )
            with open(config_path, "w") as f:
                json.dump(config, f, indent=2)
            self._log(f"Settings saved to {CONFIG_FILE}")
        except Exception as e:
            self._log(f"Failed to save settings: {e}")

    def _load_config(self):
        """Load settings from config file."""
        try:
            config_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), CONFIG_FILE
            )
            if os.path.exists(config_path):
                with open(config_path, "r") as f:
                    config = json.load(f)
                self.settings_frame.set_config(config)
                self._log(f"Settings loaded from {CONFIG_FILE}")
        except Exception as e:
            self._log(f"Using default settings ({e})")

    def _on_close(self):
        """Handle window close."""
        self._save_config()
        if self.broadcaster:
            self.broadcaster.stop()
        self.destroy()


class BuildPackageDialog(tk.Toplevel):
    """Dialog for building custom HWNP firmware packages."""

    def __init__(self, parent: OpenObscTool):
        super().__init__(parent)
        self.parent_app = parent
        self.title("Build HWNP Package")
        self.geometry("700x500")
        self.transient(parent)

        self.items: list = []
        self._setup_ui()

    def _setup_ui(self):
        main = ttk.Frame(self, padding=10)
        main.pack(fill=tk.BOTH, expand=True)

        # Board list
        board_frame = ttk.Frame(main)
        board_frame.pack(fill=tk.X, pady=(0, 5))

        ttk.Label(board_frame, text="Board List:").pack(side=tk.LEFT, padx=2)
        self.var_boards = tk.StringVar(value="")
        self.ent_boards = ttk.Entry(
            board_frame, textvariable=self.var_boards, width=60
        )
        self.ent_boards.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)

        # Items
        items_frame = ttk.LabelFrame(main, text="Items", padding=5)
        items_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))

        # Buttons
        btn_frame = ttk.Frame(items_frame)
        btn_frame.pack(fill=tk.X, pady=(0, 5))

        ttk.Button(btn_frame, text="Add File...", command=self._add_item).pack(
            side=tk.LEFT, padx=2
        )
        ttk.Button(
            btn_frame, text="Add UpgradeCheck.xml", command=self._add_upgrade_check
        ).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Remove", command=self._remove_item).pack(
            side=tk.LEFT, padx=2
        )

        # Items list
        columns = ("path", "section", "file", "policy")
        self.tree = ttk.Treeview(
            items_frame, columns=columns, show="headings", height=10
        )
        self.tree.heading("path", text="Target Path")
        self.tree.heading("section", text="Section")
        self.tree.heading("file", text="Local File")
        self.tree.heading("policy", text="Policy")

        self.tree.column("path", width=200)
        self.tree.column("section", width=100)
        self.tree.column("file", width=250)
        self.tree.column("policy", width=60)

        self.tree.pack(fill=tk.BOTH, expand=True)

        # Build button
        build_frame = ttk.Frame(main)
        build_frame.pack(fill=tk.X)

        ttk.Button(
            build_frame, text="Build Package", command=self._build
        ).pack(side=tk.RIGHT, padx=2)
        ttk.Button(build_frame, text="Cancel", command=self.destroy).pack(
            side=tk.RIGHT, padx=2
        )

    def _add_item(self):
        """Add a file as a firmware item."""
        path = filedialog.askopenfilename(
            title="Select File to Include",
            filetypes=[("All files", "*.*")],
        )
        if not path:
            return

        # Simple dialog for target path
        target = tk.simpledialog.askstring(
            "Target Path",
            "Enter the target path on the ONT device:\n"
            "(e.g., file:/var/run.sh or flash:rootfs)",
            initialvalue=f"file:/var/{os.path.basename(path)}",
            parent=self,
        )
        if not target:
            return

        section = tk.simpledialog.askstring(
            "Section",
            "Enter the section type:\n"
            "(e.g., UNKNOWN, UPGRDCHECK, ROOTFS, SIGNATURE, EFS)",
            initialvalue="UNKNOWN",
            parent=self,
        )
        if not section:
            section = "UNKNOWN"

        policy = tk.simpledialog.askinteger(
            "Policy",
            "Enter the policy value:\n"
            "0 = Normal file\n"
            "2 = Auto-execute script",
            initialvalue=0,
            minvalue=0,
            maxvalue=255,
            parent=self,
        )
        if policy is None:
            policy = 0

        self.items.append({
            "target": target,
            "section": section,
            "file": path,
            "policy": policy,
        })

        self.tree.insert(
            "",
            tk.END,
            values=(target, section, os.path.basename(path), policy),
        )

    def _add_upgrade_check(self):
        """Add a default UpgradeCheck.xml item."""
        self.items.append({
            "target": "file:/var/UpgradeCheck.xml",
            "section": "UPGRDCHECK",
            "file": None,  # Will generate
            "policy": 0,
            "data": create_upgrade_check_xml(),
        })

        self.tree.insert(
            "",
            tk.END,
            values=(
                "file:/var/UpgradeCheck.xml",
                "UPGRDCHECK",
                "(generated)",
                0,
            ),
        )

    def _remove_item(self):
        """Remove selected item."""
        sel = self.tree.selection()
        if sel:
            idx = self.tree.index(sel[0])
            self.tree.delete(sel[0])
            if idx < len(self.items):
                self.items.pop(idx)

    def _build(self):
        """Build the HWNP firmware package."""
        if not self.items:
            messagebox.showwarning("Warning", "No items to package")
            return

        path = filedialog.asksaveasfilename(
            title="Save Firmware Package",
            defaultextension=".bin",
            filetypes=[
                ("Firmware files", "*.bin"),
                ("All files", "*.*"),
            ],
        )
        if not path:
            return

        try:
            fw = HwnpFirmware()
            fw.prod_list = self.var_boards.get()

            for i, item_info in enumerate(self.items):
                item = HwnpItem()
                item.iter = i
                item.item = item_info["target"]
                item.section = item_info["section"]
                item.policy = item_info["policy"]

                if "data" in item_info and item_info["data"]:
                    item.data = item_info["data"]
                elif item_info["file"]:
                    with open(item_info["file"], "rb") as f:
                        item.data = f.read()

                fw.items.append(item)

            fw.save(path)

            self.parent_app._log(
                f"Built package: {os.path.basename(path)} "
                f"({len(self.items)} items)"
            )
            messagebox.showinfo("Success", f"Package saved to:\n{path}")
            self.destroy()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to build package:\n{e}")


def main():
    """Application entry point."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    app = OpenObscTool()
    app.mainloop()


if __name__ == "__main__":
    main()
