"""Terminal tab — LAN (Telnet) connection to ONT."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from typing import TYPE_CHECKING

from hwflash.shared.helpers import safe_int as _safe_int
from hwflash.core.terminal import TelnetClient, FirmwareDumper
from hwflash.shared.styles import FONT_FAMILY
from hwflash.ui.components.factory import ActionSpec

if TYPE_CHECKING:
    from hwflash.ui.state import AppState, AppController
    from hwflash.shared.styles import ThemeEngine


class TerminalTab(ttk.Frame):
    """Telnet / Serial terminal tab."""

    def __init__(self, parent, state: "AppState", ctrl: "AppController",
                 engine: "ThemeEngine", **kwargs):
        super().__init__(parent, padding=10, **kwargs)
        self.s = state
        self.ctrl = ctrl
        self.engine = engine
        self.widgets = ctrl.get_engine("widgets")
        self.command_engine = ctrl.get_engine("commands")
        self._build()

    # ── Build ────────────────────────────────────────────────────

    def _build(self):
        s = self.s

        # Connection
        conn_frame = ttk.LabelFrame(self, text="Connection", padding=8)
        conn_frame.pack(fill=tk.X, pady=(0, 6))

        type_row = ttk.Frame(conn_frame)
        type_row.pack(fill=tk.X, pady=2)
        ttk.Label(type_row, text="Type:", width=10).pack(side=tk.LEFT)
        # LAN-only: keep the field for layout stability but lock it to Telnet.
        type_combo = ttk.Combobox(
            type_row, textvariable=s.term_type_var,
            values=["Telnet"],
            state='readonly', width=10,
        )
        type_combo.pack(side=tk.LEFT, padx=(0, 10))
        s.term_type_var.set("Telnet")

        ttk.Label(type_row, text="Host:", width=6).pack(side=tk.LEFT)
        ttk.Entry(type_row, textvariable=s.term_host_var, width=16).pack(side=tk.LEFT, padx=(0, 6))

        ttk.Label(type_row, text="Port:").pack(side=tk.LEFT)
        ttk.Combobox(
            type_row, textvariable=s.term_port_var,
            values=["23", "22", "2323", "8023"],
            width=6,
        ).pack(side=tk.LEFT)

        btn_row = ttk.Frame(conn_frame)
        btn_row.pack(fill=tk.X, pady=(4, 0))

        ttk.Label(btn_row, text="NIC:").pack(side=tk.LEFT)
        self.term_nic_combo = ttk.Combobox(
            btn_row, textvariable=s.term_nic_var,
            state='readonly', width=28,
        )
        self.term_nic_combo.pack(side=tk.LEFT, padx=(2, 8))
        # Register for adapter refresh
        s.adapter_combos.append(self.term_nic_combo)

        if self.widgets:
            _, action_buttons = self.widgets.actions(
                btn_row,
                [
                    ActionSpec("Connect", self._term_connect, width=12),
                    ActionSpec("Disconnect", self._term_disconnect, width=12, state="disabled", padx=(0, 8)),
                ],
                pady=(0, 0),
            )
            self.term_connect_btn, self.term_disconnect_btn = action_buttons
        else:
            self.term_connect_btn = ttk.Button(
                btn_row, text="Connect", command=self._term_connect, width=12)
            self.term_connect_btn.pack(side=tk.LEFT, padx=(0, 4))
            self.term_disconnect_btn = ttk.Button(
                btn_row, text="Disconnect", command=self._term_disconnect,
                width=12, state='disabled')
            self.term_disconnect_btn.pack(side=tk.LEFT, padx=(0, 8))

        ttk.Label(btn_row, textvariable=s.term_status_var,
                  font=(FONT_FAMILY, 9)).pack(side=tk.LEFT)

        # Quick commands
        cmd_frame = ttk.LabelFrame(self, text="Quick Commands (WAP CLI)", padding=8)
        cmd_frame.pack(fill=tk.X, pady=(0, 6))

        cmd_grid = ttk.Frame(cmd_frame)
        cmd_grid.pack(fill=tk.X)
        quick_cmds = self.command_engine.ont_quick_commands() if self.command_engine else [
            ("System Info", "display sysinfo"),
            ("Version", "display version"),
            ("SN", "display sn"),
            ("MAC", "display mac"),
            ("WAN Config", "display wan config"),
            ("Optical", "display optic 0"),
            ("CPU", "display cpu"),
            ("Memory", "display memory"),
            ("Flash", "display flash"),
            ("Partitions", "cat /proc/mtd"),
            ("Processes", "ps"),
            ("Config", "display current-config"),
        ]
        for i, (label, cmd) in enumerate(quick_cmds):
            r, c = divmod(i, 6)
            ttk.Button(
                cmd_grid, text=label, width=13,
                command=lambda c=cmd: self._term_send_command(c),
            ).grid(row=r, column=c, padx=1, pady=1)

        ttk.Button(
            cmd_frame, text="Clear Output",
            command=self._term_clear, width=12,
        ).pack(anchor='e', pady=(2, 0))

        # Terminal output
        term_frame = ttk.Frame(self)
        term_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 4))

        self.term_output = scrolledtext.ScrolledText(
            term_frame, wrap=tk.WORD,
            font=('Consolas', 9),
            state='disabled',
        )
        self.term_output.pack(fill=tk.BOTH, expand=True)

        self.engine.register(self.term_output,
                             {"bg": "terminal_bg", "fg": "terminal_fg",
                              "insertbackground": "terminal_fg"})

        # Input
        input_row = ttk.Frame(self)
        input_row.pack(fill=tk.X)
        ttk.Label(input_row, text="Command:").pack(side=tk.LEFT)
        self.term_input_entry = ttk.Entry(
            input_row, textvariable=s.term_input_var, width=55)
        self.term_input_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        self.term_input_entry.bind('<Return>', lambda e: self._term_send_input())
        ttk.Button(input_row, text="Send", command=self._term_send_input, width=8).pack(side=tk.LEFT)

    # ── Terminal Handlers ────────────────────────────────────────

    def _term_connect(self):
        try:
            host = self.s.term_host_var.get().strip()
            port = _safe_int(self.s.term_port_var.get().strip(), 23)
            if not host:
                messagebox.showwarning("No Host", "Enter the ONT IP address.")
                return

            source_ip = None
            try:
                idx = self.term_nic_combo.current()
                if 0 <= idx < len(self.s.adapters):
                    a = self.s.adapters[idx]
                    if a and a.ip and a.ip != '0.0.0.0':
                        source_ip = a.ip
            except Exception:
                source_ip = None

            self.s.telnet_client = TelnetClient()
            self.s.telnet_client.on_data = self._term_on_data
            self.s.telnet_client.on_connect = lambda h, p: self._term_on_connect(f"Telnet {h}:{p}")
            self.s.telnet_client.on_disconnect = self._term_on_disconnect
            self.s.telnet_client.on_error = lambda msg: self._term_append(f"\n*** Error: {msg}\n")
            self.s.telnet_client.connect(host, port, source_ip=source_ip)

        except ImportError as e:
            messagebox.showerror("Missing Library", str(e))
        except Exception as e:
            messagebox.showerror("Connection Error", str(e))
            self.ctrl.log(f"Terminal connect error: {e}")

    def _term_disconnect(self):
        if self.s.telnet_client and self.s.telnet_client.connected:
            self.s.telnet_client.disconnect()

    def _term_on_connect(self, info):
        self.s.term_status_var.set(f"Connected: {info}")
        self.term_connect_btn.configure(state='disabled')
        self.term_disconnect_btn.configure(state='normal')
        self._term_append(f"*** Connected to {info}\n")
        self.ctrl.log(f"Terminal connected: {info}")
        # Set up firmware dumper with the active client
        if self.s.telnet_client and self.s.telnet_client.connected:
            self.s.firmware_dumper = FirmwareDumper(self.s.telnet_client)
            self.s.dump_status_var.set("Connected \u2014 Ready to read partitions")

    def _term_on_disconnect(self):
        def _update():
            self.s.term_status_var.set("Disconnected")
            self.term_connect_btn.configure(state='normal')
            self.term_disconnect_btn.configure(state='disabled')
            self._term_append("\n*** Disconnected\n")
            self.ctrl.log("Terminal disconnected")
            self.s.firmware_dumper = None
            self.s.dump_status_var.set("Connect via Terminal tab first")
        self.s.root.after(0, _update)

    def _term_on_data(self, text):
        self.s.root.after(0, lambda: self._term_append(text))

    def _term_clear(self):
        self.term_output.configure(state='normal')
        self.term_output.delete('1.0', tk.END)
        self.term_output.configure(state='disabled')

    def _term_append(self, text):
        self.term_output.configure(state='normal')
        self.term_output.insert(tk.END, text)
        self.term_output.see(tk.END)
        self.term_output.configure(state='disabled')

    def _term_send_input(self):
        text = self.s.term_input_var.get()
        self.s.term_input_var.set("")
        self._term_send_command(text)

    def _term_send_command(self, command):
        if self.s.telnet_client and self.s.telnet_client.connected:
            self.s.telnet_client.send_command(command)
            self._term_append(f"{command}\n")
        elif self.s.serial_client and self.s.serial_client.connected:
            self.s.serial_client.send_command(command)
            self._term_append(f"{command}\n")
        else:
            self._term_append("*** Not connected. Use Connect button first.\n")
