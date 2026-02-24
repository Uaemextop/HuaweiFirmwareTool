"""Terminal tab mixin for OBSC Firmware Tool."""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

from obsc_tool.gui.constants import _safe_int
from obsc_tool.terminal import (
    TelnetClient, SerialClient, FirmwareDumper, ONT_COMMANDS,
)


class TerminalTabMixin:
    """Mixin providing the Terminal tab and related methods."""

    def _build_terminal_tab(self):
        """Build the serial/telnet terminal tab."""
        tab = self.tab_terminal

        # ── Connection ───────────────────────────────────────────
        conn_frame = ttk.LabelFrame(tab, text="Connection", padding=8)
        conn_frame.pack(fill=tk.X, pady=(0, 8))

        # Connection type
        type_row = ttk.Frame(conn_frame)
        type_row.pack(fill=tk.X, pady=2)
        ttk.Label(type_row, text="Type:", width=12).pack(side=tk.LEFT)
        self.term_type_var = tk.StringVar(value="Telnet")
        ttk.Combobox(
            type_row, textvariable=self.term_type_var,
            values=["Telnet", "Serial"],
            state='readonly', width=10,
        ).pack(side=tk.LEFT, padx=(0, 10))

        ttk.Label(type_row, text="Host/Port:", width=10).pack(side=tk.LEFT)
        self.term_host_var = tk.StringVar(value="192.168.100.1")
        ttk.Entry(type_row, textvariable=self.term_host_var, width=18).pack(side=tk.LEFT, padx=(0, 5))

        ttk.Label(type_row, text="Port:").pack(side=tk.LEFT)
        self.term_port_var = tk.StringVar(value="23")
        ttk.Entry(type_row, textvariable=self.term_port_var, width=6).pack(side=tk.LEFT, padx=(0, 5))

        # Serial settings row
        serial_row = ttk.Frame(conn_frame)
        serial_row.pack(fill=tk.X, pady=2)
        ttk.Label(serial_row, text="COM Port:", width=12).pack(side=tk.LEFT)
        self.term_com_var = tk.StringVar()
        self.term_com_combo = ttk.Combobox(
            serial_row, textvariable=self.term_com_var,
            width=15,
        )
        self.term_com_combo.pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(serial_row, text="🔃", command=self._refresh_com_ports, width=3).pack(side=tk.LEFT, padx=(0, 10))

        ttk.Label(serial_row, text="Baud:").pack(side=tk.LEFT)
        self.term_baud_var = tk.StringVar(value="115200")
        ttk.Combobox(
            serial_row, textvariable=self.term_baud_var,
            values=["9600", "19200", "38400", "57600", "115200"],
            width=8,
        ).pack(side=tk.LEFT, padx=(0, 10))

        # Connect/disconnect buttons
        btn_row = ttk.Frame(conn_frame)
        btn_row.pack(fill=tk.X, pady=(5, 0))

        # NIC selector for terminal (auto-selects Ethernet)
        ttk.Label(btn_row, text="NIC:").pack(side=tk.LEFT)
        self.term_nic_var = tk.StringVar()
        self.term_nic_combo = ttk.Combobox(
            btn_row, textvariable=self.term_nic_var,
            state='readonly', width=30,
        )
        self.term_nic_combo.pack(side=tk.LEFT, padx=(2, 8))

        self.term_connect_btn = ttk.Button(
            btn_row, text="🔌 Connect", command=self._term_connect, width=14)
        self.term_connect_btn.pack(side=tk.LEFT, padx=(0, 5))
        self.term_disconnect_btn = ttk.Button(
            btn_row, text="❌ Disconnect", command=self._term_disconnect,
            width=14, state='disabled')
        self.term_disconnect_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.term_status_var = tk.StringVar(value="Disconnected")
        ttk.Label(btn_row, textvariable=self.term_status_var,
                  font=('Segoe UI', 9)).pack(side=tk.LEFT)

        # ── Quick Commands ───────────────────────────────────────
        cmd_frame = ttk.LabelFrame(tab, text="Quick Commands (WAP CLI)", padding=5)
        cmd_frame.pack(fill=tk.X, pady=(0, 8))

        cmd_grid = ttk.Frame(cmd_frame)
        cmd_grid.pack(fill=tk.X)
        quick_cmds = [
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
                cmd_grid, text=label, width=14,
                command=lambda c=cmd: self._term_send_command(c),
            ).grid(row=r, column=c, padx=1, pady=1)

        # Clear button
        ttk.Button(
            cmd_frame, text="Clear Output",
            command=self._term_clear, width=14,
        ).pack(anchor='e', pady=(3, 0))

        # ── Terminal Output ──────────────────────────────────────
        term_frame = ttk.Frame(tab)
        term_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))

        self.term_output = scrolledtext.ScrolledText(
            term_frame, wrap=tk.WORD,
            font=('Consolas', 9),
            state='disabled',
            bg='#0C0C0C', fg='#CCCCCC',
            insertbackground='#CCCCCC',
        )
        self.term_output.pack(fill=tk.BOTH, expand=True)

        # ── Input ────────────────────────────────────────────────
        input_row = ttk.Frame(tab)
        input_row.pack(fill=tk.X)
        ttk.Label(input_row, text="Command:").pack(side=tk.LEFT)
        self.term_input_var = tk.StringVar()
        self.term_input_entry = ttk.Entry(
            input_row, textvariable=self.term_input_var, width=60)
        self.term_input_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.term_input_entry.bind('<Return>', lambda e: self._term_send_input())
        ttk.Button(input_row, text="Send", command=self._term_send_input, width=8).pack(side=tk.LEFT)

    # ── Terminal Handlers ────────────────────────────────────────

    def _refresh_com_ports(self):
        """Refresh serial port list."""
        ports = SerialClient.list_ports()
        self.term_com_combo['values'] = [f"{p[0]} - {p[1]}" for p in ports]
        if ports:
            self.term_com_combo.current(0)

    def _term_connect(self):
        """Connect via telnet or serial."""
        conn_type = self.term_type_var.get()
        try:
            if conn_type == "Telnet":
                host = self.term_host_var.get().strip()
                port = _safe_int(self.term_port_var.get().strip(), 23)
                if not host:
                    messagebox.showwarning("No Host", "Enter the ONT IP address.")
                    return

                self.telnet_client = TelnetClient()
                self.telnet_client.on_data = self._term_on_data
                self.telnet_client.on_connect = lambda h, p: self._term_on_connect(f"Telnet {h}:{p}")
                self.telnet_client.on_disconnect = self._term_on_disconnect
                self.telnet_client.on_error = lambda msg: self._term_append(f"\n*** Error: {msg}\n")
                self.telnet_client.connect(host, port)

            else:  # Serial
                com = self.term_com_var.get().strip()
                if not com:
                    messagebox.showwarning("No Port", "Select a COM port.")
                    return
                port_name = com.split(' - ')[0].strip()
                baud = _safe_int(self.term_baud_var.get(), 115200)

                self.serial_client = SerialClient()
                self.serial_client.on_data = self._term_on_data
                self.serial_client.on_connect = lambda p, b: self._term_on_connect(f"Serial {p} @ {b}")
                self.serial_client.on_disconnect = self._term_on_disconnect
                self.serial_client.on_error = lambda msg: self._term_append(f"\n*** Error: {msg}\n")
                self.serial_client.connect(port_name, baud)

        except ImportError as e:
            messagebox.showerror("Missing Library", str(e))
        except Exception as e:
            messagebox.showerror("Connection Error", str(e))
            self._log(f"Terminal connect error: {e}")

    def _term_disconnect(self):
        """Disconnect terminal."""
        if self.telnet_client.connected:
            self.telnet_client.disconnect()
        if self.serial_client.connected:
            self.serial_client.disconnect()

    def _term_on_connect(self, info):
        """Handle terminal connection."""
        self.term_status_var.set(f"Connected: {info}")
        self.term_connect_btn.configure(state='disabled')
        self.term_disconnect_btn.configure(state='normal')
        self._term_append(f"*** Connected to {info}\n")
        self._log(f"Terminal connected: {info}")
        # Set up firmware dumper with the active client
        if self.telnet_client.connected:
            client = self.telnet_client
        elif self.serial_client.connected:
            client = self.serial_client
        else:
            client = None
        if client:
            self.firmware_dumper = FirmwareDumper(client)
            self.dump_status_var.set("Connected — Ready to read partitions")

    def _term_on_disconnect(self):
        """Handle terminal disconnection."""
        def _update():
            self.term_status_var.set("Disconnected")
            self.term_connect_btn.configure(state='normal')
            self.term_disconnect_btn.configure(state='disabled')
            self._term_append("\n*** Disconnected\n")
            self._log("Terminal disconnected")
            self.firmware_dumper = None
            self.dump_status_var.set("Connect via Terminal tab first")
        self.root.after(0, _update)

    def _term_on_data(self, text):
        """Handle incoming terminal data."""
        self.root.after(0, lambda: self._term_append(text))

    def _term_clear(self):
        """Clear terminal output."""
        self.term_output.configure(state='normal')
        self.term_output.delete('1.0', tk.END)
        self.term_output.configure(state='disabled')

    def _term_append(self, text):
        """Append text to terminal output."""
        self.term_output.configure(state='normal')
        self.term_output.insert(tk.END, text)
        self.term_output.see(tk.END)
        self.term_output.configure(state='disabled')

    def _term_send_input(self):
        """Send user input from the command entry."""
        text = self.term_input_var.get()
        self.term_input_var.set("")
        self._term_send_command(text)

    def _term_send_command(self, command):
        """Send a command to the connected device."""
        if self.telnet_client.connected:
            self.telnet_client.send_command(command)
            self._term_append(f"{command}\n")
        elif self.serial_client.connected:
            self.serial_client.send_command(command)
            self._term_append(f"{command}\n")
        else:
            self._term_append("*** Not connected. Use Connect button first.\n")
