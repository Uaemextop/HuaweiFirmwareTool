"""
Example demonstrating the new architecture.

This file shows how to use the new shared components, controllers,
and design system. Use this as a reference when refactoring existing tabs.
"""

import tkinter as tk
from tkinter import ttk

# Import design system
from obsc_tool.gui.styles.design_system import (
    Colors, Fonts, Spacing, apply_modern_style
)

# Import shared widgets
from obsc_tool.gui.widgets import (
    FileSelector, ProgressWidget, DataTable, LogViewer, ModernWindow
)

# Import controllers
from obsc_tool.controllers import (
    FirmwareController, NetworkController, SettingsController
)


class ExampleModernApp:
    """
    Example application using the new architecture.

    This demonstrates:
    - Using the modern window frame
    - Using shared widgets
    - Using controllers for business logic
    - Applying the design system
    """

    def __init__(self):
        """Initialize the example application."""
        # Create modern window
        self.root = ModernWindow("Example Modern App", "800x600")

        # Get content frame
        content = self.root.get_content_frame()

        # Initialize controllers
        self.firmware_controller = FirmwareController()
        self.network_controller = NetworkController()
        self.settings_controller = SettingsController()

        # Register event callbacks
        self._register_callbacks()

        # Apply modern styling
        apply_modern_style(self.root, theme='dark')

        # Build UI
        self._build_ui(content)

        # Override close handler
        self.root._on_close = self._on_close

    def _register_callbacks(self):
        """Register controller event callbacks."""
        # Firmware controller events
        self.firmware_controller.register_callback(
            'firmware_loaded', self._on_firmware_loaded
        )
        self.firmware_controller.register_callback(
            'upload_progress', self._on_upload_progress
        )
        self.firmware_controller.register_callback(
            'error', self._on_error
        )

        # Network controller events
        self.network_controller.register_callback(
            'connection_success', self._on_connection_success
        )
        self.network_controller.register_callback(
            'device_found', self._on_device_found
        )

    def _build_ui(self, parent):
        """Build the user interface."""
        # Create notebook for tabs
        notebook = ttk.Notebook(parent, padding=Spacing.MD)
        notebook.pack(fill=tk.BOTH, expand=True, padx=Spacing.MD, pady=Spacing.MD)

        # Example Tab 1: File Operations
        self._build_file_tab(notebook)

        # Example Tab 2: Network Operations
        self._build_network_tab(notebook)

        # Example Tab 3: Logs
        self._build_log_tab(notebook)

    def _build_file_tab(self, notebook):
        """Build file operations tab using shared widgets."""
        tab = ttk.Frame(notebook, padding=Spacing.MD)
        notebook.add(tab, text="  File Operations  ")

        # Title
        title = ttk.Label(
            tab, text="Firmware File Operations",
            font=Fonts.get(Fonts.SIZE_LARGE, 'bold')
        )
        title.pack(anchor=tk.W, pady=(0, Spacing.LG))

        # File selector using shared widget
        self.file_selector = FileSelector(
            tab,
            label="Firmware File:",
            mode="open",
            filetypes=[("Firmware files", "*.bin"), ("All files", "*.*")],
            on_change=self._on_file_selected,
            width=50
        )
        self.file_selector.pack(fill=tk.X, pady=(0, Spacing.MD))

        # Action buttons
        button_frame = ttk.Frame(tab)
        button_frame.pack(fill=tk.X, pady=(0, Spacing.MD))

        load_btn = ttk.Button(
            button_frame, text="Load Firmware",
            command=self._load_firmware,
            style='Accent.TButton'
        )
        load_btn.pack(side=tk.LEFT, padx=(0, Spacing.SM))

        validate_btn = ttk.Button(
            button_frame, text="Validate",
            command=self._validate_firmware
        )
        validate_btn.pack(side=tk.LEFT)

        # Progress widget using shared component
        self.progress = ProgressWidget(tab)
        self.progress.pack(fill=tk.X, pady=(Spacing.LG, 0))

        # Info section
        info_frame = ttk.LabelFrame(tab, text="Firmware Information", padding=Spacing.MD)
        info_frame.pack(fill=tk.BOTH, expand=True, pady=(Spacing.MD, 0))

        self.info_text = tk.Text(
            info_frame, height=10, width=60,
            font=Fonts.get(Fonts.SIZE_NORMAL, family=Fonts.FAMILY_MONO),
            bg=Colors.BG_DARK_SECONDARY, fg=Colors.TEXT_DARK,
            relief=tk.FLAT, padx=Spacing.SM, pady=Spacing.SM
        )
        self.info_text.pack(fill=tk.BOTH, expand=True)

    def _build_network_tab(self, notebook):
        """Build network operations tab with data table."""
        tab = ttk.Frame(notebook, padding=Spacing.MD)
        notebook.add(tab, text="  Network  ")

        # Title
        title = ttk.Label(
            tab, text="Network Devices",
            font=Fonts.get(Fonts.SIZE_LARGE, 'bold')
        )
        title.pack(anchor=tk.W, pady=(0, Spacing.LG))

        # Connection test controls
        conn_frame = ttk.Frame(tab)
        conn_frame.pack(fill=tk.X, pady=(0, Spacing.MD))

        ttk.Label(conn_frame, text="IP Address:").pack(side=tk.LEFT, padx=(0, Spacing.SM))
        self.ip_entry = ttk.Entry(conn_frame, width=15)
        self.ip_entry.insert(0, "192.168.1.1")
        self.ip_entry.pack(side=tk.LEFT, padx=(0, Spacing.SM))

        ttk.Label(conn_frame, text="Port:").pack(side=tk.LEFT, padx=(Spacing.MD, Spacing.SM))
        self.port_entry = ttk.Entry(conn_frame, width=8)
        self.port_entry.insert(0, "5555")
        self.port_entry.pack(side=tk.LEFT, padx=(0, Spacing.SM))

        test_btn = ttk.Button(
            conn_frame, text="Test Connection",
            command=self._test_connection
        )
        test_btn.pack(side=tk.LEFT, padx=(Spacing.MD, 0))

        scan_btn = ttk.Button(
            conn_frame, text="Scan Network",
            command=self._scan_network
        )
        scan_btn.pack(side=tk.LEFT, padx=(Spacing.SM, 0))

        # Data table using shared widget
        columns = [
            {'id': 'ip', 'text': 'IP Address', 'width': 150},
            {'id': 'port', 'text': 'Port', 'width': 80},
            {'id': 'status', 'text': 'Status', 'width': 100},
        ]
        self.device_table = DataTable(
            tab, columns=columns,
            on_select=self._on_device_selected,
            height=15
        )
        self.device_table.pack(fill=tk.BOTH, expand=True, pady=(Spacing.MD, 0))

    def _build_log_tab(self, notebook):
        """Build log tab using log viewer widget."""
        tab = ttk.Frame(notebook, padding=Spacing.MD)
        notebook.add(tab, text="  Logs  ")

        # Title with controls
        header = ttk.Frame(tab)
        header.pack(fill=tk.X, pady=(0, Spacing.MD))

        title = ttk.Label(
            header, text="Application Logs",
            font=Fonts.get(Fonts.SIZE_LARGE, 'bold')
        )
        title.pack(side=tk.LEFT)

        clear_btn = ttk.Button(
            header, text="Clear Logs",
            command=lambda: self.log_viewer.clear()
        )
        clear_btn.pack(side=tk.RIGHT)

        # Log viewer using shared widget
        self.log_viewer = LogViewer(tab, height=20)
        self.log_viewer.pack(fill=tk.BOTH, expand=True)

        # Add some example logs
        self.log_viewer.add_log("Application started", "info")
        self.log_viewer.add_log("Controllers initialized", "success")

    # ── Event Handlers ───────────────────────────────────────────

    def _on_file_selected(self, file_path):
        """Handle file selection."""
        self.log_viewer.add_log(f"File selected: {file_path}", "info")

    def _load_firmware(self):
        """Load firmware using controller."""
        file_path = self.file_selector.get_path()
        if not file_path:
            self.log_viewer.add_log("No file selected", "warning")
            return

        self.progress.start("Loading firmware...", "Please wait")
        self.log_viewer.add_log(f"Loading firmware: {file_path}", "info")

        # Use controller
        success = self.firmware_controller.load_firmware(file_path)

        if success:
            self.progress.stop()
        else:
            self.progress.set_error("Failed to load firmware")

    def _validate_firmware(self):
        """Validate firmware using controller."""
        if not self.firmware_controller.get_state('firmware_loaded'):
            self.log_viewer.add_log("No firmware loaded", "warning")
            return

        success = self.firmware_controller.validate_firmware()
        if success:
            self.log_viewer.add_log("Firmware validation passed", "success")
        else:
            self.log_viewer.add_log("Firmware validation failed", "error")

    def _test_connection(self):
        """Test network connection using controller."""
        ip = self.ip_entry.get()
        port = int(self.port_entry.get())

        self.log_viewer.add_log(f"Testing connection to {ip}:{port}", "info")
        success = self.network_controller.test_connection(ip, port)

    def _scan_network(self):
        """Scan network using controller."""
        self.log_viewer.add_log("Starting network scan...", "info")
        self.device_table.clear()

        # Example scan
        devices = self.network_controller.scan_network("192.168.1", 5555, 1, 10)

    def _on_device_selected(self, selection):
        """Handle device selection from table."""
        if selection:
            device = selection[0]
            self.log_viewer.add_log(
                f"Selected device: {device['ip']}:{device['port']}", "info"
            )

    # ── Controller Callbacks ─────────────────────────────────────

    def _on_firmware_loaded(self, path, size):
        """Handle firmware loaded event."""
        self.log_viewer.add_log(f"Firmware loaded: {path} ({size} bytes)", "success")
        info = self.firmware_controller.get_firmware_info()
        self.info_text.delete('1.0', tk.END)
        self.info_text.insert('1.0', f"Path: {info['path']}\nSize: {info['size_formatted']}")

    def _on_upload_progress(self, bytes_sent, total_bytes, percent, speed):
        """Handle upload progress event."""
        self.progress.update_progress(
            percent,
            f"Uploading: {percent:.1f}%",
            f"{bytes_sent}/{total_bytes} bytes @ {speed} B/s"
        )

    def _on_error(self, error, context):
        """Handle error event."""
        self.log_viewer.add_log(f"Error: {context} - {error}", "error")

    def _on_connection_success(self, ip, port):
        """Handle successful connection."""
        self.log_viewer.add_log(f"Connection successful: {ip}:{port}", "success")
        self.device_table.add_row([ip, str(port), "Online"])

    def _on_device_found(self, ip, port):
        """Handle device found event."""
        self.log_viewer.add_log(f"Device found: {ip}:{port}", "info")
        self.device_table.add_row([ip, str(port), "Found"])

    def _on_close(self):
        """Handle window close."""
        self.log_viewer.add_log("Application closing...", "info")
        self.root.destroy()

    def run(self):
        """Run the application."""
        self.root.mainloop()


if __name__ == '__main__':
    app = ExampleModernApp()
    app.run()
