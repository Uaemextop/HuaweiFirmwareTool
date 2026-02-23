"""
Main Window for ONT Firmware Flasher
Modern Windows 11 compatible interface
"""

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QGroupBox, QLabel, QPushButton,
    QComboBox, QLineEdit, QTextEdit, QProgressBar,
    QFileDialog, QSpinBox, QCheckBox, QMessageBox,
    QStatusBar, QMenuBar, QMenu
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSettings
from PyQt6.QtGui import QAction, QFont, QTextCursor

from core.serial_manager import SerialManager
from core.firmware_flasher import FirmwareFlasher
from utils.logger import get_logger

class FlashWorker(QThread):
    """Worker thread for firmware flashing operations"""
    progress = pyqtSignal(int, str)
    finished = pyqtSignal(bool, str)
    log = pyqtSignal(str)

    def __init__(self, flasher, firmware_path, config):
        super().__init__()
        self.flasher = flasher
        self.firmware_path = firmware_path
        self.config = config
        self.logger = get_logger()

    def run(self):
        """Execute firmware flashing"""
        try:
            self.log.emit(f"Starting firmware flash: {self.firmware_path}")
            self.progress.emit(10, "Initializing...")

            # Open serial connection
            if not self.flasher.connect(self.config):
                self.finished.emit(False, "Failed to connect to device")
                return

            self.progress.emit(20, "Connected to device")
            self.log.emit("Serial connection established")

            # Load firmware
            self.progress.emit(30, "Loading firmware...")
            if not self.flasher.load_firmware(self.firmware_path):
                self.finished.emit(False, "Failed to load firmware file")
                return

            self.progress.emit(40, "Firmware loaded")
            self.log.emit(f"Firmware size: {self.flasher.firmware_size} bytes")

            # Flash firmware
            self.progress.emit(50, "Flashing firmware...")
            self.log.emit("Starting flash operation (this may take several minutes)")

            success = self.flasher.flash_firmware(
                progress_callback=lambda p: self.progress.emit(50 + int(p * 0.45), f"Flashing... {p:.1f}%")
            )

            if success:
                self.progress.emit(100, "Flash complete!")
                self.log.emit("Firmware flashed successfully")
                self.finished.emit(True, "Firmware flashed successfully!")
            else:
                self.finished.emit(False, "Flash operation failed")

        except Exception as e:
            self.logger.error(f"Flash error: {e}")
            self.finished.emit(False, f"Error: {str(e)}")
        finally:
            self.flasher.disconnect()

class MainWindow(QMainWindow):
    """Main application window"""

    def __init__(self):
        super().__init__()
        self.logger = get_logger()
        self.settings = QSettings()
        self.serial_manager = SerialManager()
        self.firmware_flasher = FirmwareFlasher()
        self.flash_worker = None

        self.init_ui()
        self.load_settings()
        self.refresh_ports()

    def init_ui(self):
        """Initialize user interface"""
        self.setWindowTitle("ONT Firmware Flasher v1.0")
        self.setMinimumSize(900, 700)

        # Create menu bar
        self.create_menus()

        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Main layout
        main_layout = QVBoxLayout(central_widget)

        # Create tab widget
        tabs = QTabWidget()
        tabs.addTab(self.create_flash_tab(), "Flash Firmware")
        tabs.addTab(self.create_config_tab(), "Configuration")
        tabs.addTab(self.create_advanced_tab(), "Advanced")
        tabs.addTab(self.create_about_tab(), "About")

        main_layout.addWidget(tabs)

        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")

    def create_menus(self):
        """Create menu bar"""
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu("File")

        load_action = QAction("Load Firmware...", self)
        load_action.setShortcut("Ctrl+O")
        load_action.triggered.connect(self.browse_firmware)
        file_menu.addAction(load_action)

        file_menu.addSeparator()

        exit_action = QAction("Exit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Tools menu
        tools_menu = menubar.addMenu("Tools")

        refresh_action = QAction("Refresh Ports", self)
        refresh_action.setShortcut("F5")
        refresh_action.triggered.connect(self.refresh_ports)
        tools_menu.addAction(refresh_action)

        clear_log_action = QAction("Clear Log", self)
        clear_log_action.triggered.connect(lambda: self.log_text.clear())
        tools_menu.addAction(clear_log_action)

        # Help menu
        help_menu = menubar.addMenu("Help")

        docs_action = QAction("Documentation", self)
        docs_action.triggered.connect(self.show_documentation)
        help_menu.addAction(docs_action)

        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def create_flash_tab(self):
        """Create firmware flashing tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Connection group
        conn_group = QGroupBox("Device Connection")
        conn_layout = QVBoxLayout()

        # COM port selection
        port_layout = QHBoxLayout()
        port_layout.addWidget(QLabel("COM Port:"))
        self.port_combo = QComboBox()
        self.port_combo.setMinimumWidth(150)
        port_layout.addWidget(self.port_combo)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_ports)
        port_layout.addWidget(refresh_btn)
        port_layout.addStretch()

        conn_layout.addLayout(port_layout)

        # Baud rate
        baud_layout = QHBoxLayout()
        baud_layout.addWidget(QLabel("Baud Rate:"))
        self.baud_combo = QComboBox()
        self.baud_combo.addItems(["9600", "19200", "38400", "57600", "115200"])
        self.baud_combo.setCurrentText("115200")
        baud_layout.addWidget(self.baud_combo)
        baud_layout.addStretch()

        conn_layout.addLayout(baud_layout)
        conn_group.setLayout(conn_layout)
        layout.addWidget(conn_group)

        # Firmware group
        fw_group = QGroupBox("Firmware File")
        fw_layout = QVBoxLayout()

        # File selection
        file_layout = QHBoxLayout()
        self.firmware_path = QLineEdit()
        self.firmware_path.setPlaceholderText("Select firmware file (.bin)")
        file_layout.addWidget(self.firmware_path)

        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.browse_firmware)
        file_layout.addWidget(browse_btn)

        fw_layout.addLayout(file_layout)
        fw_group.setLayout(fw_layout)
        layout.addWidget(fw_group)

        # Timing configuration group
        timing_group = QGroupBox("Timing Configuration")
        timing_layout = QHBoxLayout()

        timing_layout.addWidget(QLabel("Timeout (ms):"))
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(100, 10000)
        self.timeout_spin.setValue(1400)
        self.timeout_spin.setSingleStep(100)
        timing_layout.addWidget(self.timeout_spin)

        timing_layout.addWidget(QLabel("Delay (ms):"))
        self.delay_spin = QSpinBox()
        self.delay_spin.setRange(1, 100)
        self.delay_spin.setValue(5)
        timing_layout.addWidget(self.delay_spin)

        timing_layout.addStretch()
        timing_group.setLayout(timing_layout)
        layout.addWidget(timing_group)

        # Progress
        progress_group = QGroupBox("Progress")
        progress_layout = QVBoxLayout()

        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        progress_layout.addWidget(self.progress_bar)

        self.progress_label = QLabel("Ready")
        progress_layout.addWidget(self.progress_label)

        progress_group.setLayout(progress_layout)
        layout.addWidget(progress_group)

        # Flash button
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        self.flash_btn = QPushButton("Flash Firmware")
        self.flash_btn.setMinimumHeight(40)
        self.flash_btn.setMinimumWidth(150)
        self.flash_btn.clicked.connect(self.start_flash)
        button_layout.addWidget(self.flash_btn)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setMinimumHeight(40)
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_flash)
        button_layout.addWidget(self.stop_btn)

        button_layout.addStretch()
        layout.addLayout(button_layout)

        # Log
        log_group = QGroupBox("Log")
        log_layout = QVBoxLayout()

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumHeight(150)
        font = QFont("Consolas", 9)
        self.log_text.setFont(font)
        log_layout.addWidget(self.log_text)

        log_group.setLayout(log_layout)
        layout.addWidget(log_group)

        return tab

    def create_config_tab(self):
        """Create configuration tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Presets group
        preset_group = QGroupBox("Quick Presets")
        preset_layout = QVBoxLayout()

        preset_info = QLabel("Select a preset configuration for common devices:")
        preset_layout.addWidget(preset_info)

        preset_buttons_layout = QHBoxLayout()

        hg8145v5_btn = QPushButton("HG8145V5 Unlock")
        hg8145v5_btn.clicked.connect(lambda: self.apply_preset("HG8145V5"))
        preset_buttons_layout.addWidget(hg8145v5_btn)

        hg8245_btn = QPushButton("HG8245 Standard")
        hg8245_btn.clicked.connect(lambda: self.apply_preset("HG8245"))
        preset_buttons_layout.addWidget(hg8245_btn)

        custom_btn = QPushButton("Custom")
        custom_btn.clicked.connect(lambda: self.apply_preset("Custom"))
        preset_buttons_layout.addWidget(custom_btn)

        preset_buttons_layout.addStretch()
        preset_layout.addLayout(preset_buttons_layout)

        preset_group.setLayout(preset_layout)
        layout.addWidget(preset_group)

        # Custom settings group
        custom_group = QGroupBox("Custom Settings")
        custom_layout = QVBoxLayout()

        # Verify after flash
        self.verify_check = QCheckBox("Verify firmware after flashing")
        self.verify_check.setChecked(True)
        custom_layout.addWidget(self.verify_check)

        # Auto reboot
        self.reboot_check = QCheckBox("Automatically reboot device after flash")
        self.reboot_check.setChecked(True)
        custom_layout.addWidget(self.reboot_check)

        # Backup
        self.backup_check = QCheckBox("Backup current firmware before flashing (if supported)")
        custom_layout.addWidget(self.backup_check)

        # Verbose logging
        self.verbose_check = QCheckBox("Enable verbose logging")
        custom_layout.addWidget(self.verbose_check)

        custom_group.setLayout(custom_layout)
        layout.addWidget(custom_group)

        # Save/Load configuration
        config_buttons = QHBoxLayout()
        config_buttons.addStretch()

        save_config_btn = QPushButton("Save Configuration")
        save_config_btn.clicked.connect(self.save_config)
        config_buttons.addWidget(save_config_btn)

        load_config_btn = QPushButton("Load Configuration")
        load_config_btn.clicked.connect(self.load_config)
        config_buttons.addWidget(load_config_btn)

        layout.addLayout(config_buttons)
        layout.addStretch()

        return tab

    def create_advanced_tab(self):
        """Create advanced settings tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Protocol settings
        protocol_group = QGroupBox("Protocol Settings")
        protocol_layout = QVBoxLayout()

        protocol_layout.addWidget(QLabel("Advanced users only - modify communication protocol parameters"))

        # Retry count
        retry_layout = QHBoxLayout()
        retry_layout.addWidget(QLabel("Max Retry Count:"))
        self.retry_spin = QSpinBox()
        self.retry_spin.setRange(1, 10)
        self.retry_spin.setValue(3)
        retry_layout.addWidget(self.retry_spin)
        retry_layout.addStretch()
        protocol_layout.addLayout(retry_layout)

        # Chunk size
        chunk_layout = QHBoxLayout()
        chunk_layout.addWidget(QLabel("Chunk Size (bytes):"))
        self.chunk_spin = QSpinBox()
        self.chunk_spin.setRange(128, 4096)
        self.chunk_spin.setValue(1024)
        self.chunk_spin.setSingleStep(128)
        chunk_layout.addWidget(self.chunk_spin)
        chunk_layout.addStretch()
        protocol_layout.addLayout(chunk_layout)

        protocol_group.setLayout(protocol_layout)
        layout.addWidget(protocol_group)

        # Developer options
        dev_group = QGroupBox("Developer Options")
        dev_layout = QVBoxLayout()

        self.debug_check = QCheckBox("Enable debug mode (detailed protocol logging)")
        dev_layout.addWidget(self.debug_check)

        self.dry_run_check = QCheckBox("Dry run (simulate without writing to device)")
        dev_layout.addWidget(self.dry_run_check)

        dev_group.setLayout(dev_layout)
        layout.addWidget(dev_group)

        layout.addStretch()

        return tab

    def create_about_tab(self):
        """Create about tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        # Title
        title = QLabel("ONT Firmware Flasher")
        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)
        title.setFont(title_font)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        # Version
        version = QLabel("Version 1.0.0")
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(version)

        layout.addSpacing(20)

        # Description
        desc = QLabel(
            "Open-source GUI tool for flashing firmware to Huawei ONT devices.\n\n"
            "This tool provides an easy-to-use interface for upgrading or modifying\n"
            "firmware on Optical Network Terminal (ONT) devices.\n\n"
            "Features:\n"
            "• Support for multiple ONT models\n"
            "• Configurable timing and protocol parameters\n"
            "• Progress monitoring and detailed logging\n"
            "• Preset configurations for common scenarios\n"
            "• Windows 11 compatible with modern UI"
        )
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc.setWordWrap(True)
        layout.addWidget(desc)

        layout.addSpacing(20)

        # License
        license_label = QLabel("Licensed under MIT License")
        license_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(license_label)

        # Repository
        repo = QLabel('<a href="https://github.com/Uaemextop/HuaweiFirmwareTool">GitHub Repository</a>')
        repo.setOpenExternalLinks(True)
        repo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(repo)

        layout.addStretch()

        return tab

    def refresh_ports(self):
        """Refresh available COM ports"""
        self.log("Refreshing COM ports...")
        ports = self.serial_manager.get_available_ports()

        self.port_combo.clear()
        for port in ports:
            self.port_combo.addItem(f"{port[0]} - {port[1]}", port[0])

        if ports:
            self.log(f"Found {len(ports)} COM port(s)")
        else:
            self.log("No COM ports found")

    def browse_firmware(self):
        """Browse for firmware file"""
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Select Firmware File",
            "",
            "Firmware Files (*.bin);;All Files (*.*)"
        )

        if filename:
            self.firmware_path.setText(filename)
            self.log(f"Selected firmware: {os.path.basename(filename)}")

    def apply_preset(self, preset_name):
        """Apply a preset configuration"""
        self.log(f"Applying preset: {preset_name}")

        if preset_name == "HG8145V5":
            self.timeout_spin.setValue(1400)
            self.delay_spin.setValue(5)
            self.baud_combo.setCurrentText("115200")
            self.verify_check.setChecked(True)
            self.reboot_check.setChecked(True)

        elif preset_name == "HG8245":
            self.timeout_spin.setValue(1200)
            self.delay_spin.setValue(10)
            self.baud_combo.setCurrentText("115200")
            self.verify_check.setChecked(True)
            self.reboot_check.setChecked(True)

        self.status_bar.showMessage(f"Applied preset: {preset_name}")

    def start_flash(self):
        """Start firmware flashing"""
        # Validate inputs
        if not self.firmware_path.text():
            QMessageBox.warning(self, "No Firmware", "Please select a firmware file")
            return

        if not os.path.exists(self.firmware_path.text()):
            QMessageBox.warning(self, "File Not Found", "Selected firmware file does not exist")
            return

        if self.port_combo.currentIndex() < 0:
            QMessageBox.warning(self, "No Port", "Please select a COM port")
            return

        # Confirm action
        reply = QMessageBox.question(
            self,
            "Confirm Flash",
            f"Flash firmware to {self.port_combo.currentText()}?\n\n"
            "This will overwrite the current firmware on the device.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply != QMessageBox.StandardButton.Yes:
            return

        # Prepare configuration
        config = {
            'port': self.port_combo.currentData(),
            'baudrate': int(self.baud_combo.currentText()),
            'timeout': self.timeout_spin.value() / 1000.0,
            'delay': self.delay_spin.value() / 1000.0,
            'verify': self.verify_check.isChecked(),
            'reboot': self.reboot_check.isChecked(),
            'backup': self.backup_check.isChecked(),
            'verbose': self.verbose_check.isChecked(),
            'debug': self.debug_check.isChecked(),
            'dry_run': self.dry_run_check.isChecked(),
            'retry_count': self.retry_spin.value(),
            'chunk_size': self.chunk_spin.value()
        }

        # Disable controls
        self.flash_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setValue(0)

        # Start worker thread
        self.flash_worker = FlashWorker(
            self.firmware_flasher,
            self.firmware_path.text(),
            config
        )
        self.flash_worker.progress.connect(self.update_progress)
        self.flash_worker.log.connect(self.log)
        self.flash_worker.finished.connect(self.flash_finished)
        self.flash_worker.start()

        self.log("=" * 60)
        self.log("Starting flash operation")
        self.status_bar.showMessage("Flashing...")

    def stop_flash(self):
        """Stop ongoing flash operation"""
        if self.flash_worker and self.flash_worker.isRunning():
            self.flash_worker.terminate()
            self.flash_worker.wait()
            self.log("Flash operation stopped by user")
            self.flash_finished(False, "Stopped by user")

    def update_progress(self, value, message):
        """Update progress bar and label"""
        self.progress_bar.setValue(value)
        self.progress_label.setText(message)

    def flash_finished(self, success, message):
        """Handle flash completion"""
        self.flash_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

        if success:
            self.log("=" * 60)
            self.log("Flash completed successfully!")
            self.status_bar.showMessage("Flash complete")
            QMessageBox.information(self, "Success", message)
        else:
            self.log(f"Flash failed: {message}")
            self.status_bar.showMessage("Flash failed")
            QMessageBox.critical(self, "Flash Failed", message)

    def log(self, message):
        """Add message to log"""
        self.log_text.append(message)
        self.log_text.moveCursor(QTextCursor.MoveOperation.End)
        self.logger.info(message)

    def save_config(self):
        """Save current configuration"""
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Save Configuration",
            "",
            "Configuration Files (*.ini)"
        )

        if filename:
            settings = QSettings(filename, QSettings.Format.IniFormat)
            self.save_settings_to(settings)
            self.log(f"Configuration saved to: {filename}")
            QMessageBox.information(self, "Saved", "Configuration saved successfully")

    def load_config(self):
        """Load configuration from file"""
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Load Configuration",
            "",
            "Configuration Files (*.ini)"
        )

        if filename:
            settings = QSettings(filename, QSettings.Format.IniFormat)
            self.load_settings_from(settings)
            self.log(f"Configuration loaded from: {filename}")
            QMessageBox.information(self, "Loaded", "Configuration loaded successfully")

    def save_settings(self):
        """Save settings to application settings"""
        self.save_settings_to(self.settings)

    def save_settings_to(self, settings):
        """Save settings to a QSettings object"""
        settings.setValue("port", self.port_combo.currentData())
        settings.setValue("baudrate", self.baud_combo.currentText())
        settings.setValue("timeout", self.timeout_spin.value())
        settings.setValue("delay", self.delay_spin.value())
        settings.setValue("verify", self.verify_check.isChecked())
        settings.setValue("reboot", self.reboot_check.isChecked())
        settings.setValue("backup", self.backup_check.isChecked())
        settings.setValue("verbose", self.verbose_check.isChecked())
        settings.setValue("debug", self.debug_check.isChecked())
        settings.setValue("retry_count", self.retry_spin.value())
        settings.setValue("chunk_size", self.chunk_spin.value())
        settings.setValue("firmware_path", self.firmware_path.text())

    def load_settings(self):
        """Load settings from application settings"""
        self.load_settings_from(self.settings)

    def load_settings_from(self, settings):
        """Load settings from a QSettings object"""
        port = settings.value("port")
        if port:
            index = self.port_combo.findData(port)
            if index >= 0:
                self.port_combo.setCurrentIndex(index)

        baudrate = settings.value("baudrate", "115200")
        self.baud_combo.setCurrentText(str(baudrate))

        self.timeout_spin.setValue(int(settings.value("timeout", 1400)))
        self.delay_spin.setValue(int(settings.value("delay", 5)))
        self.verify_check.setChecked(settings.value("verify", True, type=bool))
        self.reboot_check.setChecked(settings.value("reboot", True, type=bool))
        self.backup_check.setChecked(settings.value("backup", False, type=bool))
        self.verbose_check.setChecked(settings.value("verbose", False, type=bool))
        self.debug_check.setChecked(settings.value("debug", False, type=bool))
        self.retry_spin.setValue(int(settings.value("retry_count", 3)))
        self.chunk_spin.setValue(int(settings.value("chunk_size", 1024)))

        fw_path = settings.value("firmware_path", "")
        if fw_path:
            self.firmware_path.setText(fw_path)

    def show_documentation(self):
        """Show documentation dialog"""
        QMessageBox.information(
            self,
            "Documentation",
            "For detailed documentation, please visit:\n\n"
            "https://github.com/Uaemextop/HuaweiFirmwareTool\n\n"
            "See EXE_ANALYSIS_REPORT.md and ANALISIS_ES.md\n"
            "for technical details and usage instructions."
        )

    def show_about(self):
        """Show about dialog"""
        QMessageBox.about(
            self,
            "About ONT Firmware Flasher",
            "ONT Firmware Flasher v1.0\n\n"
            "Open-source tool for flashing Huawei ONT firmware\n\n"
            "Copyright (c) 2026\n"
            "Licensed under MIT License\n\n"
            "Windows 11 compatible"
        )

    def closeEvent(self, event):
        """Handle window close event"""
        self.save_settings()

        if self.flash_worker and self.flash_worker.isRunning():
            reply = QMessageBox.question(
                self,
                "Flash in Progress",
                "A flash operation is in progress. Are you sure you want to exit?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )

            if reply == QMessageBox.StandardButton.Yes:
                self.flash_worker.terminate()
                self.flash_worker.wait()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()
