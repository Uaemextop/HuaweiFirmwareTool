"""
Preset Dialog - UI for managing device presets
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QLineEdit, QSpinBox, QCheckBox,
    QComboBox, QTextEdit, QListWidget, QGroupBox,
    QMessageBox, QInputDialog
)
from PyQt6.QtCore import Qt

class PresetDialog(QDialog):
    """Dialog for creating/editing presets"""

    def __init__(self, parent=None, preset_manager=None, preset_id=None):
        super().__init__(parent)
        self.preset_manager = preset_manager
        self.preset_id = preset_id
        self.preset_data = None

        if preset_id and preset_manager:
            self.preset_data = preset_manager.get_preset(preset_id)

        self.init_ui()

        if self.preset_data:
            self.load_preset_data()

    def init_ui(self):
        """Initialize UI"""
        self.setWindowTitle("Preset Editor")
        self.setMinimumWidth(500)

        layout = QVBoxLayout(self)

        # Name and description
        info_group = QGroupBox("Preset Information")
        info_layout = QVBoxLayout()

        name_layout = QHBoxLayout()
        name_layout.addWidget(QLabel("Name:"))
        self.name_edit = QLineEdit()
        name_layout.addWidget(self.name_edit)
        info_layout.addLayout(name_layout)

        desc_layout = QVBoxLayout()
        desc_layout.addWidget(QLabel("Description:"))
        self.desc_edit = QTextEdit()
        self.desc_edit.setMaximumHeight(60)
        desc_layout.addWidget(self.desc_edit)
        info_layout.addLayout(desc_layout)

        info_group.setLayout(info_layout)
        layout.addWidget(info_group)

        # Communication settings
        comm_group = QGroupBox("Communication Settings")
        comm_layout = QVBoxLayout()

        # Baudrate
        baud_layout = QHBoxLayout()
        baud_layout.addWidget(QLabel("Baud Rate:"))
        self.baudrate_combo = QComboBox()
        self.baudrate_combo.addItems(["9600", "19200", "38400", "57600", "115200"])
        self.baudrate_combo.setCurrentText("115200")
        baud_layout.addWidget(self.baudrate_combo)
        baud_layout.addStretch()
        comm_layout.addLayout(baud_layout)

        # Timeout
        timeout_layout = QHBoxLayout()
        timeout_layout.addWidget(QLabel("Timeout (ms):"))
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(100, 10000)
        self.timeout_spin.setValue(1400)
        self.timeout_spin.setSingleStep(100)
        timeout_layout.addWidget(self.timeout_spin)
        timeout_layout.addStretch()
        comm_layout.addLayout(timeout_layout)

        # Delay
        delay_layout = QHBoxLayout()
        delay_layout.addWidget(QLabel("Delay (ms):"))
        self.delay_spin = QSpinBox()
        self.delay_spin.setRange(1, 100)
        self.delay_spin.setValue(5)
        delay_layout.addWidget(self.delay_spin)
        delay_layout.addStretch()
        comm_layout.addLayout(delay_layout)

        comm_group.setLayout(comm_layout)
        layout.addWidget(comm_group)

        # Protocol settings
        protocol_group = QGroupBox("Protocol Settings")
        protocol_layout = QVBoxLayout()

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

        # Retry count
        retry_layout = QHBoxLayout()
        retry_layout.addWidget(QLabel("Retry Count:"))
        self.retry_spin = QSpinBox()
        self.retry_spin.setRange(1, 10)
        self.retry_spin.setValue(3)
        retry_layout.addWidget(self.retry_spin)
        retry_layout.addStretch()
        protocol_layout.addLayout(retry_layout)

        protocol_group.setLayout(protocol_layout)
        layout.addWidget(protocol_group)

        # Options
        options_group = QGroupBox("Options")
        options_layout = QVBoxLayout()

        self.verify_check = QCheckBox("Verify firmware after flashing")
        self.verify_check.setChecked(True)
        options_layout.addWidget(self.verify_check)

        self.reboot_check = QCheckBox("Automatically reboot device")
        self.reboot_check.setChecked(True)
        options_layout.addWidget(self.reboot_check)

        self.signature_check = QCheckBox("Enable signature verification")
        options_layout.addWidget(self.signature_check)

        options_group.setLayout(options_layout)
        layout.addWidget(options_group)

        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)

        save_btn = QPushButton("Save Preset")
        save_btn.clicked.connect(self.save_preset)
        button_layout.addWidget(save_btn)

        layout.addLayout(button_layout)

    def load_preset_data(self):
        """Load preset data into form"""
        if not self.preset_data:
            return

        self.name_edit.setText(self.preset_data.get('name', ''))
        self.desc_edit.setPlainText(self.preset_data.get('description', ''))
        self.baudrate_combo.setCurrentText(str(self.preset_data.get('baudrate', 115200)))
        self.timeout_spin.setValue(self.preset_data.get('timeout', 1400))
        self.delay_spin.setValue(self.preset_data.get('delay', 5))
        self.chunk_spin.setValue(self.preset_data.get('chunk_size', 1024))
        self.retry_spin.setValue(self.preset_data.get('retry_count', 3))
        self.verify_check.setChecked(self.preset_data.get('verify', True))
        self.reboot_check.setChecked(self.preset_data.get('reboot', True))
        self.signature_check.setChecked(self.preset_data.get('signature_check', False))

    def save_preset(self):
        """Save preset"""
        name = self.name_edit.text().strip()
        if not name:
            QMessageBox.warning(self, "Invalid Name", "Please enter a preset name")
            return

        # Generate ID from name
        if not self.preset_id:
            self.preset_id = name.replace(' ', '_').replace('-', '_')

        preset_data = {
            'name': name,
            'description': self.desc_edit.toPlainText().strip(),
            'baudrate': int(self.baudrate_combo.currentText()),
            'timeout': self.timeout_spin.value(),
            'delay': self.delay_spin.value(),
            'chunk_size': self.chunk_spin.value(),
            'retry_count': self.retry_spin.value(),
            'verify': self.verify_check.isChecked(),
            'reboot': self.reboot_check.isChecked(),
            'signature_check': self.signature_check.isChecked()
        }

        if self.preset_manager:
            if self.preset_manager.add_preset(self.preset_id, preset_data):
                self.accept()
            else:
                QMessageBox.critical(self, "Error", "Failed to save preset")
        else:
            self.accept()


class PresetManagerDialog(QDialog):
    """Dialog for managing all presets"""

    def __init__(self, parent=None, preset_manager=None):
        super().__init__(parent)
        self.preset_manager = preset_manager
        self.init_ui()
        self.refresh_list()

    def init_ui(self):
        """Initialize UI"""
        self.setWindowTitle("Preset Manager")
        self.setMinimumSize(600, 400)

        layout = QHBoxLayout(self)

        # List of presets
        list_layout = QVBoxLayout()
        list_layout.addWidget(QLabel("Available Presets:"))

        self.preset_list = QListWidget()
        self.preset_list.itemDoubleClicked.connect(self.edit_preset)
        list_layout.addWidget(self.preset_list)

        layout.addLayout(list_layout, stretch=2)

        # Buttons
        button_layout = QVBoxLayout()

        new_btn = QPushButton("New Preset")
        new_btn.clicked.connect(self.new_preset)
        button_layout.addWidget(new_btn)

        edit_btn = QPushButton("Edit")
        edit_btn.clicked.connect(self.edit_preset)
        button_layout.addWidget(edit_btn)

        duplicate_btn = QPushButton("Duplicate")
        duplicate_btn.clicked.connect(self.duplicate_preset)
        button_layout.addWidget(duplicate_btn)

        delete_btn = QPushButton("Delete")
        delete_btn.clicked.connect(self.delete_preset)
        button_layout.addWidget(delete_btn)

        button_layout.addStretch()

        export_btn = QPushButton("Export...")
        export_btn.clicked.connect(self.export_preset)
        button_layout.addWidget(export_btn)

        import_btn = QPushButton("Import...")
        import_btn.clicked.connect(self.import_preset)
        button_layout.addWidget(import_btn)

        button_layout.addStretch()

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        button_layout.addWidget(close_btn)

        layout.addLayout(button_layout, stretch=1)

    def refresh_list(self):
        """Refresh preset list"""
        self.preset_list.clear()

        if not self.preset_manager:
            return

        for preset_id, preset_name in self.preset_manager.get_preset_list():
            preset = self.preset_manager.get_preset(preset_id)
            if preset:
                custom_tag = " [Custom]" if preset.get('custom', False) else ""
                self.preset_list.addItem(f"{preset_name}{custom_tag}")
                # Store preset_id in item data
                item = self.preset_list.item(self.preset_list.count() - 1)
                item.setData(Qt.ItemDataRole.UserRole, preset_id)

    def new_preset(self):
        """Create new preset"""
        dialog = PresetDialog(self, self.preset_manager)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.refresh_list()

    def edit_preset(self):
        """Edit selected preset"""
        item = self.preset_list.currentItem()
        if not item:
            return

        preset_id = item.data(Qt.ItemDataRole.UserRole)
        preset = self.preset_manager.get_preset(preset_id)

        if not preset.get('custom', False):
            QMessageBox.information(
                self,
                "Built-in Preset",
                "Built-in presets cannot be edited. You can duplicate it to create a custom version."
            )
            return

        dialog = PresetDialog(self, self.preset_manager, preset_id)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.refresh_list()

    def duplicate_preset(self):
        """Duplicate selected preset"""
        item = self.preset_list.currentItem()
        if not item:
            return

        preset_id = item.data(Qt.ItemDataRole.UserRole)
        preset = self.preset_manager.get_preset(preset_id)

        if not preset:
            return

        # Ask for new name
        new_name, ok = QInputDialog.getText(
            self,
            "Duplicate Preset",
            "Enter name for new preset:",
            text=f"{preset['name']} Copy"
        )

        if ok and new_name:
            new_preset = preset.copy()
            new_preset['name'] = new_name
            new_preset['custom'] = True

            new_id = new_name.replace(' ', '_').replace('-', '_')
            self.preset_manager.add_preset(new_id, new_preset)
            self.refresh_list()

    def delete_preset(self):
        """Delete selected preset"""
        item = self.preset_list.currentItem()
        if not item:
            return

        preset_id = item.data(Qt.ItemDataRole.UserRole)

        if not self.preset_manager.is_custom_preset(preset_id):
            QMessageBox.warning(
                self,
                "Cannot Delete",
                "Built-in presets cannot be deleted."
            )
            return

        reply = QMessageBox.question(
            self,
            "Confirm Delete",
            f"Are you sure you want to delete this preset?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            self.preset_manager.delete_preset(preset_id)
            self.refresh_list()

    def export_preset(self):
        """Export preset to file"""
        QMessageBox.information(self, "Export", "Export feature coming soon")

    def import_preset(self):
        """Import preset from file"""
        QMessageBox.information(self, "Import", "Import feature coming soon")
