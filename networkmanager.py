import sys
import threading
import queue
import os
import tempfile
import traceback
from pathlib import Path
from getpass import getpass
from typing import Optional

from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
from PySide6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QTextEdit,
    QVBoxLayout, QHBoxLayout, QFileDialog, QMessageBox, QComboBox, QCheckBox,
    QScrollArea, QFrame, QSizePolicy
)
from PySide6.QtCore import Qt, Signal, QObject


class WorkerSignals(QObject):
    finished = Signal()
    error = Signal(str)
    result = Signal(str, str)


class DeviceWorker(threading.Thread):
    def __init__(self, device: dict, signals: WorkerSignals):
        super().__init__()
        self.device = device
        self.signals = signals

    def run(self):
        try:
            connection = ConnectHandler(
                device_type=self.device["device_type"],
                ip=self.device["ip"],
                username=self.device["username"],
                password=self.device["password"],
                secret=self.device.get("secret"),
                fast_cli=True,
                global_delay_factor=0.5,
                conn_timeout=10,
            )
            if self.device.get("secret"):
                connection.enable()

            output = []
            for cmd in self.device["commands"]:
                output.append(f"$ {cmd}\n{connection.send_command(cmd, strip_prompt=True, strip_command=True)}")

            if self.device.get("firmware_file"):
                sftp = connection.sftp_conn
                remote_path = self.device["firmware_dest"]
                local_path = self.device["firmware_file"]
                sftp.put(local_path, remote_path)
                output.append(f"Firmware uploaded to {remote_path}")
                update_cmd = self.device.get("firmware_update_command")
                if update_cmd:
                    output.append(f"$ {update_cmd}\n{connection.send_command(update_cmd, strip_prompt=True, strip_command=True)}")

            connection.disconnect()
            self.signals.result.emit(self.device["ip"], "\n\n".join(output))
        except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
            self.signals.error.emit(f"{self.device['ip']}: Connection failed - {str(e)}")
        except Exception:
            err = traceback.format_exc()
            self.signals.error.emit(f"{self.device['ip']}: Unexpected error:\n{err}")
        finally:
            self.signals.finished.emit()

class DeviceEntry(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Device IP (e.g. 192.168.1.1)")
        self.device_type_combo = QComboBox()
        self.device_type_combo.addItems([
            "cisco_ios", "cisco_xe", "cisco_xr", "arista_eos",
            "juniper", "huawei", "fortinet", "paloalto_panos"
        ])
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Password")
        self.secret_input = QLineEdit()
        self.secret_input.setEchoMode(QLineEdit.Password)
        self.secret_input.setPlaceholderText("Enable Secret (optional)")

        self.commands_edit = QTextEdit()
        self.commands_edit.setPlaceholderText("Enter configuration commands, one per line")

        self.firmware_path = QLineEdit()
        self.firmware_path.setReadOnly(True)
        self.firmware_btn = QPushButton("Select Firmware File")
        self.firmware_btn.clicked.connect(self.select_firmware)

        self.firmware_dest_input = QLineEdit()
        self.firmware_dest_input.setPlaceholderText("Firmware destination path on device")

        self.firmware_update_cmd_input = QLineEdit()
        self.firmware_update_cmd_input.setPlaceholderText("Firmware update command (optional)")

        self.firmware_group = QVBoxLayout()
        self.firmware_group.addWidget(self.firmware_path)
        self.firmware_group.addWidget(self.firmware_btn)
        self.firmware_group.addWidget(self.firmware_dest_input)
        self.firmware_group.addWidget(self.firmware_update_cmd_input)

        form_layout = QVBoxLayout()
        form_layout.addWidget(QLabel("IP Address"))
        form_layout.addWidget(self.ip_input)
        form_layout.addWidget(QLabel("Device Type"))
        form_layout.addWidget(self.device_type_combo)
        form_layout.addWidget(QLabel("Username"))
        form_layout.addWidget(self.username_input)
        form_layout.addWidget(QLabel("Password"))
        form_layout.addWidget(self.password_input)
        form_layout.addWidget(QLabel("Enable Secret"))
        form_layout.addWidget(self.secret_input)
        form_layout.addWidget(QLabel("Configuration Commands"))
        form_layout.addWidget(self.commands_edit)
        form_layout.addWidget(QLabel("Firmware Upload (optional)"))
        form_layout.addLayout(self.firmware_group)

        self.layout.addLayout(form_layout)

    def select_firmware(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Firmware File", "", "All Files (*)")
        if file_path:
            self.firmware_path.setText(file_path)

    def get_device_data(self) -> Optional[dict]:
        ip = self.ip_input.text().strip()
        device_type = self.device_type_combo.currentText()
        username = self.username_input.text().strip()
        password = self.password_input.text()
        secret = self.secret_input.text() or None
        commands = [line.strip() for line in self.commands_edit.toPlainText().splitlines() if line.strip()]
        firmware_file = self.firmware_path.text().strip() or None
        firmware_dest = self.firmware_dest_input.text().strip() or None
        firmware_update_command = self.firmware_update_cmd_input.text().strip() or None

        if not ip or not username or not password or not commands:
            return None

        if firmware_file:
            if not Path(firmware_file).is_file():
                return None
            if not firmware_dest:
                return None

        return {
            "ip": ip,
            "device_type": device_type,
            "username": username,
            "password": password,
            "secret": secret,
            "commands": commands,
            "firmware_file": firmware_file,
            "firmware_dest": firmware_dest,
            "firmware_update_command": firmware_update_command,
        }

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Welcome")
        self.setMinimumSize(800, 600)
        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        self.device_entries_container = QVBoxLayout()
        self.device_entries_widget = QWidget()
        self.device_entries_widget.setLayout(self.device_entries_container)

        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setWidget(self.device_entries_widget)
        self.layout.addWidget(self.scroll_area)

        self.add_device_btn = QPushButton("Add Device")
        self.add_device_btn.clicked.connect(self.add_device_entry)
        self.layout.addWidget(self.add_device_btn)

        self.run_btn = QPushButton("Run Automation")
        self.run_btn.clicked.connect(self.run_automation)
        self.layout.addWidget(self.run_btn)

        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setLineWrapMode(QTextEdit.NoWrap)
        self.layout.addWidget(self.output)

        self.device_entries = []
        self.add_device_entry()

        self.active_workers = 0
        self.lock = threading.Lock()

    def add_device_entry(self):
        entry = DeviceEntry()
        frame = QFrame()
        frame.setFrameShape(QFrame.StyledPanel)
        frame.setLayout(QVBoxLayout())
        frame.layout().addWidget(entry)
        frame.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.device_entries_container.addWidget(frame)
        self.device_entries.append(entry)

    def run_automation(self):
        devices = []
        for entry in self.device_entries:
            data = entry.get_device_data()
            if data is None:
                QMessageBox.warning(self, "Input Error", "Please fill all required fields correctly for all devices.")
                return
            devices.append(data)

        self.output.clear()
        self.run_btn.setEnabled(False)
        self.add_device_btn.setEnabled(False)
        self.active_workers = len(devices)

        for device in devices:
            signals = WorkerSignals()
            signals.result.connect(self.handle_result)
            signals.error.connect(self.handle_error)
            signals.finished.connect(self.handle_finished)
            worker = DeviceWorker(device, signals)
            worker.start()

    def handle_result(self, ip: str, result: str):
        self.output.append(f"=== {ip} ===\n{result}\n")

    def handle_error(self, message: str):
        self.output.append(f"*** ERROR ***\n{message}\n")

    def handle_finished(self):
        with self.lock:
            self.active_workers -= 1
            if self.active_workers == 0:
                self.run_btn.setEnabled(True)
                self.add_device_btn.setEnabled(True)
                QMessageBox.information(self, "Automation Complete", "All device tasks finished.")

def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
