#!/usr/bin/env python
"""
SentinelX Activation Dialog
Professional GUI using PySide6 for license activation and trial.
"""
import sys
import os
import subprocess
import ctypes
sys.path.insert(0, 'src')

from PySide6.QtWidgets import (
    QApplication, QDialog, QVBoxLayout, QHBoxLayout, 
    QLabel, QLineEdit, QPushButton, QMessageBox, QGroupBox
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QIcon
from sentinelx.services.product_key_manager import ProductKeyManager


class ActivationDialog(QDialog):
    """Professional activation dialog using PySide6."""
    
    def __init__(self):
        super().__init__()
        self.manager = ProductKeyManager()
        self.result = None
        self.init_ui()
        self.center_window()
    
    def init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle("SentinelX License Activation")
        self.setGeometry(100, 100, 550, 420)
        self.setStyleSheet("""
            QDialog {
                background-color: #1e1e1e;
            }
            QLineEdit {
                padding: 10px;
                font-size: 11pt;
                border: 1px solid #404040;
                border-radius: 4px;
                background-color: #2d2d2d;
                color: #e0e0e0;
            }
            QLineEdit:focus {
                border: 2px solid #2196F3;
                background-color: #333333;
            }
            QPushButton {
                padding: 8px 16px;
                font-size: 10pt;
                font-weight: bold;
                border-radius: 4px;
                min-height: 36px;
                border: none;
            }
            QPushButton:hover {
                opacity: 0.9;
            }
            QPushButton:pressed {
                opacity: 0.75;
            }
            QPushButton#activateBtn {
                background-color: #2196F3;
                color: white;
            }
            QPushButton#activateBtn:hover {
                background-color: #1976D2;
            }
            QPushButton#activateBtn:pressed {
                background-color: #1565C0;
            }
            QPushButton#trialBtn {
                background-color: #4CAF50;
                color: white;
            }
            QPushButton#trialBtn:hover {
                background-color: #45a049;
            }
            QPushButton#trialBtn:pressed {
                background-color: #388E3C;
            }
            QPushButton#cancelBtn {
                background-color: #f44336;
                color: white;
            }
            QPushButton#cancelBtn:hover {
                background-color: #da190b;
            }
            QPushButton#cancelBtn:pressed {
                background-color: #c62828;
            }
            QLabel#headerLabel {
                font-size: 16pt;
                font-weight: bold;
                color: #2196F3;
            }
            QLabel#statusLabel {
                font-size: 10pt;
                color: #4CAF50;
                background-color: #1a3d1a;
                padding: 12px;
                border-radius: 4px;
                border: 1px solid #4CAF50;
                font-weight: bold;
            }
            QLabel#hintLabel {
                font-size: 8pt;
                color: #999999;
            }
            QLabel {
                color: #e0e0e0;
            }
            QGroupBox {
                color: #e0e0e0;
                border: 1px solid #404040;
                border-radius: 4px;
                padding-top: 12px;
                margin-top: 8px;
                background-color: #252525;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 4px;
                color: #2196F3;
                font-weight: bold;
            }
        """)
        
        # Main layout
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # Header
        header = QLabel("SentinelX License Activation")
        header.setObjectName("headerLabel")
        layout.addWidget(header)
        
        # Status
        status_text = f"Status: {self.manager.get_status_message()}"
        status_label = QLabel(status_text)
        status_label.setObjectName("statusLabel")
        layout.addWidget(status_label)
        self.status_label = status_label
        
        # Product Key Section
        key_section = QGroupBox("Product Key")
        key_layout = QVBoxLayout()
        
        key_label = QLabel("Enter your product key:")
        key_layout.addWidget(key_label)
        
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("SENT-M/H/AXXX-XXXX-XXXX")
        key_layout.addWidget(self.key_input)
        
        hint = QLabel("Format: SENT-M/H/AXXX-XXXX-XXXX (dashes added automatically)")
        hint.setObjectName("hintLabel")
        key_layout.addWidget(hint)
        
        plans = QLabel("Plans: M=Monthly(30d)  H=Half-yearly(180d)  A=Annual(365d)")
        plans.setObjectName("hintLabel")
        key_layout.addWidget(plans)
        
        key_section.setLayout(key_layout)
        layout.addWidget(key_section)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        activate_btn = QPushButton("Activate with Key")
        activate_btn.setObjectName("activateBtn")
        activate_btn.clicked.connect(self._on_activate)
        button_layout.addWidget(activate_btn)
        
        trial_btn = QPushButton("Start 30-Day Trial")
        trial_btn.setObjectName("trialBtn")
        trial_btn.clicked.connect(self._on_trial)
        button_layout.addWidget(trial_btn)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setObjectName("cancelBtn")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
        
        # Set focus to key input
        self.key_input.setFocus()
    
    def center_window(self):
        """Center the window on the screen."""
        screen_geometry = self.screen().availableGeometry()
        x = (screen_geometry.width() - self.width()) // 2
        y = (screen_geometry.height() - self.height()) // 2
        self.move(x, y)
    
    def _parse_product_key(self, user_input: str) -> str:
        """
        Parse user input and reconstruct product key with proper dashes.
        Accepts various formats and extracts the key components.
        """
        # Remove all whitespace and dashes
        clean = user_input.replace("-", "").replace(" ", "").upper()
        
        # Must start with SENT
        if not clean.startswith('SENT'):
            return ""
        
        # Extract components after SENT
        remainder = clean[4:]  # Get everything after 'SENT'
        
        # Should have: [M/H/A]XXX (4 chars) + XXXX (4 chars) + XXXX (4 chars) = 12 chars
        if len(remainder) != 12:
            return ""
        
        # Extract segments
        seg1 = remainder[0:4]    # First 4 chars (plan code + 3)
        seg2 = remainder[4:8]    # Next 4 chars
        seg3 = remainder[8:12]   # Last 4 chars
        
        # Reconstruct with proper dashes
        formatted_key = f"SENT-{seg1}-{seg2}-{seg3}"
        return formatted_key
    
    def _on_activate(self):
        """Handle product key activation."""
        user_input = self.key_input.text().strip()
        
        if not user_input:
            QMessageBox.warning(self, "Empty Key", "Please enter a product key.")
            return
        
        # Parse and reformat the key
        product_key = self._parse_product_key(user_input)
        
        if not product_key:
            QMessageBox.critical(
                self, "Invalid Key",
                "Product key format is invalid.\n\n"
                "Format: SENT-M/H/AXXX-XXXX-XXXX\n"
                "(Can be typed with or without dashes)"
            )
            return
        
        # Validate the formatted key
        if not self.manager.validate_product_key(product_key):
            QMessageBox.critical(
                self, "Invalid Key",
                "Product key validation failed.\n\n"
                "Please check the key and try again."
            )
            return
        
        # Activate
        if self.manager.activate(product_key):
            status = self.manager.get_status()
            plan_name = status.plan.upper() if status.plan else "UNKNOWN"
            days_text = f"{status.plan_days_remaining} days" if status.plan_days_remaining else "Unknown"
            
            QMessageBox.information(
                self, "Activation Successful",
                f"SentinelX is now licensed!\n\n"
                f"Plan: {plan_name}\n"
                f"Duration: {days_text}\n"
                f"Expires: {status.expiration_date}"
            )
            self.result = True
            self.accept()
        else:
            QMessageBox.critical(
                self, "Activation Failed",
                "Failed to activate with the provided key.\n"
                "Please verify the key and try again."
            )
    
    def _launch_gui_enhanced(self):
        """Launch the main SentinelX GUI with admin privileges."""
        try:
            print("Launching main GUI with admin privileges...")
            
            # Get paths
            workspace_root = os.getcwd()
            python_exe = sys.executable
            gui_script = os.path.join(workspace_root, 'run_gui.py')
            
            if not os.path.exists(gui_script):
                print(f"Error: run_gui.py not found at {gui_script}")
                return
            
            # Launch with admin privileges using runas (Windows only)
            if sys.platform == 'win32':
                try:
                    # Use ShellExecuteW for admin elevation on Windows
                    import ctypes
                    
                    # Construct command
                    cmd = f'"{python_exe}" "{gui_script}"'
                    
                    # Execute with admin privileges
                    result = ctypes.windll.shell32.ShellExecuteW(
                        None,
                        "runas",  # Operation: run as administrator
                        python_exe,
                        f'"{gui_script}"',
                        workspace_root,
                        1  # SW_SHOW
                    )
                    
                    if result > 32:
                        print("GUI process started with admin privileges")
                    else:
                        print(f"Failed to execute with admin privileges (error code: {result})")
                except Exception as e:
                    print(f"Error using ShellExecuteW: {e}")
                    # Fallback: try without elevation
                    subprocess.Popen(
                        [python_exe, gui_script],
                        cwd=workspace_root,
                        creationflags=subprocess.CREATE_NEW_CONSOLE
                    )
            else:
                # On non-Windows, launch normally
                subprocess.Popen(
                    [python_exe, gui_script],
                    cwd=workspace_root
                )
                
        except Exception as e:
            print(f"Failed to launch GUI: {e}")
            import traceback
            traceback.print_exc()
    
    def _on_trial(self):
        """Handle start trial - launch GUI first, then exit."""
        status = self.manager.get_status()
        
        if status.is_trial or status.is_activated:
            # Trial or activation already exists - launch GUI first, then exit
            self._launch_gui_enhanced()
            self.result = True
            self.accept()
            return
        
        # Start trial directly without confirmation dialog
        if self.manager.start_trial():
            # Launch main GUI FIRST (before closing dialog)
            self._launch_gui_enhanced()
            # THEN close activation dialog
            self.result = True
            self.accept()
        else:
            QMessageBox.critical(
                self, "Trial Failed",
                "Failed to start trial period."
            )


def main():
    """Run the activation dialog."""
    try:
        app = QApplication.instance()
        if app is None:
            app = QApplication(sys.argv)
        
        dialog = ActivationDialog()
        dialog.show()
        sys.exit(app.exec())
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main() or 0)
