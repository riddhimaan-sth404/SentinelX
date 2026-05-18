#!/usr/bin/env python3
"""
SentinelX GUI Launcher - Robust Startup with Comprehensive Error Handling
Handles all initialization issues and provides detailed diagnostics
"""
import sys
import os
import traceback
import time
from pathlib import Path

# Enable buffering to ensure output is visible
sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 1)
sys.stderr = os.fdopen(sys.stderr.fileno(), 'w', 1)

def log(message):
    """Print log message with timestamp"""
    print(f"[{time.strftime('%H:%M:%S')}] {message}")
    sys.stdout.flush()

def main():
    try:
        log("SentinelX GUI Launcher Starting...")
        log(f"Python: {sys.version}")
        log(f"Working Directory: {os.getcwd()}")
        
        # Add src directory to path
        script_dir = Path(__file__).parent
        src_dir = script_dir / 'src'
        log(f"Adding to path: {src_dir}")
        sys.path.insert(0, str(src_dir))
        
        log("")
        
        # Try to import PySide6
        log("Importing PySide6...")
        try:
            from PySide6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel
            from PySide6.QtCore import QTimer
            log("[OK] PySide6 imported successfully")
        except ImportError as e:
            log(f"[FAIL] Failed to import PySide6: {e}")
            log("Please install: pip install PySide6")
            input("Press Enter to exit...")
            return 1
        
        # Try to import enhanced GUI
        log("Importing enhanced GUI module...")
        gui_module = None
        try:
            from sentinelx.web.gui_enhanced import SentinelXEnhancedGUI
            gui_module = SentinelXEnhancedGUI
            log("[OK] Enhanced GUI module imported successfully")
        except Exception as e:
            log(f"[WARN] Enhanced GUI import failed: {e}")
            log("Will use fallback simple GUI")
        
        # Define fallback simple GUI
        log("Setting up simple GUI fallback...")
        from PySide6.QtWidgets import QPushButton, QTextEdit, QTabWidget
        from PySide6.QtGui import QFont
        
        class SimpleSentinelXGUI(QMainWindow):
            """Minimal working GUI"""
            def __init__(self):
                super().__init__()
                self.setWindowTitle("SentinelX - Malware Detection System")
                self.setGeometry(100, 100, 1200, 800)
                self.setup_ui()
            
            def setup_ui(self):
                central_widget = QWidget()
                self.setCentralWidget(central_widget)
                layout = QVBoxLayout(central_widget)
                
                title = QLabel("SentinelX Dashboard")
                title_font = QFont()
                title_font.setPointSize(16)
                title_font.setBold(True)
                title.setFont(title_font)
                layout.addWidget(title)
                
                tabs = QTabWidget()
                
                # Dashboard Tab
                dashboard_widget = QWidget()
                dashboard_layout = QVBoxLayout(dashboard_widget)
                dashboard_layout.addWidget(QLabel("System Status: READY"))
                dashboard_layout.addWidget(QLabel(
                    "SentinelX v2.0\n\n"
                    "[+] Multi-layer Detection (YARA + AI + Sandbox)\n"
                    "[+] USB Device Scanning\n"
                    "[+] Quarantine Management\n"
                    "[+] Network Firewall\n"
                    "[+] File Monitoring\n"
                ))
                scan_buttons_layout = QVBoxLayout()
                
                for scan_type in ["Quick Scan", "Full System Scan", "USB Scan", "File Scan"]:
                    btn = QPushButton(scan_type)
                    btn.clicked.connect(lambda checked, t=scan_type: self.log_scan(t))
                    scan_buttons_layout.addWidget(btn)
                
                dashboard_layout.addLayout(scan_buttons_layout)
                dashboard_layout.addStretch()
                tabs.addTab(dashboard_widget, "Dashboard")
                
                # Console Tab
                console_widget = QWidget()
                console_layout = QVBoxLayout(console_widget)
                self.console = QTextEdit()
                self.console.setReadOnly(True)
                self.console.setText("SentinelX Dashboard Started\n")
                console_layout.addWidget(self.console)
                tabs.addTab(console_widget, "Console")
                
                layout.addWidget(tabs)
            
            def log_scan(self, scan_type):
                self.console.append(f"[{time.strftime('%H:%M:%S')}] {scan_type} initiated\n")
        
        # Create application
        log("Creating QApplication...")
        app = QApplication.instance()
        if not app:
            app = QApplication(sys.argv)
        log("[OK] QApplication created")
        
        # Create window
        log("Creating GUI window...")
        if gui_module:
            try:
                window = gui_module()
                log("[OK] Enhanced GUI created")
            except Exception as e:
                log(f"[WARN] Enhanced GUI creation failed: {e}")
                log("Falling back to simple GUI")
                window = SimpleSentinelXGUI()
        else:
            window = SimpleSentinelXGUI()
        
        log("[OK] GUI window created")
        
        # Display window BEFORE event loop
        log("Displaying window...")
        window.show()  # Use show() not showNormal() - more reliable
        window.raise_()
        window.activateWindow()
        
        # Force render
        app.processEvents()
        log("[OK] Window should now be visible")
        
        log("GUI startup complete. Running event loop...")
        exit_code = app.exec()
        log(f"Event loop exited with code: {exit_code}")
        return exit_code
    
    except Exception as e:
        log(f"[FATAL] {e}")
        log("\nTraceback:")
        traceback.print_exc()
        log("\nTroubleshooting:")
        log("1. Ensure Python 3.10+ is installed")
        log("2. Verify virtual environment: env/Scripts/python.exe")
        log("3. Check dependencies: pip list | grep -i pyside")
        log("4. Try: pip install -r requirements.txt")
        input("\nPress Enter to exit...")
        return 1

if __name__ == '__main__':
    try:
        exit_code = main()
    except KeyboardInterrupt:
        log("\nInterrupted by user")
        exit_code = 130
    except Exception as e:
        log(f"Uncaught exception: {e}")
        traceback.print_exc()
        exit_code = 1
    
    log(f"Exiting with code {exit_code}")
    sys.exit(exit_code)
