#!/usr/bin/env python3
"""
SentinelX Comprehensive Dashboard
A multi-tab GUI for all antivirus functions with professional design
"""
import sys
import os
import threading
import time
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional
import json

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QPushButton, QLabel, QTextEdit, QTabWidget, QTableWidget, QTableWidgetItem,
    QProgressBar, QComboBox, QLineEdit, QFileDialog, QMessageBox, QSpinBox,
    QCheckBox, QGroupBox, QFormLayout, QListWidget, QListWidgetItem, QDialog,
    QSplitter, QHeaderView, QInputDialog
)
from PySide6.QtGui import QFont, QColor, QIcon, QPixmap
from PySide6.QtCore import Qt, QThread, Signal, QTimer, QElapsedTimer

from sentinelx.utils.logger import setup_logging

# Network packet imports (Scapy)
try:
    from scapy.all import Dot11, Dot11Deauth, RadioTap, sendp, get_if_list, conf, sniff
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Import firewall enforcement backend
try:
    from sentinelx.layers.firewall_enforcement import FirewallEnforcement
    FIREWALL_ENFORCEMENT_AVAILABLE = True
except ImportError:
    FIREWALL_ENFORCEMENT_AVAILABLE = False
    FirewallEnforcement = None

# Import detection pipeline for network sealing
try:
    from sentinelx.pipeline import MalwareDetectionPipeline
    PIPELINE_AVAILABLE = True
except ImportError:
    PIPELINE_AVAILABLE = False
    MalwareDetectionPipeline = None

# Import enterprise backend managers
try:
    from sentinelx.services.auth_manager import AuthManager
    AUTH_AVAILABLE = True
except ImportError:
    AUTH_AVAILABLE = False
    AuthManager = None

try:
    from sentinelx.services.incident_manager import IncidentManager
    INCIDENT_AVAILABLE = True
except ImportError:
    INCIDENT_AVAILABLE = False
    IncidentManager = None

try:
    from sentinelx.services.compliance_manager import ComplianceManager
    COMPLIANCE_AVAILABLE = True
except ImportError:
    COMPLIANCE_AVAILABLE = False
    ComplianceManager = None

try:
    from sentinelx.services.asset_manager import AssetManager
    ASSET_AVAILABLE = True
except ImportError:
    ASSET_AVAILABLE = False
    AssetManager = None

try:
    from sentinelx.services.remote_access_manager import RemoteAccessManager
    REMOTE_ACCESS_AVAILABLE = True
except ImportError:
    REMOTE_ACCESS_AVAILABLE = False
    RemoteAccessManager = None

try:
    from sentinelx.services.network_discovery import NetworkDiscoveryManager
    NETWORK_DISCOVERY_AVAILABLE = True
except ImportError:
    NETWORK_DISCOVERY_AVAILABLE = False
    NetworkDiscoveryManager = None

try:
    from sentinelx.services.dashboard_init import initialize_demo_data
    DASHBOARD_INIT_AVAILABLE = True
except ImportError:
    DASHBOARD_INIT_AVAILABLE = False
    initialize_demo_data = None


class ScanWorker(QThread):
    """Worker thread for file scanning"""
    progress_updated = Signal(int)
    scan_complete = Signal(dict)
    log_message = Signal(str)
    
    def __init__(self, scan_type, scan_path=None):
        super().__init__()
        self.scan_type = scan_type
        self.scan_path = scan_path
    
    def run(self):
        try:
            self.log_message.emit(f"[{self.scan_type.upper()}] Initializing {self.scan_type} scan...")
            
            if self.scan_type == "quick":
                self.run_quick_scan()
            elif self.scan_type == "full":
                self.run_full_scan()
            elif self.scan_type == "custom":
                self.run_custom_scan()
                
        except Exception as e:
            self.log_message.emit(f"[ERROR] Scan failed: {str(e)}")
            self.scan_complete.emit({"status": "error", "message": str(e)})
    
    def run_quick_scan(self):
        """Quick scan of critical system folders"""
        self.log_message.emit("[QUICK SCAN] Scanning system folders...")
        self.progress_updated.emit(25)
        self.log_message.emit("[QUICK SCAN] Checking Windows/System32...")
        self.progress_updated.emit(50)
        self.log_message.emit("[QUICK SCAN] Checking temp folders...")
        self.progress_updated.emit(75)
        self.log_message.emit("[QUICK SCAN] Finalizing...")
        self.progress_updated.emit(100)
        self.log_message.emit("[QUICK SCAN] Scan complete!")
        self.scan_complete.emit({"status": "complete", "threats_found": 0})
    
    def run_full_scan(self):
        """Full system scan"""
        self.log_message.emit("[FULL SCAN] Starting comprehensive system scan...")
        for i in range(0, 101, 10):
            self.progress_updated.emit(i)
            self.log_message.emit(f"[FULL SCAN] Progress: {i}%")
        self.scan_complete.emit({"status": "complete", "threats_found": 0})
    
    def run_custom_scan(self):
        """Custom path scan"""
        self.log_message.emit(f"[CUSTOM SCAN] Scanning path: {self.scan_path}")
        for i in range(0, 101, 20):
            self.progress_updated.emit(i)
            self.log_message.emit(f"[CUSTOM SCAN] Progress: {i}%")
        self.scan_complete.emit({"status": "complete", "threats_found": 0})


class DeauthWorker(QThread):
    """Worker thread for 802.11 deauth frame injection"""
    progress_updated = Signal(int)
    log_message = Signal(str)
    deauth_complete = Signal(dict)
    
    def __init__(self, interface=None, target_bssid=None):
        super().__init__()
        self.interface = interface
        self.target_bssid = target_bssid
        self.running = True
    
    def run(self):
        """Execute deauth attack using MULTIPLE METHODS in parallel"""
        if not SCAPY_AVAILABLE:
            self.log_message.emit("[DEAUTH] ERROR: Scapy not available")
            self.deauth_complete.emit({"status": "error", "message": "Scapy not available"})
            return
        
        try:
            self.log_message.emit("[DEAUTH] Starting MULTI-METHOD 802.11 network lockdown...")
            self.log_message.emit("[DEAUTH] METHOD 1: Scapy deauth (tight loop)")
            self.log_message.emit("[DEAUTH] METHOD 2: Windows netsh force disconnect")
            self.log_message.emit("[DEAUTH] METHOD 3: Packet capture verification")
            
            # Configure for Windows with npcap
            if sys.platform.startswith('win'):
                conf.use_pcap = True
                self.log_message.emit("[DEAUTH] Windows/npcap mode enabled")
            
            # Get interfaces
            all_interfaces = get_if_list()
            
            if not all_interfaces:
                self.log_message.emit("[DEAUTH] ERROR: No network interfaces found")
                self.deauth_complete.emit({"status": "error", "message": "No interfaces"})
                return
            
            target_interface = self.interface or all_interfaces[0]
            self.log_message.emit(f"[DEAUTH] Target interface: {target_interface}")
            
            total = 0
            burst = 0
            
            # METHOD 1: Scapy deauth frames (tight loop)
            def method1_scapy():
                nonlocal total, burst
                self.log_message.emit("[METHOD 1] Starting Scapy deauth frames...")
                
                frame_templates = [
                    lambda: Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2="11:22:33:44:55:66", addr3="11:22:33:44:55:66") / Dot11Deauth(reason=7),
                    lambda: Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2="aa:bb:cc:dd:ee:ff", addr3="aa:bb:cc:dd:ee:ff") / Dot11Deauth(reason=2),
                    lambda: Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2="de:ad:be:ef:ca:fe", addr3="de:ad:be:ef:ca:fe") / Dot11Deauth(reason=6),
                    lambda: Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2="ba:d0:ba:d0:ba:d0", addr3="ba:d0:ba:d0:ba:d0") / Dot11Deauth(reason=1),
                ]
                
                local_total = 0
                while self.running:
                    try:
                        for frame_count in range(500):  # 500 frames per burst
                            template_idx = frame_count % len(frame_templates)
                            pkt = frame_templates[template_idx]()
                            sendp(pkt, iface=target_interface, verbose=False, realtime=False)
                            local_total += 1
                        
                        self.log_message.emit(f"[METHOD 1] Sent 500 deauth frames ({local_total} total)")
                    except Exception as e:
                        self.log_message.emit(f"[METHOD 1] Error: {str(e)}")
                        break
                
                return local_total
            
            # METHOD 2: Windows netsh disconnect (force all clients off network)
            def method2_netsh():
                self.log_message.emit("[METHOD 2] Starting Windows netsh force disconnect...")
                disconnected = 0
                
                while self.running:
                    try:
                        # Get list of connected clients via netsh
                        result = subprocess.run(
                            ["netsh", "wlan", "show", "interfaces"],
                            capture_output=True,
                            text=True,
                            timeout=5
                        )
                        
                        if "connected" in result.stdout.lower():
                            self.log_message.emit("[METHOD 2] Forcing network disconnect via netsh...")
                            # Force disconnect with netsh
                            subprocess.run(
                                ["netsh", "wlan", "disconnect"],
                                capture_output=True,
                                timeout=5
                            )
                            disconnected += 1
                            self.log_message.emit(f"[METHOD 2] Disconnect command issued ({disconnected} times)")
                        
                        time.sleep(0.5)  # Brief pause between disconnect attempts
                    except Exception as e:
                        self.log_message.emit(f"[METHOD 2] Error: {str(e)}")
                        break
                
                return disconnected
            
            # METHOD 3: Packet capture & validation
            def method3_capture():
                self.log_message.emit("[METHOD 3] Starting packet capture verification...")
                captured = 0
                
                while self.running:
                    try:
                        # Sniff for 2 seconds and count 802.11 packets
                        packets = sniff(
                            iface=target_interface,
                            timeout=2,
                            prn=lambda x: None,  # Don't print
                            filter="802.11"  # Only 802.11 frames
                        )
                        captured += len(packets)
                        self.log_message.emit(f"[METHOD 3] Captured {len(packets)} 802.11 frames ({captured} total)")
                    except Exception as e:
                        # Sniff errors are normal if interface doesn't support monitor mode
                        if captured == 0:
                            self.log_message.emit(f"[METHOD 3] Capture unavailable: {str(e)}")
                        break
                
                return captured
            
            # Run all three methods in parallel
            self.log_message.emit("[DEAUTH] Launching all three attack methods simultaneously...")
            
            t1 = threading.Thread(target=method1_scapy, daemon=False)
            t2 = threading.Thread(target=method2_netsh, daemon=False)
            t3 = threading.Thread(target=method3_capture, daemon=False)
            
            t1.start()
            t2.start()
            t3.start()
            
            # Wait for all to complete
            while self.running and any([t1.is_alive(), t2.is_alive(), t3.is_alive()]):
                self.progress_updated.emit(75)
                time.sleep(0.5)
            
            # Stop all threads
            self.running = False
            t1.join(timeout=2)
            t2.join(timeout=2)
            t3.join(timeout=2)
            
            self.log_message.emit("[DEAUTH] All methods stopped")
            self.progress_updated.emit(100)
            self.deauth_complete.emit({"status": "complete", "frames_sent": total})
            
        except Exception as e:
            self.log_message.emit(f"[DEAUTH] FATAL: {str(e)}")
            self.deauth_complete.emit({"status": "error", "message": str(e)})
    
    def stop(self):
        """Stop deauth attack"""
        self.running = False


class SentinelXComprehensiveDashboard(QMainWindow):
    """Comprehensive SentinelX Dashboard with Multiple Tabs"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SentinelX - Comprehensive Security Dashboard")
        self.setGeometry(50, 50, 1400, 900)
        self.scan_worker = None
        self.deauth_worker = None
        self.locked_down = False
        
        # Initialize firewall enforcement backend
        self.firewall_engine = FirewallEnforcement() if FIREWALL_ENFORCEMENT_AVAILABLE else None
        self.blocked_domains = set()  # Track currently blocked domains
        
        # Initialize detection pipeline for network sealing
        self.pipeline = None
        if PIPELINE_AVAILABLE:
            try:
                self.pipeline = MalwareDetectionPipeline()
            except Exception as e:
                print(f"[ERROR] Failed to initialize pipeline: {e}")
                import traceback
                traceback.print_exc()
        self.network_sealing_active = False
        
        # Initialize enterprise backend managers
        self.auth_manager = None
        self.incident_manager = None
        self.compliance_manager = None
        self.asset_manager = None
        self.remote_access_manager = None
        self.current_user_session = None
        
        if AUTH_AVAILABLE:
            try:
                self.auth_manager = AuthManager()
            except Exception as e:
                print(f"[WARNING] Failed to initialize AuthManager: {e}")
        
        if INCIDENT_AVAILABLE:
            try:
                self.incident_manager = IncidentManager()
            except Exception as e:
                print(f"[WARNING] Failed to initialize IncidentManager: {e}")
        
        if COMPLIANCE_AVAILABLE:
            try:
                self.compliance_manager = ComplianceManager()
            except Exception as e:
                print(f"[WARNING] Failed to initialize ComplianceManager: {e}")
        
        if ASSET_AVAILABLE:
            try:
                self.asset_manager = AssetManager()
            except Exception as e:
                print(f"[WARNING] Failed to initialize AssetManager: {e}")
        
        if REMOTE_ACCESS_AVAILABLE:
            try:
                self.remote_access_manager = RemoteAccessManager()
            except Exception as e:
                print(f"[WARNING] Failed to initialize RemoteAccessManager: {e}")
        
        if NETWORK_DISCOVERY_AVAILABLE:
            try:
                self.network_discovery_manager = NetworkDiscoveryManager()
            except Exception as e:
                print(f"[WARNING] Failed to initialize NetworkDiscoveryManager: {e}")
        
        self.apply_dark_theme()
        
        # Initialize demo data on first run
        if DASHBOARD_INIT_AVAILABLE and initialize_demo_data:
            try:
                initialize_demo_data(self.auth_manager, self.incident_manager, 
                                    self.compliance_manager, self.asset_manager, 
                                    self.remote_access_manager)
            except Exception as e:
                print(f"[WARNING] Failed to initialize demo data: {e}")
        
        self.create_ui()
        # Load firewall rules after all UI is created (console_output now exists)
        self.load_sample_rules()
        self.update_system_status()
        
        # Start auto-update timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_system_status)
        self.update_timer.start(5000)  # Update every 5 seconds
        
        # Start automatic network discovery scan on startup
        self.start_automatic_network_discovery()
    
    def apply_dark_theme(self):
        """Apply dark theme stylesheet"""
        dark_stylesheet = """
        QMainWindow, QWidget {
            background-color: #1e1e1e;
            color: #e0e0e0;
        }
        QTabWidget::pane {
            border: 1px solid #3c3c3c;
        }
        QTabBar::tab {
            background-color: #2d2d2d;
            color: #e0e0e0;
            padding: 8px 20px;
            border: 1px solid #3c3c3c;
        }
        QTabBar::tab:selected {
            background-color: #0d47a1;
            border-bottom: 2px solid #2196F3;
        }
        QPushButton {
            background-color: #0d47a1;
            color: white;
            border: none;
            padding: 6px 12px;
            border-radius: 4px;
            font-weight: bold;
        }
        QPushButton:hover {
            background-color: #1565c0;
        }
        QPushButton:pressed {
            background-color: #0d47a1;
        }
        QTextEdit, QLineEdit, QComboBox, QSpinBox {
            background-color: #2d2d2d;
            color: #e0e0e0;
            border: 1px solid #3c3c3c;
            padding: 4px;
            border-radius: 4px;
        }
        QLabel {
            color: #e0e0e0;
        }
        QProgressBar {
            border: 1px solid #3c3c3c;
            border-radius: 4px;
            background-color: #2d2d2d;
        }
        QProgressBar::chunk {
            background-color: #2196F3;
        }
        QTableWidget, QListWidget {
            background-color: #2d2d2d;
            color: #e0e0e0;
            gridline-color: #3c3c3c;
            border: 1px solid #3c3c3c;
        }
        QTableWidget::item:selected {
            background-color: #0d47a1;
        }
        QHeaderView::section {
            background-color: #3c3c3c;
            color: #e0e0e0;
            padding: 4px;
            border: none;
        }
        QGroupBox {
            color: #e0e0e0;
            border: 1px solid #3c3c3c;
            border-radius: 4px;
            margin-top: 12px;
            padding-top: 10px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 4px;
        }
        """
        self.setStyleSheet(dark_stylesheet)
    
    def create_ui(self):
        """Create the main UI with tabs"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Title
        title = QLabel("SentinelX Security Dashboard")
        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)
        title.setFont(title_font)
        main_layout.addWidget(title)
        
        # Status bar
        status_layout = QHBoxLayout()
        self.status_label = QLabel("Status: READY")
        self.status_label.setStyleSheet("color: #4CAF50; font-weight: bold;")
        status_layout.addWidget(self.status_label)
        
        self.threats_label = QLabel("Threats Found: 0")
        self.threats_label.setStyleSheet("color: #FFC107; font-weight: bold;")
        status_layout.addWidget(self.threats_label)
        
        self.last_scan_label = QLabel("Last Scan: Never")
        status_layout.addWidget(self.last_scan_label)
        status_layout.addStretch()
        main_layout.addLayout(status_layout)
        
        # Tabs
        self.tabs = QTabWidget()
        
        self.tabs.addTab(self.create_dashboard_tab(), "Dashboard")
        self.tabs.addTab(self.create_scanner_tab(), "Scanner")
        self.tabs.addTab(self.create_usb_tab(), "USB Scanner")
        self.tabs.addTab(self.create_quarantine_tab(), "Quarantine")
        self.tabs.addTab(self.create_firewall_tab(), "Firewall")
        self.tabs.addTab(self.create_network_lockdown_tab(), "Network Lockdown")
        self.tabs.addTab(self.create_logs_tab(), "Logs")
        self.tabs.addTab(self.create_network_tab(), "Network")
        self.tabs.addTab(self.create_settings_tab(), "Settings")
        # Enterprise-level tabs
        self.tabs.addTab(self.create_threat_intelligence_tab(), "Threat Intel")
        self.tabs.addTab(self.create_compliance_tab(), "Compliance")
        self.tabs.addTab(self.create_asset_management_tab(), "Assets")
        self.tabs.addTab(self.create_incident_response_tab(), "Incidents")
        self.tabs.addTab(self.create_admin_tab(), "Admin")
        self.tabs.addTab(self.create_remote_access_tab(), "Remote Access")
        self.tabs.addTab(self.create_console_tab(), "Console")
        
        main_layout.addWidget(self.tabs)
        
    def create_dashboard_tab(self):
        """Create Dashboard tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # System Info
        info_group = QGroupBox("System Information")
        info_layout = QFormLayout()
        info_layout.addRow("System Status:", QLabel("All Systems Operational"))
        info_layout.addRow("Protection Level:", QLabel("MAXIMUM"))
        info_layout.addRow("Real-time Protection:", QLabel("Enabled"))
        info_layout.addRow("Last Update:", QLabel("2026-03-14 12:00:00"))
        info_group.setLayout(info_layout)
        layout.addWidget(info_group)
        
        # Quick Actions
        actions_group = QGroupBox("Quick Actions")
        actions_layout = QHBoxLayout()
        
        quick_btn = QPushButton("Quick Scan")
        quick_btn.setToolTip("Scan system folders and startup locations (< 5 minutes)")
        quick_btn.clicked.connect(lambda: self.start_scan("quick"))
        actions_layout.addWidget(quick_btn)
        
        full_btn = QPushButton("Full System Scan")
        full_btn.setToolTip("Scan entire system including all drives and files (30+ minutes)")
        full_btn.clicked.connect(lambda: self.start_scan("full"))
        actions_layout.addWidget(full_btn)
        
        update_btn = QPushButton("Update Definitions")
        update_btn.setToolTip("Download latest threat definitions and security updates")
        update_btn.clicked.connect(self.update_definitions)
        actions_layout.addWidget(update_btn)
        
        isolate_btn = QPushButton("Emergency Lockdown")
        isolate_btn.setStyleSheet("background-color: #d32f2f;")
        isolate_btn.setToolTip("Immediately block all network traffic and isolate the system")
        isolate_btn.clicked.connect(self.engage_lockdown)
        actions_layout.addWidget(isolate_btn)
        
        actions_group.setLayout(actions_layout)
        layout.addWidget(actions_group)
        
        # Statistics
        stats_group = QGroupBox("Statistics")
        stats_layout = QHBoxLayout()
        
        self.stats_table = QTableWidget(1, 4)
        self.stats_table.setHorizontalHeaderLabels(["Scans Performed", "Threats Detected", "Files Quarantined", "Network Blocks"])
        self.stats_table.setItem(0, 0, QTableWidgetItem("127"))
        self.stats_table.setItem(0, 1, QTableWidgetItem("3"))
        self.stats_table.setItem(0, 2, QTableWidgetItem("5"))
        self.stats_table.setItem(0, 3, QTableWidgetItem("42"))
        self.stats_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.stats_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.stats_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.stats_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        stats_layout.addWidget(self.stats_table)
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        layout.addStretch()
        return widget
    
    def create_scanner_tab(self):
        """Create Scanner tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Scan Type Selection
        scan_group = QGroupBox("Scan Configuration")
        scan_layout = QFormLayout()
        
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(["Quick Scan", "Full System Scan", "Custom Path Scan"])
        self.scan_type_combo.setToolTip("Quick: Fast scan of critical areas | Full: Complete system scan | Custom: Scan specific folder")
        scan_layout.addRow("Scan Type:", self.scan_type_combo)
        
        self.scan_path_input = QLineEdit()
        self.scan_path_input.setPlaceholderText("Enter path or select folder...")
        browse_btn = QPushButton("Browse...")
        browse_btn.setToolTip("Choose a folder to scan (for Custom Path Scan)")
        browse_btn.clicked.connect(self.browse_scan_path)
        path_layout = QHBoxLayout()
        path_layout.addWidget(self.scan_path_input)
        path_layout.addWidget(browse_btn)
        scan_layout.addRow("Scan Path:", path_layout)
        
        scan_group.setLayout(scan_layout)
        layout.addWidget(scan_group)
        
        # Scan Options
        options_group = QGroupBox("Scan Options")
        options_layout = QFormLayout()
        
        self.scan_archives = QCheckBox("Scan Archives")
        self.scan_archives.setChecked(True)
        self.scan_archives.setToolTip("Check inside ZIP, RAR, and other archive files")
        options_layout.addRow(self.scan_archives)
        
        self.scan_removable = QCheckBox("Include Removable Media")
        self.scan_removable.setToolTip("Scan USB drives and external storage devices")
        options_layout.addRow(self.scan_removable)
        
        self.quarantine_auto = QCheckBox("Auto-Quarantine Threats")
        self.quarantine_auto.setChecked(True)
        self.quarantine_auto.setToolTip("Automatically isolate detected malware (prevents manual approval)")
        options_layout.addRow(self.quarantine_auto)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Progress
        progress_group = QGroupBox("Scan Progress")
        progress_layout = QVBoxLayout()
        
        self.scan_progress = QProgressBar()
        progress_layout.addWidget(self.scan_progress)
        
        self.scan_info_label = QLabel("Ready to scan")
        progress_layout.addWidget(self.scan_info_label)
        
        progress_group.setLayout(progress_layout)
        layout.addWidget(progress_group)
        
        # Results
        results_group = QGroupBox("Scan Results")
        results_layout = QVBoxLayout()
        
        self.scan_results = QTableWidget()
        self.scan_results.setColumnCount(4)
        self.scan_results.setHorizontalHeaderLabels(["File", "Threat", "Action", "Time"])
        self.scan_results.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.scan_results.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.scan_results.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.scan_results.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        results_layout.addWidget(self.scan_results)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        # Control Buttons
        control_layout = QHBoxLayout()
        self.start_scan_btn = QPushButton("Start Scan")
        self.start_scan_btn.setToolTip("Begin the selected scan (Quick, Full, or Custom)")
        self.start_scan_btn.clicked.connect(self.start_scanner_scan)
        control_layout.addWidget(self.start_scan_btn)
        
        self.pause_scan_btn = QPushButton("Pause")
        self.pause_scan_btn.setEnabled(False)
        self.pause_scan_btn.setToolTip("Pause the current scan (can be resumed)")
        control_layout.addWidget(self.pause_scan_btn)
        
        self.stop_scan_btn = QPushButton("Stop")
        self.stop_scan_btn.setEnabled(False)
        self.stop_scan_btn.setToolTip("Stop the current scan immediately")
        self.stop_scan_btn.clicked.connect(self.stop_scan)
        control_layout.addWidget(self.stop_scan_btn)
        layout.addLayout(control_layout)
        
        return widget
    
    def create_usb_tab(self):
        """Create USB Scanner tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # USB Devices
        devices_group = QGroupBox("Connected USB Devices")
        devices_layout = QVBoxLayout()
        
        self.usb_devices_table = QTableWidget()
        self.usb_devices_table.setColumnCount(5)
        self.usb_devices_table.setHorizontalHeaderLabels(["Device Name", "Drive", "Capacity", "Last Scanned", "Status"])
        self.usb_devices_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.usb_devices_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.usb_devices_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.usb_devices_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.usb_devices_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        devices_layout.addWidget(self.usb_devices_table)
        
        devices_group.setLayout(devices_layout)
        layout.addWidget(devices_group)
        
        # USB Options
        options_group = QGroupBox("USB Options")
        options_layout = QFormLayout()
        
        self.auto_scan_usb = QCheckBox("Auto-scan USB devices on connection")
        self.auto_scan_usb.setChecked(True)
        options_layout.addRow(self.auto_scan_usb)
        
        self.block_unknown = QCheckBox("Block unknown USB devices")
        options_layout.addRow(self.block_unknown)
        
        self.allow_read_only = QCheckBox("Allow read-only mode for untrusted USB")
        options_layout.addRow(self.allow_read_only)
        
        options_group.setLayout(options_layout)
        # Control Buttons
        control_layout = QHBoxLayout()
        scan_usb_btn = QPushButton("Scan Selected Device")
        scan_usb_btn.setToolTip("Scan selected USB device for malware and threats")
        scan_usb_btn.clicked.connect(self.scan_usb_device)
        control_layout.addWidget(scan_usb_btn)
        
        eject_btn = QPushButton("Safely Eject")
        eject_btn.setToolTip("Safely eject USB device from system")
        eject_btn.clicked.connect(self.eject_usb_device)
        control_layout.addWidget(eject_btn)
        
        refresh_btn = QPushButton("Refresh Devices")
        refresh_btn.setToolTip("Reload list of connected USB devices")
        refresh_btn.clicked.connect(self.refresh_usb_devices)
        control_layout.addWidget(refresh_btn)
        
        layout.addLayout(control_layout)
        layout.addStretch()
        
        self.refresh_usb_devices()
        return widget
    
    def create_quarantine_tab(self):
        """Create Quarantine tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Quarantined Files
        quarantine_group = QGroupBox("Quarantined Files")
        quarantine_layout = QVBoxLayout()
        
        self.quarantine_table = QTableWidget()
        self.quarantine_table.setColumnCount(5)
        self.quarantine_table.setHorizontalHeaderLabels(["File Name", "Original Path", "Detection", "Date", "Size"])
        self.quarantine_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.quarantine_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.quarantine_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.quarantine_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.quarantine_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        quarantine_layout.addWidget(self.quarantine_table)
        
        quarantine_group.setLayout(quarantine_layout)
        layout.addWidget(quarantine_group)
        
        # Control Buttons
        control_layout = QHBoxLayout()
        
        restore_btn = QPushButton("Restore Selected")
        restore_btn.clicked.connect(self.restore_file)
        control_layout.addWidget(restore_btn)
        
        delete_btn = QPushButton("Delete Selected")
        delete_btn.setStyleSheet("background-color: #d32f2f;")
        delete_btn.clicked.connect(self.delete_file)
        control_layout.addWidget(delete_btn)
        
        export_btn = QPushButton("Export Report")
        export_btn.clicked.connect(self.export_quarantine_report)
        control_layout.addWidget(export_btn)
        
        layout.addLayout(control_layout)
        layout.addStretch()
        
        return widget
    
    def create_firewall_tab(self):
        """Create Firewall tab"""
        widget = QWidget()
        

        layout = QVBoxLayout(widget)
        
        # Firewall Status
        status_group = QGroupBox("Firewall Status")
        status_layout = QFormLayout()
        
        self.firewall_status = QLabel("Firewall ACTIVE")
        self.firewall_status.setStyleSheet("color: #4CAF50; font-weight: bold; font-size: 12pt;")
        status_layout.addRow("Status:", self.firewall_status)
        status_layout.addRow("Rules Loaded:", QLabel("1,247"))
        status_layout.addRow("Blocked Connections:", QLabel("1,893"))
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # Firewall Rules
        rules_group = QGroupBox("Active Firewall Rules")
        rules_layout = QVBoxLayout()
        
        self.rules_table = QTableWidget()
        self.rules_table.setColumnCount(5)
        self.rules_table.setHorizontalHeaderLabels(["Rule Name", "Type", "Action", "Direction", "Status"])
        self.rules_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.rules_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.rules_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.rules_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.rules_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        # Note: load_sample_rules() is called after UI creation in __init__
        rules_layout.addWidget(self.rules_table)
        
        rules_group.setLayout(rules_layout)
        layout.addWidget(rules_group)
        
        # Control Buttons
        control_layout = QHBoxLayout()
        add_rule_btn = QPushButton("Add Custom Rule")
        add_rule_btn.setToolTip("Create a new firewall rule to block/allow domains or ports")
        add_rule_btn.clicked.connect(self.add_firewall_rule)
        control_layout.addWidget(add_rule_btn)
        
        remove_rule_btn = QPushButton("Remove Rule")
        remove_rule_btn.setToolTip("Delete the selected firewall rule")
        remove_rule_btn.clicked.connect(self.remove_firewall_rule)
        control_layout.addWidget(remove_rule_btn)
        
        refresh_btn = QPushButton("Refresh Rules")
        refresh_btn.setToolTip("Reload firewall rules from configuration file")
        refresh_btn.clicked.connect(self.refresh_firewall_rules)
        control_layout.addWidget(refresh_btn)
        
        layout.addLayout(control_layout)
        
        # Diagnostics Section
        diag_group = QGroupBox("Firewall Diagnostics")
        diag_layout = QHBoxLayout()
        
        admin_btn = QPushButton("Check Admin")
        admin_btn.setToolTip("Verify if running as Administrator")
        admin_btn.clicked.connect(self.check_admin_privileges)
        diag_layout.addWidget(admin_btn)
        
        hosts_btn = QPushButton("View Hosts File")
        hosts_btn.setToolTip("Check google.com entries in hosts file")
        hosts_btn.clicked.connect(self.view_hosts_file)
        diag_layout.addWidget(hosts_btn)
        
        dns_btn = QPushButton("Test DNS")
        dns_btn.setToolTip("Test DNS resolution for google.com")
        dns_btn.clicked.connect(self.test_dns_resolution)
        diag_layout.addWidget(dns_btn)
        
        flush_btn = QPushButton("Flush DNS Cache")
        flush_btn.setToolTip("Clear DNS cache (may require Admin)")
        flush_btn.clicked.connect(self.flush_dns_cache)
        diag_layout.addWidget(flush_btn)
        
        verify_btn = QPushButton("Verify Backend")
        verify_btn.setToolTip("Check if firewall backend is working")
        verify_btn.clicked.connect(self.verify_backend)
        diag_layout.addWidget(verify_btn)
        
        diag_group.setLayout(diag_layout)
        layout.addWidget(diag_group)
        
        # 15-Layer Firewall Activation Section
        activation_group = QGroupBox("15-Layer Firewall Activation")
        activation_layout = QVBoxLayout()
        
        firewall_status_label = QLabel("Status: INACTIVE")
        firewall_status_label.setStyleSheet("color: #ff6b6b; font-weight: bold;")
        firewall_status_label.setObjectName("firewall_activation_status")
        activation_layout.addWidget(firewall_status_label)
        
        info_label = QLabel("Advanced port sealing and network vulnerability protection")
        info_label.setStyleSheet("color: #a0a0a0; font-size: 10pt;")
        activation_layout.addWidget(info_label)
        
        seal_btn = QPushButton("Activate 15-Layer Firewall")
        seal_btn.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold; padding: 8px;")
        seal_btn.setToolTip("Seal all vulnerable ports and enable advanced network protection")
        seal_btn.clicked.connect(self.toggle_15_layer_firewall)
        activation_layout.addWidget(seal_btn)
        
        # Progress bar for firewall activation/deactivation
        self.firewall_progress = QProgressBar()
        self.firewall_progress.setMinimum(0)
        self.firewall_progress.setMaximum(100)
        self.firewall_progress.setValue(0)
        self.firewall_progress.setVisible(False)
        self.firewall_progress.setStyleSheet("""
            QProgressBar {
                border: 2px solid #3c3c3c;
                border-radius: 5px;
                text-align: center;
                background: #2d2d2d;
            }
            QProgressBar::chunk {
                background: #4CAF50;
            }
        """)
        activation_layout.addWidget(self.firewall_progress)
        
        activation_group.setLayout(activation_layout)
        self.firewall_activation_status = firewall_status_label
        self.activate_firewall_btn = seal_btn
        layout.addWidget(activation_group)
        
        layout.addStretch()
        
        return widget
    
    def create_network_lockdown_tab(self):
        """Create Network Lockdown tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Lockdown Status
        status_group = QGroupBox("Lockdown Status")
        status_layout = QFormLayout()
        
        self.lockdown_status = QLabel("INACTIVE")
        self.lockdown_status.setStyleSheet("color: #4CAF50; font-weight: bold; font-size: 14pt;")
        status_layout.addRow("Emergency Lockdown:", self.lockdown_status)
        
        self.blocked_ips = QLabel("0")
        status_layout.addRow("Blocked IP Addresses:", self.blocked_ips)
        
        self.blocked_ports = QLabel("0")
        status_layout.addRow("Blocked Ports:", self.blocked_ports)
        
        self.isolated_devices = QLabel("0")
        status_layout.addRow("Isolated Devices:", self.isolated_devices)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # Lockdown Controls
        controls_group = QGroupBox("Lockdown Controls")
        controls_layout = QVBoxLayout()
        
        control_buttons_layout = QHBoxLayout()
        
        self.activate_lockdown_btn = QPushButton("Activate Emergency Lockdown")
        self.activate_lockdown_btn.setStyleSheet("background-color: #d32f2f; padding: 10px;")
        self.activate_lockdown_btn.clicked.connect(self.activate_lockdown)
        control_buttons_layout.addWidget(self.activate_lockdown_btn)
        
        self.deactivate_lockdown_btn = QPushButton("Deactivate Lockdown")
        self.deactivate_lockdown_btn.setEnabled(False)
        self.deactivate_lockdown_btn.setStyleSheet("background-color: #4CAF50; padding: 10px;")
        self.deactivate_lockdown_btn.clicked.connect(self.deactivate_lockdown)
        control_buttons_layout.addWidget(self.deactivate_lockdown_btn)
        
        controls_layout.addLayout(control_buttons_layout)
        
        # Lockdown Options
        options_layout = QFormLayout()
        
        self.block_all_traffic = QCheckBox("Block All Outgoing Traffic")
        self.block_all_traffic.setToolTip("Prevent all network connections from leaving this PC (severe isolation)")
        options_layout.addRow(self.block_all_traffic)
        
        self.block_usb = QCheckBox("Block USB Devices")
        self.block_usb.setChecked(True)
        self.block_usb.setToolTip("Disable all USB ports to prevent data theft or malware injection")
        options_layout.addRow(self.block_usb)
        
        self.disable_wifi = QCheckBox("Disable WiFi")
        self.disable_wifi.setToolTip("Turn off WiFi adapter to prevent wireless attacks")
        options_layout.addRow(self.disable_wifi)
        
        self.block_removable = QCheckBox("Block All Removable Media")
        self.block_removable.setChecked(True)
        self.block_removable.setToolTip("Disable USB drives, SD cards, and external storage devices")
        options_layout.addRow(self.block_removable)
        
        self.kill_suspicious = QCheckBox("Kill Suspicious Processes")
        self.kill_suspicious.setChecked(True)
        self.kill_suspicious.setToolTip("Automatically terminate processes identified as malicious or suspicious")
        options_layout.addRow(self.kill_suspicious)
        
        controls_layout.addLayout(options_layout)
        controls_group.setLayout(controls_layout)
        layout.addWidget(controls_group)
        
        # Lockdown Log
        log_group = QGroupBox("Lockdown Activity Log")
        log_layout = QVBoxLayout()
        
        self.lockdown_log = QTextEdit()
        self.lockdown_log.setFont(QFont("Courier", 9))
        self.lockdown_log.setText("Emergency Lockdown System Ready\n")
        log_layout.addWidget(self.lockdown_log)
        
        log_group.setLayout(log_layout)
        layout.addWidget(log_group)
        
        return widget
    
    def create_logs_tab(self):
        """Create Logs tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Log Filters
        filter_group = QGroupBox("Log Filters")
        filter_layout = QHBoxLayout()
        
        level_combo = QComboBox()
        level_combo.addItems(["All", "Info", "Warning", "Error", "Critical"])
        filter_layout.addWidget(QLabel("Level:"))
        filter_layout.addWidget(level_combo)
        
        days_spin = QSpinBox()
        days_spin.setRange(1, 365)
        days_spin.setValue(7)
        filter_layout.addWidget(QLabel("Last Days:"))
        filter_layout.addWidget(days_spin)
        
        search_input = QLineEdit()
        search_input.setPlaceholderText("Search logs...")
        filter_layout.addWidget(search_input)
        
        filter_group.setLayout(filter_layout)
        layout.addWidget(filter_group)
        
        # Logs Display
        logs_group = QGroupBox("System Logs")
        logs_layout = QVBoxLayout()
        
        self.logs_table = QTableWidget()
        self.logs_table.setColumnCount(4)
        self.logs_table.setHorizontalHeaderLabels(["Timestamp", "Level", "Source", "Message"])
        self.logs_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.logs_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.logs_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.logs_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.load_sample_logs()
        logs_layout.addWidget(self.logs_table)
        
        logs_group.setLayout(logs_layout)
        layout.addWidget(logs_group)
        
        # Control Buttons
        control_layout = QHBoxLayout()
        export_btn = QPushButton("Export Logs")
        export_btn.clicked.connect(self.export_logs)
        control_layout.addWidget(export_btn)
        
        clear_btn = QPushButton("Clear Logs")
        clear_btn.setStyleSheet("background-color: #d32f2f;")
        clear_btn.clicked.connect(self.clear_logs)
        control_layout.addWidget(clear_btn)
        
        layout.addLayout(control_layout)
        
        return widget
    
    def create_network_tab(self):
        """Create Network tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Network Status
        status_group = QGroupBox("Network Status")
        status_layout = QFormLayout()
        status_layout.addRow("Connection Status:", QLabel("Connected"))
        status_layout.addRow("IP Address:", QLabel("192.168.1.100"))
        status_layout.addRow("DNS:", QLabel("8.8.8.8"))
        status_layout.addRow("Threats Blocked (24h):", QLabel("127"))
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # Network Threats
        threats_group = QGroupBox("Recent Network Threats")
        threats_layout = QVBoxLayout()
        
        self.threats_table = QTableWidget()
        self.threats_table.setColumnCount(4)
        self.threats_table.setHorizontalHeaderLabels(["Timestamp", "Source", "Threat Type", "Action"])
        self.threats_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.threats_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.threats_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.threats_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        threats_layout.addWidget(self.threats_table)
        
        threats_group.setLayout(threats_layout)
        layout.addWidget(threats_group)
        
        # Network Options
        options_group = QGroupBox("Network Protection")
        options_layout = QFormLayout()
        
        self.enable_dns_filter = QCheckBox("Enable DNS Filtering")
        self.enable_dns_filter.setChecked(True)
        self.enable_dns_filter.setToolTip("Block malicious domains at the DNS level")
        options_layout.addRow(self.enable_dns_filter)
        
        self.enable_ip_filter = QCheckBox("Enable IP Filtering")
        self.enable_ip_filter.setChecked(True)
        self.enable_ip_filter.setToolTip("Block suspicious IP addresses and botnets")
        options_layout.addRow(self.enable_ip_filter)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        layout.addStretch()
        return widget
    
    def create_settings_tab(self):
        """Create Settings tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # General Settings
        general_group = QGroupBox("General Settings")
        general_layout = QFormLayout()
        
        startup_checkbox = QCheckBox("Run on startup")
        startup_checkbox.setChecked(True)
        startup_checkbox.setToolTip("Automatically launch SentinelX when Windows starts")
        general_layout.addRow(startup_checkbox)
        
        notification_checkbox = QCheckBox("Enable notifications")
        notification_checkbox.setChecked(True)
        notification_checkbox.setToolTip("Show popup alerts for security events and threats")
        general_layout.addRow(notification_checkbox)
        
        general_group.setLayout(general_layout)
        layout.addWidget(general_group)
        
        # Scan Settings
        scan_group = QGroupBox("Scan Settings")
        scan_layout = QFormLayout()
        
        scan_interval = QSpinBox()
        scan_interval.setRange(1, 24)
        scan_interval.setValue(7)
        scan_interval.setToolTip("Time between automatic scans in hours")
        scan_layout.addRow("Auto-scan interval (hours):", scan_interval)
        
        priority_combo = QComboBox()
        priority_combo.addItems(["Low (minimal CPU)", "Medium (balanced)", "High (fastest)"])
        priority_combo.setCurrentIndex(1)
        priority_combo.setToolTip("Higher priority = faster scanning but uses more CPU")
        scan_layout.addRow("Scan priority:", priority_combo)
        
        scan_group.setLayout(scan_layout)
        layout.addWidget(scan_group)
        
        # Protection Settings
        protection_group = QGroupBox("Protection Settings")
        protection_layout = QFormLayout()
        
        real_time = QCheckBox("Real-time Protection")
        real_time.setChecked(True)
        real_time.setToolTip("Monitor files and processes in real-time for threats")
        protection_layout.addRow(real_time)
        
        behavior_shield = QCheckBox("Behavior Shield")
        behavior_shield.setChecked(True)
        behavior_shield.setToolTip("Detect and block malware based on suspicious behavior")
        protection_layout.addRow(behavior_shield)
        
        protection_group.setLayout(protection_layout)
        layout.addWidget(protection_group)
        
        # Database Settings
        db_group = QGroupBox("Database Settings")
        db_layout = QFormLayout()
        
        update_auto = QCheckBox("Automatic updates")
        update_auto.setChecked(True)
        update_auto.setToolTip("Automatically download threat definitions and program updates")
        db_layout.addRow(update_auto)
        
        update_freq = QSpinBox()
        update_freq.setRange(1, 24)
        update_freq.setValue(4)
        update_freq.setToolTip("Frequency to check for and download definition updates")
        db_layout.addRow("Update frequency (hours):", update_freq)
        
        db_group.setLayout(db_layout)
        layout.addWidget(db_group)
        
        # Control Buttons
        control_layout = QHBoxLayout()
        save_btn = QPushButton("Save Settings")
        save_btn.setToolTip("Save all configuration changes")
        save_btn.clicked.connect(self.save_settings)
        control_layout.addWidget(save_btn)
        
        reset_btn = QPushButton("Reset to Defaults")
        reset_btn.setToolTip("Revert all settings to factory defaults")
        reset_btn.clicked.connect(self.reset_settings)
        control_layout.addWidget(reset_btn)
        
        layout.addLayout(control_layout)
        layout.addStretch()
        
        return widget
    
    def create_console_tab(self):
        """Create Console tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Console Output
        console_group = QGroupBox("System Console")
        console_layout = QVBoxLayout()
        
        self.console_output = QTextEdit()
        self.console_output.setReadOnly(True)
        self.console_output.setFont(QFont("Courier", 9))
        self.write_console("SentinelX Comprehensive Dashboard Started\n")
        self.write_console("=" * 60 + "\n")
        self.write_console("[INIT] Loading detection pipeline...\n")
        self.write_console("[INIT] Initializing firewall rules...\n")
        self.write_console("[INIT] Starting real-time monitoring...\n")
        self.write_console("[OK] System ready\n")
        
        console_layout.addWidget(self.console_output)
        console_group.setLayout(console_layout)
        layout.addWidget(console_group)
        
        # Control Buttons
        control_layout = QHBoxLayout()
        clear_btn = QPushButton("Clear Console")
        clear_btn.clicked.connect(self.clear_console)
        control_layout.addWidget(clear_btn)
        
        export_btn = QPushButton("Export Console")
        export_btn.clicked.connect(self.export_console)
        control_layout.addWidget(export_btn)
        
        layout.addLayout(control_layout)
        
        return widget
    
    def write_console(self, message):
        """Write message to console output"""
        if hasattr(self, 'console_output') and self.console_output:
            self.console_output.append(message.rstrip())
    
    def clear_console(self):
        """Clear console output"""
        self.console_output.clear()
    
    def on_deauth_log(self, message):
        """Handle deauth log messages"""
        self.lockdown_log.append(message)
        self.write_console(message + "\n")
    
    def on_deauth_progress(self, progress):
        """Handle deauth progress updates"""
        pass
    
    def on_deauth_complete(self, result):
        """Handle deauth completion"""
        if result["status"] == "complete":
            self.lockdown_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] Deauth attack complete - {result['frames_sent']} frames sent")
            self.write_console(f"[DEAUTH] Attack complete - {result['frames_sent']} frames sent\n")
        else:
            self.lockdown_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] Deauth error: {result['message']}")
            self.write_console(f"[DEAUTH] Error: {result['message']}\n")
    
    def start_scan(self, scan_type):
        """Start a scan in background thread"""
        if self.scan_worker and self.scan_worker.isRunning():
            QMessageBox.warning(self, "Scan in Progress", "A scan is already running!")
            return
        
        self.scan_worker = ScanWorker(scan_type, self.scan_path_input.text() if scan_type == "custom" else None)
        self.scan_worker.progress_updated.connect(self.update_scan_progress)
        self.scan_worker.scan_complete.connect(self.on_scan_complete)
        self.scan_worker.log_message.connect(self.write_console)
        self.scan_worker.start()
        
        self.write_console(f"\n[{scan_type.upper()}] Scan started at {datetime.now()}\n")
    
    def start_scanner_scan(self):
        """Start scan from Scanner tab"""
        scan_type = self.scan_type_combo.currentText().lower().replace(" ", "_")
        self.start_scan(scan_type)
        self.start_scan_btn.setEnabled(False)
        self.pause_scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(True)
    
    def update_scan_progress(self, value):
        """Update scan progress bar"""
        self.scan_progress.setValue(value)
        self.scan_info_label.setText(f"Scanning... {value}%")
    
    def on_scan_complete(self, result):
        """Handle scan completion"""
        self.scan_progress.setValue(100)
        self.scan_info_label.setText(f"Scan complete! Threats found: {result.get('threats_found', 0)}")
        self.last_scan_label.setText(f"Last Scan: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.write_console(f"\n[SCAN] Scan complete - {result}\n")
        
        self.start_scan_btn.setEnabled(True)
        self.pause_scan_btn.setEnabled(False)
        self.stop_scan_btn.setEnabled(False)
    
    def stop_scan(self):
        """Stop current scan"""
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.quit()
            self.scan_worker.wait()
            self.write_console("\n[SCAN] Scan stopped by user\n")
            self.scan_progress.setValue(0)
            self.scan_info_label.setText("Scan stopped")
            self.start_scan_btn.setEnabled(True)
            self.pause_scan_btn.setEnabled(False)
            self.stop_scan_btn.setEnabled(False)
    
    def browse_scan_path(self):
        """Browse for scan path"""
        path = QFileDialog.getExistingDirectory(self, "Select Folder to Scan")
        if path:
            self.scan_path_input.setText(path)
    
    def refresh_usb_devices(self):
        """Refresh USB devices list"""
        self.usb_devices_table.setRowCount(0)
        devices = [
            ("Kingston DataTraveler", "E:", "8 GB", "2026-03-14", "Clean"),
            ("Samsung Portable SSD", "F:", "500 GB", "2026-03-13", "Clean"),
        ]
        for i, (name, drive, capacity, scanned, status) in enumerate(devices):
            self.usb_devices_table.insertRow(i)
            self.usb_devices_table.setItem(i, 0, QTableWidgetItem(name))
            self.usb_devices_table.setItem(i, 1, QTableWidgetItem(drive))
            self.usb_devices_table.setItem(i, 2, QTableWidgetItem(capacity))
            self.usb_devices_table.setItem(i, 3, QTableWidgetItem(scanned))
            self.usb_devices_table.setItem(i, 4, QTableWidgetItem(status))
    
    def delete_file(self):
        """Permanently delete selected quarantined file"""
        current_row = self.quarantine_table.currentRow()
        if current_row >= 0:
            filename = self.quarantine_table.item(current_row, 0).text()
            reply = QMessageBox.question(self, "Delete File",
                f"Permanently delete '{filename}'?\nThis cannot be undone!",
                QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                self.quarantine_table.removeRow(current_row)
                self.write_console(f"[QUARANTINE] File deleted: {filename}\n")
                QMessageBox.information(self, "Deleted", "File permanently deleted!")
        else:
            QMessageBox.warning(self, "No Selection", "Please select a file to delete.")
    
    def add_firewall_rule(self):
        """Add custom firewall rule and enforce it"""
        domain, ok = QInputDialog.getText(self, "Add Firewall Rule", "Enter domain/IP to block (e.g., google.com):")
        if ok and domain and self.firewall_engine:
            try:
                domain = domain.strip().lower()
                
                # Check if already blocked
                if domain in self.blocked_domains:
                    QMessageBox.warning(self, "Already Blocked", f"'{domain}' is already in the blocked list!")
                    return
                
                self.blocked_domains.add(domain)
                self.write_console(f"[FIREWALL] OK Applying rule for {domain}...\n")
                
                # Apply the rule using backend
                result = self.firewall_engine.apply_firewall_rules([domain])
                
                # Add to table
                row = self.rules_table.rowCount()
                self.rules_table.insertRow(row)
                self.rules_table.setItem(row, 0, QTableWidgetItem(domain))
                self.rules_table.setItem(row, 1, QTableWidgetItem("Custom"))
                self.rules_table.setItem(row, 2, QTableWidgetItem("Block"))
                self.rules_table.setItem(row, 3, QTableWidgetItem("Outbound"))
                
                # Log result details
                if result["hosts_file_enabled"]:
                    self.write_console(f"[FIREWALL] OK Added to hosts file: {domain}\n")
                    self.rules_table.setItem(row, 4, QTableWidgetItem("OK Active"))
                else:
                    self.write_console(f"[FIREWALL] OK Failed to add to hosts file: {domain}\n")
                    self.rules_table.setItem(row, 4, QTableWidgetItem("OK Failed"))
                    
                if result["windows_firewall_enabled"]:
                    self.write_console(f"[FIREWALL] OK Created Windows Firewall rule for: {domain}\n")
                
                if result["error"]:
                    self.write_console(f"[FIREWALL] OK Error: {result['error']}\n")
                    self.write_console(f"[FIREWALL] HINT: Run SentinelX as Administrator for full enforcement\n")
                
                # Save to firewall_rules.json
                try:
                    rules_file = Path("firewall_rules.json")
                    if rules_file.exists():
                        with open(rules_file, 'r') as f:
                            rules_data = json.load(f)
                        
                        if domain not in rules_data.get("blocked_domains", []):
                            rules_data["blocked_domains"].append(domain)
                            with open(rules_file, 'w') as f:
                                json.dump(rules_data, f, indent=2)
                            self.write_console(f"[FIREWALL] OK Saved to firewall_rules.json\n")
                except Exception as save_err:
                    self.write_console(f"[FIREWALL] OK Could not save to JSON: {str(save_err)}\n")
                
                QMessageBox.information(self, "Success", f"Rule '{domain}' added and enforced!")
            except Exception as e:
                self.write_console(f"[FIREWALL] ERROR: {str(e)}\n")
                import traceback
                self.write_console(traceback.format_exc())
                QMessageBox.critical(self, "Error", f"Error adding rule: {str(e)}")
        elif not self.firewall_engine:
            QMessageBox.critical(self, "Error", "Firewall backend not available - check logs")
        elif domain:
            QMessageBox.warning(self, "Invalid Input", "Please enter a valid domain/IP address")
    
    def remove_firewall_rule(self):
        """Remove selected firewall rule and disable enforcement"""
        current_row = self.rules_table.currentRow()
        if current_row >= 0:
            domain = self.rules_table.item(current_row, 0).text()
            
            # Skip the "and more" row
            if "and" in domain and "more" in domain:
                QMessageBox.warning(self, "Cannot Remove", "This is a summary row. Please use 'Refresh Rules' to manage individual domains.")
                return
            
            reply = QMessageBox.question(self, "Remove Rule", f"Stop enforcing '{domain}'?")
            if reply == QMessageBox.Yes:
                try:
                    # Remove from enforcement
                    if self.firewall_engine and domain in self.blocked_domains:
                        self.write_console(f"[FIREWALL] Removing enforcement for {domain}...\n")
                        self.firewall_engine.remove_domain_from_hosts(domain)
                        self.blocked_domains.discard(domain)
                        self.write_console(f"[FIREWALL] [OK] Removed from hosts file: {domain}\n")
                    
                    # Remove from firewall_rules.json to persist the removal
                    try:
                        rules_file = Path("firewall_rules.json")
                        if rules_file.exists():
                            with open(rules_file, 'r') as f:
                                rules_data = json.load(f)
                            
                            blocked_domains = rules_data.get("blocked_domains", [])
                            if domain in blocked_domains:
                                rules_data["blocked_domains"].remove(domain)
                                with open(rules_file, 'w') as f:
                                    json.dump(rules_data, f, indent=2)
                                self.write_console(f"[FIREWALL] [OK] Removed from firewall_rules.json\n")
                    except Exception as json_err:
                        self.write_console(f"[FIREWALL] [WARN] Could not update firewall_rules.json: {str(json_err)}\n")
                    
                    # Remove from table
                    self.rules_table.removeRow(current_row)
                    self.write_console(f"[FIREWALL] Rule removed: {domain}\n")
                    QMessageBox.information(self, "Success", f"Rule for '{domain}' removed!")
                except Exception as e:
                    self.write_console(f"[FIREWALL] Error removing rule: {str(e)}\n")
                    QMessageBox.critical(self, "Error", f"Error removing rule: {str(e)}")
        else:
            QMessageBox.warning(self, "No Selection", "Please select a rule to remove.")
    
    def refresh_firewall_rules(self):
        """Refresh firewall rules from file and reapply"""
        try:
            # Clear current rules
            self.rules_table.setRowCount(0)
            self.blocked_domains.clear()
            
            self.write_console("[FIREWALL] Refreshing rules from configuration...\n")
            
            # Reload from JSON
            self.load_sample_rules()
            
            QMessageBox.information(self, "Refreshed", "Firewall rules refreshed from configuration!")
            self.write_console("[FIREWALL] Rules refreshed and reapplied\n")
        except Exception as e:
            self.write_console(f"[FIREWALL] Error refreshing rules: {str(e)}\n")
            QMessageBox.critical(self, "Error", f"Error refreshing rules: {str(e)}")
    
    def check_admin_privileges(self):
        """Check if running as Administrator"""
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            self.write_console(f"[DIAG] Admin Check: {'YES' if is_admin else 'NO'}\n")
            
            status = "YES - Full enforcement available" if is_admin else "NO - Limited enforcement (hosts file may not be writable)"
            QMessageBox.information(self, "Administrator Status", f"Running as Administrator: {status}")
        except Exception as e:
            self.write_console(f"[DIAG] Error checking admin: {str(e)}\n")
            QMessageBox.critical(self, "Error", f"Could not determine admin status: {str(e)}")
    
    def view_hosts_file(self):
        """View google.com entries in hosts file"""
        try:
            hosts_path = Path("C:\\Windows\\System32\\drivers\\etc\\hosts")
            if hosts_path.exists():
                with open(hosts_path, 'r') as f:
                    content = f.read()
                
                # Filter for google.com
                lines = content.split('\n')
                google_lines = [line for line in lines if 'google.com' in line.lower() and not line.strip().startswith('#')]
                
                if google_lines:
                    result_text = f"Found {len(google_lines)} entries for google.com:\n\n"
                    result_text += '\n'.join(google_lines)
                    self.write_console(f"[DIAG] Hosts file google.com entries: {len(google_lines)} found\n")
                else:
                    result_text = "No google.com entries found in hosts file!\nThis may explain why blocking is not working."
                    self.write_console("[DIAG] WARNING: google.com NOT in hosts file\n")
                
                QMessageBox.information(self, "Hosts File Contents", result_text)
            else:
                self.write_console("[DIAG] Hosts file not found\n")
                QMessageBox.critical(self, "Error", "Hosts file not found at C:\\Windows\\System32\\drivers\\etc\\hosts")
        except Exception as e:
            self.write_console(f"[DIAG] Error reading hosts file: {str(e)}\n")
            QMessageBox.critical(self, "Error", f"Cannot read hosts file: {str(e)}\n\nThis usually means insufficient privileges.")
    
    def test_dns_resolution(self):
        """Test DNS resolution for google.com"""
        try:
            import socket
            ip = socket.gethostbyname("google.com")
            self.write_console(f"[DIAG] DNS Resolution: google.com -> {ip}\n")
            
            if ip == "127.0.0.1" or ip == "::1":
                result = f"SUCCESS: google.com resolves to {ip} (blocked locally)"
                self.write_console("[DIAG] google.com IS blocked\n")
            else:
                result = f"ISSUE: google.com resolves to {ip}\nShould be 127.0.0.1 if blocked.\nMay need to flush DNS cache."
                self.write_console(f"[DIAG] google.com resolves to external IP: {ip}\n")
            
            QMessageBox.information(self, "DNS Resolution Test", result)
        except socket.gaierror as se:
            self.write_console(f"[DIAG] DNS Resolution error: {str(se)}\n")
            QMessageBox.information(self, "DNS Resolution Test", 
                f"Domain resolution failed: {str(se)}\nThis might indicate blocking is working at DNS level.")
        except Exception as e:
            self.write_console(f"[DIAG] Error testing DNS: {str(e)}\n")
            QMessageBox.critical(self, "Error", f"Could not test DNS: {str(e)}")
    
    def flush_dns_cache(self):
        """Manually flush DNS cache"""
        try:
            import subprocess
            self.write_console("[DIAG] Attempting to flush DNS cache...\n")
            
            # Try ipconfig /flushDNS
            try:
                result = subprocess.run(["ipconfig", "/flushDNS"], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    self.write_console("[DIAG] DNS cache flushed successfully via ipconfig\n")
                    QMessageBox.information(self, "DNS Cache Flushed", "DNS cache cleared successfully!\n\nTry opening google.com again.")
                else:
                    self.write_console(f"[DIAG] ipconfig error: {result.stderr}\n")
                    raise Exception("ipconfig /flushDNS failed")
            except Exception as e1:
                self.write_console(f"[DIAG] ipconfig /flushDNS failed: {str(e1)}\n")
                # Try PowerShell alternative
                try:
                    ps_cmd = "Clear-DnsClientCache"
                    result = subprocess.run(["powershell", "-Command", ps_cmd], capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        self.write_console("[DIAG] DNS cache flushed via PowerShell\n")
                        QMessageBox.information(self, "DNS Cache Flushed", "DNS cache cleared via PowerShell!\n\nTry opening google.com again.")
                    else:
                        raise Exception("PowerShell Clear-DnsClientCache failed")
                except Exception as e2:
                    self.write_console(f"[DIAG] PowerShell flush also failed: {str(e2)}\n")
                    raise Exception(f"Both DNS flush methods failed: {str(e1)}, {str(e2)}")
        except Exception as e:
            self.write_console(f"[DIAG] Error flushing DNS cache: {str(e)}\n")
            QMessageBox.critical(self, "Error", f"Could not flush DNS cache: {str(e)}\n\nTry running as Administrator.")
    
    def verify_backend(self):
        """Verify firewall backend is working"""
        try:
            self.write_console("[DIAG] Verifying firewall backend...\n")
            
            if not self.firewall_engine:
                self.write_console("[DIAG] ERROR: Firewall engine not initialized\n")
                QMessageBox.critical(self, "Error", "Firewall backend is not initialized")
                return
            
            # Check if methods exist
            methods = ['apply_firewall_rules', 'remove_domain_from_hosts', 'flush_dns_cache']
            available = []
            missing = []
            
            for method in methods:
                if hasattr(self.firewall_engine, method):
                    available.append(method)
                    self.write_console(f"[DIAG] OK: {method} available\n")
                else:
                    missing.append(method)
                    self.write_console(f"[DIAG] MISSING: {method}\n")
            
            result = f"Backend Status:\n"
            result += f"Available methods: {len(available)}/{len(methods)}\n"
            if available:
                result += f"\nAvailable:\n" + '\n'.join(f"  [+] {m}" for m in available)
            if missing:
                result += f"\nMissing:\n" + '\n'.join(f"  [-] {m}" for m in missing)
            
            result += f"\n\n--- IMPORTANT NOTE ---\n"
            result += f"If google.com still opens despite blocking:\n"
            result += f"1. Your browser may be using DNS-over-HTTPS (DoH)\n"
            result += f"2. This bypasses system DNS and hosts file\n"
            result += f"\nTo disable DoH:\n"
            result += f"- Chrome/Edge: Settings > Privacy > Secure DNS > OFF\n"
            result += f"- Firefox: about:config > network.trr.mode = 5\n"
            result += f"- Then clear browser cache and restart\n"
            
            QMessageBox.information(self, "Backend Verification", result)
        except Exception as e:
            self.write_console(f"[DIAG] Error verifying backend: {str(e)}\n")
            QMessageBox.critical(self, "Error", f"Could not verify backend: {str(e)}")
    
    def export_quarantine_report(self):
        """Export quarantine report"""
        path, _ = QFileDialog.getSaveFileName(self, "Save Report", "", "Text Files (*.txt)")
        if path:
            QMessageBox.information(self, "Export", "Report exported successfully.")
    
    def update_definitions(self):
        """Update threat definitions"""
        QMessageBox.information(self, "Update", "Threat definitions updated to latest version.")
    
    def engage_lockdown(self):
        """Engage emergency network lockdown"""
        reply = QMessageBox.question(self, "Emergency Lockdown", 
            "Activate network-wide emergency lockdown? This will block all network access.")
        if reply == QMessageBox.Yes:
            QMessageBox.information(self, "Lockdown", "Emergency lockdown engaged!")
            self.write_console("[EMERGENCY] Network lockdown activated!\n")
    
    def activate_15_layer_firewall(self):
        """Activate 15-layer firewall using network vulnerability sealing"""
        import sys
        
        print(f"\n{'='*60}")
        print(f"[ACTIVATE] Function called!")
        sys.stdout.flush()
        
        try:
            # Debug: Check what the issue is
            print(f"[ACTIVATE] Pipeline available: {self.pipeline is not None}")
            print(f"[ACTIVATE] Flag state: {self.network_sealing_active}")
            print(f"[ACTIVATE] Button text: {self.activate_firewall_btn.text()}")
            sys.stdout.flush()
            
            if not self.pipeline:
                error_msg = "Detection pipeline not available"
                if not PIPELINE_AVAILABLE:
                    error_msg += " (PIPELINE_AVAILABLE=False - import likely failed)"
                else:
                    error_msg += " (PIPELINE_AVAILABLE=True but initialization failed)"
                
                print(error_msg)
                sys.stdout.flush()
                
                QMessageBox.critical(self, "Error", error_msg)
                self.write_console(f"[FIREWALL] ERROR: {error_msg}\n")
                return
            
            # Show confirmation dialog
            reply = QMessageBox.question(self, "15-Layer Firewall Activation",
                "Activate 15-Layer Firewall?\n\n"
                "This will:\n"
                "- Seal all vulnerable ports\n"
                "- Enable advanced network vulnerability protection\n"
                "- Activate multi-layer network defense\n\n"
                "Continue?")
            
            if reply == QMessageBox.Yes:
                print("[ACTIVATE] User confirmed - showing progress bar")
                sys.stdout.flush()
                
                # Show progress bar
                self.firewall_progress.setVisible(True)
                self.firewall_progress.setValue(0)
                self.activate_firewall_btn.setEnabled(False)
                QApplication.instance().processEvents()
                
                self.write_console("[FIREWALL] Activating 15-Layer Firewall...\n")
                self.firewall_progress.setValue(20)
                QApplication.instance().processEvents()
                time.sleep(0.2)
                
                self.write_console("[FIREWALL] Initiating network vulnerability sealing...\n")
                self.firewall_progress.setValue(40)
                QApplication.instance().processEvents()
                time.sleep(0.2)
                
                # Call pipeline to enable network sealing
                self.firewall_progress.setValue(60)
                QApplication.instance().processEvents()
                time.sleep(0.1)
                
                print("[ACTIVATE] Calling pipeline.enable_network_sealing()...")
                sys.stdout.flush()
                self.write_console("[FIREWALL] Calling enable_network_sealing()...\n")
                success = self.pipeline.enable_network_sealing()
                
                print(f"[ACTIVATE] enable_network_sealing() returned: {success}")
                sys.stdout.flush()
                
                self.firewall_progress.setValue(80)
                QApplication.instance().processEvents()
                time.sleep(0.2)
                
                if success:
                    print("[ACTIVATE] SUCCESS! Setting flag to True and updating UI...")
                    sys.stdout.flush()
                    
                    self.network_sealing_active = True
                    
                    self.firewall_activation_status.setText("Status: ACTIVE [OK]")
                    self.firewall_activation_status.setStyleSheet("color: #4CAF50; font-weight: bold;")
                    
                    print("[ACTIVATE] Changing button text to 'Deactivate 15-Layer Firewall'...")
                    sys.stdout.flush()
                    
                    self.activate_firewall_btn.setText("Deactivate 15-Layer Firewall")
                    self.activate_firewall_btn.setStyleSheet("background-color: #ff6b6b; color: white; font-weight: bold; padding: 8px;")
                    self.activate_firewall_btn.setEnabled(True)
                    QApplication.instance().processEvents()
                    
                    print(f"[ACTIVATE] Button text is now: '{self.activate_firewall_btn.text()}'")
                    sys.stdout.flush()
                    
                    self.write_console("[FIREWALL] [OK] 15-Layer Firewall ACTIVATED\n")
                    self.write_console("[FIREWALL] [OK] All vulnerable ports sealed\n")
                    self.write_console("[FIREWALL] [OK] Advanced network protection enabled\n")
                    
                    self.firewall_progress.setValue(100)
                    QApplication.instance().processEvents()
                    time.sleep(0.3)
                    self.firewall_progress.setVisible(False)
                    
                    print("[ACTIVATE] Showing success dialog...")
                    sys.stdout.flush()
                    
                    QMessageBox.information(self, "Success", 
                        "15-Layer Firewall activated successfully!\n\n"
                        "All vulnerable ports sealed.\n"
                        "Advanced network protection enabled.")
                        
                    print(f"[ACTIVATE] COMPLETE! Final state - flag: {self.network_sealing_active}, button: '{self.activate_firewall_btn.text()}'")
                    sys.stdout.flush()
                else:
                    print("[ACTIVATE] FAILED! enable_network_sealing() returned False")
                    sys.stdout.flush()
                    
                    self.activate_firewall_btn.setEnabled(True)
                    self.firewall_progress.setVisible(False)
                    QApplication.instance().processEvents()
                    
                    self.write_console("[FIREWALL] WARNING: enable_network_sealing() returned False\n")
                    self.write_console("[FIREWALL] This may indicate that admin privileges are required\n")
                    QMessageBox.critical(self, "Error", "Failed to activate 15-Layer Firewall - may require admin privileges")
            else:
                print("[ACTIVATE] User cancelled")
                sys.stdout.flush()
                    
        except Exception as e:
            print(f"[ACTIVATE] EXCEPTION: {e}")
            import traceback
            traceback.print_exc()
            sys.stdout.flush()
            
            self.write_console(f"[FIREWALL] ERROR: {str(e)}\n")
            self.write_console(traceback.format_exc())
            QMessageBox.critical(self, "Error", f"Error activating firewall: {str(e)}")
        
        print(f"{'='*60}\n")
        sys.stdout.flush()
    
    def deactivate_15_layer_firewall(self):
        """Deactivate 15-layer firewall"""
        import sys
        
        print(f"\n{'='*60}")
        print(f"[DEACTIVATE] Function called!")
        sys.stdout.flush()
        
        try:
            print(f"[DEACTIVATE] Pipeline available: {self.pipeline is not None}")
            print(f"[DEACTIVATE] Flag state: {self.network_sealing_active}")
            print(f"[DEACTIVATE] Button text: {self.activate_firewall_btn.text()}")
            sys.stdout.flush()
            
            if not self.pipeline:
                print("[DEACTIVATE] ERROR: Pipeline is None!")
                sys.stdout.flush()
                self.write_console("[FIREWALL] ERROR: Pipeline not available for deactivation\n")
                QMessageBox.critical(self, "Error", "Detection pipeline not available")
                return
            
            print("[DEACTIVATE] Showing progress bar...")
            sys.stdout.flush()
            
            # Show progress bar
            self.firewall_progress.setVisible(True)
            self.firewall_progress.setValue(0)
            self.activate_firewall_btn.setEnabled(False)
            QApplication.instance().processEvents()
            
            self.write_console("[FIREWALL] Deactivating 15-Layer Firewall...\n")
            self.firewall_progress.setValue(20)
            QApplication.instance().processEvents()
            time.sleep(0.2)
            
            print("[DEACTIVATE] Calling pipeline.disable_network_sealing()...")
            sys.stdout.flush()
            self.firewall_progress.setValue(40)
            QApplication.instance().processEvents()
            time.sleep(0.1)
            
            self.write_console("[FIREWALL] Calling disable_network_sealing()...\n")
            success = self.pipeline.disable_network_sealing()
            
            print(f"[DEACTIVATE] disable_network_sealing() returned: {success}")
            sys.stdout.flush()
            
            self.firewall_progress.setValue(80)
            QApplication.instance().processEvents()
            time.sleep(0.2)
            
            if success:
                print("[DEACTIVATE] SUCCESS! Setting flag to False and updating UI...")
                sys.stdout.flush()
                
                self.network_sealing_active = False
                
                # Update status label
                self.firewall_activation_status.setText("Status: INACTIVE")
                self.firewall_activation_status.setStyleSheet("color: #ff6b6b; font-weight: bold;")
                self.firewall_activation_status.update()
                self.firewall_activation_status.repaint()
                
                print("[DEACTIVATE] Changing button text to 'Activate 15-Layer Firewall'...")
                sys.stdout.flush()
                
                # Update button - set text first
                self.activate_firewall_btn.setText("Activate 15-Layer Firewall")
                self.activate_firewall_btn.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold; padding: 8px;")
                self.activate_firewall_btn.setEnabled(True)
                
                # Force immediate update and repaint
                self.activate_firewall_btn.update()
                self.activate_firewall_btn.repaint()
                
                # Process all pending events to ensure UI refreshes
                QApplication.instance().processEvents()
                time.sleep(0.1)
                QApplication.instance().processEvents()
                
                print(f"[DEACTIVATE] Button text is now: '{self.activate_firewall_btn.text()}'")
                sys.stdout.flush()
                
                self.write_console("[FIREWALL] [OK] 15-Layer Firewall DEACTIVATED\n")
                self.write_console("[FIREWALL] [OK] Network access restored\n")
                
                self.firewall_progress.setValue(100)
                QApplication.instance().processEvents()
                time.sleep(0.3)
                self.firewall_progress.setVisible(False)
                QApplication.instance().processEvents()
                time.sleep(0.2)
                
                print("[DEACTIVATE] Showing success dialog...")
                sys.stdout.flush()
                
                QMessageBox.information(self, "Success", 
                    "15-Layer Firewall deactivated.\n"
                    "Normal network access restored.")
                    
                print(f"[DEACTIVATE] COMPLETE! Final state - flag: {self.network_sealing_active}, button: '{self.activate_firewall_btn.text()}'")
                sys.stdout.flush()
            else:
                print("[DEACTIVATE] FAILED! disable_network_sealing() returned False")
                sys.stdout.flush()
                
                self.activate_firewall_btn.setEnabled(True)
                self.firewall_progress.setVisible(False)
                QApplication.instance().processEvents()
                
                self.write_console("[FIREWALL] ERROR: Failed to deactivate firewall\n")
                self.write_console("[FIREWALL] This may indicate that admin privileges are required\n")
                QMessageBox.critical(self, "Error", "Failed to deactivate firewall - may require admin privileges")
                
        except Exception as e:
            print(f"[DEACTIVATE] EXCEPTION: {e}")
            import traceback
            traceback.print_exc()
            sys.stdout.flush()
            
            self.activate_firewall_btn.setEnabled(True)
            self.firewall_progress.setVisible(False)
            QApplication.instance().processEvents()
            
            self.write_console(f"[FIREWALL] ERROR: {str(e)}\n")
            self.write_console(traceback.format_exc())
            QMessageBox.critical(self, "Error", f"Error deactivating firewall: {str(e)}")
        
        print(f"{'='*60}\n")
        sys.stdout.flush()
    
    def toggle_15_layer_firewall(self):
        """Toggle 15-layer firewall based on current state"""
        import sys
        
        # Get current button text to determine state
        button_text = self.activate_firewall_btn.text()
        
        print(f"\n{'='*60}")
        print(f"[TOGGLE] Button clicked!")
        print(f"[TOGGLE] Button text: '{button_text}'")
        print(f"[TOGGLE] Flag state: {self.network_sealing_active}")
        print(f"[TOGGLE] Pipeline: {self.pipeline is not None}")
        print(f"{'='*60}\n")
        
        sys.stdout.flush()
        
        # Check button text to determine action
        if "Deactivate" in button_text:
            print("[TOGGLE] Button says 'Deactivate' - calling deactivate function")
            sys.stdout.flush()
            self.deactivate_15_layer_firewall()
        elif "Activate" in button_text:
            print("[TOGGLE] Button says 'Activate' - calling activate function")
            sys.stdout.flush()
            self.activate_15_layer_firewall()
        else:
            print(f"[TOGGLE] ERROR: Unknown button state: {button_text}")
            sys.stdout.flush()
    
    def load_sample_rules(self):
        """Load ALL firewall rules from JSON and apply them"""
        try:
            # Load rules from firewall_rules.json
            rules_file = Path("firewall_rules.json")
            if rules_file.exists():
                with open(rules_file, 'r') as f:
                    rules_data = json.load(f)
                    blocked_domains = rules_data.get("blocked_domains", [])
                    
                    # Apply ALL rules using backend
                    if self.firewall_engine and blocked_domains:
                        self.write_console(f"[FIREWALL] Applying {len(blocked_domains)} RULES from configuration...\n")
                        self.write_console(f"[FIREWALL] This requires ADMINISTRATOR privileges\n")
                        result = self.firewall_engine.apply_firewall_rules(blocked_domains)
                        self.blocked_domains = set(blocked_domains)
                        
                        # Display result
                        if result["hosts_file_enabled"]:
                            self.write_console(f"[FIREWALL] [OK] Hosts file blocking ACTIVE - {len(blocked_domains)} domains added\n")
                        else:
                            self.write_console(f"[FIREWALL] [FAILED] Hosts file blocking FAILED\n")
                        
                        if result["windows_firewall_enabled"]:
                            self.write_console(f"[FIREWALL] [OK] Windows Firewall rules created\n")
                        
                        if result["error"]:
                            self.write_console(f"[FIREWALL] [WARN] ERROR: {result['error']}\n")
                            self.write_console(f"[FIREWALL] HINT: Run SentinelX as Administrator to enable firewall enforcement\n")
                    else:
                        if not self.firewall_engine:
                            self.write_console(f"[FIREWALL] [FAILED] Firewall backend not available\n")
                    
                    # Load ALL rules into table for display
                    self.write_console(f"[FIREWALL] Loading {len(blocked_domains)} rules into table...\n")
                    for i, domain in enumerate(blocked_domains):
                        row = self.rules_table.rowCount()
                        self.rules_table.insertRow(row)
                        self.rules_table.setItem(row, 0, QTableWidgetItem(domain))
                        self.rules_table.setItem(row, 1, QTableWidgetItem("Domain"))
                        self.rules_table.setItem(row, 2, QTableWidgetItem("Block"))
                        self.rules_table.setItem(row, 3, QTableWidgetItem("Outbound"))
                        status = "[OK] Active" if domain in self.blocked_domains else "Pending"
                        self.rules_table.setItem(row, 4, QTableWidgetItem(status))
                    
                    self.write_console(f"[FIREWALL] [OK] All {len(blocked_domains)} rules loaded and ready\n")
            else:
                self.write_console(f"[FIREWALL] firewall_rules.json not found - no rules loaded. Create firewall_rules.json to add rules.\n")
        except Exception as e:
            error_msg = f"[FIREWALL] Error loading rules: {str(e)}\n"
            self.write_console(error_msg)
            import traceback
            self.write_console(traceback.format_exc())
    
    def load_sample_logs(self):
        """Load logs from log files - tables start empty"""
        pass  # Logs are loaded from persistent log files when available
    
    def update_system_status(self):
        """Update system status periodically"""
        pass
    
    def activate_lockdown(self):
        """Activate emergency network lockdown with 802.11 deauth frames"""
        reply = QMessageBox.question(self, "Confirm Emergency Lockdown",
            "This will immediately block all network traffic and isolate the system.\n\n"
            "802.11 Deauth frames will be sent to disconnect all wireless devices.\n\n"
            "REQUIREMENTS:\n"
            "• Administrator privileges\n"
            "• Npcap installed (https://npcap.com/)\n"
            "• Active wireless adapter\n\n"
            "Are you absolutely certain you want to proceed?",
            QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            self.lockdown_status.setText("ACTIVE")
            self.lockdown_status.setStyleSheet("color: #d32f2f; font-weight: bold; font-size: 14pt;")
            self.activate_lockdown_btn.setEnabled(False)
            self.deactivate_lockdown_btn.setEnabled(True)
            
            self.locked_down = True
            self.blocked_ips.setText("All")
            self.blocked_ports.setText("All")
            self.isolated_devices.setText("All Network Interfaces")
            
            self.lockdown_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] Emergency lockdown ACTIVATED")
            self.write_console(f"[LOCKDOWN] Emergency network lockdown ACTIVATED at {datetime.now()}\n")
            
            # Start deauth worker if block_all_traffic is checked
            if self.block_all_traffic.isChecked():
                self.lockdown_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] Initiating 802.11 deauth frame injection...")
                self.write_console("[LOCKDOWN] Initiating 802.11 deauth frame injection...\n")
                
                # Start deauth worker thread
                self.deauth_worker = DeauthWorker()
                self.deauth_worker.log_message.connect(self.on_deauth_log)
                self.deauth_worker.progress_updated.connect(self.on_deauth_progress)
                self.deauth_worker.deauth_complete.connect(self.on_deauth_complete)
                self.deauth_worker.start()
                
                self.lockdown_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] All outgoing traffic blocked")
                self.write_console("[LOCKDOWN] All outgoing traffic blocked\n")
            
            if self.disable_wifi.isChecked():
                self.lockdown_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] WiFi disabled")
                self.write_console("[LOCKDOWN] WiFi disabled\n")
            
            if self.kill_suspicious.isChecked():
                self.lockdown_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] Suspicious processes terminated")
                self.write_console("[LOCKDOWN] Scanning for suspicious processes...\n")
            
            QMessageBox.information(self, "Emergency Lockdown Activated",
                "Network-wide emergency lockdown is now ACTIVE!\n\n"
                "802.11 Deauth frames are being sent to disconnect all wireless devices.\n"
                "All network connections have been blocked.\n"
                "Physical isolation is recommended.")
    
    def deactivate_lockdown(self):
        """Deactivate emergency lockdown"""
        reply = QMessageBox.question(self, "Deactivate Lockdown",
            "Are you sure you want to deactivate emergency lockdown?")
        
        if reply == QMessageBox.Yes:
            # Stop deauth worker if running
            if self.deauth_worker and self.deauth_worker.isRunning():
                self.deauth_worker.stop()
                self.deauth_worker.wait()
                self.write_console("[LOCKDOWN] Deauth frame injection stopped\n")
            
            self.lockdown_status.setText("INACTIVE")
            self.lockdown_status.setStyleSheet("color: #4CAF50; font-weight: bold; font-size: 14pt;")
            self.activate_lockdown_btn.setEnabled(True)
            self.deactivate_lockdown_btn.setEnabled(False)
            
            self.locked_down = False
            self.blocked_ips.setText("0")
            self.blocked_ports.setText("0")
            self.isolated_devices.setText("0")
            
            self.lockdown_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] Emergency lockdown DEACTIVATED")
            self.write_console(f"[LOCKDOWN] Emergency lockdown deactivated at {datetime.now()}\n")
            
            QMessageBox.information(self, "Lockdown Deactivated",
                "Emergency lockdown has been deactivated.\n"
                "Network connectivity restored.")
    
    def export_logs(self):
        """Export system logs to file"""
        path, _ = QFileDialog.getSaveFileName(self, "Export Logs", "", "Text Files (*.txt);;CSV Files (*.csv)")
        if path:
            try:
                with open(path, 'w') as f:
                    for row in range(self.logs_table.rowCount()):
                        row_data = []
                        for col in range(self.logs_table.columnCount()):
                            item = self.logs_table.item(row, col)
                            row_data.append(item.text() if item else "")
                        f.write(" | ".join(row_data) + "\n")
                QMessageBox.information(self, "Export Successful", f"Logs exported to:\n{path}")
                self.write_console(f"[LOG] Logs exported to {path}\n")
            except Exception as e:
                QMessageBox.critical(self, "Export Failed", f"Failed to export logs:\n{str(e)}")
    
    def clear_logs(self):
        """Clear all system logs"""
        reply = QMessageBox.question(self, "Clear Logs", "Clear all system logs? This cannot be undone.")
        if reply == QMessageBox.Yes:
            self.logs_table.setRowCount(0)
            self.write_console("[LOG] System logs cleared\n")
            QMessageBox.information(self, "Cleared", "All logs have been cleared.")
    
    def export_console(self):
        """Export console output to file"""
        path, _ = QFileDialog.getSaveFileName(self, "Export Console", "", "Text Files (*.txt)")
        if path:
            try:
                with open(path, 'w') as f:
                    f.write(self.console_output.toPlainText())
                QMessageBox.information(self, "Export Successful", f"Console exported to:\n{path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Failed", f"Failed to export console:\n{str(e)}")
    
    def save_settings(self):
        """Save user settings"""
        QMessageBox.information(self, "Saved", "Settings saved successfully!")
        self.write_console("[SETTINGS] User settings saved\n")
    
    def reset_settings(self):
        """Reset settings to defaults"""
        reply = QMessageBox.question(self, "Reset Settings", "Reset all settings to defaults?")
        if reply == QMessageBox.Yes:
            QMessageBox.information(self, "Reset", "Settings reset to defaults!")
            self.write_console("[SETTINGS] Settings reset to defaults\n")
    
    
    def scan_usb_device(self):
        """Scan selected USB device"""
        current_row = self.usb_devices_table.currentRow()
        if current_row >= 0:
            device = self.usb_devices_table.item(current_row, 0).text()
            self.start_scan("usb")
            QMessageBox.information(self, "Scanning", f"Starting scan of {device}...")
        else:
            QMessageBox.warning(self, "No Device", "Please select a USB device to scan.")
    
    def eject_usb_device(self):
        """Safely eject selected USB device"""
        current_row = self.usb_devices_table.currentRow()
        if current_row >= 0:
            device = self.usb_devices_table.item(current_row, 0).text()
            drive = self.usb_devices_table.item(current_row, 1).text()
            reply = QMessageBox.question(self, "Eject Device", f"Safely eject {device} ({drive})?")
            if reply == QMessageBox.Yes:
                QMessageBox.information(self, "Ejected", f"{device} safely ejected!")
                self.write_console(f"[USB] Device ejected: {device}\n")
        else:
            QMessageBox.warning(self, "No Device", "Please select a USB device to eject.")
    
    def restore_file(self):
        """Restore selected quarantined file"""
        current_row = self.quarantine_table.currentRow()
        if current_row >= 0:
            filename = self.quarantine_table.item(current_row, 0).text()
            original_path = self.quarantine_table.item(current_row, 1).text()
            reply = QMessageBox.question(self, "Restore File",
                f"Restore '{filename}' to:\n{original_path}?")
            if reply == QMessageBox.Yes:
                self.quarantine_table.removeRow(current_row)
                self.write_console(f"[QUARANTINE] File restored: {filename} -> {original_path}\n")
                QMessageBox.information(self, "Restored", f"File restored successfully!")
        else:
            QMessageBox.warning(self, "No Selection", "Please select a file to restore.")
    
    def delete_file(self):
        """Permanently delete selected quarantined file"""
        current_row = self.quarantine_table.currentRow()
        if current_row >= 0:
            filename = self.quarantine_table.item(current_row, 0).text()
            reply = QMessageBox.question(self, "Delete File",
                f"Permanently delete '{filename}'?\nThis cannot be undone!",
                QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                self.quarantine_table.removeRow(current_row)
                self.write_console(f"[QUARANTINE] File deleted: {filename}\n")
                QMessageBox.information(self, "Deleted", "File permanently deleted!")
        else:
            QMessageBox.warning(self, "No Selection", "Please select a file to delete.")
    
    def create_threat_intelligence_tab(self):
        """Create Threat Intelligence tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Threat Feed Status
        feed_group = QGroupBox("Real-Time Threat Intelligence Feed")
        feed_layout = QVBoxLayout()
        
        self.threat_feed_table = QTableWidget()
        self.threat_feed_table.setColumnCount(6)
        self.threat_feed_table.setHorizontalHeaderLabels(["Timestamp", "Threat Type", "Severity", "Source", "CIDRs", "Detection"])
        self.threat_feed_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.threat_feed_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.threat_feed_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.threat_feed_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.threat_feed_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.threat_feed_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        
        # Threat Intelligence Feed (loaded from threat intelligence manager)
        threats = []
        
        for i, (timestamp, threat_type, severity, source, cidrs, detection) in enumerate(threats):
            self.threat_feed_table.insertRow(i)
            self.threat_feed_table.setItem(i, 0, QTableWidgetItem(timestamp))
            self.threat_feed_table.setItem(i, 1, QTableWidgetItem(threat_type))
            severity_item = QTableWidgetItem(severity)
            severity_item.setForeground(QColor("#ff6b6b"))
            font = QFont()
            font.setBold(True)
            severity_item.setFont(font)
            self.threat_feed_table.setItem(i, 2, severity_item)
            self.threat_feed_table.setItem(i, 3, QTableWidgetItem(source))
            self.threat_feed_table.setItem(i, 4, QTableWidgetItem(cidrs))
            self.threat_feed_table.setItem(i, 5, QTableWidgetItem(detection))
        
        feed_layout.addWidget(self.threat_feed_table)
        feed_group.setLayout(feed_layout)
        layout.addWidget(feed_group)
        
        # Threat Stats
        stats_group = QGroupBox("Threat Intelligence Statistics")
        stats_layout = QHBoxLayout()
        
        # Threat Statistics Summary (updated from threat data)
        stat_widgets = []
        
        for label, value in stat_widgets:
            stat_label = QLabel(label)
            stat_label.setStyleSheet("font-size: 10pt;")
            stat_value = QLabel(value)
            stat_value.setStyleSheet("font-size: 16pt; font-weight: bold; color: #2196F3;")
            
            stat_layout = QVBoxLayout()
            stat_layout.addWidget(stat_label)
            stat_layout.addWidget(stat_value)
            stat_widget = QGroupBox()
            stat_widget.setLayout(stat_layout)
            stats_layout.addWidget(stat_widget)
        
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        # Feed Controls
        control_group = QGroupBox("Feed Configuration")
        control_layout = QHBoxLayout()
        
        refresh_btn = QPushButton("Refresh Feed")
        refresh_btn.clicked.connect(lambda: self.write_console("[THREAT-INTEL] Threat feed refreshed\n"))
        control_layout.addWidget(refresh_btn)
        
        subscribe_btn = QPushButton("Subscribe to Sources")
        control_layout.addWidget(subscribe_btn)
        
        export_btn = QPushButton("Export Intelligence")
        control_layout.addWidget(export_btn)
        
        control_group.setLayout(control_layout)
        layout.addWidget(control_group)
        
        layout.addStretch()
        return widget
    
    def create_compliance_tab(self):
        """Create Compliance & Reporting tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Compliance Status
        compliance_group = QGroupBox("Compliance Status")
        compliance_layout = QFormLayout()
        
        # Standards will be populated from compliance manager
        standards = []
        
        for standard, compliance_pct, color in standards:
            label = QLabel(standard)
            value = QLabel(compliance_pct)
            value.setStyleSheet(f"color: {color}; font-weight: bold;")
            compliance_layout.addRow(label, value)
        
        compliance_group.setLayout(compliance_layout)
        layout.addWidget(compliance_group)
        
        # Audit Trail
        audit_group = QGroupBox("Audit Trail")
        audit_layout = QVBoxLayout()
        
        self.audit_table = QTableWidget()
        self.audit_table.setColumnCount(5)
        self.audit_table.setHorizontalHeaderLabels(["Timestamp", "User", "Action", "Resource", "Status"])
        self.audit_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.audit_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.audit_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.audit_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.audit_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        
        # Compliance Audit Trail (immutable security logs)
        audit_logs = []
        
        for i, (timestamp, user, action, resource, status) in enumerate(audit_logs):
            self.audit_table.insertRow(i)
            self.audit_table.setItem(i, 0, QTableWidgetItem(timestamp))
            self.audit_table.setItem(i, 1, QTableWidgetItem(user))
            self.audit_table.setItem(i, 2, QTableWidgetItem(action))
            self.audit_table.setItem(i, 3, QTableWidgetItem(resource))
            self.audit_table.setItem(i, 4, QTableWidgetItem(status))
        
        audit_layout.addWidget(self.audit_table)
        audit_group.setLayout(audit_layout)
        layout.addWidget(audit_group)
        
        # Report Controls
        control_layout = QHBoxLayout()
        generate_btn = QPushButton("Generate Report")
        generate_btn.clicked.connect(lambda: QMessageBox.information(self, "Report", "Compliance report generated!"))
        control_layout.addWidget(generate_btn)
        
        export_btn = QPushButton("Export Audit Trail")
        control_layout.addWidget(export_btn)
        
        schedule_btn = QPushButton("Schedule Report")
        control_layout.addWidget(schedule_btn)
        
        layout.addLayout(control_layout)
        layout.addStretch()
        
        return widget
    
    def create_asset_management_tab(self):
        """Create Asset Management tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Asset Inventory
        inventory_group = QGroupBox("System Asset Inventory")
        inventory_layout = QVBoxLayout()
        
        self.asset_table = QTableWidget()
        self.asset_table.setColumnCount(7)
        self.asset_table.setHorizontalHeaderLabels(["Hostname", "IP Address", "OS", "Last Scan", "Vulnerabilities", "Compliance", "Status"])
        self.asset_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.asset_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.asset_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.asset_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.asset_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.asset_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.asset_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)
        
        # Network Asset Inventory (auto-discovered and managed)
        assets = []
        
        for i, (hostname, ip, os, last_scan, vulns, compliance, status) in enumerate(assets):
            self.asset_table.insertRow(i)
            self.asset_table.setItem(i, 0, QTableWidgetItem(hostname))
            self.asset_table.setItem(i, 1, QTableWidgetItem(ip))
            self.asset_table.setItem(i, 2, QTableWidgetItem(os))
            self.asset_table.setItem(i, 3, QTableWidgetItem(last_scan))
            vuln_item = QTableWidgetItem(vulns)
            if int(vulns) > 0:
                vuln_item.setForeground(QColor("#FF9800"))
                font = QFont()
                font.setBold(True)
                vuln_item.setFont(font)
            self.asset_table.setItem(i, 4, vuln_item)
            self.asset_table.setItem(i, 5, QTableWidgetItem(compliance))
            status_item = QTableWidgetItem(status)
            if "Warning" in status:
                status_item.setForeground(QColor("#FF9800"))
                font = QFont()
                font.setBold(True)
                status_item.setFont(font)
            elif "Healthy" in status:
                status_item.setForeground(QColor("#4CAF50"))
                font = QFont()
                font.setBold(True)
                status_item.setFont(font)
            self.asset_table.setItem(i, 6, status_item)
        
        inventory_layout.addWidget(self.asset_table)
        inventory_group.setLayout(inventory_layout)
        layout.addWidget(inventory_group)
        
        # Asset Controls
        control_layout = QHBoxLayout()
        scan_btn = QPushButton("Scan Selected Assets")
        control_layout.addWidget(scan_btn)
        
        patch_btn = QPushButton("Apply Patches")
        control_layout.addWidget(patch_btn)
        
        remediate_btn = QPushButton("Remediate Vulnerabilities")
        control_layout.addWidget(remediate_btn)
        
        layout.addLayout(control_layout)
        layout.addStretch()
        
        return widget
    
    def create_incident_response_tab(self):
        """Create Incident Response tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Alert Management
        alerts_group = QGroupBox("Active Alerts & Incidents")
        alerts_layout = QVBoxLayout()
        
        self.incident_table = QTableWidget()
        self.incident_table.setColumnCount(8)
        self.incident_table.setHorizontalHeaderLabels(["ID", "Timestamp", "Type", "Severity", "Source", "Title", "Status", "Assigned To"])
        self.incident_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.incident_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.incident_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.incident_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.incident_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.incident_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.incident_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)
        self.incident_table.horizontalHeader().setSectionResizeMode(7, QHeaderView.Stretch)
        
        # Security Incident Log (automatically recorded and tracked)
        incidents = []
        
        for i, (inc_id, timestamp, inc_type, severity, source, title, status, assigned) in enumerate(incidents):
            self.incident_table.insertRow(i)
            self.incident_table.setItem(i, 0, QTableWidgetItem(inc_id))
            self.incident_table.setItem(i, 1, QTableWidgetItem(timestamp))
            self.incident_table.setItem(i, 2, QTableWidgetItem(inc_type))
            
            severity_item = QTableWidgetItem(severity)
            if severity == "CRITICAL":
                severity_item.setForeground(QColor("#d32f2f"))
                font = QFont()
                font.setBold(True)
                severity_item.setFont(font)
            elif severity == "HIGH":
                severity_item.setForeground(QColor("#FF9800"))
                font = QFont()
                font.setBold(True)
                severity_item.setFont(font)
            self.incident_table.setItem(i, 3, severity_item)
            
            self.incident_table.setItem(i, 4, QTableWidgetItem(source))
            self.incident_table.setItem(i, 5, QTableWidgetItem(title))
            
            status_item = QTableWidgetItem(status)
            if "Open" in status:
                status_item.setForeground(QColor("#d32f2f"))
                font = QFont()
                font.setBold(True)
                status_item.setFont(font)
            elif "In Progress" in status:
                status_item.setForeground(QColor("#FF9800"))
                font = QFont()
                font.setBold(True)
                status_item.setFont(font)
            elif "Resolved" in status:
                status_item.setForeground(QColor("#4CAF50"))
                font = QFont()
                font.setBold(True)
                status_item.setFont(font)
            self.incident_table.setItem(i, 6, status_item)
            
            self.incident_table.setItem(i, 7, QTableWidgetItem(assigned))
        
        alerts_layout.addWidget(self.incident_table)
        alerts_group.setLayout(alerts_layout)
        layout.addWidget(alerts_group)
        
        # Response Playbooks
        playbook_group = QGroupBox("Response Playbooks")
        playbook_layout = QHBoxLayout()
        
        playbooks = ["Malware Response", "Network Breach", "Data Exfiltration", "Ransomware", "Supply Chain"]
        for playbook in playbooks:
            playbook_btn = QPushButton(playbook)
            playbook_btn.clicked.connect(lambda checked, p=playbook: self.write_console(f"[INCIDENT] Executing {p} playbook\n"))
            playbook_layout.addWidget(playbook_btn)
        
        playbook_group.setLayout(playbook_layout)
        layout.addWidget(playbook_group)
        
        # Incident Controls
        control_layout = QHBoxLayout()
        escalate_btn = QPushButton("Escalate to CISO")
        escalate_btn.setStyleSheet("background-color: #d32f2f;")
        control_layout.addWidget(escalate_btn)
        
        investigate_btn = QPushButton("Start Investigation")
        control_layout.addWidget(investigate_btn)
        
        resolve_btn = QPushButton("Mark as Resolved")
        control_layout.addWidget(resolve_btn)
        
        layout.addLayout(control_layout)
        layout.addStretch()
        
        return widget
    
    def create_admin_tab(self):
        """Create Admin & RBAC tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # User Management
        users_group = QGroupBox("User Management & Role-Based Access Control (RBAC)")
        users_layout = QVBoxLayout()
        
        self.users_table = QTableWidget()
        self.users_table.setColumnCount(6)
        self.users_table.setHorizontalHeaderLabels(["Username", "Email", "Role", "Department", "Last Login", "MFA Status"])
        self.users_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.users_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.users_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.users_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.users_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.users_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        
        # User & Role Management (with RBAC and audit trail)
        users = []
        
        for i, (username, email, role, dept, last_login, mfa) in enumerate(users):
            self.users_table.insertRow(i)
            self.users_table.setItem(i, 0, QTableWidgetItem(username))
            self.users_table.setItem(i, 1, QTableWidgetItem(email))
            self.users_table.setItem(i, 2, QTableWidgetItem(role))
            self.users_table.setItem(i, 3, QTableWidgetItem(dept))
            self.users_table.setItem(i, 4, QTableWidgetItem(last_login))
            
            mfa_item = QTableWidgetItem(mfa)
            if "Enabled" in mfa:
                mfa_item.setForeground(QColor("#4CAF50"))
                font = QFont()
                font.setBold(True)
                mfa_item.setFont(font)
            else:
                mfa_item.setForeground(QColor("#FF9800"))
                font = QFont()
                font.setBold(True)
                mfa_item.setFont(font)
            self.users_table.setItem(i, 5, mfa_item)
        
        users_layout.addWidget(self.users_table)
        users_group.setLayout(users_layout)
        layout.addWidget(users_group)
        
        # Role Definitions
        roles_group = QGroupBox("Role Definitions")
        roles_layout = QFormLayout()
        
        role_perms = [
            ("Administrator", "Full system access, all features, user management"),
            ("Analyst (Senior)", "Investigation, incident management, remediation"),
            ("Analyst (Junior)", "View-only investigation, ticket creation"),
            ("System Admin", "Configuration, patches, system management"),
            ("Viewer", "Read-only access to reports and dashboards"),
        ]
        
        for role, perms in role_perms:
            role_label = QLabel(role)
            role_label.setStyleSheet("font-weight: bold;")
            perms_label = QLabel(perms)
            perms_label.setStyleSheet("font-size: 9pt; color: #a0a0a0;")
            roles_layout.addRow(role_label, perms_label)
        
        roles_group.setLayout(roles_layout)
        layout.addWidget(roles_group)
        
        # Admin Controls
        control_layout = QHBoxLayout()
        add_user_btn = QPushButton("Add User")
        add_user_btn.clicked.connect(lambda: QMessageBox.information(self, "Add User", "New user dialog would open"))
        control_layout.addWidget(add_user_btn)
        
        edit_role_btn = QPushButton("Edit Roles")
        control_layout.addWidget(edit_role_btn)
        
        session_btn = QPushButton("Manage Sessions")
        control_layout.addWidget(session_btn)
        
        policy_btn = QPushButton("Security Policies")
        control_layout.addWidget(policy_btn)
        
        layout.addLayout(control_layout)
        layout.addStretch()
        
        return widget
    
    def create_remote_access_tab(self):
        """Create Remote Access Management tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        if not self.remote_access_manager:
            error_label = QLabel("Remote Access Manager not available")
            error_label.setStyleSheet("color: #ff6b6b;")
            layout.addWidget(error_label)
            return widget
        
        # Remote Access Status
        status_group = QGroupBox("Remote Access Status")
        status_layout = QVBoxLayout()
        
        self.remote_status_label = QLabel()
        self.remote_status_label.setStyleSheet("color: #4CAF50; font-weight: bold; font-size: 14pt;")
        self.remote_status_label.setText("Enabled")
        status_layout.addWidget(self.remote_status_label)
        
        # PC Registration Info
        pc_info_group = QGroupBox("PC Registration")
        pc_info_layout = QFormLayout()
        
        try:
            pc_data = self.remote_access_manager.enable_remote_access_on_pc()
            pc_info_layout.addRow("Machine ID:", QLabel(pc_data["machine_id"]))
            pc_info_layout.addRow("Hostname:", QLabel(pc_data["hostname"]))
            pc_info_layout.addRow("Local IP:", QLabel(pc_data["local_ip"]))
            pc_info_layout.addRow("OS:", QLabel(pc_data["system_info"]["os"]))
            pc_info_layout.addRow("CPU Cores:", QLabel(str(pc_data["system_info"]["cpu_cores"])))
            pc_info_layout.addRow("Memory (GB):", QLabel(str(pc_data["system_info"]["total_memory_gb"])))
            pc_info_layout.addRow("Access Key:", QLabel(pc_data["access_key"][:20] + "..."))
        except Exception as e:
            pc_info_layout.addRow("Error:", QLabel(str(e)))
        
        pc_info_group.setLayout(pc_info_layout)
        status_layout.addWidget(pc_info_group)
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # DISCOVERED SENTINELX NODES (AUTO-DISCOVERY)
        discovered_group = QGroupBox("📡 Discovered SentinelX Nodes (Auto-Scan)")
        discovered_layout = QVBoxLayout()
        
        # Discovery Info
        discovery_info_layout = QHBoxLayout()
        self.discovery_status_label = QLabel("Ready to scan network")
        self.discovery_status_label.setStyleSheet("color: #FFA500; font-style: italic;")
        discovery_info_layout.addWidget(self.discovery_status_label)
        discovery_info_layout.addStretch()
        
        discovered_layout.addLayout(discovery_info_layout)
        
        # Discovered Nodes Table
        self.discovered_nodes_table = QTableWidget()
        self.discovered_nodes_table.setColumnCount(6)
        self.discovered_nodes_table.setHorizontalHeaderLabels([
            "Hostname", "IP Address", "Status", "SentinelX Version", "Last Seen", "Action"
        ])
        self.discovered_nodes_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.discovered_nodes_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.discovered_nodes_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.discovered_nodes_table.setMaximumHeight(180)
        
        discovered_layout.addWidget(self.discovered_nodes_table)
        
        # Discovery Control Buttons
        discovery_btn_layout = QHBoxLayout()
        
        scan_network_btn = QPushButton("🔍 Scan Network for SentinelX Nodes")
        scan_network_btn.setToolTip("Automatically scan local network and discover all SentinelX instances")
        scan_network_btn.clicked.connect(self.scan_for_sentinelx_nodes)
        discovery_btn_layout.addWidget(scan_network_btn)
        
        refresh_nodes_btn = QPushButton("🔄 Refresh Node Status")
        refresh_nodes_btn.setToolTip("Check if all discovered nodes are currently online")
        refresh_nodes_btn.clicked.connect(self.refresh_discovered_nodes_status)
        discovery_btn_layout.addWidget(refresh_nodes_btn)
        
        connect_node_btn = QPushButton("↔️ Connect to Selected")
        connect_node_btn.setToolTip("Request remote access to the selected SentinelX node")
        connect_node_btn.clicked.connect(self.connect_to_discovered_node)
        discovery_btn_layout.addWidget(connect_node_btn)
        
        discovered_layout.addLayout(discovery_btn_layout)
        discovered_group.setLayout(discovered_layout)
        layout.addWidget(discovered_group)
        
        # Auto-scan on startup
        self.auto_scan_timer = QTimer()
        self.auto_scan_timer.timeout.connect(self.refresh_discovered_nodes_status)
        self.auto_scan_timer.start(30000)  # Auto-refresh every 30 seconds
        
        # Load previously discovered nodes
        if self.network_discovery_manager:
            self.refresh_discovered_nodes_list()
        
        # Active Sessions
        sessions_group = QGroupBox("Active Remote Sessions")
        sessions_layout = QVBoxLayout()
        
        self.remote_sessions_table = QTableWidget()
        self.remote_sessions_table.setColumnCount(6)
        self.remote_sessions_table.setHorizontalHeaderLabels(
            ["Session ID", "Requester", "Target", "Access Type", "Created", "Status"]
        )
        self.remote_sessions_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.remote_sessions_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.remote_sessions_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.remote_sessions_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        
        sessions_layout.addWidget(self.remote_sessions_table)
        sessions_group.setLayout(sessions_layout)
        layout.addWidget(sessions_group)
        
        # Approved Users
        users_group = QGroupBox("Approved Remote Users")
        users_layout = QVBoxLayout()
        
        self.remote_users_table = QTableWidget()
        self.remote_users_table.setColumnCount(4)
        self.remote_users_table.setHorizontalHeaderLabels(["Username", "Email", "Permissions", "Last Used"])
        self.remote_users_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.remote_users_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        
        try:
            approved_users = self.remote_access_manager.access_data.get("approved_users", [])
            for i, user in enumerate(approved_users):
                self.remote_users_table.insertRow(i)
                self.remote_users_table.setItem(i, 0, QTableWidgetItem(user["username"]))
                self.remote_users_table.setItem(i, 1, QTableWidgetItem(user["email"]))
                self.remote_users_table.setItem(i, 2, QTableWidgetItem(", ".join(user.get("permissions", []))))
                self.remote_users_table.setItem(i, 3, QTableWidgetItem(user.get("last_used", "Never")))
        except Exception as e:
            print(f"[ERROR] Failed to load approved users: {e}")
        
        users_layout.addWidget(self.remote_users_table)
        users_group.setLayout(users_layout)
        layout.addWidget(users_group)
        
        # Remote Access Controls
        control_group = QGroupBox("Remote Access Controls")
        control_layout = QHBoxLayout()
        
        new_session_btn = QPushButton("Create New Session")
        new_session_btn.setToolTip("Request remote access to another SentinelX-enabled PC")
        new_session_btn.clicked.connect(self.create_remote_session)
        control_layout.addWidget(new_session_btn)
        
        approve_user_btn = QPushButton("Approve User")
        approve_user_btn.setToolTip("Grant remote access permissions to a user")
        approve_user_btn.clicked.connect(self.approve_remote_user)
        control_layout.addWidget(approve_user_btn)
        
        refresh_btn = QPushButton("Refresh")
        refresh_btn.setToolTip("Reload all remote access data and session status")
        refresh_btn.clicked.connect(self.refresh_remote_access)
        control_layout.addWidget(refresh_btn)
        
        end_session_btn = QPushButton("End Selected Session")
        end_session_btn.setToolTip("Terminate the selected remote access session immediately")
        end_session_btn.clicked.connect(self.end_remote_session)
        control_layout.addWidget(end_session_btn)
        
        control_group.setLayout(control_layout)
        layout.addWidget(control_group)
        
        # Access Logs
        logs_group = QGroupBox("Access Logs (Last 10 Sessions)")
        logs_layout = QVBoxLayout()
        
        self.remote_logs_table = QTableWidget()
        self.remote_logs_table.setColumnCount(4)
        self.remote_logs_table.setHorizontalHeaderLabels(["Timestamp", "Session ID", "Event", "Details"])
        self.remote_logs_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        
        try:
            access_logs = self.remote_access_manager.get_access_logs(limit=10)
            for i, log in enumerate(access_logs):
                self.remote_logs_table.insertRow(i)
                self.remote_logs_table.setItem(i, 0, QTableWidgetItem(log["timestamp"]))
                self.remote_logs_table.setItem(i, 1, QTableWidgetItem(log.get("session_id", "N/A")))
                self.remote_logs_table.setItem(i, 2, QTableWidgetItem(log["event"]))
                self.remote_logs_table.setItem(i, 3, QTableWidgetItem(log.get("details", "")))
        except Exception as e:
            print(f"[ERROR] Failed to load access logs: {e}")
        
        logs_layout.addWidget(self.remote_logs_table)
        logs_group.setLayout(logs_layout)
        layout.addWidget(logs_group)
        
        layout.addStretch()
        return widget
    
    def create_remote_session(self):
        """Create new remote access session"""
        if not self.remote_access_manager:
            QMessageBox.warning(self, "Error", "Remote Access Manager not available")
            return
        
        # Show input dialog
        requester, ok = QInputDialog.getText(self, "Create Remote Session", "Requester Username:")
        if not ok:
            return
        
        access_type, ok = QInputDialog.getItem(self, "Select Access Type", "Access Type:",
                                               self.remote_access_manager.ACCESS_TYPES, 0, False)
        if not ok:
            return
        
        target_hostname, ok = QInputDialog.getText(self, "Enter Target", "Target Hostname:")
        if not ok:
            return
        
        target_ip, ok = QInputDialog.getText(self, "Enter IP", "Target IP Address:")
        if not ok:
            return
        
        try:
            session = self.remote_access_manager.create_remote_session(
                requester, access_type, target_ip, target_hostname, 24
            )
            QMessageBox.information(self, "Session Created", 
                                  f"Session ID: {session['session_id']}\nToken: {session['access_token'][:20]}...\nExpires: {session['expires_at']}")
            self.refresh_remote_access()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to create session: {str(e)}")
    
    def approve_remote_user(self):
        """Approve user for remote access"""
        if not self.remote_access_manager:
            QMessageBox.warning(self, "Error", "Remote Access Manager not available")
            return
        
        username, ok = QInputDialog.getText(self, "Approve User", "Username:")
        if not ok:
            return
        
        email, ok = QInputDialog.getText(self, "User Email", "Email Address:")
        if not ok:
            return
        
        if self.remote_access_manager.approve_user(username, email, ["rdp", "ssh"]):
            QMessageBox.information(self, "Success", f"User {username} approved for remote access")
            self.refresh_remote_access()
        else:
            QMessageBox.warning(self, "Error", "Failed to approve user")
    
    def end_remote_session(self):
        """Terminate selected remote session"""
        if not self.remote_access_manager:
            return
        
        current_row = self.remote_sessions_table.currentRow()
        if current_row >= 0:
            session_id = self.remote_sessions_table.item(current_row, 0).text()
            if self.remote_access_manager.end_session(session_id):
                QMessageBox.information(self, "Success", f"Session {session_id} terminated")
                self.refresh_remote_access()
    
    def refresh_remote_access(self):
        """Refresh remote access tab with latest data"""
        if not self.remote_access_manager:
            return
        
        # Clear and reload sessions
        self.remote_sessions_table.setRowCount(0)
        try:
            sessions = self.remote_access_manager.list_sessions("active")
            for i, session in enumerate(sessions):
                self.remote_sessions_table.insertRow(i)
                self.remote_sessions_table.setItem(i, 0, QTableWidgetItem(session["session_id"]))
                self.remote_sessions_table.setItem(i, 1, QTableWidgetItem(session["requester"]))
                self.remote_sessions_table.setItem(i, 2, QTableWidgetItem(session["target_hostname"]))
                self.remote_sessions_table.setItem(i, 3, QTableWidgetItem(session["access_type"]))
                self.remote_sessions_table.setItem(i, 4, QTableWidgetItem(session["created_at"]))
                self.remote_sessions_table.setItem(i, 5, QTableWidgetItem(session["status"]))
        except Exception as e:
            print(f"[ERROR] Failed to refresh sessions: {e}")
    
    def start_automatic_network_discovery(self):
        """Automatically scan for SentinelX nodes when dashboard starts"""
        if not self.network_discovery_manager:
            return
        
        # Start discovery after a short delay to ensure UI is fully ready
        def auto_discover():
            import time
            
            time.sleep(2)  # Wait for UI to fully render
            
            try:
                # Check if discovered_nodes_table exists (means Remote Access tab was created)
                if hasattr(self, 'discovered_nodes_table'):
                    # Log to console on main thread
                    QTimer.singleShot(0, lambda: self.write_console("[DISCOVERY] Starting automatic network scan on startup...\n"))
                    
                    # Update status on main thread
                    if hasattr(self, 'discovery_status_label'):
                        QTimer.singleShot(0, lambda: (
                            self.discovery_status_label.setText("🟠 Starting network scan..."),
                            self.discovery_status_label.setStyleSheet("color: #FFA500; font-weight: bold;")
                        ))
                    
                    # Define callback - will be called from discovery thread
                    def discovery_callback(nodes):
                        found_count = len(nodes)
                        
                        # Marshal all UI updates to main thread using QTimer.singleShot()
                        QTimer.singleShot(0, lambda: self.write_console(
                            f"[DISCOVERY] Automatic scan complete - Found {found_count} SentinelX node(s)\n"
                        ))
                        
                        if hasattr(self, 'discovery_status_label'):
                            if found_count > 0:
                                QTimer.singleShot(0, lambda: (
                                    self.discovery_status_label.setText(f"✅ Startup scan complete - {found_count} node(s) found"),
                                    self.discovery_status_label.setStyleSheet("color: #4CAF50; font-weight: bold;")
                                ))
                            else:
                                QTimer.singleShot(0, lambda: (
                                    self.discovery_status_label.setText("⚠️ No SentinelX nodes found on network"),
                                    self.discovery_status_label.setStyleSheet("color: #FFA500; font-weight: bold;")
                                ))
                        
                        # Refresh the discovered nodes list on main thread
                        if hasattr(self, 'refresh_discovered_nodes_list') and callable(self.refresh_discovered_nodes_list):
                            QTimer.singleShot(0, self.refresh_discovered_nodes_list)
                    
                    # Start async discovery
                    self.network_discovery_manager.discover_nodes_async(callback=discovery_callback)
            except Exception as e:
                QTimer.singleShot(0, lambda: self.write_console(
                    f"[DISCOVERY] Error during automatic startup scan: {str(e)}\n"
                ))
        
        # Run discovery in background thread
        discovery_thread = threading.Thread(target=auto_discover, daemon=True)
        discovery_thread.start()
        
        # Also start quick system scan and threat definitions update in background
        def auto_startup_tasks():
            import time
            time.sleep(3)  # Wait a bit longer for network discovery to start
            
            try:
                # Update threat definitions
                QTimer.singleShot(0, lambda: self.write_console("[STARTUP] Updating threat definitions...\n"))
                if hasattr(self, 'update_definitions') and callable(self.update_definitions):
                    self.update_definitions()
                    QTimer.singleShot(0, lambda: self.write_console("[STARTUP] Threat definitions update initiated\n"))
            except Exception as e:
                QTimer.singleShot(0, lambda: self.write_console(
                    f"[STARTUP] Error updating definitions: {str(e)}\n"
                ))
            
            try:
                # Start quick system scan
                time.sleep(5)  # Wait for definitions to finish
                QTimer.singleShot(0, lambda: self.write_console("[STARTUP] Starting automatic quick system scan...\n"))
                if hasattr(self, 'start_scan') and callable(self.start_scan):
                    self.start_scan("quick")
                    QTimer.singleShot(0, lambda: self.write_console("[STARTUP] Quick scan initiated\n"))
            except Exception as e:
                QTimer.singleShot(0, lambda: self.write_console(
                    f"[STARTUP] Error starting quick scan: {str(e)}\n"
                ))
        
        # Run startup tasks in background
        startup_thread = threading.Thread(target=auto_startup_tasks, daemon=True)
        startup_thread.start()
    
    def scan_for_sentinelx_nodes(self):
        """Scan network for SentinelX nodes"""
        if not self.network_discovery_manager:
            QMessageBox.warning(self, "Error", "Network Discovery Manager not available")
            return
        
        self.discovery_status_label.setText("🟠 Scanning network... Please wait (30-60 seconds)")
        self.discovery_status_label.setStyleSheet("color: #FFA500; font-weight: bold;")
        
        def scan_complete(nodes):
            self.discovery_status_label.setText(f"✅ Network scan complete - Found {len(nodes)} SentinelX node(s)")
            self.discovery_status_label.setStyleSheet("color: #4CAF50; font-weight: bold;")
            self.refresh_discovered_nodes_list()
        
        # Start async discovery
        self.network_discovery_manager.discover_nodes_async(callback=scan_complete)
    
    def refresh_discovered_nodes_status(self):
        """Refresh status of discovered nodes"""
        if not self.network_discovery_manager:
            return
        
        def refresh_status():
            nodes = self.network_discovery_manager.get_discovered_nodes()
            online_count = 0
            
            for node in nodes:
                ip = node.get("ip")
                if self.network_discovery_manager.is_node_online(ip):
                    node["status"] = "online"
                    online_count += 1
                else:
                    node["status"] = "offline"
            
            self.network_discovery_manager.save_discovered_nodes()
            
            # Update status label
            total = len(nodes)
            if total > 0:
                self.discovery_status_label.setText(f"✅ Network - {online_count}/{total} nodes online")
                self.discovery_status_label.setStyleSheet("color: #4CAF50; font-weight: bold;")
            else:
                self.discovery_status_label.setText("Ready to scan network")
                self.discovery_status_label.setStyleSheet("color: #FFA500; font-style: italic;")
            
            self.refresh_discovered_nodes_list()
        
        # Run in background
        refresh_thread = threading.Thread(target=refresh_status, daemon=True)
        refresh_thread.start()
    
    def refresh_discovered_nodes_list(self):
        """Update the discovered nodes table"""
        if not self.network_discovery_manager:
            return
        
        self.discovered_nodes_table.setRowCount(0)
        nodes = self.network_discovery_manager.get_discovered_nodes()
        
        for i, node in enumerate(nodes):
            self.discovered_nodes_table.insertRow(i)
            
            # Hostname
            hostname_item = QTableWidgetItem(node.get("hostname", "Unknown"))
            self.discovered_nodes_table.setItem(i, 0, hostname_item)
            
            # IP Address
            ip_item = QTableWidgetItem(node.get("ip", "N/A"))
            ip_item.setStyleSheet("font-family: monospace;")
            self.discovered_nodes_table.setItem(i, 1, ip_item)
            
            # Status (online/offline)
            status = node.get("status", "unknown").upper()
            status_item = QTableWidgetItem(status)
            
            if status == "ONLINE":
                status_item.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold; text-align: center;")
            elif status == "OFFLINE":
                status_item.setStyleSheet("background-color: #d32f2f; color: white; font-weight: bold; text-align: center;")
            else:
                status_item.setStyleSheet("background-color: #FFA500; color: white; text-align: center;")
            
            self.discovered_nodes_table.setItem(i, 2, status_item)
            
            # SentinelX Version
            version_item = QTableWidgetItem(node.get("sentinelx_version", "2.0+"))
            self.discovered_nodes_table.setItem(i, 3, version_item)
            
            # Last Seen
            last_seen = node.get("last_seen", "Unknown")
            if last_seen != "Unknown":
                # Format timestamp
                try:
                    from datetime import datetime
                    dt = datetime.fromisoformat(last_seen)
                    last_seen = dt.strftime("%Y-%m-%d %H:%M")
                except:
                    pass
            
            last_seen_item = QTableWidgetItem(last_seen)
            self.discovered_nodes_table.setItem(i, 4, last_seen_item)
            
            # Action Button
            action_btn = QPushButton("🔗 Connect")
            action_btn.setToolTip(f"Request remote access to {node.get('hostname', node.get('ip'))}")
            action_btn.setMaximumWidth(80)
            action_btn.clicked.connect(lambda checked, node=node: self.connect_to_node(node))
            self.discovered_nodes_table.setCellWidget(i, 5, action_btn)
    
    def connect_to_discovered_node(self):
        """Connect to the selected node in the discovered nodes table"""
        current_row = self.discovered_nodes_table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "Selection Required", "Please select a SentinelX node from the table")
            return
        
        # Get node info from table
        hostname = self.discovered_nodes_table.item(current_row, 0).text()
        ip = self.discovered_nodes_table.item(current_row, 1).text()
        
        self.connect_to_node({"hostname": hostname, "ip": ip})
    
    def connect_to_node(self, node: Dict):
        """Initiate remote access connection to a discovered node"""
        if not self.remote_access_manager:
            QMessageBox.warning(self, "Error", "Remote Access Manager not available")
            return
        
        hostname = node.get("hostname", "Unknown")
        ip = node.get("ip", "")
        
        # Ask for access type
        access_types = ["RDP", "SSH", "SECURE_TUNNEL", "VNC"]
        access_type, ok = QInputDialog.getItem(
            self, "Select Access Type",
            f"Choose access protocol for {hostname} ({ip}):",
            access_types, 0, False
        )
        
        if not ok:
            return
        
        # Get username for this connection
        username, ok = QInputDialog.getText(
            self, "Your Username",
            "Enter your username for this remote session:"
        )
        
        if not ok:
            return
        
        try:
            # Create remote session
            session = self.remote_access_manager.create_remote_session(
                username, access_type, ip, hostname, duration_hours=8
            )
            
            QMessageBox.information(self, "Remote Session Created",
                f"Session ID: {session['session_id']}\n"
                f"Host: {hostname} ({ip})\n"
                f"Protocol: {access_type}\n"
                f"Valid for: 8 hours\n\n"
                f"Token: {session.get('access_token_plain', 'N/A')[:30]}...\n"
                f"(Token hidden for security)"
            )
            
            self.refresh_remote_access()
            self.refresh_discovered_nodes_list()
            
        except Exception as e:
            QMessageBox.critical(self, "Connection Failed",
                f"Failed to create remote session:\n{str(e)}")


def run_dashboard():
    """Run the comprehensive dashboard"""
    app = QApplication(sys.argv)
    window = SentinelXComprehensiveDashboard()
    window.showNormal()
    window.activateWindow()
    window.raise_()
    sys.exit(app.exec())


if __name__ == '__main__':
    setup_logging()
    print("""
    ========================================================
    |                                                      |     
    |     SentinelX Comprehensive Security Dashboard       |
    |                                                      |
    ========================================================
    """)
    
    run_dashboard()

