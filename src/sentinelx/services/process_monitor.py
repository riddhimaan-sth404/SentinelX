"""
Process Monitoring Service: Detects suspicious process behavior.
"""

import subprocess
import json
import threading
from typing import List, Dict, Optional
from dataclasses import dataclass
from datetime import datetime

from sentinelx.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ProcessAlert:
    """Represents a suspicious process."""
    process_name: str
    process_id: int
    parent_process: Optional[str]
    command_line: str
    severity: str  # low, medium, high, critical
    indicators: List[str]
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


class ProcessMonitor:
    """Monitor running processes for suspicious behavior."""
    
    SUSPICIOUS_PROCESSES = {
        'svchost.exe': {'severity': 'low', 'patterns': ['cmd.exe', 'powershell.exe']},
        'explorer.exe': {'severity': 'medium', 'patterns': ['cmd.exe', 'powershell.exe']},
        'notepad.exe': {'severity': 'medium', 'patterns': ['.exe', '.dll']},
        'msiexec.exe': {'severity': 'medium', 'patterns': ['temp', 'appdata']},
    }
    
    DANGEROUS_IMPORTS = {
        'CreateRemoteThread': 'code_injection',
        'WriteProcessMemory': 'code_injection',
        'SetWindowsHookEx': 'hook_injection',
        'InternetConnect': 'network_access',
        'URLDownloadToFile': 'file_download',
    }
    
    def __init__(self):
        self.alerts: List[ProcessAlert] = []
        self.running = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.scan_interval = 10
    
    def start_monitoring(self):
        """Start process monitoring."""
        if self.running:
            return
        
        self.running = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="ProcessMonitor"
        )
        self.monitor_thread.start()
        logger.info("[PROCESS-MONITOR] Process monitoring started")
    
    def stop_monitoring(self):
        """Stop process monitoring."""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("[PROCESS-MONITOR] Process monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        while self.running:
            try:
                self._scan_processes()
                import time
                time.sleep(self.scan_interval)
            except Exception as e:
                logger.error(f"[PROCESS-MONITOR] Error: {str(e)}")
    
    def _scan_processes(self):
        """Scan running processes for suspicious behavior."""
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-Process | Select-Object Name, Id, ProcessName, CommandLine | ConvertTo-Json"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0 and result.stdout.strip():
                processes = json.loads(result.stdout)
                if not isinstance(processes, list):
                    processes = [processes]
                
                for proc in processes:
                    self._check_process(proc)
        
        except Exception as e:
            logger.debug(f"[PROCESS-MONITOR] Scan error: {str(e)}")
    
    def _check_process(self, proc_info: dict):
        """Check individual process for suspicious behavior."""
        try:
            proc_name = proc_info.get('ProcessName', '').lower()
            cmd_line = proc_info.get('CommandLine', '').lower()
            proc_id = proc_info.get('Id', 0)
            
            if not proc_name:
                return
            
            indicators = []
            severity = 'low'
            
            # Check for suspicious command lines
            if proc_name in self.SUSPICIOUS_PROCESSES:
                patterns = self.SUSPICIOUS_PROCESSES[proc_name]['patterns']
                for pattern in patterns:
                    if pattern in cmd_line:
                        indicators.append(f"Suspicious pattern: {pattern}")
                        severity = 'high'
            
            # Check for suspicious process names
            suspicious_names = ['rundll32', 'regsvcs', 'regasm', 'InstallUtil', 'csc']
            if any(name in proc_name for name in suspicious_names):
                indicators.append("Known LOLBin process")
                severity = 'high'
            
            # Check for suspicious paths
            if any(path in cmd_line for path in ['temp', 'appdata', 'windows\\system32\\drivers']):
                indicators.append("Execution from suspicious directory")
                if severity != 'high':
                    severity = 'medium'
            
            if indicators:
                alert = ProcessAlert(
                    process_name=proc_name,
                    process_id=proc_id,
                    parent_process=proc_info.get('Parent', 'unknown'),
                    command_line=proc_info.get('CommandLine', ''),
                    severity=severity,
                    indicators=indicators
                )
                
                self.alerts.append(alert)
                logger.warning(f"[PROCESS-MONITOR] Suspicious process detected: {proc_name} (PID: {proc_id}) - {', '.join(indicators)}")
        
        except Exception as e:
            logger.debug(f"[PROCESS-MONITOR] Error checking process: {str(e)}")
