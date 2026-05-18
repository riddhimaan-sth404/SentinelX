"""
Real-time File Monitoring Service: Detects file modifications and suspicious changes.
"""

import threading
import time
import os
from pathlib import Path
from typing import Dict, Set, Optional
from dataclasses import dataclass
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent

from sentinelx.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class FileChangeEvent:
    """Represents a detected file change."""
    event_type: str  # 'created', 'modified', 'deleted', 'moved'
    file_path: str
    timestamp: str = None
    is_suspicious: bool = False
    reason: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


class SuspiciousFileHandler(FileSystemEventHandler):
    """Handles file system events and detects suspicious activity."""
    
    SUSPICIOUS_PATTERNS = {
        '.exe': 'executable',
        '.dll': 'library',
        '.sys': 'system_driver',
        '.scr': 'screensaver',
        '.bat': 'batch_script',
        '.cmd': 'batch_script',
        '.vbs': 'vbscript',
        '.ps1': 'powershell_script',
        '.js': 'javascript',
    }
    
    SYSTEM_PROTECTED_DIRS = {
        'System32',
        'SysWOW64',
        'drivers',
        'config',
        'boot',
    }
    
    def __init__(self, monitor):
        super().__init__()
        self.monitor = monitor
    
    def on_created(self, event):
        if event.is_directory:
            return
        self._check_event('created', event.src_path)
    
    def on_modified(self, event):
        if event.is_directory:
            return
        self._check_event('modified', event.src_path)
    
    def on_deleted(self, event):
        if event.is_directory:
            return
        self._check_event('deleted', event.src_path)
    
    def _check_event(self, event_type: str, file_path: str):
        try:
            path = Path(file_path)
            is_suspicious = False
            reason = None
            
            # Check if executable created in system dirs
            if any(protected in file_path for protected in self.SYSTEM_PROTECTED_DIRS):
                if path.suffix.lower() in self.SUSPICIOUS_PATTERNS:
                    is_suspicious = True
                    reason = f"Suspicious {self.SUSPICIOUS_PATTERNS[path.suffix.lower()]} in protected directory"
            
            # Check for double extensions
            if file_path.count('.') >= 2:
                is_suspicious = True
                reason = "Double extension detected (potential obfuscation)"
            
            # Check for zero-byte files (dropper pattern)
            if path.exists() and path.stat().st_size == 0 and path.suffix.lower() in ['.exe', '.dll']:
                is_suspicious = True
                reason = "Zero-byte executable (dropper pattern)"
            
            event_obj = FileChangeEvent(
                event_type=event_type,
                file_path=file_path,
                is_suspicious=is_suspicious,
                reason=reason
            )
            
            self.monitor.events.append(event_obj)
            
            if is_suspicious:
                logger.warning(f"[FILE-MONITOR] SUSPICIOUS: {event_type} {file_path} - {reason}")
        
        except Exception as e:
            logger.debug(f"[FILE-MONITOR] Error checking event: {str(e)}")


class RealtimeFileMonitor:
    """Real-time file system monitoring service."""
    
    def __init__(self):
        self.running = False
        self.observer: Optional[Observer] = None
        self.events: list = []
        self.watched_paths = {
            Path.home() / 'Desktop',
            Path.home() / 'Downloads',
            Path(os.environ.get('APPDATA', 'C:\\Users\\AppData\\Roaming')),
            Path(os.environ.get('LOCALAPPDATA', 'C:\\Users\\AppData\\Local')),
        }
    
    def start_monitoring(self):
        """Start real-time file monitoring."""
        if self.running:
            return
        
        self.running = True
        self.observer = Observer()
        handler = SuspiciousFileHandler(self)
        
        for path in self.watched_paths:
            if path.exists():
                self.observer.schedule(handler, str(path), recursive=True)
        
        self.observer.start()
        logger.info("[FILE-MONITOR] Real-time file monitoring started")
    
    def stop_monitoring(self):
        """Stop real-time monitoring."""
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.running = False
            logger.info("[FILE-MONITOR] Real-time file monitoring stopped")
    
    def get_suspicious_events(self) -> list:
        """Get all suspicious file events."""
        return [e for e in self.events if e.is_suspicious]
