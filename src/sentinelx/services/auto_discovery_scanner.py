"""
Auto-Discovery Scanner: Continuous background file scanning of critical directories.
"""

import threading
import time
from pathlib import Path
from typing import List, Dict
from datetime import datetime

from sentinelx.utils.logger import get_logger

logger = get_logger(__name__)


class AutoDiscoveryScannerService:
    """Automatically scan critical directories in background."""
    
    # Critical paths to continuously monitor
    CRITICAL_PATHS = [
        'C:\\Windows\\Temp',
        'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup',
        'C:\\Users\\*/AppData\\Local\\Temp',
        'C:\\Users\\*/Downloads',
        'C:\\Users\\*/Desktop',
    ]
    
    def __init__(self, pipeline=None, scan_interval: int = 300):
        """
        Initialize auto-discovery scanner.
        
        Args:
            pipeline: MalwareDetectionPipeline instance
            scan_interval: Seconds between scans (default 5 minutes)
        """
        self.pipeline = pipeline
        self.scan_interval = scan_interval
        self.scanner_thread = None
        self.running = False
        self.scan_stats = {
            'total_scans': 0,
            'files_scanned': 0,
            'threats_found': 0,
            'last_scan_time': None,
            'last_threats': [],
        }
    
    def start_scanning(self):
        """Start the auto-discovery scanner daemon."""
        if self.running:
            return
        
        self.running = True
        self.scanner_thread = threading.Thread(target=self._scanning_loop, daemon=True)
        self.scanner_thread.start()
        logger.warning("[AUTO_SCAN] Auto-Discovery Scanner started - continuous background scanning active")
    
    def stop_scanning(self):
        """Stop the auto-discovery scanner."""
        self.running = False
        logger.info("[AUTO_SCAN] Auto-Discovery Scanner stopped")
    
    def _scanning_loop(self):
        """Main scanning loop - continuously scan critical directories."""
        logger.info("[AUTO_SCAN] Scanning loop started")
        
        while self.running:
            try:
                scan_start = datetime.now()
                self.scan_stats['total_scans'] += 1
                
                logger.info(f"[AUTO_SCAN] Starting background scan #{self.scan_stats['total_scans']}")
                
                # Scan each critical path
                threats_this_scan = []
                for path_pattern in self.CRITICAL_PATHS:
                    if not self.running:
                        break
                    
                    threats = self._scan_directory_pattern(path_pattern)
                    threats_this_scan.extend(threats)
                
                scan_duration = (datetime.now() - scan_start).total_seconds()
                
                # Update stats
                if threats_this_scan:
                    self.scan_stats['threats_found'] += len(threats_this_scan)
                    self.scan_stats['last_threats'] = threats_this_scan[-5:]  # Keep last 5
                    logger.warning(f"[AUTO_SCAN] Scan #{self.scan_stats['total_scans']} found {len(threats_this_scan)} threats in {scan_duration:.1f}s")
                else:
                    logger.info(f"[AUTO_SCAN] Scan #{self.scan_stats['total_scans']} complete - no threats in {scan_duration:.1f}s")
                
                self.scan_stats['last_scan_time'] = datetime.now().isoformat()
                
                # Wait before next scan
                time.sleep(self.scan_interval)
            
            except Exception as e:
                logger.error(f"[AUTO_SCAN] Error in scanning loop: {str(e)}")
                time.sleep(self.scan_interval)
    
    def _scan_directory_pattern(self, path_pattern: str) -> List[Dict]:
        """
        Scan a directory pattern (supports wildcards).
        
        Args:
            path_pattern: Directory path with optional wildcards
            
        Returns:
            List of threats found
        """
        if not self.pipeline:
            return []
        
        threats = []
        
        try:
            # Expand wildcards (for user directories)
            if '*' in path_pattern:
                # Handle C:\\Users\\* pattern
                if 'C:\\Users\\*' in path_pattern:
                    users_dir = Path('C:\\Users')
                    if users_dir.exists():
                        for user_dir in users_dir.iterdir():
                            if user_dir.is_dir():
                                expanded_path = path_pattern.replace('*', user_dir.name)
                                threats.extend(self._scan_directory(expanded_path))
                    return threats
            
            # Direct directory scan
            threats.extend(self._scan_directory(path_pattern))
        
        except Exception as e:
            logger.debug(f"[AUTO_SCAN] Error scanning pattern {path_pattern}: {str(e)}")
        
        return threats
    
    def _scan_directory(self, directory: str) -> List[Dict]:
        """
        Scan a directory for threats.
        
        Args:
            directory: Directory path to scan
            
        Returns:
            List of threats found
        """
        threats = []
        
        try:
            path = Path(directory)
            if not path.exists():
                return []
            
            # Scan all files in directory (non-recursive first, then subfolders)
            file_count = 0
            for file_path in path.glob('*'):
                if not self.running:
                    break
                
                if file_path.is_file():
                    file_count += 1
                    
                    try:
                        result = self.pipeline.scan_file(str(file_path))
                        self.scan_stats['files_scanned'] += 1
                        
                        if result and result.is_malicious:
                            threat_info = {
                                'file': str(file_path),
                                'hash': result.file_hash,
                                'threat_type': result.threat_type if hasattr(result, 'threat_type') else 'unknown',
                                'timestamp': datetime.now().isoformat(),
                            }
                            threats.append(threat_info)
                            logger.warning(f"[AUTO_SCAN] THREAT DETECTED: {file_path}")
                    
                    except Exception as e:
                        logger.debug(f"[AUTO_SCAN] Error scanning file {file_path}: {str(e)}")
            
            if file_count > 0:
                logger.debug(f"[AUTO_SCAN] Scanned {file_count} files in {directory}")
        
        except Exception as e:
            logger.debug(f"[AUTO_SCAN] Error scanning directory {directory}: {str(e)}")
        
        return threats
    
    def get_scan_statistics(self) -> Dict:
        """Get auto-scanner statistics."""
        return {
            'scanner_active': self.running,
            'total_scans_completed': self.scan_stats['total_scans'],
            'total_files_scanned': self.scan_stats['files_scanned'],
            'total_threats_found': self.scan_stats['threats_found'],
            'last_scan_time': self.scan_stats['last_scan_time'],
            'scan_interval_seconds': self.scan_interval,
            'recent_threats': self.scan_stats['last_threats'],
        }
