"""
Network Monitoring Service: Real-time detection of file downloads and data breaches.
Monitors network activity, intercepts downloads, scans for malware, and allows/blocks accordingly.
"""

import threading
import time
import os
import json
import hashlib
import socket
import struct
import subprocess
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
from collections import defaultdict

from sentinelx.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class NetworkEvent:
    """Represents a network activity event."""
    event_type: str  # 'download', 'upload', 'data_exfiltration', 'suspicious_connection'
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    file_path: Optional[str] = None
    file_size: Optional[int] = None
    file_hash: Optional[str] = None
    severity: str = 'low'  # low, medium, high, critical
    timestamp: str = None
    scanned: bool = False
    scan_result: Optional[str] = None  # clean, malicious, suspicious
    allowed: bool = False
    reason: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


@dataclass
class DataBreachIndicator:
    """Represents a potential data breach event."""
    breach_type: str  # 'credential_exfil', 'data_exfil', 'ransomware_comms', 'c2_contact'
    source_ip: str
    dest_ip: str
    dest_port: int
    severity: str  # critical, high, medium
    indicators: List[str]  # What triggered the detection
    timestamp: str = None
    remediated: bool = False
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


class NetworkMonitor:
    """
    Real-time network monitoring service.
    Detects downloads, monitors for data breaches, and validates downloads via scanning.
    """
    
    # Known malicious IPs and domains
    MALICIOUS_IPS = {
        '10.0.0.1',      # Example botnet C2
        '192.168.100.1', # Example command server
    }
    
    # High-risk ports (data exfiltration candidates)
    HIGH_RISK_PORTS = {
        5900: 'VNC',           # Remote desktop
        3389: 'RDP',           # Remote desktop
        22: 'SSH',             # Secure shell (could be used for exfil)
        445: 'SMB',            # File sharing
        139: 'NetBIOS',        # Legacy file sharing
        21: 'FTP',             # File transfer (often malicious)
        25: 'SMTP',            # Email (data exfil vector)
        53: 'DNS',             # DNS tunneling (data exfil)
        123: 'NTP',            # NTP tunneling
    }
    
    # Common download locations to monitor
    DOWNLOAD_LOCATIONS = {
        Path.home() / 'Downloads',
        Path.home() / 'Desktop',
        Path(os.environ.get('TEMP', 'C:\\Temp')),
        Path(os.environ.get('TMP', 'C:\\Tmp')),
    }
    
    # Suspicious file extensions for downloads
    SUSPICIOUS_EXTENSIONS = {
        '.exe', '.dll', '.sys', '.scr', '.vbs', '.js', '.bat', '.cmd',
        '.ps1', '.psc1', '.msi', '.jar', '.zip', '.rar', '.7z', '.ace',
        '.iso', '.img', '.dmg', '.pkg', '.deb', '.rpm', '.sh', '.bash'
    }
    
    # Suspicious keywords in network data (credentials, sensitive data)
    BREACH_INDICATORS = {
        'password': 'credential',
        'passwd': 'credential',
        'pwd': 'credential',
        'secret': 'credential',
        'apikey': 'credential',
        'api_key': 'credential',
        'token': 'credential',
        'bearer': 'credential',
        'credit': 'financial',
        'ssn': 'financial',
        'social': 'financial',
        'card': 'financial',
        'account': 'financial',
        'bank': 'financial',
        'routing': 'financial',
        'private': 'sensitive',
        'confidential': 'sensitive',
        'classified': 'sensitive',
        'proprietary': 'sensitive',
    }
    
    def __init__(self, pipeline=None):
        """
        Initialize network monitor.
        
        Args:
            pipeline: MalwareDetectionPipeline instance for scanning downloads
        """
        self.pipeline = pipeline
        self.running = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.events: List[NetworkEvent] = []
        self.breaches: List[DataBreachIndicator] = []
        self.monitored_downloads: Dict[str, NetworkEvent] = {}
        self.event_lock = threading.Lock()
        self.scan_interval = 2  # Check for downloads every 2 seconds
        
        # Load malicious URLs and domains
        self.malicious_urls = self._load_malicious_urls()
        self.malicious_domains = self._load_malicious_domains()
        
        logger.info(f"[NETWORK-MONITOR] Loaded {len(self.malicious_urls)} malicious URLs")
        logger.info(f"[NETWORK-MONITOR] Loaded {len(self.malicious_domains)} malware domains")
        
    def start_monitoring(self):
        """Start background network monitoring."""
        if self.running:
            logger.warning("[NETWORK-MONITOR] Service already running")
            return
        
        self.running = True
        self.monitor_thread = threading.Thread(
            target=self._monitoring_loop,
            daemon=True,
            name="NetworkMonitor"
        )
        self.monitor_thread.start()
        logger.info("[NETWORK-MONITOR] Network monitoring service started")
    
    def stop_monitoring(self):
        """Stop network monitoring."""
        if self.running:
            self.running = False
            if self.monitor_thread:
                self.monitor_thread.join(timeout=5)
            logger.info("[NETWORK-MONITOR] Network monitoring service stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop running in background thread."""
        while self.running:
            try:
                # Check for new downloads
                self._check_downloads()
                
                # Monitor for data breaches
                self._check_data_breaches()
                
                # Process network connections
                self._analyze_connections()
                
                # Clean up old events (keep last 1000)
                if len(self.events) > 1000:
                    with self.event_lock:
                        self.events = self.events[-1000:]
                
                time.sleep(self.scan_interval)
                
            except Exception as e:
                logger.error(f"[NETWORK-MONITOR] Monitoring error: {str(e)}")
                time.sleep(1)
    
    def _check_downloads(self):
        """Monitor download folders for new files."""
        try:
            for download_dir in self.DOWNLOAD_LOCATIONS:
                if not download_dir.exists():
                    continue
                
                try:
                    for file_path in download_dir.glob('*'):
                        if not file_path.is_file():
                            continue
                        
                        # Check if already processed
                        file_key = str(file_path)
                        if file_key in self.monitored_downloads:
                            continue
                        
                        # Check if suspicious file type
                        if file_path.suffix.lower() in self.SUSPICIOUS_EXTENSIONS:
                            self._handle_suspicious_download(file_path)
                        else:
                            # Still monitor all downloads for completeness
                            self._handle_download(file_path)
                
                except (PermissionError, OSError) as e:
                    logger.debug(f"[NETWORK-MONITOR] Cannot access {download_dir}: {str(e)}")
        
        except Exception as e:
            logger.error(f"[NETWORK-MONITOR] Download check error: {str(e)}")
    
    def _handle_download(self, file_path: Path):
        """Handle detected file download."""
        try:
            file_size = file_path.stat().st_size
            file_hash = self._calculate_hash(file_path)
            
            event = NetworkEvent(
                event_type='download',
                source_ip='unknown',  # Would require packet capture for real IP
                dest_ip='local',
                source_port=0,
                dest_port=0,
                protocol='HTTP/HTTPS',
                file_path=str(file_path),
                file_size=file_size,
                file_hash=file_hash,
                severity='low'
            )
            
            with self.event_lock:
                self.events.append(event)
                self.monitored_downloads[str(file_path)] = event
            
            logger.debug(f"[NETWORK-MONITOR] Detected download: {file_path}")
            
        except Exception as e:
            logger.error(f"[NETWORK-MONITOR] Error handling download {file_path}: {str(e)}")
    
    def _handle_suspicious_download(self, file_path: Path):
        """Handle detected suspicious file download with scanning."""
        try:
            file_size = file_path.stat().st_size
            file_hash = self._calculate_hash(file_path)
            
            logger.warning(f"[NETWORK-MONITOR] SUSPICIOUS DOWNLOAD DETECTED: {file_path} ({file_path.suffix})")
            
            event = NetworkEvent(
                event_type='download',
                source_ip='unknown',
                dest_ip='local',
                source_port=0,
                dest_port=0,
                protocol='HTTP/HTTPS',
                file_path=str(file_path),
                file_size=file_size,
                file_hash=file_hash,
                severity='high'
            )
            
            # Check if from malicious source first
            if self._is_from_malicious_source(url=str(file_path)):
                scan_result = 'malicious'
                allowed = False
                reason = "Source is on malicious URL/domain list"
                logger.critical(f"[NETWORK-MONITOR] ❌ BLOCKED - FROM KNOWN MALICIOUS SOURCE: {file_path}")
                self._quarantine_file(file_path)
            else:
                # Scan the file if pipeline available
                scan_result = 'unknown'
                allowed = False
                reason = "Pending scan"
                
                if self.pipeline:
                    try:
                        logger.info(f"[NETWORK-MONITOR] Scanning downloaded file: {file_path}")
                        scan_result_obj = self.pipeline.scan_file(str(file_path))
                        
                        if scan_result_obj.is_malicious:
                            scan_result = 'malicious'
                            allowed = False
                            reason = f"Malicious (Risk: {scan_result_obj.risk_level})"
                            logger.critical(f"[NETWORK-MONITOR] ❌ BLOCKED MALICIOUS DOWNLOAD: {file_path}")
                            
                            # Attempt to quarantine
                            self._quarantine_file(file_path)
                        else:
                            scan_result = 'clean'
                            allowed = True
                            reason = "Passed malware scan"
                            logger.info(f"[NETWORK-MONITOR] ✓ ALLOWED download (clean): {file_path}")
                    
                    except Exception as e:
                        scan_result = 'error'
                        reason = f"Scan failed: {str(e)}"
                        logger.error(f"[NETWORK-MONITOR] Scan error for {file_path}: {str(e)}")
            
            event.scanned = True
            event.scan_result = scan_result
            event.allowed = allowed
            event.reason = reason
            
            with self.event_lock:
                self.events.append(event)
                self.monitored_downloads[str(file_path)] = event
            
            # Log the decision
            self._log_download_decision(event)
            
        except Exception as e:
            logger.error(f"[NETWORK-MONITOR] Error handling suspicious download: {str(e)}")
    
    def _quarantine_file(self, file_path: Path):
        """Attempt to quarantine a malicious file."""
        try:
            quarantine_dir = Path('quarantine/network_downloads')
            quarantine_dir.mkdir(parents=True, exist_ok=True)
            
            quarantine_name = f"{file_path.stem}_MALICIOUS_{datetime.now().strftime('%Y%m%d_%H%M%S')}{file_path.suffix}"
            quarantine_path = quarantine_dir / quarantine_name
            
            # Move file to quarantine
            file_path.rename(quarantine_path)
            
            logger.warning(f"[NETWORK-MONITOR] Quarantined malicious file: {quarantine_path}")
            
        except Exception as e:
            logger.error(f"[NETWORK-MONITOR] Failed to quarantine {file_path}: {str(e)}")
    
    def _check_data_breaches(self):
        """Monitor for data exfiltration patterns."""
        try:
            # Check for suspicious outbound connections with high data transfer
            self._detect_exfiltration_patterns()
            
            # Check for C2 (Command & Control) communications
            self._detect_c2_communications()
            
            # Check for ransomware communication patterns
            self._detect_ransomware_comms()
            
        except Exception as e:
            logger.error(f"[NETWORK-MONITOR] Data breach check error: {str(e)}")
    
    def _detect_exfiltration_patterns(self):
        """Detect potential data exfiltration."""
        try:
            # Use netstat to check active connections
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-NetTCPConnection -State Established | "
                 "Where-Object {$_.RemotePort -in @(21,25,53,123,445,5900)} | "
                 "Select-Object LocalAddress, RemoteAddress, RemotePort, State"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.strip().split('\n')
                for line in lines[3:]:  # Skip header lines
                    if not line.strip():
                        continue
                    
                    parts = line.split()
                    if len(parts) >= 3:
                        remote_ip = parts[1]
                        remote_port = int(parts[2]) if parts[2].isdigit() else 0
                        
                        if remote_port in self.HIGH_RISK_PORTS:
                            # Potential exfiltration
                            indicators = [
                                f"Unusual port {remote_port}",
                                f"Large data transfer potential"
                            ]
                            
                            breach = DataBreachIndicator(
                                breach_type='data_exfil',
                                source_ip='local',
                                dest_ip=remote_ip,
                                dest_port=remote_port,
                                severity='high',
                                indicators=indicators
                            )
                            
                            with self.event_lock:
                                self.breaches.append(breach)
                            
                            logger.warning(f"[NETWORK-MONITOR] ⚠️ DATA EXFILTRATION RISK: {remote_ip}:{remote_port}")
        
        except subprocess.TimeoutExpired:
            logger.debug("[NETWORK-MONITOR] Connection check timed out")
        except Exception as e:
            logger.debug(f"[NETWORK-MONITOR] Error checking exfiltration: {str(e)}")
    
    def _detect_c2_communications(self):
        """Detect Command & Control communications."""
        try:
            # Check DNS queries for suspicious domains
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-DnsClientCache | "
                 "Where-Object {$_.Name -match '(xmpp|irc|tor|proxy)' -or $_.Type -eq 'A'} | "
                 "Select-Object Name -First 10"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    domain = line.strip()
                    
                    # Check against known malicious domains
                    if self._is_from_malicious_source(domain=domain):
                        indicators = [f"Known malicious domain: {domain}"]
                        breach = DataBreachIndicator(
                            breach_type='c2_contact',
                            source_ip='local',
                            dest_ip='unknown',
                            dest_port=0,
                            severity='critical',
                            indicators=indicators
                        )
                        
                        with self.event_lock:
                            self.breaches.append(breach)
                        
                        logger.warning(f"[NETWORK-MONITOR] 🚨 C2 COMMUNICATION DETECTED (MALICIOUS DOMAIN): {domain}")
                    elif any(keyword in line.lower() for keyword in ['xmpp', 'irc', 'tor']):
                        indicators = [f"Suspicious DNS query: {line}"]
                        
                        breach = DataBreachIndicator(
                            breach_type='c2_contact',
                            source_ip='local',
                            dest_ip='unknown',
                            dest_port=0,
                            severity='critical',
                            indicators=indicators
                        )
                        
                        with self.event_lock:
                            self.breaches.append(breach)
                        
                        logger.warning(f"[NETWORK-MONITOR] 🚨 C2 COMMUNICATION DETECTED: {line}")
        
        except Exception as e:
            logger.debug(f"[NETWORK-MONITOR] Error checking C2: {str(e)}")
    
    def _detect_ransomware_comms(self):
        """Detect ransomware communication patterns."""
        try:
            # Look for multiple failed connection attempts (common ransomware pattern)
            failed_connections = defaultdict(int)
            
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-NetTCPConnection -State Established | "
                 "Measure-Object | Select-Object Count"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                connection_count = int(result.stdout.strip().split(':')[-1].strip())
                
                # Ransomware typically makes many connection attempts
                if connection_count > 50:
                    indicators = [
                        f"Abnormally high connection count: {connection_count}",
                        "Pattern consistent with ransomware scanning"
                    ]
                    
                    breach = DataBreachIndicator(
                        breach_type='ransomware_comms',
                        source_ip='local',
                        dest_ip='multiple',
                        dest_port=0,
                        severity='critical',
                        indicators=indicators
                    )
                    
                    with self.event_lock:
                        self.breaches.append(breach)
                    
                    logger.warning(f"[NETWORK-MONITOR] 🚨 RANSOMWARE PATTERN DETECTED: {connection_count} connections")
        
        except Exception as e:
            logger.debug(f"[NETWORK-MONITOR] Error checking ransomware: {str(e)}")
    
    def _analyze_connections(self):
        """Analyze active network connections for anomalies."""
        try:
            # Get current network connections
            result = subprocess.run(
                ["netstat", "-an"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                # Analyze for suspicious patterns
                connections = result.stdout.split('\n')
                established_count = sum(1 for c in connections if 'ESTABLISHED' in c)
                listening_count = sum(1 for c in connections if 'LISTENING' in c)
                
                # Log anomalies
                if established_count > 100:
                    logger.warning(f"[NETWORK-MONITOR] Unusual number of established connections: {established_count}")
        
        except Exception as e:
            logger.debug(f"[NETWORK-MONITOR] Error analyzing connections: {str(e)}")
    
    @staticmethod
    def _calculate_hash(file_path: Path) -> str:
        """Calculate SHA256 hash of file."""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"[NETWORK-MONITOR] Error calculating hash: {str(e)}")
            return "error"
    
    def _log_download_decision(self, event: NetworkEvent):
        """Log download allow/block decision."""
        try:
            log_path = Path('logs/network_downloads.json')
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Read existing log
            if log_path.exists():
                with open(log_path, 'r') as f:
                    data = json.load(f)
            else:
                data = {'downloads': []}
            
            # Add new entry
            data['downloads'].append(asdict(event))
            
            # Keep only last 100 entries
            if len(data['downloads']) > 100:
                data['downloads'] = data['downloads'][-100:]
            
            # Write back
            with open(log_path, 'w') as f:
                json.dump(data, f, indent=2)
        
        except Exception as e:
            logger.error(f"[NETWORK-MONITOR] Error logging decision: {str(e)}")
    
    def get_network_report(self) -> str:
        """Get formatted report of network activity."""
        with self.event_lock:
            download_count = sum(1 for e in self.events if e.event_type == 'download')
            allowed_count = sum(1 for e in self.events if e.allowed)
            blocked_count = sum(1 for e in self.events if e.event_type == 'download' and not e.allowed and e.scanned)
            breach_count = len(self.breaches)
        
        report = f"[NETWORK-MONITOR] Report:\n"
        report += f"  Downloads detected: {download_count}\n"
        report += f"  Files allowed: {allowed_count}\n"
        report += f"  Files blocked: {blocked_count}\n"
        report += f"  Data breach indicators: {breach_count}\n"
        
        if self.breaches:
            report += f"\n[NETWORK-MONITOR] Active Breach Indicators:\n"
            for breach in self.breaches[-5:]:
                report += f"  - {breach.breach_type} ({breach.severity}): {', '.join(breach.indicators[:2])}\n"
        
        return report
    
    def _load_malicious_urls(self) -> set:
        """Load malicious URLs from data/urls.txt."""
        try:
            urls = set()
            url_file = Path('data/urls.txt')
            if url_file.exists():
                with open(url_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            urls.add(line.lower())
            return urls
        except Exception as e:
            logger.error(f"[NETWORK-MONITOR] Error loading URLs: {str(e)}")
            return set()
    
    def _load_malicious_domains(self) -> set:
        """Load malware domains from data/malware_domains.json."""
        try:
            domains = set()
            domains_file = Path('data/malware_domains.json')
            if domains_file.exists():
                with open(domains_file, 'r') as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        for domain in data.get('domains', []):
                            domains.add(domain.lower())
                    elif isinstance(data, list):
                        for domain in data:
                            if isinstance(domain, str):
                                domains.add(domain.lower())
                            elif isinstance(domain, dict) and 'domain' in domain:
                                domains.add(domain['domain'].lower())
            return domains
        except Exception as e:
            logger.error(f"[NETWORK-MONITOR] Error loading domains: {str(e)}")
            return set()
    
    def _is_from_malicious_source(self, url: str = None, domain: str = None) -> bool:
        """Check if URL or domain is in malicious lists."""
        if url:
            url_lower = url.lower()
            # Check exact match and partial matches
            for malicious_url in self.malicious_urls:
                if malicious_url in url_lower or url_lower in malicious_url:
                    return True
        
        if domain:
            domain_lower = domain.lower()
            # Check exact match and subdomain matches
            for malicious_domain in self.malicious_domains:
                if malicious_domain in domain_lower or domain_lower in malicious_domain:
                    return True
        
        return False
