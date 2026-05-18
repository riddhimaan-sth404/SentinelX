"""
Network Packet Capture Module - Monitor and analyze network traffic
Captures packets, identifies suspicious patterns, and logs security events
"""
import json
import logging
import threading
import time
from pathlib import Path
from typing import List, Dict, Optional, Callable
from datetime import datetime
from dataclasses import dataclass, field, asdict
from collections import defaultdict

logger = logging.getLogger(__name__)

# Try to import scapy for packet capturing
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.debug("Scapy not available - packet capture will use simulation mode")


@dataclass
class PacketInfo:
    """Captured packet information"""
    timestamp: str
    source_ip: str
    dest_ip: str
    protocol: str  # TCP, UDP, ICMP, DNS, etc.
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    size: int = 0
    payload_size: int = 0
    flags: str = ""
    is_suspicious: bool = False
    threat_level: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
    reason: str = ""
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return asdict(self)


@dataclass
class TrafficStatistics:
    """Network traffic statistics"""
    total_packets: int = 0
    total_bytes: int = 0
    packets_by_protocol: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    suspicious_packets: int = 0
    blocked_packets: int = 0
    top_source_ips: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    top_dest_ips: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    top_ports: Dict[int, int] = field(default_factory=lambda: defaultdict(int))


class PacketCapture:
    """
    Network packet capture and analysis engine.
    Monitors network traffic, identifies suspicious patterns, and logs security events.
    """
    
    def __init__(self, config_dir: Path = None, capture_filter: str = None):
        """
        Initialize packet capture engine
        
        Args:
            config_dir: Directory to store packet logs
            capture_filter: BPF filter for packet capturing (e.g., 'tcp port 22')
        """
        if config_dir is None:
            config_dir = Path.cwd()
        
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        self.capture_filter = capture_filter or ""
        self.packets_log = self.config_dir / "captured_packets.json"
        self.stats_log = self.config_dir / "packet_statistics.json"
        
        self.captured_packets: List[PacketInfo] = []
        self.statistics = TrafficStatistics()
        self.is_capturing = False
        self.capture_thread: Optional[threading.Thread] = None
        
        # Suspicious patterns
        self.suspicious_ports = {
            31337, 27374, 6667, 666, 1337,  # backdoor ports
            135, 139, 445, 593, 636,        # SMB/WINS
            10000, 20000, 30000,             # common malware
        }
        
        self.suspicious_keywords = [
            b'payload', b'shellcode', b'malware', b'exploit',
            b'inject', b'cmd.exe', b'powershell', b'reverse',
            b'ncat', b'netcat', b'telnet', b'ssh-brute'
        ]
        
        self._load_logs()
        logger.info(f"Packet Capture initialized ({'live' if SCAPY_AVAILABLE else 'simulation'} mode)")
    
    def _load_logs(self):
        """Load existing packet logs"""
        try:
            if self.packets_log.exists():
                with open(self.packets_log, 'r') as f:
                    data = json.load(f)
                    self.captured_packets = [
                        PacketInfo(**pkt) for pkt in data.get('packets', [])
                    ][-1000:]  # Keep last 1000 packets
                logger.debug(f"Loaded {len(self.captured_packets)} captured packets")
        except Exception as e:
            logger.error(f"Error loading packet logs: {e}")
    
    def _save_logs(self):
        """Save packet logs to JSON"""
        try:
            with open(self.packets_log, 'w') as f:
                json.dump(
                    {'packets': [pkt.to_dict() for pkt in self.captured_packets[-1000:]]},
                    f,
                    indent=2
                )
        except Exception as e:
            logger.error(f"Error saving packet logs: {e}")
    
    def _save_statistics(self):
        """Save traffic statistics"""
        try:
            stats_dict = {
                'total_packets': self.statistics.total_packets,
                'total_bytes': self.statistics.total_bytes,
                'suspicious_packets': self.statistics.suspicious_packets,
                'blocked_packets': self.statistics.blocked_packets,
                'packets_by_protocol': dict(self.statistics.packets_by_protocol),
                'top_source_ips': dict(sorted(
                    self.statistics.top_source_ips.items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:50]),
                'top_dest_ips': dict(sorted(
                    self.statistics.top_dest_ips.items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:50]),
                'top_ports': dict(sorted(
                    self.statistics.top_ports.items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:50]),
                'last_updated': datetime.now().isoformat()
            }
            
            with open(self.stats_log, 'w') as f:
                json.dump(stats_dict, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving statistics: {e}")
    
    def _analyze_packet(self, packet) -> Optional[PacketInfo]:
        """Analyze a captured packet for suspicious activity"""
        if not packet.haslayer(IP):
            return None
        
        try:
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            
            packet_info = PacketInfo(
                timestamp=datetime.now().isoformat(),
                source_ip=src_ip,
                dest_ip=dst_ip,
                protocol="IP",
                size=len(packet)
            )
            
            # Analyze based on protocol
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                packet_info.protocol = "TCP"
                packet_info.source_port = tcp_layer.sport
                packet_info.dest_port = tcp_layer.dport
                packet_info.flags = str(tcp_layer.flags)
                packet_info.payload_size = len(tcp_layer.payload)
                
                # Check for suspicious ports
                if tcp_layer.dport in self.suspicious_ports or tcp_layer.sport in self.suspicious_ports:
                    packet_info.is_suspicious = True
                    packet_info.threat_level = "MEDIUM"
                    packet_info.reason = f"Suspicious port: {tcp_layer.dport or tcp_layer.sport}"
                
                # Check for port scanning patterns (flags)
                if tcp_layer.flags & 0x01:  # SYN flag alone
                    packet_info.is_suspicious = True
                    packet_info.threat_level = "MEDIUM"
                    packet_info.reason = "Possible port scan (SYN)"
                
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                packet_info.protocol = "UDP"
                packet_info.source_port = udp_layer.sport
                packet_info.dest_port = udp_layer.dport
                packet_info.payload_size = len(udp_layer.payload)
                
                # Check for DNS requests
                if packet.haslayer(DNS):
                    packet_info.protocol = "DNS"
                    dns_layer = packet[DNS]
                    
                    # Check for DNS exfiltration patterns
                    if dns_layer.qd:
                        for query in dns_layer.qd:
                            qname = str(query.qname.decode() if isinstance(query.qname, bytes) else query.qname)
                            
                            # Suspicious DNS query patterns
                            if any(keyword in qname.lower() for keyword in ['malware', 'botnet', 'c2', 'command', 'exfil']):
                                packet_info.is_suspicious = True
                                packet_info.threat_level = "HIGH"
                                packet_info.reason = f"Suspicious DNS query: {qname}"
                
            elif packet.haslayer(ICMP):
                packet_info.protocol = "ICMP"
                icmp_layer = packet[ICMP]
                packet_info.payload_size = len(icmp_layer.payload)
                
                # Detect ICMP tunneling (excessive payload)
                if len(icmp_layer.payload) > 1000:
                    packet_info.is_suspicious = True
                    packet_info.threat_level = "MEDIUM"
                    packet_info.reason = "Possible ICMP tunneling"
            
            # Check payload for suspicious keywords
            if packet.haslayer(Raw):
                raw_data = bytes(packet[Raw].load)
                for keyword in self.suspicious_keywords:
                    if keyword in raw_data:
                        packet_info.is_suspicious = True
                        packet_info.threat_level = "HIGH"
                        packet_info.reason = f"Suspicious keyword in payload: {keyword.decode()}"
                        break
            
            # Check for private IP ranges being accessed (lateral movement)
            if self._is_private_ip(dst_ip):
                if not self._is_private_ip(src_ip):
                    packet_info.is_suspicious = True
                    packet_info.threat_level = "MEDIUM"
                    packet_info.reason = "External to internal network access (lateral movement)"
            
            return packet_info
            
        except Exception as e:
            logger.debug(f"Error analyzing packet: {e}")
            return None
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        try:
            parts = [int(x) for x in ip.split('.')]
            if len(parts) == 4:
                # 10.0.0.0/8
                if parts[0] == 10:
                    return True
                # 172.16.0.0/12
                if parts[0] == 172 and 16 <= parts[1] <= 31:
                    return True
                # 192.168.0.0/16
                if parts[0] == 192 and parts[1] == 168:
                    return True
                # 127.0.0.0/8 (loopback)
                if parts[0] == 127:
                    return True
            return False
        except:
            return False
    
    def _packet_callback(self, packet) -> None:
        """Callback for packet processing during live capture"""
        packet_info = self._analyze_packet(packet)
        if packet_info:
            self._process_packet(packet_info)
    
    def _process_packet(self, packet_info: PacketInfo) -> None:
        """Process analyzed packet"""
        self.captured_packets.append(packet_info)
        self.statistics.total_packets += 1
        self.statistics.total_bytes += packet_info.size
        self.statistics.packets_by_protocol[packet_info.protocol] += 1
        
        if packet_info.source_ip:
            self.statistics.top_source_ips[packet_info.source_ip] += 1
        if packet_info.dest_ip:
            self.statistics.top_dest_ips[packet_info.dest_ip] += 1
        if packet_info.dest_port:
            self.statistics.top_ports[packet_info.dest_port] += 1
        
        if packet_info.is_suspicious:
            self.statistics.suspicious_packets += 1
            logger.warning(f"[PACKET] SUSPICIOUS: {packet_info.protocol} {packet_info.source_ip}:{packet_info.source_port} "
                          f"-> {packet_info.dest_ip}:{packet_info.dest_port} "
                          f"({packet_info.threat_level}): {packet_info.reason}")
    
    def start_capture(self, interface: Optional[str] = None, packet_count: int = 0) -> None:
        """
        Start capturing packets
        
        Args:
            interface: Network interface to capture on (e.g., 'eth0')
            packet_count: Maximum packets to capture (0 = unlimited)
        """
        if self.is_capturing:
            logger.warning("Packet capture already in progress")
            return
        
        if not SCAPY_AVAILABLE:
            logger.warning("Scapy not available - cannot start live capture")
            return
        
        self.is_capturing = True
        logger.info(f"Starting packet capture on interface: {interface or 'auto'}")
        
        def capture_packets():
            try:
                sniff(
                    iface=interface,
                    prn=self._packet_callback,
                    filter=self.capture_filter,
                    store=False,
                    stop_filter=lambda x: not self.is_capturing,
                    timeout=300  # 5 minute timeout
                )
            except PermissionError:
                logger.error("Packet capture requires administrator privileges")
                self.is_capturing = False
            except Exception as e:
                logger.error(f"Error during packet capture: {e}")
                self.is_capturing = False
        
        self.capture_thread = threading.Thread(target=capture_packets, daemon=True)
        self.capture_thread.start()
    
    def stop_capture(self) -> None:
        """Stop capturing packets"""
        if not self.is_capturing:
            logger.warning("Packet capture is not running")
            return
        
        self.is_capturing = False
        logger.info("Stopping packet capture")
        
        # Save logs
        self._save_logs()
        self._save_statistics()
        
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
    
    def simulate_capture(self, duration: int = 30) -> None:
        """
        Simulate packet capture for testing (generates synthetic packets)
        
        Args:
            duration: How long to simulate (seconds)
        """
        logger.info(f"Simulating packet capture for {duration} seconds")
        
        common_ports = [80, 443, 22, 21, 25, 53, 3389, 3306, 5432, 27017]
        test_ips = [
            ("192.168.1.100", "8.8.8.8"),
            ("192.168.1.50", "1.1.1.1"),
            ("10.0.0.1", "192.168.1.1"),
        ]
        
        start_time = time.time()
        packet_num = 0
        
        while time.time() - start_time < duration:
            try:
                # Generate synthetic packets
                src, dst = test_ips[packet_num % len(test_ips)]
                port = common_ports[packet_num % len(common_ports)]
                protocol = ["TCP", "UDP", "DNS"][packet_num % 3]
                
                packet_info = PacketInfo(
                    timestamp=datetime.now().isoformat(),
                    source_ip=src,
                    dest_ip=dst,
                    protocol=protocol,
                    source_port=50000 + (packet_num % 1000),
                    dest_port=port,
                    size=100 + (packet_num % 1000),
                    payload_size=50 + (packet_num % 500),
                    flags="SYN" if packet_num % 10 == 0 else "PSH",
                    is_suspicious=packet_num % 50 == 0,
                    threat_level="MEDIUM" if packet_num % 50 == 0 else "LOW",
                    reason="Test suspicious packet" if packet_num % 50 == 0 else ""
                )
                
                self._process_packet(packet_info)
                packet_num += 1
                
                time.sleep(0.1)  # Simulate packet arrival
                
            except Exception as e:
                logger.error(f"Error in simulation: {e}")
                break
        
        logger.info(f"Simulation complete. Captured {packet_num} packets")
        self._save_logs()
        self._save_statistics()
    
    def get_captured_packets(self, limit: int = 100, filter_suspicious: bool = False) -> List[Dict]:
        """
        Get captured packets
        
        Args:
            limit: Maximum packets to return
            filter_suspicious: Only return suspicious packets
            
        Returns:
            List of packet dictionaries
        """
        packets = self.captured_packets[-limit:]
        
        if filter_suspicious:
            packets = [p for p in packets if p.is_suspicious]
        
        return [p.to_dict() for p in reversed(packets)]
    
    def get_suspicious_packets(self, threat_level: str = None) -> List[Dict]:
        """
        Get suspicious packets by threat level
        
        Args:
            threat_level: Filter by threat level (LOW, MEDIUM, HIGH, CRITICAL)
            
        Returns:
            List of suspicious packet dictionaries
        """
        suspicious = [p for p in self.captured_packets if p.is_suspicious]
        
        if threat_level:
            suspicious = [p for p in suspicious if p.threat_level == threat_level]
        
        return [p.to_dict() for p in reversed(suspicious[-100:])]
    
    def get_statistics(self) -> Dict:
        """Get traffic statistics"""
        return {
            'total_packets': self.statistics.total_packets,
            'total_bytes': self.statistics.total_bytes,
            'suspicious_packets': self.statistics.suspicious_packets,
            'blocked_packets': self.statistics.blocked_packets,
            'packets_by_protocol': dict(self.statistics.packets_by_protocol),
            'top_source_ips': dict(sorted(
                self.statistics.top_source_ips.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]),
            'top_dest_ips': dict(sorted(
                self.statistics.top_dest_ips.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]),
            'top_ports': dict(sorted(
                self.statistics.top_ports.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]),
        }
    
    def clear_logs(self) -> None:
        """Clear captured packets and statistics"""
        self.captured_packets = []
        self.statistics = TrafficStatistics()
        self._save_logs()
        self._save_statistics()
        logger.info("Packet logs cleared")
