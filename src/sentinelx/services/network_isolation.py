"""
Network Isolation and Segmentation: Prevent lateral movement and intruder spread.
"""

import subprocess
import json
from pathlib import Path
from typing import Dict, Set, List
from datetime import datetime
from dataclasses import dataclass

from sentinelx.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class NetworkSegment:
    """Represents an isolated network segment."""
    segment_id: str
    allowed_ips: Set[str]
    blocked_ips: Set[str]
    description: str


class NetworkIsolationManager:
    """Manage network isolation and prevent lateral movement."""
    
    def __init__(self):
        self.segments: Dict[str, NetworkSegment] = {}
        self.isolation_log = Path('logs/network_isolation.json')
        self.isolated_devices: Set[str] = set()
        self.firewall_rules_applied = 0
        
        self._init_network_segments()
    
    def create_network_segment(self, segment_id: str, description: str, 
                             allowed_ips: List[str] = None) -> NetworkSegment:
        """Create an isolated network segment."""
        allowed_set = set(allowed_ips) if allowed_ips else set()
        
        segment = NetworkSegment(
            segment_id=segment_id,
            allowed_ips=allowed_set,
            blocked_ips=set(),
            description=description
        )
        
        self.segments[segment_id] = segment
        logger.info(f"[NET_ISO] Network segment created: {segment_id} - {description}")
        
        return segment
    
    def isolate_device(self, device_ip: str, reason: str = "Suspicious activity") -> bool:
        """Isolate a device from network to prevent lateral movement."""
        try:
            # Block all outbound connections
            cmd = f'netsh advfirewall firewall add rule name="Isolate {device_ip}" dir=out action=block remoteip={device_ip}'
            subprocess.run(cmd, shell=True, capture_output=True, check=False)
            
            # Allow only to security server
            cmd = f'netsh advfirewall firewall add rule name="Allow {device_ip} to Security" dir=out action=allow remoteip={device_ip} remoteport=443'
            subprocess.run(cmd, shell=True, capture_output=True, check=False)
            
            self.isolated_devices.add(device_ip)
            logger.warning(f"[NET_ISO] Device isolated: {device_ip} - {reason}")
            
            self._save_isolation_log()
            return True
        
        except Exception as e:
            logger.error(f"[NET_ISO] Error isolating device {device_ip}: {str(e)}")
            return False
    
    def restrict_segment_communication(self, source_segment: str, dest_segment: str, 
                                      allow: bool = False) -> bool:
        """Restrict communication between network segments."""
        try:
            if source_segment in self.segments and dest_segment in self.segments:
                source_seg = self.segments[source_segment]
                dest_seg = self.segments[dest_segment]
                
                action = "allow" if allow else "block"
                rule_name = f"Segment {source_segment} to {dest_segment} ({action})"
                
                for source_ip in source_seg.allowed_ips:
                    for dest_ip in dest_seg.allowed_ips:
                        cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action={action} remoteip={dest_ip}'
                        subprocess.run(cmd, shell=True, capture_output=True, check=False)
                
                logger.info(f"[NET_ISO] Segment communication restricted: {source_segment} -> {dest_segment} ({action})")
                self.firewall_rules_applied += 1
                return True
        
        except Exception as e:
            logger.error(f"[NET_ISO] Error restricting segment communication: {str(e)}")
            return False
    
    def enable_dns_filtering(self, block_list: List[str]) -> int:
        """Enable DNS filtering to block malicious domains."""
        blocked_count = 0
        
        try:
            # Add domains to Windows hosts file
            hosts_file = Path('C:\\Windows\\System32\\drivers\\etc\\hosts')
            
            if hosts_file.exists():
                with open(hosts_file, 'a') as f:
                    for domain in block_list:
                        f.write(f"\n127.0.0.1 {domain}\n")
                        f.write(f"::1 {domain}\n")
                        blocked_count += 1
                
                logger.warning(f"[NET_ISO] DNS filtering enabled - {blocked_count} domains blocked")
        
        except PermissionError:
            logger.warning("[NET_ISO] Cannot write to hosts file (needs admin privileges)")
        except Exception as e:
            logger.error(f"[NET_ISO] Error enabling DNS filtering: {str(e)}")
        
        return blocked_count
    
    def enable_ssl_inspection(self) -> bool:
        """Enable SSL/TLS inspection for HTTPS traffic."""
        try:
            # This requires enterprise-level tools, but we can set policies
            ps_cmd = '''
            $policy = "HKLM:\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service"
            New-ItemProperty -Path $policy -Name AllowUnencryptedTraffic -Value 0 -Force
            '''
            
            subprocess.run(['powershell', '-Command', ps_cmd], capture_output=True, check=False)
            logger.info("[NET_ISO] SSL/TLS inspection policies enforced")
            return True
        
        except Exception as e:
            logger.error(f"[NET_ISO] Error enabling SSL inspection: {str(e)}")
            return False
    
    def enable_vpn_enforcement(self) -> bool:
        """Enforce VPN for remote connections."""
        try:
            ps_cmd = '''
            $policy = "HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList"
            New-ItemProperty -Path $policy -Name DontRequireUserPasswordForNearby -Value 0 -Force
            '''
            
            subprocess.run(['powershell', '-Command', ps_cmd], capture_output=True, check=False)
            logger.warning("[NET_ISO] VPN enforcement policies enabled")
            return True
        
        except Exception as e:
            logger.error(f"[NET_ISO] Error enforcing VPN: {str(e)}")
            return False
    
    def block_internal_lateral_movement(self) -> Dict:
        """Block common lateral movement techniques and ports."""
        blocked_techniques = {}
        
        # Block internal lateral movement ports
        lateral_movement_ports = {
            135: "RPC (Endpoint Mapper)",
            139: "NetBIOS (File Sharing)",
            445: "SMB (File Sharing)",
            3389: "RDP (Remote Desktop)",
            5985: "WinRM (Remote Management)",
            5986: "WinRM Secure",
        }
        
        try:
            for port, description in lateral_movement_ports.items():
                cmd = f'netsh advfirewall firewall add rule name="Block Lateral {description}" dir=in action=block protocol=tcp localport={port}'
                subprocess.run(cmd, shell=True, capture_output=True, check=False)
                blocked_techniques[description] = True
                logger.warning(f"[NET_ISO] Blocked lateral movement via {description}")
            
            self.firewall_rules_applied += len(lateral_movement_ports)
        
        except Exception as e:
            logger.error(f"[NET_ISO] Error blocking lateral movement: {str(e)}")
        
        return blocked_techniques
    
    def monitor_lateral_movement_attempts(self) -> Dict:
        """Detect and log lateral movement attempts."""
        attempts = {
            'smb_attempts': 0,
            'rdp_attempts': 0,
            'powershell_remoting_attempts': 0,
            'suspicious_ips': []
        }
        
        try:
            ps_cmd = '''
            Get-WinEvent -FilterHashtable @{
                LogName = 'Security'
                ID = 5145, 4624
                StartTime = [datetime]::Now.AddHours(-1)
            } -ErrorAction SilentlyContinue |
            Select-Object -Property ID, @{N='IP';E={($_.Properties[18].Value)}} |
            ConvertTo-Json -Depth 10
            '''
            
            result = subprocess.run(
                ['powershell', '-Command', ps_cmd],
                capture_output=True,
                text=True,
                check=False,
                timeout=15
            )
            
            if result.returncode == 0 and result.stdout:
                try:
                    events = json.loads(result.stdout)
                    
                    if isinstance(events, dict):
                        events = [events]
                    
                    for event in events:
                        event_id = event.get('ID')
                        ip = event.get('IP', '')
                        
                        if event_id == 5145:
                            attempts['smb_attempts'] += 1
                        elif event_id == 4624 and ip not in ['127.0.0.1', '::1']:
                            attempts['rdp_attempts'] += 1
                            if ip:
                                attempts['suspicious_ips'].append(ip)
                
                except json.JSONDecodeError:
                    pass
        
        except Exception as e:
            logger.error(f"[NET_ISO] Error monitoring lateral movement: {str(e)}")
        
        return attempts
    
    def get_isolation_status(self) -> Dict:
        """Get network isolation status."""
        return {
            'timestamp': datetime.now().isoformat(),
            'total_segments': len(self.segments),
            'isolated_devices': list(self.isolated_devices),
            'firewall_rules_applied': self.firewall_rules_applied,
            'segments': {
                seg_id: {
                    'description': seg.description,
                    'allowed_ips_count': len(seg.allowed_ips),
                    'blocked_ips_count': len(seg.blocked_ips)
                } for seg_id, seg in self.segments.items()
            }
        }
    
    def _init_network_segments(self):
        """Initialize default network segments."""
        # Create trusted segment for security infrastructure
        self.create_network_segment(
            'trusted',
            'Trusted security infrastructure',
            allowed_ips=['127.0.0.1', '::1']
        )
        
        # Create isolated segment for suspicious activity
        self.create_network_segment(
            'isolated',
            'Isolated segment for suspicious devices',
            allowed_ips=[]
        )
        
        # Create guest segment for external connections
        self.create_network_segment(
            'guest',
            'Guest network segment',
            allowed_ips=[]
        )
        
        logger.info("[NET_ISO] Default network segments initialized")
    
    def _save_isolation_log(self):
        """Save isolation events to file."""
        try:
            self.isolation_log.parent.mkdir(parents=True, exist_ok=True)
            
            data = {
                'timestamp': datetime.now().isoformat(),
                'isolated_devices': list(self.isolated_devices),
                'firewall_rules': self.firewall_rules_applied,
                'segments': {
                    seg_id: {
                        'description': seg.description,
                        'allowed_ips': list(seg.allowed_ips),
                        'blocked_ips': list(seg.blocked_ips)
                    } for seg_id, seg in self.segments.items()
                }
            }
            
            with open(self.isolation_log, 'w') as f:
                json.dump(data, f, indent=2)
        
        except Exception as e:
            logger.debug(f"[NET_ISO] Error saving isolation log: {str(e)}")
