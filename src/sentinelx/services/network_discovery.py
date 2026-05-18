"""
Network Discovery Service for SentinelX
Automatically discovers and identifies all SentinelX-enabled nodes on the local network
Supports ARP scanning, port detection, and node identification
"""

import threading
import socket
import subprocess
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import ipaddress

class NetworkDiscoveryManager:
    """Discovers and identifies SentinelX nodes on the network"""
    
    SENTINELX_SERVICE_PORT = 9547  # SentinelX remote access service port
    SENTINELX_BROADCAST_PORT = 9548  # SentinelX broadcast/discovery port
    
    def __init__(self, db_path: str = "logs/discovered_nodes.json"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.discovered_nodes = {}
        self.discovery_thread = None
        self.is_discovering = False
        self.load_discovered_nodes()
    
    def load_discovered_nodes(self):
        """Load previously discovered nodes from file"""
        if self.db_path.exists():
            try:
                with open(self.db_path, 'r') as f:
                    self.discovered_nodes = json.load(f)
            except:
                self.discovered_nodes = {}
        else:
            self.discovered_nodes = {}
    
    def save_discovered_nodes(self):
        """Save discovered nodes to file"""
        try:
            with open(self.db_path, 'w') as f:
                json.dump(self.discovered_nodes, f, indent=2)
        except Exception as e:
            print(f"[DISCOVERY] Error saving nodes: {e}")
    
    def get_local_network_info(self) -> Optional[Dict]:
        """Get local network information (IP range and subnet mask)"""
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            
            # Extract subnet from IP (assumes /24 network)
            parts = local_ip.split('.')
            network_base = f"{parts[0]}.{parts[1]}.{parts[2]}"
            
            return {
                "hostname": hostname,
                "local_ip": local_ip,
                "network_base": network_base,
                "subnet": f"{network_base}.0/24"
            }
        except Exception as e:
            print(f"[DISCOVERY] Error getting network info: {e}")
            return None
    
    def get_local_gateway(self) -> Optional[str]:
        """Get the local network gateway IP"""
        try:
            if socket.gethostname() or True:  # Windows
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                lines = result.stdout.split('\n')
                for i, line in enumerate(lines):
                    if 'Default Gateway' in line and ':' in line:
                        gateway = line.split(':')[1].strip()
                        if gateway and gateway != '':
                            return gateway
        except:
            pass
        return None
    
    def scan_arp_table(self) -> List[str]:
        """Scan ARP table for active IPs on the network"""
        active_ips = []
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            for line in lines:
                parts = line.split()
                if len(parts) > 0 and '.' in parts[0]:
                    ip = parts[0].strip()
                    if ip and ip != '?' and not ip.startswith('Interface'):
                        active_ips.append(ip)
        except Exception as e:
            print(f"[DISCOVERY] ARP scan error: {e}")
        return active_ips
    
    def scan_network_range(self) -> List[str]:
        """Scan the local network range for active hosts"""
        network_info = self.get_local_network_info()
        if not network_info:
            return []
        
        active_ips = []
        network_base = network_info["network_base"]
        
        # Check IPs 1-254 in the subnet
        for i in range(1, 30):  # Scan first 30 IPs for speed
            ip = f"{network_base}.{i}"
            try:
                # Quick socket timeout check
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.2)
                result = sock.connect_ex((ip, 445))  # SMB port as quick check
                sock.close()
                if result == 0:
                    active_ips.append(ip)
            except:
                pass
        
        return active_ips
    
    def check_sentinelx_service(self, ip: str) -> bool:
        """Check if a host has SentinelX service running"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, self.SENTINELX_SERVICE_PORT))
            sock.close()
            return result == 0
        except:
            return False
    
    def get_sentinelx_node_info(self, ip: str) -> Optional[Dict]:
        """Retrieve SentinelX node information"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, self.SENTINELX_SERVICE_PORT))
            
            # Send discovery request
            request = json.dumps({"action": "discover", "request_type": "node_info"})
            sock.send(request.encode() + b'\n')
            
            # Receive response
            response = sock.recv(4096).decode()
            sock.close()
            
            if response:
                return json.loads(response)
        except:
            pass
        
        # Fallback: return basic info
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = "Unknown"
        
        return {
            "ip": ip,
            "hostname": hostname,
            "status": "online",
            "sentinelx_version": "2.0+",
            "last_seen": datetime.now().isoformat()
        }
    
    def discover_nodes_async(self, callback=None):
        """Asynchronously discover SentinelX nodes in the network"""
        def _discover():
            self.is_discovering = True
            print("[DISCOVERY] Starting network scan for SentinelX nodes...")
            
            # Get active IPs from ARP table first (faster)
            active_ips = self.scan_arp_table()
            
            # If ARP yields results, use those; otherwise scan range
            if not active_ips:
                print("[DISCOVERY] Scanning network range...")
                active_ips = self.scan_network_range()
            
            print(f"[DISCOVERY] Found {len(active_ips)} active IPs, testing for SentinelX...")
            
            # Check each IP for SentinelX service
            found_nodes = []
            for ip in active_ips:
                if self.check_sentinelx_service(ip):
                    print(f"[DISCOVERY] Found SentinelX at {ip}")
                    node_info = self.get_sentinelx_node_info(ip)
                    if node_info:
                        self.discovered_nodes[ip] = node_info
                        found_nodes.append(node_info)
            
            self.save_discovered_nodes()
            self.is_discovering = False
            
            print(f"[DISCOVERY] Discovery complete: {len(found_nodes)} SentinelX nodes found")
            
            if callback:
                callback(found_nodes)
        
        self.discovery_thread = threading.Thread(target=_discover, daemon=True)
        self.discovery_thread.start()
    
    def discover_nodes(self) -> List[Dict]:
        """Synchronous network discovery (can be slow)"""
        print("[DISCOVERY] Starting synchronous network scan...")
        
        # Get active IPs
        active_ips = self.scan_arp_table()
        if not active_ips:
            active_ips = self.scan_network_range()
        
        # Check for SentinelX services
        found_nodes = []
        for ip in active_ips:
            if self.check_sentinelx_service(ip):
                node_info = self.get_sentinelx_node_info(ip)
                if node_info:
                    self.discovered_nodes[ip] = node_info
                    found_nodes.append(node_info)
        
        self.save_discovered_nodes()
        return found_nodes
    
    def get_discovered_nodes(self) -> List[Dict]:
        """Get list of all discovered SentinelX nodes"""
        return list(self.discovered_nodes.values())
    
    def is_node_online(self, ip: str) -> bool:
        """Check if a previously discovered node is still online"""
        return self.check_sentinelx_service(ip)
    
    def refresh_node_status(self, ip: str) -> Optional[Dict]:
        """Refresh status of a specific discovered node"""
        try:
            if self.is_node_online(ip):
                node_info = self.get_sentinelx_node_info(ip)
                self.discovered_nodes[ip] = node_info
                self.save_discovered_nodes()
                return node_info
            else:
                # Mark as offline
                if ip in self.discovered_nodes:
                    self.discovered_nodes[ip]["status"] = "offline"
                    self.save_discovered_nodes()
                return self.discovered_nodes.get(ip)
        except Exception as e:
            print(f"[DISCOVERY] Error refreshing node {ip}: {e}")
            return None
    
    def remove_node(self, ip: str):
        """Remove a node from discovered list"""
        if ip in self.discovered_nodes:
            del self.discovered_nodes[ip]
            self.save_discovered_nodes()
    
    def get_node_by_hostname(self, hostname: str) -> Optional[Dict]:
        """Find a discovered node by hostname"""
        for node in self.discovered_nodes.values():
            if node.get("hostname", "").lower() == hostname.lower():
                return node
        return None
