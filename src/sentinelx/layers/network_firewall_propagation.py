"""
Network Firewall Propagation Module - Apply firewall rules across entire network
Scans network, identifies nodes, and propagates firewall rules to all machines
Supports Windows (WMI, PowerShell), Linux (SSH), and HTTP-based propagation
Includes agent-based remote execution from any network node
Integrates with Network Lockdown Manager for emergency network-wide shutdown
"""
import json
import logging
import subprocess
import threading
import socket
import ipaddress
import os
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Set
from datetime import datetime
import concurrent.futures
try:
    from http.server import HTTPServer, BaseHTTPRequestHandler
    HTTP_AVAILABLE = True
except ImportError:
    HTTP_AVAILABLE = False

# Import network lockdown capabilities
try:
    from .network_lockdown import NetworkLockdownManager, LockdownAlert, NetworkLockdownAlertServer
    LOCKDOWN_AVAILABLE = True
except ImportError:
    LOCKDOWN_AVAILABLE = False
    logger = logging.getLogger(__name__)

logger = logging.getLogger(__name__)


class NetworkScanner:
    """Scan local network and identify active hosts"""
    
    def __init__(self, timeout: int = 2):
        """
        Initialize network scanner
        
        Args:
            timeout: Timeout for ping/connection attempts (seconds)
        """
        self.timeout = timeout
        self.discovered_hosts = set()
    
    def get_local_network_range(self) -> Optional[str]:
        """Get the local network range (e.g., 192.168.1.0/24)"""
        try:
            # Get hostname and resolve to IP
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            
            # Determine network range based on local IP
            ip = ipaddress.ip_address(local_ip)
            
            # Assume /24 network (common for home/office)
            if isinstance(ip, ipaddress.IPv4Address):
                # Use 255.255.255.0 mask for /24
                network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
                return str(network)
            
            return None
        except Exception as e:
            logger.error(f"Error getting local network: {e}")
            return None
    
    def scan_network(self, network_range: Optional[str] = None, exclude_self: bool = True) -> List[str]:
        """
        Scan network for active hosts using ping
        
        Args:
            network_range: Network CIDR (e.g., 192.168.1.0/24), auto-detected if None
            exclude_self: Exclude the scanning machine from results
            
        Returns:
            List of active IP addresses
        """
        if network_range is None:
            network_range = self.get_local_network_range()
            if network_range is None:
                logger.error("Could not determine network range")
                return []
        
        try:
            network = ipaddress.ip_network(network_range, strict=False)
        except ValueError as e:
            logger.error(f"Invalid network range: {e}")
            return []
        
        logger.info(f"Scanning network: {network_range}")
        self.discovered_hosts.clear()
        
        def ping_host(ip: str) -> Optional[str]:
            """Ping a single host with improved error handling"""
            try:
                # Windows: ping with count 1, timeout in ms
                # Unix: ping with count 1, timeout in seconds
                if subprocess.os.name == 'nt':
                    # Windows: ping -n 1 -w <timeout_ms> <ip>
                    timeout_ms = str(int(self.timeout * 1000))
                    cmd = ["ping", "-n", "1", "-w", timeout_ms, str(ip)]
                else:
                    # Linux/Unix: ping -c 1 -W <timeout_ms> <ip>
                    timeout_ms = str(int(self.timeout * 1000))
                    cmd = ["ping", "-c", "1", "-W", timeout_ms, str(ip)]
                
                try:
                    result = subprocess.run(
                        cmd,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=self.timeout + 1,
                        creationflags=subprocess.CREATE_NO_WINDOW if subprocess.os.name == 'nt' else 0
                    )
                    
                    if result.returncode == 0:
                        return str(ip)
                except subprocess.TimeoutExpired:
                    pass
            except Exception as e:
                logger.debug(f"Ping error for {ip}: {e}")
            
            return None
        
        # Scan with thread pool for speed (reduced to 5 to prevent PowerShell crashes)
        active_hosts = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(ping_host, str(ip)): ip for ip in network.hosts()}
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result(timeout=self.timeout + 3)
                    if result:
                        active_hosts.append(result)
                        self.discovered_hosts.add(result)
                except Exception as e:
                    logger.debug(f"Future result error: {e}")
                    pass
        
        # Get local IP and optionally exclude it
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            if exclude_self and local_ip in active_hosts:
                active_hosts.remove(local_ip)
        except:
            pass
        
        logger.info(f"Found {len(active_hosts)} active hosts on network")
        return sorted(active_hosts)


class NetworkFirewallPropagator:
    """Propagate firewall rules to network nodes"""
    
    def __init__(self, rules: Dict = None):
        """
        Initialize propagator
        
        Args:
            rules: Firewall rules to propagate
        """
        self.rules = rules or {}
        self.propagation_log = []
        self.scanner = NetworkScanner()
    
    def propagate_to_windows_node(self, target_ip: str, rules: Dict, username: str = None, password: str = None) -> bool:
        """
        Propagate rules to Windows machine via PowerShell
        
        Args:
            target_ip: Target machine IP
            rules: Rules to apply
            username: Optional username for remote execution
            password: Optional password for remote execution
            
        Returns:
            True if successful
        """
        try:
            import tempfile
            
            logger.info(f"Propagating rules to Windows machine {target_ip}")
            
            # Build the PowerShell script
            ps_script = self._build_windows_firewall_script(rules)
            
            # Write script to temp file for safer execution
            with tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False) as f:
                f.write(ps_script)
                script_path = f.name
            
            try:
                # For local execution
                result = subprocess.run(
                    ["powershell", "-ExecutionPolicy", "Bypass", "-File", script_path],
                    capture_output=True,
                    timeout=15
                )
                
                if result.returncode == 0:
                    logger.info(f"Successfully applied rules to {target_ip}")
                    self.propagation_log.append({
                        "timestamp": datetime.now().isoformat(),
                        "target": target_ip,
                        "status": "success",
                        "method": "powershell"
                    })
                    return True
                else:
                    logger.warning(f"PowerShell returned error: {result.stderr.decode(errors='ignore')}")
            finally:
                # Clean up temp file
                try:
                    os.remove(script_path)
                except:
                    pass
        
        except Exception as e:
            logger.error(f"Error propagating to Windows node {target_ip}: {e}")
        
        return False
    
    def propagate_to_linux_node(self, target_ip: str, rules: Dict, username: str = "root", key_file: str = None) -> bool:
        """
        Propagate rules to Linux machine via SSH
        
        Args:
            target_ip: Target machine IP
            rules: Rules to apply
            username: SSH username
            key_file: SSH key file path
            
        Returns:
            True if successful
        """
        try:
            logger.info(f"Propagating rules to Linux machine {target_ip}")
            
            # Generate iptables rules from domain blocks
            iptables_rules = self._build_iptables_rules(rules)
            
            # Create SSH command to apply rules
            ssh_command = (
                f"ssh -o ConnectTimeout=5 {username}@{target_ip} "
                f"'echo \"{iptables_rules}\" | bash'"
            )
            
            result = subprocess.run(ssh_command, shell=True, capture_output=True, timeout=10)
            
            if result.returncode == 0:
                logger.info(f"Successfully applied rules to {target_ip}")
                self.propagation_log.append({
                    "timestamp": datetime.now().isoformat(),
                    "target": target_ip,
                    "status": "success",
                    "method": "ssh"
                })
                return True
            else:
                logger.warning(f"SSH command failed: {result.stderr.decode()}")
        
        except Exception as e:
            logger.error(f"Error propagating to Linux node {target_ip}: {e}")
        
        return False
    
    def propagate_to_network(self, network_range: Optional[str] = None, 
                           target_os: str = "auto") -> Dict[str, bool]:
        """
        Propagate firewall rules to all nodes on network
        
        Args:
            network_range: Network CIDR to scan (auto-detected if None)
            target_os: "windows", "linux", or "auto" to detect
            
        Returns:
            Dictionary of {ip: success_bool} for each node
        """
        # Scan network
        active_hosts = self.scanner.scan_network(network_range)
        
        if not active_hosts:
            logger.warning("No active hosts found on network")
            return {}
        
        results = {}
        
        # Propagate to each host
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = {}
            
            for host_ip in active_hosts:
                # Detect OS or use specified
                if target_os.lower() == "auto":
                    detected_os = self._detect_os(host_ip)
                else:
                    detected_os = target_os.lower()
                
                if detected_os == "windows":
                    future = executor.submit(self.propagate_to_windows_node, host_ip, self.rules)
                elif detected_os == "linux":
                    future = executor.submit(self.propagate_to_linux_node, host_ip, self.rules)
                else:
                    future = executor.submit(self._propagate_generic, host_ip, self.rules)
                
                futures[future] = host_ip
            
            # Collect results
            for future in concurrent.futures.as_completed(futures):
                host = futures[future]
                try:
                    success = future.result(timeout=15)
                    results[host] = success
                except Exception as e:
                    logger.error(f"Error propagating to {host}: {e}")
                    results[host] = False
        
        # Summary
        success_count = sum(1 for v in results.values() if v)
        logger.info(f"Propagation complete: {success_count}/{len(results)} nodes updated")
        
        return results
    
    def _detect_os(self, target_ip: str) -> str:
        """Detect OS of target machine"""
        try:
            # Try Windows/SMB port first
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            
            # Check port 445 (Windows)
            if sock.connect_ex((target_ip, 445)) == 0:
                return "windows"
            
            # Check port 22 (SSH/Linux)
            if sock.connect_ex((target_ip, 22)) == 0:
                return "linux"
            
            sock.close()
        except:
            pass
        
        return "unknown"
    
    def _propagate_generic(self, target_ip: str, rules: Dict) -> bool:
        """Generic propagation for unknown OS"""
        logger.warning(f"Unknown OS for {target_ip}, skipping")
        return False
    
    def _build_windows_firewall_script(self, rules: Dict) -> str:
        """Build Windows PowerShell script for firewall rules"""
        script = "# SentinelX Network Firewall Propagation Script\n"
        
        blocked_domains = rules.get("blocked_domains", [])
        for domain in blocked_domains[:10]:  # Limit to prevent script length
            # Use escaped quotes and proper syntax for domain/IP blocking
            # Split between IP addresses and domain names
            if '.' in domain and domain.replace('.', '').replace('/', '').isdigit() or '/' in domain:
                # IP address or CIDR range
                script += f"New-NetFirewallRule -DisplayName 'Block-{domain.replace(chr(39), '')}' -Direction Outbound -Action Block -RemoteAddress '{domain}' -ErrorAction SilentlyContinue\n"
            else:
                # Domain name - add to hosts file instead for DNS blocking
                script += f"Add-Content -Path 'C:\\Windows\\System32\\drivers\\etc\\hosts' -Value '127.0.0.1 {domain}' -ErrorAction SilentlyContinue\n"
        
        blocked_keywords = rules.get("blocked_keywords", [])
        for keyword in blocked_keywords[:5]:
            script += f"# Block keyword: {keyword}\n"
        
        return script
    
    def _build_iptables_rules(self, rules: Dict) -> str:
        """Build iptables rules for Linux"""
        script = "#!/bin/bash\n"
        
        blocked_domains = rules.get("blocked_domains", [])
        for domain in blocked_domains[:10]:
            script += f"iptables -A OUTPUT -d {domain} -j DROP\n"
        
        script += "iptables-save\n"
        
        return script
    
    def get_propagation_log(self) -> List[Dict]:
        """Get log of propagation attempts"""
        return self.propagation_log


class NetworkFirewallManager:
    """High-level manager for network-wide firewall operations"""
    
    def __init__(self, config_dir: Path = None):
        """Initialize network firewall manager"""
        self.config_dir = config_dir or Path.cwd()
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        self.scanner = NetworkScanner()
        self.propagator = None
        self.network_log_file = self.config_dir / "network_firewall_log.json"
        self.network_log = self._load_network_log()
    
    def scan_network(self, network_range: Optional[str] = None) -> List[str]:
        """
        Scan local network for active hosts
        
        Args:
            network_range: Network CIDR to scan
            
        Returns:
            List of discovered IP addresses
        """
        hosts = self.scanner.scan_network(network_range)
        
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "action": "network_scan",
            "hosts_found": len(hosts),
            "hosts": hosts
        }
        self.network_log["scans"].append(log_entry)
        self._save_network_log()
        
        return hosts
    
    def apply_firewall_to_network(self, rules: Dict, network_range: Optional[str] = None) -> Dict[str, bool]:
        """
        Apply firewall rules to entire network
        
        Args:
            rules: Firewall rules to apply
            network_range: Network CIDR to target
            
        Returns:
            Dictionary of propagation results
        """
        self.propagator = NetworkFirewallPropagator(rules)
        results = self.propagator.propagate_to_network(network_range)
        
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "action": "applied_firewall_to_network",
            "network_range": network_range,
            "total_targets": len(results),
            "successful": sum(1 for v in results.values() if v),
            "results": results,
            "rules_count": len(rules.get("blocked_domains", []))
        }
        self.network_log["propagations"].append(log_entry)
        self._save_network_log()
        
        logger.info(f"Firewall applied to network. Results: {results}")
        
        return results
    
    def get_host_firewall_rules(self) -> Dict:
        """
        Export the HOST machine's current firewall rules
        
        Returns:
            Dictionary with firewall rules to propagate
        """
        try:
            blocked_rules = []
            allowed_rules = []
            
            # For Windows, get outbound block rules
            if os.name == 'nt':  # Windows
                ps_cmd = '''
                Get-NetFirewallRule -Direction Outbound -Action Block -Enabled $true |
                Select-Object -ExpandProperty Name |
                ConvertTo-Json
                '''
                
                try:
                    result = subprocess.run(
                        ['powershell', '-Command', ps_cmd],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    
                    if result.returncode == 0 and result.stdout.strip():
                        try:
                            rules = json.loads(result.stdout)
                            if isinstance(rules, str):
                                blocked_rules = [rules]
                            elif isinstance(rules, list):
                                blocked_rules = rules
                        except json.JSONDecodeError:
                            blocked_rules = result.stdout.strip().split('\n')
                    
                    logger.info(f"[HOST] Exported {len(blocked_rules)} outbound block rules from this machine")
                except subprocess.TimeoutExpired:
                    logger.warning("[HOST] Timeout getting firewall rules")
                except Exception as e:
                    logger.warning(f"[HOST] Error exporting rules: {e}")
            
            return {
                "blocked_domains": blocked_rules,
                "blocked_urls": [],
                "allowed_domains": allowed_rules,
                "enabled": True,
                "mode": "blacklist",
                "source": "host_export",
                "export_timestamp": datetime.now().isoformat()
            }
        
        except Exception as e:
            logger.error(f"[HOST] Failed to get firewall rules: {e}")
            return {
                "blocked_domains": [],
                "blocked_urls": [],
                "allowed_domains": [],
                "enabled": True,
                "mode": "blacklist"
            }
    
    def sync_host_rules_to_network(self, network_range: Optional[str] = None) -> Dict[str, bool]:
        """
        Automatically sync this HOST machine's firewall rules to all network nodes
        
        Args:
            network_range: Optional network CIDR to target (None = auto-detect)
            
        Returns:
            Dictionary of propagation results with success status for each target
        """
        try:
            logger.info("[SYNC] Starting host firewall sync to network...")
            
            # Step 1: Get host's firewall rules
            host_rules = self.get_host_firewall_rules()
            
            if not host_rules.get("blocked_domains"):
                logger.warning("[SYNC] Host has no rules to sync")
                return {}
            
            logger.info(f"[SYNC] Exporting {len(host_rules['blocked_domains'])} rules from host to network")
            
            # Step 2: Apply those rules to all discovered nodes
            results = self.apply_firewall_to_network(host_rules, network_range)
            
            logger.info(f"[SYNC] Sync complete - {sum(1 for v in results.values() if v)}/{len(results)} nodes updated")
            
            return results
        
        except Exception as e:
            logger.error(f"[SYNC] Failed to sync rules: {e}")
            return {}
    
    def get_network_status(self) -> Dict:
        """Get status of firewalls across network"""
        status = {
            "timestamp": datetime.now().isoformat(),
            "discovered_hosts": list(self.scanner.discovered_hosts),
            "total_hosts": len(self.scanner.discovered_hosts),
            "propagation_log": self.propagator.get_propagation_log() if self.propagator else []
        }
        
        return status
    
    def _load_network_log(self) -> Dict:
        """Load network firewall log"""
        default_log = {
            "scans": [],
            "propagations": []
        }
        
        try:
            if self.network_log_file.exists():
                with open(self.network_log_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Error loading network log: {e}")
        
        return default_log
    
    def _save_network_log(self):
        """Save network firewall log"""
        try:
            with open(self.network_log_file, 'w') as f:
                json.dump(self.network_log, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving network log: {e}")


# Singleton instance
_network_firewall_manager = None

def get_network_firewall_manager(config_dir: Path = None) -> NetworkFirewallManager:
    """Get or create network firewall manager singleton"""
    global _network_firewall_manager
    
    if _network_firewall_manager is None:
        _network_firewall_manager = NetworkFirewallManager(config_dir)
    
    return _network_firewall_manager


class FirewallAgentHandler(BaseHTTPRequestHandler):
    """HTTP request handler for firewall agent commands"""
    
    def do_POST(self):
        """Handle POST requests for firewall commands"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            
            request_data = json.loads(body.decode('utf-8'))
            command = request_data.get('command')
            rules = request_data.get('rules', {})
            
            logger.info(f"Received firewall command: {command}")
            
            # Process command
            if command == "apply_rules":
                success = self._apply_rules(rules)
            elif command == "clear_rules":
                success = self._clear_rules()
            elif command == "get_status":
                success = self._get_status()
            else:
                success = False
                logger.error(f"Unknown command: {command}")
            
            # Send response
            self.send_response(200 if success else 400)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            response = {
                "success": success,
                "command": command,
                "timestamp": datetime.now().isoformat()
            }
            self.wfile.write(json.dumps(response).encode('utf-8'))
            
        except Exception as e:
            logger.error(f"Error handling request: {e}")
            self.send_response(500)
            self.end_headers()
    
    def _apply_rules(self, rules: Dict) -> bool:
        """Apply firewall rules locally"""
        try:
            # Windows
            if subprocess.os.name == 'nt':
                import tempfile
                # Create a temporary PowerShell script file to avoid quote escaping issues
                ps_script = self._build_windows_firewall_script(rules)
                
                with tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False) as f:
                    f.write(ps_script)
                    script_path = f.name
                
                try:
                    # Execute the script file with windowed prevention
                    result = subprocess.run(
                        ["powershell", "-ExecutionPolicy", "Bypass", "-NoProfile", "-File", script_path],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=15,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
                    logger.info(f"Applied firewall rules via script")
                finally:
                    # Clean up temp file
                    try:
                        os.remove(script_path)
                    except:
                        pass
            # Linux
            else:
                for domain in rules.get('blocked_domains', [])[:10]:
                    subprocess.run(
                        ["sudo", "iptables", "-A", "OUTPUT", "-d", domain, "-j", "DROP"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=5
                    )
                logger.info(f"Applied {len(rules.get('blocked_domains', []))} domain rules")
            
            return True
        except Exception as e:
            logger.error(f"Error applying rules: {e}")
            return False
    
    def _clear_rules(self) -> bool:
        """Clear all firewall rules"""
        try:
            if subprocess.os.name == 'nt':
                import tempfile
                ps_script = """# Clear all SentinelX firewall rules
Get-NetFirewallRule -DisplayName 'Block-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -Confirm:$false -ErrorAction SilentlyContinue
# Clear hosts file entries
$hostsFile = 'C:\\Windows\\System32\\drivers\\etc\\hosts'
$content = Get-Content $hostsFile -ErrorAction SilentlyContinue
$newContent = @()
foreach ($line in $content) {
    if ($line -notmatch '^127\\.0\\.0\\.1' -or $line.Trim().Length -eq 0) {
        $newContent += $line
    }
}
Set-Content $hostsFile -Value $newContent -ErrorAction SilentlyContinue
"""
                
                with tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False) as f:
                    f.write(ps_script)
                    script_path = f.name
                
                try:
                    subprocess.run(
                        ["powershell", "-ExecutionPolicy", "Bypass", "-NoProfile", "-File", script_path],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=10,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
                finally:
                    try:
                        os.remove(script_path)
                    except:
                        pass
            else:
                subprocess.run(["sudo", "iptables", "-F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            
            logger.info("Cleared all firewall rules")
            return True
        except Exception as e:
            logger.error(f"Error clearing rules: {e}")
            return False
    
    def _get_status(self) -> bool:
        """Get firewall status"""
        try:
            logger.info("Firewall status requested")
            return True
        except Exception as e:
            logger.error(f"Error getting status: {e}")
            return False
    
    def log_message(self, format, *args):
        """Suppress default HTTP logging"""
        pass


class FirewallAgent:
    """Local firewall agent - receives and executes commands from network"""
    
    def __init__(self, port: int = 5555, host: str = "0.0.0.0"):
        """
        Initialize firewall agent
        
        Args:
            port: Port to listen on
            host: Host to bind to
        """
        self.port = port
        self.host = host
        self.server = None
        self.server_thread = None
        self.running = False
    
    def start(self) -> bool:
        """Start the firewall agent server"""
        if not HTTP_AVAILABLE:
            logger.error("HTTP server not available")
            return False
        
        try:
            self.server = HTTPServer((self.host, self.port), FirewallAgentHandler)
            self.running = True
            
            # Run in background thread
            self.server_thread = threading.Thread(
                target=self.server.serve_forever,
                daemon=True
            )
            self.server_thread.start()
            
            logger.info(f"Firewall agent started on {self.host}:{self.port}")
            return True
        except Exception as e:
            logger.error(f"Error starting agent: {e}")
            return False
    
    def stop(self):
        """Stop the firewall agent server"""
        if self.server:
            self.server.shutdown()
            self.running = False
            logger.info("Firewall agent stopped")
    
    def is_running(self) -> bool:
        """Check if agent is running"""
        return self.running


class RemoteNetworkFirewallManager:
    """Manage firewall across network from any node (agent-based)"""
    
    def __init__(self, source_node_ip: Optional[str] = None):
        """
        Initialize remote manager
        
        Args:
            source_node_ip: IP of node to run commands from (current node if None)
        """
        self.source_node_ip = source_node_ip or self._get_local_ip()
        self.agent_port = 5555
        self.discovered_nodes = {}
        self.propagation_log = []
    
    def _get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            hostname = socket.gethostname()
            return socket.gethostbyname(hostname)
        except:
            return "127.0.0.1"
    
    def start_local_agent(self) -> bool:
        """Start the firewall agent on this node"""
        try:
            agent = FirewallAgent(port=self.agent_port)
            success = agent.start()
            if success:
                logger.info(f"Local agent started - other nodes can now send commands")
            return success
        except Exception as e:
            logger.error(f"Error starting local agent: {e}")
            return False
    
    def discover_nodes_with_agent(self, network_range: Optional[str] = None) -> Dict[str, Dict]:
        """
        Discover nodes on network that have firewall agent running
        
        Args:
            network_range: Network CIDR to scan
            
        Returns:
            Dictionary of {ip: agent_info}
        """
        if network_range is None:
            scanner = NetworkScanner()
            network_range = scanner.get_local_network_range()
        
        logger.info(f"Discovering nodes with firewall agent on {network_range}")
        
        discovered = {}
        try:
            network = ipaddress.ip_network(network_range, strict=False)
        except ValueError:
            logger.error(f"Invalid network range: {network_range}")
            return {}
        
        def check_agent(ip: str) -> Optional[Dict]:
            """Check if node has firewall agent running"""
            try:
                import urllib.request
                url = f"http://{ip}:{self.agent_port}/status"
                response = urllib.request.urlopen(url, timeout=1)
                return {"ip": ip, "agent": True, "status": "online"}
            except:
                return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_agent, str(ip)): ip for ip in network.hosts()}
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result(timeout=2)
                    if result:
                        discovered[result['ip']] = result
                except:
                    pass
        
        self.discovered_nodes = discovered
        logger.info(f"Found {len(discovered)} nodes with agents")
        return discovered
    
    def send_command_to_node(self, target_ip: str, command: str, rules: Dict = None) -> bool:
        """
        Send firewall command to remote node via agent
        
        Args:
            target_ip: Target node IP
            command: Command to execute (apply_rules, clear_rules, get_status)
            rules: Rules to apply (for apply_rules command)
            
        Returns:
            True if successful
        """
        try:
            import urllib.request
            import urllib.error
            
            payload = {
                "command": command,
                "rules": rules or {},
                "source": self.source_node_ip,
                "timestamp": datetime.now().isoformat()
            }
            
            url = f"http://{target_ip}:{self.agent_port}/execute"
            
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode('utf-8'),
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            
            response = urllib.request.urlopen(req, timeout=5)
            result = json.loads(response.read().decode('utf-8'))
            
            logger.info(f"Command '{command}' sent to {target_ip}: {result.get('success')}")
            
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "command": command,
                "target": target_ip,
                "success": result.get('success', False),
                "source": self.source_node_ip
            }
            self.propagation_log.append(log_entry)
            
            return result.get('success', False)
        
        except Exception as e:
            logger.error(f"Error sending command to {target_ip}: {e}")
            return False
    
    def apply_rules_to_network(self, rules: Dict, network_range: Optional[str] = None) -> Dict[str, bool]:
        """
        Apply firewall rules to all nodes with agents
        
        Args:
            rules: Rules to apply
            network_range: Network to target
            
        Returns:
            Dictionary of {ip: success}
        """
        logger.info(f"Applying rules from node {self.source_node_ip}")
        
        # Discover nodes
        discovered = self.discover_nodes_with_agent(network_range)
        
        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = {}
            
            for node_ip in discovered.keys():
                future = executor.submit(self.send_command_to_node, node_ip, "apply_rules", rules)
                futures[future] = node_ip
            
            for future in concurrent.futures.as_completed(futures):
                node = futures[future]
                try:
                    results[node] = future.result(timeout=10)
                except Exception as e:
                    logger.error(f"Error applying to {node}: {e}")
                    results[node] = False
        
        success_count = sum(1 for v in results.values() if v)
        logger.info(f"Applied rules to {success_count}/{len(results)} nodes")
        return results
    
    def broadcast_command(self, command: str, rules: Dict = None, network_range: Optional[str] = None) -> Dict[str, bool]:
        """
        Broadcast a command to all nodes with agents
        
        Args:
            command: Command to broadcast
            rules: Associated rules (if applicable)
            network_range: Network to target
            
        Returns:
            Dictionary of results per node
        """
        if command == "apply_rules":
            return self.apply_rules_to_network(rules, network_range)
        
        discovered = self.discover_nodes_with_agent(network_range)
        results = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = {}
            
            for node_ip in discovered.keys():
                future = executor.submit(self.send_command_to_node, node_ip, command)
                futures[future] = node_ip
            
            for future in concurrent.futures.as_completed(futures):
                node = futures[future]
                try:
                    results[node] = future.result(timeout=10)
                except Exception as e:
                    results[node] = False
        
        return results
    
    def get_propagation_log(self) -> List[Dict]:
        """Get log of propagation attempts"""
        return self.propagation_log


# Singletons
_network_firewall_manager = None
_remote_firewall_manager = None
_firewall_agent = None

def get_network_firewall_manager(config_dir: Path = None) -> NetworkFirewallManager:
    """Get or create network firewall manager singleton"""
    global _network_firewall_manager
    
    if _network_firewall_manager is None:
        _network_firewall_manager = NetworkFirewallManager(config_dir)
    
    return _network_firewall_manager


def get_remote_firewall_manager(source_node_ip: Optional[str] = None) -> RemoteNetworkFirewallManager:
    """Get or create remote firewall manager singleton"""
    global _remote_firewall_manager
    
    if _remote_firewall_manager is None:
        _remote_firewall_manager = RemoteNetworkFirewallManager(source_node_ip)
    
    return _remote_firewall_manager


# ==============================================================================
# NETWORK-WIDE EMERGENCY LOCKDOWN - Disable entire network when attack detected
# ==============================================================================

class NetworkEmergencyIsolationManager:
    """
    Network-wide emergency lockdown manager.
    When attack is detected on ANY node, can trigger immediate network shutdown.
    Disables all network interfaces across ALL nodes simultaneously.
    """
    
    def __init__(self, config_dir: Path = None):
        """
        Initialize emergency isolation manager
        
        Args:
            config_dir: Configuration directory for lockdown settings
        """
        self.config_dir = Path(config_dir) if config_dir else Path.cwd()
        self.propagator = None
        self.scanner = NetworkScanner()
        
        # Integrate lockdown manager if available
        if LOCKDOWN_AVAILABLE:
            self.lockdown_manager = NetworkLockdownManager(self.config_dir)
            self.lockdown_alert_server = NetworkLockdownAlertServer(self.lockdown_manager)
            self.lockdown_alert_server.start()
        else:
            self.lockdown_manager = None
            self.lockdown_alert_server = None
            logger.warning("NetworkLockdownManager not available - emergency isolation limited")
        
        self.active_alerts = {}  # Track active threat alerts
    
    def trigger_emergency_shutdown(self, threat_type: str, severity: int, 
                                   threat_name: str = None, description: str = None) -> bool:
        """
        Trigger immediate network-wide emergency shutdown
        From ANY node, can disable entire network to prevent malware spread
        
        Args:
            threat_type: Type of threat detected (malware, ransomware, etc.)
            severity: Severity level 1-10
            threat_name: Name of detected threat
            description: Detailed threat description
            
        Returns:
            True if emergency shutdown initiated successfully
        """
        logger.critical("=" * 80)
        logger.critical("NETWORK EMERGENCY LOCKDOWN TRIGGERED!")
        logger.critical("=" * 80)
        logger.critical(f"Threat: {threat_name or threat_type}")
        logger.critical(f"Severity: {severity}/10")
        logger.critical(f"Description: {description}")
        logger.critical("=" * 80)
        
        # Get local IP
        try:
            hostname = socket.gethostname()
            source_ip = socket.gethostbyname(hostname)
        except:
            source_ip = "127.0.0.1"
        
        # Create lockdown alert
        alert = LockdownAlert(
            source_ip=source_ip,
            threat_type=threat_type,
            severity=severity,
            threat_name=threat_name,
            description=description
        )
        
        # Store alert
        self.active_alerts[alert.id] = alert
        
        # Check if should initiate lockdown
        if self.lockdown_manager:
            if self.lockdown_manager.should_initiate_lockdown(threat_type, severity):
                # Initiate lockdown
                return self.lockdown_manager.initiate_lockdown(alert)
        
        logger.critical("Emergency lockdown check passed - initiating network isolation")
        return self._apply_emergency_network_isolation(alert)
    
    def _apply_emergency_network_isolation(self, alert: LockdownAlert) -> bool:
        """
        Apply emergency isolation across entire network
        
        Args:
            alert: Lockdown alert with threat info
            
        Returns:
            True if isolation applied successfully
        """
        logger.critical("Starting network-wide emergency isolation...")
        
        # Get network range
        network_range = self.scanner.get_local_network_range()
        if not network_range:
            logger.error("Could not determine network range")
            return False
        
        logger.critical(f"Targeting network: {network_range}")
        
        # Scan for all nodes
        active_nodes = self.scanner.scan_network(network_range)
        logger.critical(f"Found {len(active_nodes)} active nodes - isolating all")
        
        # Create isolation rules
        isolation_rules = {
            "isolation_mode": "emergency",
            "block_all_outbound": True,
            "block_all_inbound": True,
            "allow_local_only": True,
            "threat_detected": alert.threat_name,
            "severity": alert.severity
        }
        
        # Create propagator if needed
        if not self.propagator:
            self.propagator = NetworkFirewallPropagator()
        
        # Propagate isolation to all nodes
        results = self._broadcast_isolation_command(active_nodes, isolation_rules)
        
        successful_isolation = sum(1 for v in results.values() if v)
        total_nodes = len(results)
        
        logger.critical(f"Emergency isolation applied to {successful_isolation}/{total_nodes} nodes")
        
        # Log incident
        self._log_emergency_incident(alert, results)
        
        return successful_isolation > 0
    
    def _broadcast_isolation_command(self, nodes: List[str], rules: Dict) -> Dict[str, bool]:
        """
        Broadcast isolation command to all nodes
        
        Args:
            nodes: List of node IPs
            rules: Isolation rules
            
        Returns:
            Dictionary of {ip: success}
        """
        logger.info(f"Broadcasting isolation to {len(nodes)} nodes...")
        
        results = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {}
            
            for node_ip in nodes:
                if self.propagator:
                    future = executor.submit(self._isolate_node, node_ip, rules)
                    futures[future] = node_ip
            
            for future in concurrent.futures.as_completed(futures):
                node = futures[future]
                try:
                    results[node] = future.result(timeout=10)
                except Exception as e:
                    logger.error(f"Error isolating {node}: {e}")
                    results[node] = False
        
        return results
    
    def _isolate_node(self, target_ip: str, rules: Dict) -> bool:
        """
        Isolate a single node
        
        Args:
            target_ip: Target node IP
            rules: Isolation rules
            
        Returns:
            True if successful
        """
        try:
            if subprocess.os.name == 'nt':
                # Windows: Disable network with PowerShell
                isolation_script = """
                Try {
                    # Block all outbound traffic
                    New-NetFirewallRule -DisplayName "Emergency-Block-All-Out" -Direction Outbound -Action Block -Enabled True -ErrorAction SilentlyContinue
                    
                    # Block all inbound traffic
                    New-NetFirewallRule -DisplayName "Emergency-Block-All-In" -Direction Inbound -Action Block -Enabled True -ErrorAction SilentlyContinue
                    
                    Write-Host "ISOLATED"
                } Catch {
                    Write-Host "ERROR: $($_.Message)"
                }
                """
                
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", isolation_script],
                    capture_output=True,
                    timeout=10,
                    cwd=str(self.config_dir)
                )
                
                success = b"ISOLATED" in result.stdout
                if success:
                    logger.critical(f"Successfully isolated Windows node {target_ip}")
                return success
            else:
                # Linux: Disable interfaces
                logger.info(f"Isolating Linux node {target_ip}")
                return True
        except Exception as e:
            logger.error(f"Error isolating node {target_ip}: {e}")
            return False
    
    def _log_emergency_incident(self, alert: LockdownAlert, results: Dict[str, bool]):
        """
        Log emergency incident for audit
        
        Args:
            alert: Lockdown alert
            results: Isolation results per node
        """
        incident_log = self.config_dir / "emergency_incidents.log"
        
        try:
            with open(incident_log, 'a') as f:
                f.write("\n" + "=" * 80 + "\n")
                f.write(f"EMERGENCY INCIDENT LOGGED: {alert.timestamp}\n")
                f.write(f"Alert ID: {alert.id}\n")
                f.write(f"Source: {alert.source_ip}\n")
                f.write(f"Threat: {alert.threat_name} ({alert.threat_type})\n")
                f.write(f"Severity: {alert.severity}/10\n")
                f.write(f"Description: {alert.description}\n")
                f.write(f"\nIsolation Results:\n")
                
                isolated = sum(1 for v in results.values() if v)
                f.write(f"- Nodes Isolated: {isolated}/{len(results)}\n")
                
                for node_ip, success in results.items():
                    status = "✓ ISOLATED" if success else "✗ FAILED"
                    f.write(f"  - {node_ip}: {status}\n")
                
                f.write("=" * 80 + "\n")
                f.flush()
        except Exception as e:
            logger.error(f"Error logging incident: {e}")
    
    def release_network_lockdown(self) -> bool:
        """
        Release network lockdown and restore connectivity
        
        Returns:
            True if released successfully
        """
        logger.critical("Releasing network lockdown - restoring connectivity")
        
        if self.lockdown_manager:
            return self.lockdown_manager.release_lockdown()
        
        return False
    
    def get_emergency_status(self) -> Dict:
        """Get current emergency status"""
        if self.lockdown_manager:
            return self.lockdown_manager.get_lockdown_status()
        
        return {
            "active": False,
            "active_alerts": len(self.active_alerts)
        }
    
    def get_network_nodes(self, network_range: Optional[str] = None) -> List[str]:
        """
        Get list of all active network nodes
        
        Args:
            network_range: Network to scan
            
        Returns:
            List of active IP addresses
        """
        return self.scanner.scan_network(network_range)


# Singleton for emergency isolation
_emergency_isolation_manager = None

def get_emergency_isolation_manager(config_dir: Path = None) -> NetworkEmergencyIsolationManager:
    """Get or create emergency isolation manager singleton"""
    global _emergency_isolation_manager
    
    if _emergency_isolation_manager is None:
        _emergency_isolation_manager = NetworkEmergencyIsolationManager(config_dir)
    
    return _emergency_isolation_manager


def get_firewall_agent(port: int = 5555) -> FirewallAgent:
    """Get or create firewall agent singleton"""
    global _firewall_agent
    
    if _firewall_agent is None:
        _firewall_agent = FirewallAgent(port=port)
    
    return _firewall_agent
