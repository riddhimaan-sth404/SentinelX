"""
Advanced Windows Firewall Enforcement - Uses System-Level Block Rules
Implements actual Windows Firewall blocking via netsh, not just hosts file
"""

import os
import sys
import socket
import threading
import logging
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Tuple, Set
from datetime import datetime

logger = logging.getLogger(__name__)


class AdvancedFirewallEnforcement:
    """
    System-level firewall enforcement using Windows Firewall (netsh)
    Blocks domains at network layer using outbound rules
    """
    
    def __init__(self):
        """Initialize advanced firewall enforcement"""
        self.blocked_domains = set()
        self.blocked_ips = set()
        self.firewall_rules = {}  # rule_name -> rule_data
        self.is_admin = self._check_admin()
        logger.info(f"AdvancedFirewallEnforcement initialized - Admin: {self.is_admin}")
    
    def _check_admin(self) -> bool:
        """Check if running with administrator privileges"""
        try:
            return os.getuid() == 0
        except AttributeError:
            # Windows
            try:
                import ctypes
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                return False
    
    def _run_system_command(self, cmd: List[str], show_output: bool = False) -> Tuple[bool, str]:
        """
        Run a system command and return success/output
        
        Args:
            cmd: Command list
            show_output: Whether to include output in logs
            
        Returns:
            (success, output_message)
        """
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                check=False,
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
            )
            
            output = result.stdout.decode('utf-8', errors='ignore') if result.stdout else ""
            error = result.stderr.decode('utf-8', errors='ignore') if result.stderr else ""
            
            if result.returncode == 0:
                return True, output
            else:
                msg = error if error else output
                return False, msg
        except subprocess.TimeoutExpired:
            return False, "Command timeout"
        except Exception as e:
            return False, str(e)
    
    def _flush_dns_cache(self) -> bool:
        """Flush DNS cache to clear cached entries"""
        try:
            # Multiple methods to ensure DNS flush
            methods = [
                ['ipconfig', '/flushDNS'],
                ['powershell', '-Command', 'Clear-DnsClientCache'],
            ]
            
            for cmd in methods:
                success, _ = self._run_system_command(cmd)
                if success:
                    logger.info("DNS cache flushed")
                    return True
            
            logger.warning("Could not flush DNS cache")
            return False
        except Exception as e:
            logger.error(f"DNS flush error: {e}")
            return False
    
    def _resolve_domain_to_ips(self, domain: str) -> Set[str]:
        """
        Resolve domain to all known IPs
        Includes common IPs for CDN services
        
        Args:
            domain: Domain to resolve
            
        Returns:
            Set of IP addresses
        """
        ips = set()
        
        # Clean domain
        domain = domain.replace('http://', '').replace('https://', '').split('/')[0].strip()
        
        # Try DNS resolution
        try:
            # Get primary IP
            primary_ip = socket.gethostbyname(domain)
            if primary_ip:
                ips.add(primary_ip)
                logger.debug(f"Resolved {domain} -> {primary_ip}")
            
            # Try to get all addresses (getaddrinfo)
            try:
                for info in socket.getaddrinfo(domain, None):
                    ip = info[4][0]
                    if ip and not ip.startswith('::'):  # Skip IPv6 for now
                        ips.add(ip)
            except Exception:
                pass
                
        except socket.gaierror:
            logger.warning(f"Could not resolve {domain}")
        except Exception as e:
            logger.error(f"Resolution error for {domain}: {e}")
        
        return ips
    
    def create_firewall_block_rule(self, domain: str) -> bool:
        """
        Create Windows Firewall block rule for a domain
        Blocks all outbound traffic to the domain/IP
        
        Args:
            domain: Domain to block
            
        Returns:
            True if rule created successfully
        """
        if not self.is_admin:
            logger.error("Firewall rule creation requires administrator privileges")
            return False
        
        try:
            # Clean domain
            domain_clean = domain.replace('http://', '').replace('https://', '').split('/')[0].strip()
            
            # Resolve to IPs
            ips = self._resolve_domain_to_ips(domain_clean)
            
            if not ips:
                logger.warning(f"Could not resolve {domain_clean} to any IP address")
                return False
            
            success_count = 0
            
            # Create rules for each IP
            for ip in ips:
                rule_name = f"SentinelX_Block_{ip.replace('.', '_')}"
                
                # Try with TCP and UDP separately (netsh doesn't support comma-separated protocols)
                for protocol in ['tcp', 'udp']:
                    cmd = [
                        'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                        f'name={rule_name}_{protocol}',
                        'dir=out',
                        'action=block',
                        f'remoteip={ip}',
                        f'protocol={protocol}',
                        'enable=yes'
                    ]
                    
                    success, output = self._run_system_command(cmd)
                    
                    if success or 'already exists' in output.lower():
                        logger.info(f"Firewall rule created: {rule_name}_{protocol}")
                        self.firewall_rules[f"{rule_name}_{protocol}"] = {'domain': domain_clean, 'ip': ip, 'protocol': protocol}
                        success_count += 1
                    else:
                        logger.warning(f"Failed to create {protocol} rule for {ip}")
            
            if success_count > 0:
                logger.info(f"✓ Created {success_count} firewall rules for {domain_clean}")
                return True
            else:
                return False
                
        except Exception as e:
            logger.error(f"Error creating firewall rule: {e}")
            return False
    
    def block_domain_dnsapi(self, domain: str) -> bool:
        """
        Block domain using DNS filter via registry
        Requires admin to modify DNS settings
        
        Args:
            domain: Domain to block
            
        Returns:
            True if successful
        """
        if not self.is_admin:
            logger.debug("DNS API blocking requires admin")
            return False
        
        try:
            # Clean domain
            domain = domain.replace('http://', '').replace('https://', '').split('/')[0].strip()
            
            # Add to hosts file as well
            hosts_file = r"C:\Windows\System32\drivers\etc\hosts"
            
            try:
                # Read current hosts
                with open(hosts_file, 'r') as f:
                    content = f.read()
                
                # Check if already added
                if domain in content:
                    logger.debug(f"Domain already in hosts file: {domain}")
                    return True
                
                # Add new entry
                entry = f"127.0.0.1\t{domain}\t# SentinelX Blocked\n"
                
                with open(hosts_file, 'a') as f:
                    f.write(entry)
                
                logger.info(f"Added to hosts file: {domain}")
                self._flush_dns_cache()
                return True
                
            except PermissionError:
                logger.error("Permission denied modifying hosts file")
                return False
                
        except Exception as e:
            logger.error(f"DNS API blocking error: {e}")
            return False
    
    def block_domain_comprehensive(self, domain: str) -> Dict[str, bool]:
        """
        Block domain using ALL available methods
        Uses: Firewall rules + hosts file + DNS cache flush
        
        Args:
            domain: Domain to block
            
        Returns:
            Dict showing which methods succeeded
        """
        results = {
            'firewall_rules': False,
            'hosts_file': False,
            'dns_flushed': False,
            'total_rules': 0
        }
        
        # Method 1: Windows Firewall rules (most reliable)
        try:
            if self.create_firewall_block_rule(domain):
                results['firewall_rules'] = True
                results['total_rules'] = len(self._resolve_domain_to_ips(domain))
        except Exception as e:
            logger.error(f"Firewall rules failed: {e}")
        
        # Method 2: Hosts file entry
        try:
            if self.block_domain_dnsapi(domain):
                results['hosts_file'] = True
        except Exception as e:
            logger.error(f"Hosts file blocking failed: {e}")
        
        # Method 3: Flush DNS cache
        try:
            if self._flush_dns_cache():
                results['dns_flushed'] = True
        except Exception as e:
            logger.error(f"DNS flush failed: {e}")
        
        self.blocked_domains.add(domain)
        
        logger.info(f"Comprehensive blocking applied: {results}")
        return results
    
    def unblock_domain(self, domain: str) -> bool:
        """
        Remove all rules for a domain
        
        Args:
            domain: Domain to unblock
            
        Returns:
            True if successful
        """
        try:
            success_count = 0
            
            # Find and remove all associated rules (both TCP and UDP)
            rules_to_delete = [name for name, data in self.firewall_rules.items() 
                             if data.get('domain') == domain]
            
            for rule_name in rules_to_delete:
                cmd = [
                    'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                    f'name={rule_name}'
                ]
                
                success, _ = self._run_system_command(cmd)
                if success:
                    del self.firewall_rules[rule_name]
                    success_count += 1
                    logger.info(f"Removed firewall rule: {rule_name}")
            
            # Remove from hosts file
            try:
                hosts_file = r"C:\Windows\System32\drivers\etc\hosts"
                if os.path.exists(hosts_file):
                    with open(hosts_file, 'r') as f:
                        lines = f.readlines()
                    
                    # Filter out lines with this domain
                    filtered = [l for l in lines if domain not in l]
                    
                    if len(filtered) < len(lines):
                        with open(hosts_file, 'w') as f:
                            f.writelines(filtered)
                        logger.info(f"Removed from hosts file: {domain}")
                        self._flush_dns_cache()
            except Exception as e:
                logger.warning(f"Could not remove from hosts file: {e}")
            
            if domain in self.blocked_domains:
                self.blocked_domains.discard(domain)
                logger.info(f"✓ Unblocked domain: {domain}")
                return True
            
            return success_count > 0
            
        except Exception as e:
            logger.error(f"Error unblocking domain: {e}")
            return False
    
    def get_blocked_domains(self) -> List[str]:
        """Get list of currently blocked domains"""
        return list(self.blocked_domains)
    
    def get_firewall_rules(self) -> Dict:
        """Get all active firewall rules"""
        return self.firewall_rules.copy()
    
    def verify_blocking(self, domain: str) -> Tuple[bool, str]:
        """
        Verify if domain is actually blocked
        
        Args:
            domain: Domain to check
            
        Returns:
            (is_blocked, reason)
        """
        try:
            # Check firewall rules
            if domain in self.blocked_domains:
                # Try to connect
                try:
                    socket.create_connection((domain, 80), timeout=2)
                    return False, "Connection succeeded (not blocked)"
                except (socket.timeout, socket.error, OSError):
                    return True, "Connection failed (blocked at network layer)"
            else:
                return False, "Domain not in block list"
                
        except Exception as e:
            return False, f"Verification error: {str(e)}"


def get_advanced_firewall_enforcement() -> AdvancedFirewallEnforcement:
    """Get or create advanced firewall enforcement instance"""
    return AdvancedFirewallEnforcement()
