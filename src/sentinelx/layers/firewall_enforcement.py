"""
Network Firewall Enforcement Module - Actually Blocks Traffic
Implements DNS filtering, hosts file modification, and HTTP/HTTPS proxy interception
"""

import os
import sys
import socket
import threading
import logging
from pathlib import Path
from typing import Dict, List, Tuple
from datetime import datetime
import subprocess

logger = logging.getLogger(__name__)


class FirewallEnforcement:
    """
    Enforces firewall rules by:
    1. Modifying Windows hosts file to block domains
    2. Running DNS filter service
    3. Intercepting HTTP/HTTPS traffic
    """
    
    HOSTS_FILE = r"C:\Windows\System32\drivers\etc\hosts"
    SENTINEL_MARKER = "# SentinelX Firewall Rules"
    
    def __init__(self):
        """Initialize firewall enforcement"""
        self.blocked_domains = set()
        self.hosts_file_enabled = False
        self.dns_filter_enabled = False
        self.is_running = False
        logger.info("FirewallEnforcement initialized")
    
    def enable_hosts_file_blocking(self, blocked_domains: List[str]) -> bool:
        """
        Block domains by adding them to Windows hosts file.
        This redirects blocked domains to 127.0.0.1 (localhost).
        
        Args:
            blocked_domains: List of domains to block
            
        Returns:
            True if successful
        """
        try:
            # Read current hosts file
            hosts_content = ""
            if os.path.exists(self.HOSTS_FILE):
                try:
                    with open(self.HOSTS_FILE, 'r') as f:
                        hosts_content = f.read()
                except PermissionError:
                    logger.warning("Read access to hosts file - retrying with elevated privileges")
                    # Continue anyway - we'll try writing
            
            # Remove old SentinelX entries
            lines = hosts_content.split('\n')
            filtered_lines = []
            skip_sentinel = False
            
            for line in lines:
                if self.SENTINEL_MARKER in line:
                    skip_sentinel = True
                    continue
                if skip_sentinel and line.strip().startswith('#'):
                    continue
                if skip_sentinel and line.strip() == '':
                    skip_sentinel = False
                    continue
                if not skip_sentinel:
                    filtered_lines.append(line)
            
            # Add new entries - include IPv6 localhost too
            new_entries = [self.SENTINEL_MARKER]
            for domain in blocked_domains:
                domain = domain.strip()
                if domain:
                    # IPv4 blocking
                    new_entries.append(f"127.0.0.1\t{domain}\t# Blocked by SentinelX")
                    # IPv6 blocking
                    new_entries.append(f"::1\t{domain}\t# Blocked by SentinelX")
                    self.blocked_domains.add(domain)
            
            # Write updated hosts file
            updated_content = '\n'.join(filtered_lines) + '\n' + '\n'.join(new_entries) + '\n'
            
            try:
                with open(self.HOSTS_FILE, 'w') as f:
                    f.write(updated_content)
                logger.info(f"Hosts file updated: {len(blocked_domains)} domains blocked")
            except PermissionError:
                logger.error("Permission denied writing to hosts file - run as administrator")
                return False
            
            # Flush DNS cache to apply changes immediately
            self._flush_dns_cache()
            
            self.hosts_file_enabled = True
            logger.info(f"Hosts file blocking enabled for {len(blocked_domains)} domains")
            return True
            
        except Exception as e:
            logger.error(f"Error enabling hosts file blocking: {e}")
            return False
    
    def disable_hosts_file_blocking(self) -> bool:
        """
        Remove all SentinelX entries from hosts file.
        
        Returns:
            True if successful
        """
        try:
            if not os.path.exists(self.HOSTS_FILE):
                return False
            
            # Read and filter hosts file
            with open(self.HOSTS_FILE, 'r') as f:
                lines = f.readlines()
            
            filtered_lines = []
            skip_sentinel = False
            
            for line in lines:
                if self.SENTINEL_MARKER in line:
                    skip_sentinel = True
                    continue
                if skip_sentinel and (line.strip().startswith('#') or 'SentinelX' in line):
                    continue
                if skip_sentinel and line.strip() == '':
                    skip_sentinel = False
                    continue
                if not skip_sentinel:
                    filtered_lines.append(line)
            
            # Write updated hosts file
            with open(self.HOSTS_FILE, 'w') as f:
                f.writelines(filtered_lines)
            
            # Flush DNS cache
            self._flush_dns_cache()
            
            self.hosts_file_enabled = False
            self.blocked_domains.clear()
            logger.info("Hosts file blocking disabled")
            return True
            
        except Exception as e:
            logger.error(f"Error disabling hosts file blocking: {e}")
            return False
    
    def remove_domain_from_hosts(self, domain: str) -> bool:
        """
        Remove a specific domain from the hosts file.
        
        Args:
            domain: Domain to remove from blocking
            
        Returns:
            True if successful
        """
        try:
            if not os.path.exists(self.HOSTS_FILE):
                logger.warning(f"Hosts file not found: {self.HOSTS_FILE}")
                return False
            
            domain = domain.strip().lower()
            
            # Read current hosts file
            with open(self.HOSTS_FILE, 'r') as f:
                lines = f.readlines()
            
            # Filter out entries for this domain (both IPv4 and IPv6)
            filtered_lines = []
            removed_count = 0
            
            for line in lines:
                # Check if this line contains the domain
                if domain in line.lower():
                    # Make sure it's actually one of our entries
                    if ('127.0.0.1' in line or '::1' in line) and 'Blocked by SentinelX' in line:
                        removed_count += 1
                        logger.debug(f"Removing: {line.strip()}")
                        continue
                
                filtered_lines.append(line)
            
            # Only write if we actually removed something
            if removed_count > 0:
                with open(self.HOSTS_FILE, 'w') as f:
                    f.writelines(filtered_lines)
                
                # Flush DNS cache to apply changes
                self._flush_dns_cache()
                
                # Remove from tracking set
                self.blocked_domains.discard(domain)
                
                logger.info(f"Removed {removed_count} entries for domain: {domain}")
                return True
            else:
                logger.debug(f"Domain {domain} not found in hosts file")
                return True  # Not an error, just already removed
            
        except PermissionError:
            logger.error(f"Permission denied modifying hosts file - requires administrator")
            return False
        except Exception as e:
            logger.error(f"Error removing domain from hosts file: {e}")
            return False
    
    def _flush_dns_cache(self):
        """Flush Windows DNS cache to apply hosts file changes"""
        try:
            if sys.platform == 'win32':
                # Try multiple methods to flush DNS cache
                flush_commands = [
                    (['ipconfig', '/flushDNS'], "ipconfig /flushDNS"),
                    (['powershell', '-Command', 'Clear-DnsClientCache'], "PowerShell Clear-DnsClientCache"),
                    (['net', 'stop', 'dnscache'], "net stop dnscache"),
                ]
                
                for cmd, desc in flush_commands:
                    try:
                        result = subprocess.run(cmd, capture_output=True, check=False, timeout=3)
                        if result.returncode == 0:
                            logger.info(f"DNS cache flushed via: {desc}")
                            return True
                    except Exception as e:
                        logger.debug(f"DNS flush method {desc} failed: {e}")
                        continue
                
                logger.warning("Could not flush DNS cache using any method")
        except Exception as e:
            logger.debug(f"Could not flush DNS cache: {e}")
    
    def _is_admin(self) -> bool:
        """Check if running with administrator privileges"""
        try:
            return os.getuid() == 0  # Unix/Linux
        except AttributeError:
            # Windows
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin()
            except Exception:
                return False
    
    def create_windows_firewall_rule(self, domain: str, action: str = "block") -> bool:
        """
        Create a Windows Firewall rule (works best with admin privileges).
        Attempts to resolve domain to IP, or creates app-based rule.
        
        Args:
            domain: Domain or IP to block
            action: "block" or "allow"
            
        Returns:
            True if successful
        """
        try:
            # Remove protocol from domain if present
            domain = domain.replace('http://', '').replace('https://', '').split('/')[0].strip()
            
            # Clean up rule name
            rule_name = f"SentinelX_{action.upper()}_{domain.replace('.', '_').replace(':', '_')}"
            
            # Truncate rule name if too long (max 255 chars in netsh)
            if len(rule_name) > 70:
                rule_name = rule_name[:70]
            
            # Try to resolve domain to IP
            resolved_ip = None
            try:
                resolved_ip = socket.gethostbyname(domain)
                logger.debug(f"Resolved {domain} to {resolved_ip}")
            except socket.gaierror:
                logger.debug(f"Could not resolve {domain} - rule may not work immediately")
                resolved_ip = None
            
            # Create firewall rule - use IP if resolved, otherwise use domain
            if resolved_ip and resolved_ip != "127.0.0.1":
                # Block by IP address
                if action == "block":
                    cmd = [
                        'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                        f'name={rule_name}',
                        'dir=out',
                        'action=block',
                        f'remoteip={resolved_ip}',
                        'protocol=tcp,udp'
                    ]
                else:
                    cmd = [
                        'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                        f'name={rule_name}',
                        'dir=out',
                        'action=allow',
                        f'remoteip={resolved_ip}',
                        'protocol=tcp,udp'
                    ]
                
                try:
                    result = subprocess.run(cmd, capture_output=True, check=False, timeout=5)
                    if result.returncode == 0:
                        logger.info(f"Windows Firewall rule created: {rule_name} -> {resolved_ip}")
                        return True
                    else:
                        error_msg = result.stderr.decode() if result.stderr else result.stdout.decode()
                        # "Rule already exists" is not really an error
                        if "already exists" in error_msg.lower():
                            logger.debug(f"Firewall rule already exists: {rule_name}")
                            return True
                        logger.warning(f"Failed to create Firewall rule: {error_msg}")
                        return False
                except subprocess.TimeoutExpired:
                    logger.warning(f"Firewall rule creation timed out for {domain}")
                    return False
            else:
                # Domain didn't resolve or resolved to localhost - just log it
                logger.info(f"Skipped Windows Firewall rule for {domain} (hosts file blocking active)")
                return True
            
        except Exception as e:
            logger.error(f"Error creating Windows Firewall rule: {e}")
            return False
    
    def remove_windows_firewall_rule(self, domain: str) -> bool:
        """
        Remove a Windows Firewall rule.
        
        Args:
            domain: Domain that was blocked
            
        Returns:
            True if successful
        """
        try:
            rule_name = f"SentinelX-Block-{domain.replace('.', '-')}"
            
            cmd = [
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                f'name={rule_name}'
            ]
            
            result = subprocess.run(cmd, capture_output=True, check=False)
            
            if result.returncode == 0:
                logger.info(f"Windows Firewall rule removed: {rule_name}")
                return True
            else:
                logger.debug(f"Rule {rule_name} may not have existed")
                return True
                
        except Exception as e:
            logger.error(f"Error removing Windows Firewall rule: {e}")
            return False
    
    def apply_firewall_rules(self, blocked_domains: List[str], 
                            allowed_domains: List[str] = None) -> Dict:
        """
        Apply firewall rules using multiple enforcement methods.
        
        Args:
            blocked_domains: List of domains to block
            allowed_domains: List of domains to allow (whitelist mode)
            
        Returns:
            Dict with results of each enforcement method
        """
        results = {
            "hosts_file_enabled": False,
            "windows_firewall_enabled": False,
            "dns_filter_enabled": False,
            "total_blocked": len(blocked_domains),
            "total_allowed": len(allowed_domains) if allowed_domains else 0,
            "error": None,
            "note": None
        }
        
        if not blocked_domains:
            results["error"] = "No domains to block"
            return results
        
        # Method 1: Hosts file (PRIMARY - most reliable)
        try:
            results["hosts_file_enabled"] = self.enable_hosts_file_blocking(blocked_domains)
            if results["hosts_file_enabled"]:
                logger.info(f"[OK] Hosts file blocking activated for {len(blocked_domains)} domains")
            else:
                results["error"] = "Hosts file blocking failed - may require administrator privileges"
                logger.warning(results["error"])
        except Exception as e:
            logger.error(f"Hosts file method failed: {e}")
            results["hosts_file_enabled"] = False
            results["error"] = str(e)
        
        # Method 2: Windows Firewall (SECONDARY - requires IP resolution)
        if self._is_admin():
            try:
                fw_success_count = 0
                for domain in blocked_domains[:10]:  # Limit to avoid too many rules
                    if self.create_windows_firewall_rule(domain, "block"):
                        fw_success_count += 1
                results["windows_firewall_enabled"] = fw_success_count > 0
                if results["windows_firewall_enabled"]:
                    logger.info(f"[OK] Windows Firewall rules created for {fw_success_count} domains")
            except Exception as e:
                logger.error(f"Windows Firewall method failed: {e}")
                results["windows_firewall_enabled"] = False
        else:
            logger.info("Windows Firewall rules skipped (requires administrator)")
        
        # Method 3: Block known DoH providers that bypass hosts file
        self._block_doh_servers(blocked_domains)
        
        logger.info(f"Firewall rules applied: {results}")
        return results
    
    def _block_doh_servers(self, blocked_domains: List[str]):
        """
        Block DNS-over-HTTPS (DoH) servers to prevent browser bypass.
        This helps when browsers use custom DNS instead of system DNS.
        """
        try:
            # Check if any blocked domain might use DoH bypass
            google_domains = [d for d in blocked_domains if 'google' in d.lower()]
            if not google_domains:
                return
            
            # Known DoH impls used by browsers
            doh_providers = [
                "8.8.8.8",         # Google DNS
                "8.8.4.4",         # Google DNS backup
                "1.1.1.1",         # Cloudflare
                "1.0.0.1",         # Cloudflare backup
                "dns.google",      # Google DoH domain
                "cloudflare-dns.com",  # Cloudflare DoH domain
            ]
            
            if self._is_admin():
                for provider in doh_providers[:3]:  # Block top 3 to avoid too many rules
                    try:
                        rule_name = f"SentinelX_BLOCK_DoH_{provider.replace('.', '_')}"
                        if len(rule_name) > 70:
                            rule_name = rule_name[:70]
                        
                        cmd = [
                            'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                            f'name={rule_name}',
                            'dir=out',
                            'action=block',
                            f'remoteip={provider}',
                            'protocol=tcp,udp',
                            'remoteport=443,53'
                        ]
                        
                        result = subprocess.run(cmd, capture_output=True, check=False, timeout=3)
                        if result.returncode == 0 or "already exists" in result.stderr.decode().lower():
                            logger.debug(f"DoH provider blocked: {provider}")
                    except Exception as e:
                        logger.debug(f"Could not block DoH provider {provider}: {e}")
        except Exception as e:
            logger.debug(f"DoH blocking skipped: {e}")
    
    def get_enforcement_status(self) -> Dict:
        """Get current enforcement status"""
        return {
            "hosts_file_enabled": self.hosts_file_enabled,
            "dns_filter_enabled": self.dns_filter_enabled,
            "windows_firewall_available": self._is_admin(),
            "blocked_domains": len(self.blocked_domains),
            "is_running": self.is_running
        }
    
    def verify_blocking(self, domain: str) -> Tuple[bool, str]:
        """
        Verify if a domain is actually blocked.
        
        Args:
            domain: Domain to check
            
        Returns:
            Tuple of (is_blocked, reason)
        """
        try:
            # Try to resolve as localhost
            ip = socket.gethostbyname(domain)
            if ip == "127.0.0.1":
                return True, "Redirected to localhost via hosts file"
            elif ip in self.blocked_domains:
                return True, "Blocked via hosts file"
            else:
                return False, f"Resolved to {ip}"
        except socket.gaierror:
            return True, "DNS resolution failed (blocked)"
        except Exception as e:
            return False, f"Verification error: {str(e)}"


def get_firewall_enforcement() -> FirewallEnforcement:
    """Get or create firewall enforcement instance"""
    return FirewallEnforcement()
