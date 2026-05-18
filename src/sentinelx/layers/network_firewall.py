"""
Network Firewall Module - Manage network access with URL/domain blocking and filtering
Provides configurable URL whitelist and blacklist with DNS interception capabilities
Includes network packet capture and analysis
"""
import json
import logging
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from urllib.parse import urlparse
from datetime import datetime

logger = logging.getLogger(__name__)

# Import packet capture module
try:
    from sentinelx.layers.packet_capture import PacketCapture
    PACKET_CAPTURE_AVAILABLE = True
except ImportError:
    PACKET_CAPTURE_AVAILABLE = False
    PacketCapture = None
    logger.debug("Packet capture module not available")


class NetworkFirewall:
    """Configurable firewall for URL/domain blocking and filtering with packet capture"""
    
    def __init__(self, config_dir: Path = None):
        """
        Initialize firewall with configuration directory
        
        Args:
            config_dir: Directory to store firewall rules (default: current directory)
        """
        if config_dir is None:
            config_dir = Path.cwd()
        
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        self.rules_file = self.config_dir / "firewall_rules.json"
        self.blocks_file = self.config_dir / "firewall_blocks.json"
        
        self.rules = self._load_rules()
        self.blocks = self._load_blocks()
        
        # Initialize packet capture
        self.packet_capture = None
        if PACKET_CAPTURE_AVAILABLE:
            try:
                self.packet_capture = PacketCapture(self.config_dir)
                logger.info("Packet capture engine initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize packet capture: {e}")
        
        logger.info("Network Firewall initialized")
    
    def _load_rules(self) -> Dict:
        """Load firewall rules from JSON file"""
        default_rules = {
            "enabled": True,
            "mode": "whitelist",  # "whitelist", "blacklist", or "hybrid"
            "blocked_domains": [],
            "blocked_urls": [],
            "allowed_domains": [],
            "allowed_urls": [],
            "blocked_keywords": [],
            "allowed_keywords": [],
            "rules_count": 0,
            "last_updated": datetime.now().isoformat()
        }
        
        try:
            if self.rules_file.exists():
                with open(self.rules_file, 'r') as f:
                    loaded = json.load(f)
                    # Merge with defaults to handle new keys
                    default_rules.update(loaded)
                    logger.info(f"Loaded {len(loaded.get('blocked_domains', []))} firewall rules")
                    return default_rules
        except Exception as e:
            logger.error(f"Error loading firewall rules: {e}")
        
        return default_rules
    
    def _load_blocks(self) -> Dict:
        """Load blocked requests log"""
        default_blocks = {
            "blocked_requests": [],
            "total_blocked": 0
        }
        
        try:
            if self.blocks_file.exists():
                with open(self.blocks_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Error loading block log: {e}")
        
        return default_blocks
    
    def _save_rules(self):
        """Save firewall rules to JSON file"""
        try:
            self.rules['rules_count'] = (
                len(self.rules.get('blocked_domains', [])) +
                len(self.rules.get('blocked_urls', [])) +
                len(self.rules.get('allowed_domains', [])) +
                len(self.rules.get('allowed_urls', []))
            )
            self.rules['last_updated'] = datetime.now().isoformat()
            
            with open(self.rules_file, 'w') as f:
                json.dump(self.rules, f, indent=2)
            logger.info("Firewall rules saved")
        except Exception as e:
            logger.error(f"Error saving firewall rules: {e}")
    
    def _save_blocks(self):
        """Save blocked requests log"""
        try:
            with open(self.blocks_file, 'w') as f:
                json.dump(self.blocks, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving block log: {e}")
    
    def set_firewall_mode(self, mode: str) -> bool:
        """
        Set firewall mode
        
        Args:
            mode: "whitelist" (allow only listed), "blacklist" (block only listed), or "hybrid"
            
        Returns:
            True if successful
        """
        if mode not in ["whitelist", "blacklist", "hybrid"]:
            logger.warning(f"Invalid firewall mode: {mode}")
            return False
        
        self.rules['mode'] = mode
        self._save_rules()
        logger.info(f"Firewall mode changed to: {mode}")
        return True
    
    def set_firewall_enabled(self, enabled: bool) -> bool:
        """Enable or disable firewall"""
        self.rules['enabled'] = enabled
        self._save_rules()
        logger.info(f"Firewall {'enabled' if enabled else 'disabled'}")
        return True
    
    def _parse_url_to_domain(self, url: str) -> str:
        """
        Extract domain from URL string.
        Handles full URLs like https://example.com/path and IP addresses.
        
        Args:
            url: Full URL, domain, or IP address
            
        Returns:
            Extracted domain or original input if already a domain
        """
        if not url:
            return None
        
        url = url.lower().strip()
        
        # If it looks like a domain/IP already (no scheme), return as-is
        if '://' not in url:
            # Clean up common formats
            url = url.removeprefix('http://').removeprefix('https://')
            url = url.removeprefix('ftp://').removeprefix('ftps://')
            # Remove path if present
            if '/' in url:
                url = url.split('/')[0]
            # Remove port if present
            if ':' in url and not url.startswith('['):  # Don't remove : from IPv6
                url = url.split(':')[0]
            return url
        
        # Parse full URL
        try:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path
            
            # Remove port
            if ':' in domain and not domain.startswith('['):
                domain = domain.split(':')[0]
            
            # Remove common prefixes
            domain = domain.lstrip('www.')
            domain = domain.removeprefix('mail.')
            domain = domain.removeprefix('files.')
            
            return domain if domain else None
        except Exception as e:
            logger.debug(f"Error parsing URL {url}: {e}")
            return url
    
    def add_url_to_blocklist(self, url_or_domain: str) -> bool:
        """
        Add a URL or domain to the blocklist.
        Automatically extracts domain from full URLs.
        Accepts: https://example.com, example.com, 192.168.1.1, etc.
        
        Args:
            url_or_domain: Full URL, domain, or IP address
            
        Returns:
            True if successfully added
        """
        domain = self._parse_url_to_domain(url_or_domain)
        if not domain:
            logger.warning(f"Could not extract domain from: {url_or_domain}")
            return False
        
        return self.add_blocked_domain(domain)
    
    def add_url_to_whitelist(self, url_or_domain: str) -> bool:
        """
        Add a URL or domain to the whitelist.
        Automatically extracts domain from full URLs.
        Accepts: https://example.com, example.com, 192.168.1.1, etc.
        
        Args:
            url_or_domain: Full URL, domain, or IP address
            
        Returns:
            True if successfully added
        """
        domain = self._parse_url_to_domain(url_or_domain)
        if not domain:
            logger.warning(f"Could not extract domain from: {url_or_domain}")
            return False
        
        return self.add_allowed_domain(domain)
    
    def add_blocked_domain(self, domain: str) -> bool:
        """Add domain to blacklist"""
        domain = domain.lower().strip()
        if not domain:
            return False
        
        if domain not in self.rules['blocked_domains']:
            self.rules['blocked_domains'].append(domain)
            self._save_rules()
            logger.info(f"Added blocked domain: {domain}")
            return True
        
        return False
    
    def add_blocked_url(self, url: str) -> bool:
        """Add complete URL to blacklist"""
        url = url.lower().strip()
        if not url:
            return False
        
        if url not in self.rules['blocked_urls']:
            self.rules['blocked_urls'].append(url)
            self._save_rules()
            logger.info(f"Added blocked URL: {url}")
            return True
        
        return False
    
    def add_allowed_domain(self, domain: str) -> bool:
        """Add domain to whitelist"""
        domain = domain.lower().strip()
        if not domain:
            return False
        
        if domain not in self.rules['allowed_domains']:
            self.rules['allowed_domains'].append(domain)
            self._save_rules()
            logger.info(f"Added allowed domain: {domain}")
            return True
        
        return False
    
    def add_allowed_url(self, url: str) -> bool:
        """Add complete URL to whitelist"""
        url = url.lower().strip()
        if not url:
            return False
        
        if url not in self.rules['allowed_urls']:
            self.rules['allowed_urls'].append(url)
            self._save_rules()
            logger.info(f"Added allowed URL: {url}")
            return True
        
        return False
    
    def add_blocked_keyword(self, keyword: str) -> bool:
        """Add keyword to blocked keywords list"""
        keyword = keyword.lower().strip()
        if not keyword:
            return False
        
        if keyword not in self.rules['blocked_keywords']:
            self.rules['blocked_keywords'].append(keyword)
            self._save_rules()
            logger.info(f"Added blocked keyword: {keyword}")
            return True
        
        return False
    
    def remove_blocked_domain(self, domain: str) -> bool:
        """Remove domain from blacklist"""
        domain = domain.lower().strip()
        if domain in self.rules['blocked_domains']:
            self.rules['blocked_domains'].remove(domain)
            self._save_rules()
            logger.info(f"Removed blocked domain: {domain}")
            return True
        return False
    
    def remove_blocked_url(self, url: str) -> bool:
        """Remove URL from blacklist"""
        url = url.lower().strip()
        if url in self.rules['blocked_urls']:
            self.rules['blocked_urls'].remove(url)
            self._save_rules()
            logger.info(f"Removed blocked URL: {url}")
            return True
        return False
    
    def remove_allowed_domain(self, domain: str) -> bool:
        """Remove domain from whitelist"""
        domain = domain.lower().strip()
        if domain in self.rules['allowed_domains']:
            self.rules['allowed_domains'].remove(domain)
            self._save_rules()
            logger.info(f"Removed allowed domain: {domain}")
            return True
        return False
    
    def remove_allowed_url(self, url: str) -> bool:
        """Remove URL from whitelist"""
        url = url.lower().strip()
        if url in self.rules['allowed_urls']:
            self.rules['allowed_urls'].remove(url)
            self._save_rules()
            logger.info(f"Removed allowed URL: {url}")
            return True
        return False
    
    def remove_blocked_keyword(self, keyword: str) -> bool:
        """Remove keyword from blocked list"""
        keyword = keyword.lower().strip()
        if keyword in self.rules['blocked_keywords']:
            self.rules['blocked_keywords'].remove(keyword)
            self._save_rules()
            logger.info(f"Removed blocked keyword: {keyword}")
            return True
        return False
    
    def should_block_url(self, url: str) -> Tuple[bool, str]:
        """
        Check if URL should be blocked based on firewall rules
        
        Args:
            url: URL to check
            
        Returns:
            Tuple of (should_block: bool, reason: str)
        """
        if not self.rules['enabled']:
            return False, "Firewall disabled"
        
        url_lower = url.lower()
        
        # Parse URL to get domain
        try:
            parsed = urlparse(url if url.startswith('http') else f'http://{url}')
            domain = parsed.netloc.lower()
        except:
            domain = url_lower
        
        mode = self.rules['mode']
        
        # Check explicit whitelist first
        if domain in self.rules['allowed_domains'] or url_lower in self.rules['allowed_urls']:
            return False, "Whitelisted"
        
        # Check for blocked keywords
        for keyword in self.rules['blocked_keywords']:
            if keyword in url_lower:
                return True, f"Contains blocked keyword: {keyword}"
        
        if mode == "whitelist":
            # In whitelist mode, block unless explicitly allowed
            if domain in self.rules['allowed_domains'] or url_lower in self.rules['allowed_urls']:
                return False, "Whitelisted"
            return True, "Not in whitelist"
        
        elif mode == "blacklist":
            # In blacklist mode, allow unless explicitly blocked
            if domain in self.rules['blocked_domains'] or url_lower in self.rules['blocked_urls']:
                return True, f"Blacklisted"
            return False, "Not blacklisted"
        
        elif mode == "hybrid":
            # In hybrid mode, block if in blacklist OR not in whitelist (if whitelist exists)
            if domain in self.rules['blocked_domains'] or url_lower in self.rules['blocked_urls']:
                return True, "Blacklisted"
            
            if self.rules['allowed_domains'] or self.rules['allowed_urls']:
                if domain not in self.rules['allowed_domains'] and url_lower not in self.rules['allowed_urls']:
                    return True, "Not in whitelist"
            
            return False, "Allowed in hybrid mode"
        
        return False, "No rules matched"
    
    def log_blocked_request(self, url: str, reason: str, timestamp: str = None):
        """Log a blocked request"""
        if timestamp is None:
            timestamp = datetime.now().isoformat()
        
        block_entry = {
            "url": url,
            "reason": reason,
            "timestamp": timestamp
        }
        
        self.blocks['blocked_requests'].append(block_entry)
        self.blocks['total_blocked'] = len(self.blocks['blocked_requests'])
        
        # Keep only last 1000 blocked requests
        if len(self.blocks['blocked_requests']) > 1000:
            self.blocks['blocked_requests'] = self.blocks['blocked_requests'][-1000:]
        
        self._save_blocks()
        logger.info(f"Blocked URL: {url} - Reason: {reason}")
    
    def get_firewall_stats(self) -> Dict:
        """Get firewall statistics"""
        return {
            "enabled": self.rules['enabled'],
            "mode": self.rules['mode'],
            "blocked_domains_count": len(self.rules['blocked_domains']),
            "blocked_urls_count": len(self.rules['blocked_urls']),
            "allowed_domains_count": len(self.rules['allowed_domains']),
            "allowed_urls_count": len(self.rules['allowed_urls']),
            "blocked_keywords_count": len(self.rules['blocked_keywords']),
            "total_rules": self.rules['rules_count'],
            "total_blocked_requests": self.blocks['total_blocked'],
            "last_updated": self.rules['last_updated']
        }
    
    def get_all_rules(self) -> Dict:
        """Get all firewall rules"""
        return self.rules.copy()
    
    def clear_block_log(self) -> bool:
        """Clear the block log"""
        self.blocks = {
            "blocked_requests": [],
            "total_blocked": 0
        }
        self._save_blocks()
        logger.info("Block log cleared")
        return True
    
    def import_rules(self, rules_dict: Dict) -> bool:
        """Import rules from dictionary"""
        try:
            if 'blocked_domains' in rules_dict:
                self.rules['blocked_domains'] = rules_dict['blocked_domains']
            if 'blocked_urls' in rules_dict:
                self.rules['blocked_urls'] = rules_dict['blocked_urls']
            if 'allowed_domains' in rules_dict:
                self.rules['allowed_domains'] = rules_dict['allowed_domains']
            if 'allowed_urls' in rules_dict:
                self.rules['allowed_urls'] = rules_dict['allowed_urls']
            if 'blocked_keywords' in rules_dict:
                self.rules['blocked_keywords'] = rules_dict['blocked_keywords']
            if 'mode' in rules_dict:
                self.rules['mode'] = rules_dict['mode']
            
            self._save_rules()
            logger.info("Rules imported successfully")
            return True
        except Exception as e:
            logger.error(f"Error importing rules: {e}")
            return False
    
    def export_rules(self) -> Dict:
        """Export all firewall rules"""
        return {
            "mode": self.rules['mode'],
            "blocked_domains": self.rules['blocked_domains'],
            "blocked_urls": self.rules['blocked_urls'],
            "allowed_domains": self.rules['allowed_domains'],
            "allowed_urls": self.rules['allowed_urls'],
            "blocked_keywords": self.rules['blocked_keywords'],
            "exported_at": datetime.now().isoformat()
        }
    
    def add_urls_batch(self, urls: List[str], block: bool = True) -> Dict:
        """
        Add multiple URLs/domains at once (batch operation).
        
        Args:
            urls: List of URLs, domains, or IP addresses
            block: True to add to blocklist, False for whitelist
            
        Returns:
            Dict with results {"success": count, "failed": count, "errors": [errors]}
        """
        results = {
            "success": 0,
            "failed": 0,
            "errors": []
        }
        
        for url in urls:
            try:
                if block:
                    if self.add_url_to_blocklist(url):
                        results["success"] += 1
                    else:
                        results["failed"] += 1
                        results["errors"].append(f"Failed to add {url} to blocklist")
                else:
                    if self.add_url_to_whitelist(url):
                        results["success"] += 1
                    else:
                        results["failed"] += 1
                        results["errors"].append(f"Failed to add {url} to whitelist")
            except Exception as e:
                results["failed"] += 1
                results["errors"].append(f"Error processing {url}: {e}")
        
        logger.info(f"Batch operation: Added {results['success']} URLs, {results['failed']} failed")
        return results
    
    def is_valid_url_or_domain(self, url_string: str) -> bool:
        """
        Check if a string is a valid URL or domain format.
        
        Args:
            url_string: String to validate
            
        Returns:
            True if it looks like a valid URL/domain, False otherwise
        """
        if not url_string or not isinstance(url_string, str):
            return False
        
        url_string = url_string.strip().lower()
        
        # Empty after strip
        if not url_string:
            return False
        
        # Check for invalid characters
        invalid_chars = '<>{}|\\^`'
        if any(char in url_string for char in invalid_chars):
            return False
        
        # Check for minimum domain structure
        # Could be: domain.com, 192.168.1.1, https://example.com, etc
        if '.' in url_string or ':' in url_string or '://' in url_string:
            return True
        
        return False
    
    def get_blocked_requests_summary(self, limit: int = 50) -> List[Dict]:
        """
        Get summary of recent blocked requests.
        
        Args:
            limit: Maximum number of recent blocks to return
            
        Returns:
            List of blocked request entries (newest first)
        """
        requests = self.blocks.get('blocked_requests', [])[-limit:]
        return list(reversed(requests))  # Return newest first
    
    def get_rules_by_type(self, rule_type: str) -> List[str]:
        """
        Get rules of a specific type.
        
        Args:
            rule_type: One of 'blocked_domains', 'blocked_urls', 'allowed_domains',
                      'allowed_urls', 'blocked_keywords'
            
        Returns:
            List of rules of the specified type
        """
        if rule_type in self.rules:
            return self.rules[rule_type].copy()
        return []
    
    # ===== Packet Capture Methods =====
    
    def start_packet_capture(self, interface: Optional[str] = None, simulate: bool = False) -> bool:
        """
        Start capturing network packets
        
        Args:
            interface: Network interface to capture on (optional)
            simulate: If True, simulate packet capture for testing
            
        Returns:
            True if capture started successfully
        """
        if not self.packet_capture:
            logger.warning("Packet capture not available")
            return False
        
        try:
            if simulate:
                logger.info("Starting packet capture simulation...")
                # Run simulation in background thread
                import threading
                thread = threading.Thread(target=self.packet_capture.simulate_capture, kwargs={'duration': 60})
                thread.daemon = True
                thread.start()
            else:
                logger.info("Starting live packet capture...")
                self.packet_capture.start_capture(interface)
            return True
        except Exception as e:
            logger.error(f"Failed to start packet capture: {e}")
            return False
    
    def stop_packet_capture(self) -> None:
        """Stop capturing network packets"""
        if self.packet_capture:
            self.packet_capture.stop_capture()
    
    def is_packet_capture_running(self) -> bool:
        """Check if packet capture is currently running"""
        if self.packet_capture:
            return self.packet_capture.is_capturing
        return False
    
    def get_captured_packets(self, limit: int = 100, suspicious_only: bool = False) -> List[Dict]:
        """
        Get captured packets
        
        Args:
            limit: Maximum packets to return
            suspicious_only: Filter to only suspicious packets
            
        Returns:
            List of captured packet information
        """
        if not self.packet_capture:
            return []
        
        if suspicious_only:
            return self.packet_capture.get_suspicious_packets()
        return self.packet_capture.get_captured_packets(limit)
    
    def get_packet_statistics(self) -> Dict:
        """Get network traffic statistics from packet capture"""
        if not self.packet_capture:
            return {}
        
        return self.packet_capture.get_statistics()
    
    def clear_packet_logs(self) -> None:
        """Clear captured packet logs"""
        if self.packet_capture:
            self.packet_capture.clear_logs()


def get_network_firewall(config_dir: Path = None) -> NetworkFirewall:
    """Factory function to get firewall instance"""
    return NetworkFirewall(config_dir)
