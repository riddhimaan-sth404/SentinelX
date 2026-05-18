"""
Threat Intelligence Aggregator: Collect and analyze threats from multiple sources.
"""

import json
from pathlib import Path
from typing import Set, Dict, List
from collections import defaultdict
from datetime import datetime

from sentinelx.utils.logger import get_logger

logger = get_logger(__name__)


class ThreatIntelligenceAggregator:
    """Aggregate and analyze threat intelligence."""
    
    def __init__(self):
        self.threats_db = Path('logs/threat_intelligence.json')
        self.iocs = {
            'files': set(),           # File hashes/paths
            'ips': set(),             # IP addresses
            'domains': set(),         # Domain names
            'urls': set(),            # Full URLs
            'process_hashes': set(),  # Process signatures
            'registry_keys': set(),   # Registry paths
        }
        self.threat_actors = defaultdict(list)
        self.malware_families = defaultdict(list)
        self.attack_patterns = defaultdict(int)
        self.loading_sources = []
        
        self._load_threat_db()
    
    def add_file_ioc(self, file_hash: str, filename: str = None, source: str = 'unknown'):
        """Add file to IOCs."""
        self.iocs['files'].add(file_hash)
        self._log_ioc('file', file_hash, source)
    
    def add_ip_ioc(self, ip: str, source: str = 'unknown'):
        """Add IP to IOCs."""
        self.iocs['ips'].add(ip)
        self._log_ioc('ip', ip, source)
    
    def add_domain_ioc(self, domain: str, source: str = 'unknown'):
        """Add domain to IOCs."""
        self.iocs['domains'].add(domain)
        self._log_ioc('domain', domain, source)
    
    def add_url_ioc(self, url: str, source: str = 'unknown'):
        """Add URL to IOCs."""
        self.iocs['urls'].add(url)
        self._log_ioc('url', url, source)
    
    def add_process_ioc(self, process_hash: str, process_name: str = None, source: str = 'unknown'):
        """Add process to IOCs."""
        self.iocs['process_hashes'].add(process_hash)
        self._log_ioc('process', process_hash, source)
    
    def add_registry_ioc(self, registry_key: str, source: str = 'unknown'):
        """Add registry key to IOCs."""
        self.iocs['registry_keys'].add(registry_key)
        self._log_ioc('registry', registry_key, source)
    
    def add_threat_actor(self, actor_name: str, known_techniques: List[str] = None, 
                        attributed_malware: List[str] = None):
        """Register known threat actor."""
        self.threat_actors[actor_name] = {
            'techniques': known_techniques or [],
            'malware': attributed_malware or [],
            'detected': datetime.now().isoformat()
        }
        logger.info(f"[THREAT_INTEL] Actor registered: {actor_name}")
    
    def add_malware_family(self, family_name: str, variants: List[str] = None, 
                          capabilities: List[str] = None):
        """Register malware family."""
        self.malware_families[family_name] = {
            'variants': variants or [],
            'capabilities': capabilities or [],
            'first_seen': datetime.now().isoformat()
        }
        logger.info(f"[THREAT_INTEL] Malware family registered: {family_name}")
    
    def track_attack_pattern(self, pattern: str, count: int = 1):
        """Track attack patterns."""
        self.attack_patterns[pattern] += count
    
    def check_ioc_match(self, ioc_value: str, ioc_type: str) -> bool:
        """Check if IOC matches known threats."""
        if ioc_type not in self.iocs:
            return False
        
        return ioc_value in self.iocs[ioc_type]
    
    def check_domain_threat(self, domain: str) -> Dict:
        """Check if domain is known threat."""
        is_threat = domain in self.iocs['domains']
        
        result = {
            'domain': domain,
            'is_threat': is_threat,
            'threat_type': 'known_malicious_domain' if is_threat else 'unknown'
        }
        
        # Check for overlapping patterns with threat actors
        for actor, data in self.threat_actors.items():
            if domain in str(data):
                result['attributed_actor'] = actor
                break
        
        return result
    
    def check_ip_threat(self, ip: str) -> Dict:
        """Check if IP is known threat."""
        is_threat = ip in self.iocs['ips']
        
        result = {
            'ip': ip,
            'is_threat': is_threat,
            'threat_type': 'c2_server' if is_threat else 'unknown'
        }
        
        return result
    
    def check_file_threat(self, file_hash: str) -> Dict:
        """Check if file is known threat."""
        is_threat = file_hash in self.iocs['files']
        
        result = {
            'file_hash': file_hash,
            'is_threat': is_threat,
            'threat_type': 'known_malware' if is_threat else 'unknown'
        }
        
        # Check malware families
        for family, data in self.malware_families.items():
            if file_hash in str(data):
                result['malware_family'] = family
                break
        
        return result
    
    def get_threat_summary(self) -> Dict:
        """Get threat intelligence summary."""
        return {
            'timestamp': datetime.now().isoformat(),
            'total_iocs': sum(len(v) for v in self.iocs.values()),
            'ioc_breakdown': {
                'files': len(self.iocs['files']),
                'ips': len(self.iocs['ips']),
                'domains': len(self.iocs['domains']),
                'urls': len(self.iocs['urls']),
                'process_hashes': len(self.iocs['process_hashes']),
                'registry_keys': len(self.iocs['registry_keys']),
            },
            'known_threat_actors': len(self.threat_actors),
            'known_malware_families': len(self.malware_families),
            'top_attack_patterns': sorted(
                self.attack_patterns.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:10]
        }
    
    def load_from_malicious_urls_file(self, file_path: str = 'data/urls.txt'):
        """Load IOCs from malicious URLs file."""
        try:
            path = Path(file_path)
            if path.exists():
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    count = 0
                    for line in f:
                        url = line.strip()
                        if url and not url.startswith('#'):
                            self.add_url_ioc(url, 'urls.txt')
                            # Extract domain
                            try:
                                domain = url.split('/')[2] if '://' in url else url
                                if domain:
                                    self.add_domain_ioc(domain, 'urls.txt')
                                    count += 1
                            except:
                                pass
                    
                    logger.info(f"[THREAT_INTEL] Loaded {count} URLs from {file_path}")
        except Exception as e:
            logger.error(f"[THREAT_INTEL] Error loading URLs: {str(e)}")
    
    def load_from_malware_domains_file(self, file_path: str = 'data/malware_domains.json'):
        """Load IOCs from malware domains file."""
        try:
            path = Path(file_path)
            if path.exists():
                with open(path, 'r') as f:
                    data = json.load(f)
                    
                    count = 0
                    if isinstance(data, dict):
                        # Handle domain -> malware family mappings
                        for domain, malware_info in data.items():
                            self.add_domain_ioc(domain, 'malware_domains.json')
                            
                            if isinstance(malware_info, (list, dict)):
                                if isinstance(malware_info, list):
                                    for family in malware_info:
                                        self.add_malware_family(family)
                                else:
                                    family = malware_info.get('family', 'unknown')
                                    if family:
                                        self.add_malware_family(family)
                            count += 1
                    
                    logger.info(f"[THREAT_INTEL] Loaded {count} domains from {file_path}")
        except Exception as e:
            logger.error(f"[THREAT_INTEL] Error loading domains: {str(e)}")
    
    def load_from_yara_signatures(self, yara_file: str):
        """Load threat intelligence from YARA signatures."""
        try:
            path = Path(yara_file)
            if path.exists():
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                    # Extract malware family names from YARA rule names
                    import re
                    rules = re.findall(r'rule\s+(\w+)', content)
                    for rule in rules:
                        self.track_attack_pattern(rule)
                    
                    logger.info(f"[THREAT_INTEL] Loaded {len(rules)} YARA rule references")
        except Exception as e:
            logger.error(f"[THREAT_INTEL] Error loading from YARA: {str(e)}")
    
    def _log_ioc(self, ioc_type: str, value: str, source: str):
        """Log IOC addition."""
        logger.debug(f"[THREAT_INTEL] IOC added - {ioc_type}: {value} (source: {source})")
        self._save_threat_db()
    
    def _save_threat_db(self):
        """Save threat database."""
        try:
            self.threats_db.parent.mkdir(parents=True, exist_ok=True)
            
            data = {
                'timestamp': datetime.now().isoformat(),
                'iocs': {
                    'files': list(self.iocs['files']),
                    'ips': list(self.iocs['ips']),
                    'domains': list(self.iocs['domains']),
                    'urls': list(self.iocs['urls']),
                    'process_hashes': list(self.iocs['process_hashes']),
                    'registry_keys': list(self.iocs['registry_keys']),
                },
                'threat_actors': dict(self.threat_actors),
                'malware_families': dict(self.malware_families),
            }
            
            with open(self.threats_db, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            logger.debug(f"[THREAT_INTEL] Error saving DB: {str(e)}")
    
    def _load_threat_db(self):
        """Load threat database."""
        try:
            if self.threats_db.exists():
                with open(self.threats_db, 'r') as f:
                    data = json.load(f)
                    
                    # Load IOCs
                    ioc_data = data.get('iocs', {})
                    self.iocs['files'] = set(ioc_data.get('files', []))
                    self.iocs['ips'] = set(ioc_data.get('ips', []))
                    self.iocs['domains'] = set(ioc_data.get('domains', []))
                    self.iocs['urls'] = set(ioc_data.get('urls', []))
                    self.iocs['process_hashes'] = set(ioc_data.get('process_hashes', []))
                    self.iocs['registry_keys'] = set(ioc_data.get('registry_keys', []))
                    
                    # Load threat actors and families
                    self.threat_actors = defaultdict(list, data.get('threat_actors', {}))
                    self.malware_families = defaultdict(list, data.get('malware_families', {}))
                    
                    logger.info(f"[THREAT_INTEL] Loaded threat database with {sum(len(v) for v in self.iocs.values())} IOCs")
        except Exception as e:
            logger.error(f"[THREAT_INTEL] Error loading DB: {str(e)}")
