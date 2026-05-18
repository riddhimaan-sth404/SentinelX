"""
YARA Signature Layer: Fast static malware signature detection.
Targets persistence mechanisms (Registry Run keys) and code injection patterns.
"""
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    import logging
    logging.warning("yara-python not installed. YARA scanning will be disabled.")

import os
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass
from sentinelx.config.settings import get_config
from sentinelx.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class YaraMatch:
    """Result from YARA rule match."""
    rule_name: str
    tags: List[str]
    strings: List[tuple]  # (offset, match_identifier, matched_data)
    severity: str  # high, medium, low
    matched_file: str
    

class YaraSignatureLayer:
    """
    Static signature-based malware detection using YARA.
    Fast pre-filter for known malware patterns.
    """
    
    def __init__(self):
        """Initialize YARA signature layer."""
        self.config = get_config().yara
        self.rules = None
        self.yara_available = YARA_AVAILABLE
        self._severity_map = {
            'persistence': 'high',
            'code_injection': 'high',
            'suspicious_api': 'medium',
            'suspicious_behavior': 'medium',
            'anomaly': 'low'
        }
        
        if self.config.enabled and YARA_AVAILABLE:
            self._load_rules()
        elif self.config.enabled and not YARA_AVAILABLE:
            logger.warning("YARA rules enabled but yara-python not installed. YARA scanning disabled.")

    
    def _load_rules(self):
        """Load YARA rules from file, with fallback support."""
        if not YARA_AVAILABLE:
            logger.warning("YARA not available, cannot load rules")
            return
        
        # Determine project root directory (where this file is 3 levels up: sentinelx/layers/yara_scanner.py)
        project_root = Path(__file__).parent.parent.parent.parent  # ../../../.. from this file
        
        # Priority order for rule loading - use absolute paths based on project root
        yara_full_path = project_root / 'rules' / 'yara-rules-full.yar'  # HIGHEST PRIORITY - most comprehensive
        # Note: sentinelx_master_signatures.yar has syntax errors and is skipped
        # master_path = project_root / 'rules' / 'sentinelx_master_signatures.yar'
        rules_path = project_root / self.config.rules_path
        fallback_path = project_root / getattr(self.config, 'fallback_path', 'rules/comprehensive_malware_signatures.yar')
        enterprise_path = project_root / 'rules' / 'enterprise_advanced_signatures.yar'
        
        logger.debug(f"Project root: {project_root}")
        logger.debug(f"Looking for YARA rules in: {project_root / 'rules'}")
        
        # Collect all rule files to compile
        rule_files = []
        
        # Load YARA rules full database FIRST (highest priority - 386k+ lines, most comprehensive)
        if yara_full_path.exists():
            rule_files.append(str(yara_full_path.absolute()))
            logger.info(f"Loading YARA rules full database (PRIMARY): {yara_full_path} - 386k+ community signatures")
        else:
            logger.debug(f"YARA full database not found at: {yara_full_path}")
            # Try enterprise ruleset as backup if full database not available
            if enterprise_path.exists():
                rule_files.append(str(enterprise_path.absolute()))
                logger.info(f"Loading enterprise advanced ruleset: {enterprise_path}")
            else:
                logger.debug(f"Enterprise ruleset not found at: {enterprise_path}")
            
            # Try primary ruleset as additional source
            if rules_path.exists():
                rule_files.append(str(rules_path.absolute()))
                logger.info(f"Loading primary ruleset: {rules_path}")
            else:
                logger.debug(f"Primary ruleset not found at: {rules_path}")
            
            # Try fallback ruleset as final option
            if fallback_path.exists():
                rule_files.append(str(fallback_path.absolute()))
                logger.info(f"Loading fallback ruleset: {fallback_path}")
            else:
                logger.debug(f"Fallback ruleset not found at: {fallback_path}")
        
        # Always add enterprise ruleset even if full database loaded (for supplementary rules)
        if not yara_full_path.exists() and enterprise_path.exists() and enterprise_path not in rule_files:
            rule_files.append(str(enterprise_path.absolute()))
            logger.info(f"Adding enterprise advanced ruleset as supplementary: {enterprise_path}")
        
        # Compile all rules together
        if rule_files:
            try:
                # Verify all files exist and compile individually first to catch syntax errors
                verified_files = []
                for f in rule_files:
                    file_path = Path(f)
                    if not file_path.exists():
                        logger.warning(f"Skipping non-existent YARA file: {f}")
                        continue
                    
                    if not file_path.is_file():
                        logger.warning(f"Skipping non-file YARA path: {f}")
                        continue
                    
                    if os.path.getsize(f) == 0:
                        logger.warning(f"Skipping empty YARA file: {f}")
                        continue
                    
                    # Try to compile individually first to catch syntax errors
                    try:
                        test_compile = yara.compile(filepath=f)
                        verified_files.append(f)
                        logger.debug(f"Verified YARA file: {Path(f).name}")
                    except yara.Error as compile_error:
                        logger.warning(f"Skipping YARA file with syntax error ({Path(f).name}): {compile_error}")
                        continue
                
                if not verified_files:
                    logger.warning("No valid YARA files found after syntax verification")
                    self._create_default_rules()
                    return
                
                # If only one file, use it directly
                if len(verified_files) == 1:
                    try:
                        self.rules = yara.compile(filepath=verified_files[0])
                        logger.info(f"YARA ruleset loaded successfully: {Path(verified_files[0]).name}")
                        logger.info(f"Enterprise-grade detection with APT, ransomware, and advanced evasion patterns enabled")
                        return
                    except yara.Error as e:
                        logger.error(f"Failed to compile single YARA file: {e}")
                        self._create_default_rules()
                        return
                
                # If multiple files, compile them together
                filepaths_dict = {f: f"ns{i}" for i, f in enumerate(verified_files)}
                namespace = yara.compile(filepaths=filepaths_dict)
                self.rules = namespace
                logger.info(f"YARA rulesets compiled successfully - Total files: {len(verified_files)}")
                logger.info(f"Enterprise-grade detection with APT, ransomware, and advanced evasion patterns enabled")
                return
            except yara.Error as e:
                logger.error(f"Failed to compile YARA rules: {e}")
                logger.warning(f"Falling back to default rules")
                logger.warning(f"Attempting to load rules individually...")
                
                # Try loading individually
                for rule_file in rule_files:
                    try:
                        self.rules = yara.compile(filepath=rule_file)
                        logger.info(f"YARA rules loaded successfully: {rule_file}")
                        return
                    except yara.Error as e:
                        logger.error(f"Failed to compile {rule_file}: {e}")
                        continue
        
        # If all fail, create default minimal rules
        logger.warning(f"Could not load any YARA rules. Creating defaults...")
        self._create_default_rules()
    
    def _create_default_rules(self):
        """Create basic default rules if none exist."""
        if not YARA_AVAILABLE:
            logger.warning("Cannot create YARA rules - yara-python not installed")
            return
            
        default_rules = """
rule DefaultMalwareIndicators {
    meta:
        description = "Default malware indicators"
        author = "SentinelX"
    strings:
        $suspicious_api1 = "CreateRemoteThread"
        $suspicious_api2 = "WriteProcessMemory"
        $suspicious_api3 = "VirtualAllocEx"
    condition:
        any of them
}
"""
        # Use absolute path based on project root
        project_root = Path(__file__).parent.parent.parent.parent
        rules_path = project_root / self.config.rules_path
        rules_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(rules_path, 'w') as f:
                f.write(default_rules)
            self.rules = yara.compile(source=default_rules)
            logger.info(f"Default YARA rules created at {rules_path}")
        except Exception as e:
            logger.error(f"Failed to create default rules: {e}")
    
    def scan_file(self, file_path: str) -> List[YaraMatch]:
        """
        Scan a file with YARA rules.
        
        Args:
            file_path: Path to file to scan
            
        Returns:
            List of YaraMatch objects
        """
        if not self.config.enabled or self.rules is None:
            return []
        
        try:
            matches = self.rules.match(file_path, timeout=self.config.timeout)
            result = []
            
            for match in matches:
                # Determine severity based on tags
                severity = 'low'
                for tag in match.tags:
                    if tag in self._severity_map:
                        severity = self._severity_map[tag]
                        break
                
                yara_match = YaraMatch(
                    rule_name=match.rule,
                    tags=match.tags,
                    strings=match.strings,
                    severity=severity,
                    matched_file=file_path
                )
                result.append(yara_match)
            
            if result:
                logger.debug(f"YARA matches found for {file_path}: {[m.rule_name for m in result]}")
            
            return result
        
        except yara.TimeoutError:
            logger.warning(f"YARA scan timeout for {file_path}")
            return []
        except Exception as e:
            logger.error(f"Error scanning {file_path} with YARA: {e}")
            return []
    
    def scan_buffer(self, buffer: bytes, rule_name: str = None) -> List[YaraMatch]:
        """
        Scan a buffer of bytes with YARA rules.
        
        Args:
            buffer: Bytes to scan
            rule_name: Optional specific rule to use
            
        Returns:
            List of YaraMatch objects
        """
        if not self.config.enabled or self.rules is None:
            return []
        
        try:
            if rule_name:
                matches = [m for m in self.rules.match(data=buffer, timeout=self.config.timeout) 
                          if m.rule == rule_name]
            else:
                matches = self.rules.match(data=buffer, timeout=self.config.timeout)
            
            result = []
            for match in matches:
                severity = 'low'
                for tag in match.tags:
                    if tag in self._severity_map:
                        severity = self._severity_map[tag]
                        break
                
                yara_match = YaraMatch(
                    rule_name=match.rule,
                    tags=match.tags,
                    strings=match.strings,
                    severity=severity,
                    matched_file="<buffer>"
                )
                result.append(yara_match)
            
            return result
        
        except Exception as e:
            logger.error(f"Error scanning buffer with YARA: {e}")
            return []
    
    def is_suspicious(self, file_path: str, severity_threshold: str = 'medium') -> bool:
        """
        Quick check if file matches suspicious YARA rules.
        
        Args:
            file_path: Path to file
            severity_threshold: Minimum severity to flag ('low', 'medium', 'high')
            
        Returns:
            True if suspicious matches found
        """
        matches = self.scan_file(file_path)
        threshold_levels = {'low': 0, 'medium': 1, 'high': 2}
        threshold_value = threshold_levels.get(severity_threshold, 0)
        
        for match in matches:
            if threshold_levels.get(match.severity, 0) >= threshold_value:
                return True
        return False
    
    def get_signature_details(self) -> Dict:
        """
        Get summary of loaded YARA rules.
        
        Returns:
            Dictionary with rule statistics
        """
        if self.rules is None:
            return {"status": "No rules loaded"}
        
        rules_info = self.rules.match(data=b"")  # Get rule metadata
        return {
            "rules_file": self.config.rules_path,
            "timeout": self.config.timeout,
            "enabled": self.config.enabled,
            "rules_count": len(rules_info) if rules_info else 0
        }
