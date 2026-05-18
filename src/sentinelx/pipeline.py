"""
Main Pipeline Orchestrator: Coordinates all detection layers.
Implements the complete hybrid detection workflow.
Scan Order: YARA -> Non-AI Heuristics -> AI/ML Analysis
Integrates Network-wide Emergency Lockdown for critical threats
"""
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import json
import hashlib
import time
from pathlib import Path
import os
import stat
from sentinelx.layers.discovery import DiscoveryLayer, FileInfo
from sentinelx.layers.yara_scanner import YaraSignatureLayer
from sentinelx.layers.heuristics_layer import NonAIHeuristicsLayer
from sentinelx.layers.ai_layer import LightGBMLayer
from sentinelx.layers.usb_scanner import USBScanner, USBDevice
from sentinelx.layers.registry_scanner import RegistryUSBScanner
from sentinelx.layers.windows_whitelist import get_whitelist
from sentinelx.layers.rootkit_detection import RootkitDetectionLayer, RootkitScanResult
from sentinelx.layers.packet_capture import PacketCapture
from sentinelx.layers.network_firewall_propagation import (
    get_emergency_isolation_manager,
    NetworkEmergencyIsolationManager
)
from sentinelx.utils.usb_timestamp import USBTimestampExtractor
# Hybrid Analysis removed - use local Cuckoo sandbox instead
# # Hybrid Analysis removed - use local Cuckoo sandbox instead
# from sentinelx.api.hybrid_analysis import HybridAnalysisClient, AnalysisStatus
from sentinelx.services.network_vulnerability_sealer import NetworkVulnerabilitySealer
from sentinelx.services.network_vulnerability_sealer_advanced import AdvancedNetworkVulnerabilitySealer
from sentinelx.services.network_monitor import NetworkMonitor
from sentinelx.services.malware_prevention_engine import MalwarePreventionEngine
from sentinelx.services.network_isolation import NetworkIsolationManager
from sentinelx.services.auto_discovery_scanner import AutoDiscoveryScannerService
from sentinelx.services.comprehensive_15_layer_firewall import Comprehensive15LayerFirewall
from sentinelx.services.ten_layer_file_scanning import TenLayerFileScanner, ThreatLevel, ScanDecision
from sentinelx.services.quarantine_manager import QuarantineManager
from sentinelx.config.settings import get_config
from sentinelx.utils.logger import get_logger

logger = get_logger(__name__)



@dataclass
class ScanResult:
    """Result of a complete file scan through the pipeline."""
    file_path: str
    file_hash: str
    file_size: int
    
    # Layer results
    yara_matches: list = None  # List of YaraMatch results
    yara_flagged: bool = False
    
    heuristics_score: float = None
    heuristics_flagged: bool = False
    heuristics_flags: list = None
    
    ai_score: float = None
    ai_flagged: bool = False
    needs_sandbox: bool = False
    
    sandbox_result: Dict = None
    sandbox_submitted: bool = False
    
    # Rootkit detection results
    rootkit_score: float = None
    rootkit_flagged: bool = False
    rootkit_confidence: float = 0.0
    rootkit_indicators: list = None
    
    # Final determination
    is_malicious: bool = False
    risk_level: str = 'clean'  # clean, gray, malicious
    detection_path: list = None  # Which layers detected it
    
    # Metadata
    scan_timestamp: str = None
    scan_duration: float = 0.0
    
    # System file ownership
    file_owner: str = None
    is_system_owned: bool = False
    threat_notification: bool = False  # Raise concern to user instead of quarantine
    
    # Quarantine status
    quarantined: bool = False  # Whether file was quarantined


# Module-level singleton pipeline instance
_pipeline_instance = None


def get_pipeline():
    """
    Get or create the global malware detection pipeline instance.
    Returns the same instance for all callers (singleton pattern).
    """
    global _pipeline_instance
    if _pipeline_instance is None:
        _pipeline_instance = MalwareDetectionPipeline()
    return _pipeline_instance


class MalwareDetectionPipeline:
    """
    Multi-stage hybrid malware detection pipeline.
    Scan Order: YARA (Signatures) -> Non-AI Heuristics -> AI/ML Analysis -> Sandbox
    Combines static signatures, behavioral heuristics, AI analysis, and sandbox detonation.
    """
    
    def __init__(self):
        """Initialize the detection pipeline with all layers."""
        self.config = get_config()
        
        # Initialize scanning layers ONLY (no background services at startup)
        self.discovery_layer = DiscoveryLayer()
        self.yara_layer = YaraSignatureLayer()
        self.heuristics_layer = NonAIHeuristicsLayer()
        self.ai_layer = LightGBMLayer()
        self.usb_scanner = USBScanner()
        self.registry_usb_scanner = RegistryUSBScanner()
        self.usb_timestamp_extractor = USBTimestampExtractor()
        self.rootkit_detector = RootkitDetectionLayer()
        self.whitelist = get_whitelist()
        
        # Initialize background services but DO NOT START them (user can enable via GUI)
        self.network_sealer = NetworkVulnerabilitySealer(enable_remediation=True)
        self.advanced_network_sealer = AdvancedNetworkVulnerabilitySealer(enable_blocking=True)
        self._network_sealing_enabled = False
        
        # Initialize prevention and isolation but defer activation
        self.prevention_engine = MalwarePreventionEngine()
        self.network_isolation = NetworkIsolationManager()
        self.network_monitor = NetworkMonitor(pipeline=self)
        self.auto_discovery_scanner = AutoDiscoveryScannerService(pipeline=self)
        
        # Process monitoring flag (do NOT start automatically)
        self._process_monitoring_enabled = False
        
        # Initialize 15-layer firewall object (defer full configuration to improve startup time)
        self.firewall_15_layer = Comprehensive15LayerFirewall()
        self._firewall_configured = False
        
        # Initialize 10-Layer Advanced File Scanner for suspicious files
        self.ten_layer_scanner = TenLayerFileScanner()
        
        # Initialize Quarantine Manager for automatic quarantine of malicious files
        self.quarantine_manager = QuarantineManager()
        
        # Network Packet Capture for traffic analysis
        try:
            log_dir = Path('logs')
            if hasattr(self.config, 'get'):
                log_dir = Path(self.config.get('log_directory', 'logs'))
            self.packet_capture = PacketCapture(log_dir)
            logger.info("Network Packet Capture engine initialized")
        except Exception as e:
            logger.warning(f"Failed to initialize packet capture: {e}")
            self.packet_capture = None
        
        # Initialize Network-wide Emergency Lockdown Manager
        try:
            log_dir = Path('logs')
            if hasattr(self.config, 'get'):
                log_dir = Path(self.config.get('log_directory', 'logs'))
            self.emergency_lockdown_manager = get_emergency_isolation_manager(log_dir)
            logger.info("Network Emergency Lockdown Manager initialized")
            logger.info("CRITICAL THREAT DETECTION: Network-wide emergency shutdown available")
        except Exception as e:
            logger.warning(f"Failed to initialize emergency lockdown: {e}")
            self.emergency_lockdown_manager = None
        
        logger.info("Malware Detection Pipeline initialized - Scan Order: YARA -> Heuristics -> AI")
        logger.info("Quarantine Manager ready for automatic malicious file quarantine")
        logger.info("Background services deferred (can be enabled via GUI):") 
        logger.info("  - Network Vulnerability Sealer")
        logger.info("  - Auto-Discovery Scanner")
        logger.info("  - Network Monitoring")
        logger.info("  - Process Hijacking Monitor")
        logger.info("  - 15-Layer Firewall System")
        logger.info("10-LAYER ADVANCED FILE SCANNER READY FOR SUSPICIOUS FILES")
        logger.info("NETWORK-WIDE EMERGENCY LOCKDOWN AVAILABLE FOR CRITICAL THREATS")
    
    def _trigger_ten_layer_scan(self, file_path: str, origin: str = "unknown", user_privilege: str = "user",
                                target_type: str = "workstation", execution_intent: str = None):
        """
        Trigger 10-layer advanced scanning for suspicious files
        
        Args:
            file_path: Path to the suspicious file
            origin: Where the file came from (email, download, usb, etc.)
            user_privilege: User privilege level (user, admin)
            target_type: Type of target system
            execution_intent: Intended execution method
        """
        try:
            logger.info(f"[10-LAYER] Initiating comprehensive 10-layer scan for: {file_path}")
            
            # Execute 10-layer scan
            scan_result = self.ten_layer_scanner.scan_file(
                file_path=file_path,
                origin=origin,
                user_privilege=user_privilege,
                target_type=target_type,
                execution_intent=execution_intent
            )
            
            # Process scan results
            self._process_ten_layer_result(scan_result)
            
            # Export detailed report
            report_path = f"logs/ten_layer_scan_{scan_result.file_hash[:8]}_{int(time.time())}.json"
            self.ten_layer_scanner.export_scan_result(scan_result, report_path)
            logger.info(f"[10-LAYER] Scan report exported to: {report_path}")
            
        except Exception as e:
            logger.error(f"[10-LAYER] Scan failed: {e}")
    
    def _process_ten_layer_result(self, scan_result):
        """
        Process results from 10-layer scan and take appropriate actions
        
        Args:
            scan_result: ScanResult object from 10-layer scanner
        """
        logger.info(f"[10-LAYER] Processing results for {scan_result.file_path}")
        logger.info(f"[10-LAYER] Final Decision: {scan_result.final_decision.value}")
        logger.info(f"[10-LAYER] Threat Level: {scan_result.threat_level.value}")
        logger.info(f"[10-LAYER] Risk Score: {scan_result.scores.final_risk_score:.2%}")
        
        # Take action based on decision
        if scan_result.final_decision == ScanDecision.BLOCK:
            logger.critical(f"[10-LAYER] BLOCKING FILE: {scan_result.file_path}")
            self.alert_system.send_alert(
                "CRITICAL",
                f"10-Layer scan BLOCKED suspicious file: {scan_result.file_path}",
                f"Threats: {', '.join(scan_result.threats_detected)}"
            )
            
            # Lock file and prevent execution
            try:
                os.chmod(scan_result.file_path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
            except Exception as e:
                logger.warning(f"Could not change file permissions: {e}")
        
        elif scan_result.final_decision == ScanDecision.QUARANTINE:
            logger.warning(f"[10-LAYER] QUARANTINING FILE: {scan_result.file_path}")
            self.alert_system.send_alert(
                "HIGH",
                f"10-Layer scan QUARANTINED suspicious file: {scan_result.file_path}",
                f"Threats: {', '.join(scan_result.threats_detected)}"
            )
            
            # Quarantine the file
            if hasattr(self, 'quarantine_manager'):
                self.quarantine_manager.quarantine_file(
                    scan_result.file_path,
                    reason=f"10-layer scan detected: {', '.join(scan_result.threats_detected)}"
                )
        
        elif scan_result.final_decision == ScanDecision.ISOLATE:
            logger.critical(f"[10-LAYER] ISOLATING SYSTEM: {scan_result.file_path}")
            self.alert_system.send_alert(
                "CRITICAL",
                f"10-Layer scan ISOLATED SYSTEM for file: {scan_result.file_path}",
                f"Threats: {', '.join(scan_result.threats_detected)}"
            )
            
            # Isolate network access
            if hasattr(self, 'network_isolation'):
                self.network_isolation.isolate_device(reason="10-layer scan critical threat")
        
        elif scan_result.final_decision == ScanDecision.ESCALATE:
            logger.critical(f"[10-LAYER] ESCALATING TO HUMAN REVIEW: {scan_result.file_path}")
            self.alert_system.send_alert(
                "CRITICAL",
                f"10-Layer scan ESCALATED for human review: {scan_result.file_path}",
                f"Risk Score: {scan_result.scores.final_risk_score:.2%}\nThreats: {', '.join(scan_result.threats_detected)}"
            )
    
    def check_file_suspicious(self, file_path: str) -> bool:
        """
        Quick check if a file is suspicious based on basic indicators
        
        Returns:
            True if file should trigger 10-layer scan
        """
        try:
            if not os.path.exists(file_path):
                return False
            
            # Check file extension
            suspicious_extensions = ['.exe', '.dll', '.bat', '.cmd', '.vbs', '.ps1', '.scr', '.com']
            if os.path.splitext(file_path)[1].lower() in suspicious_extensions:
                return True
            
            # Check file size (unusually large or very small)
            file_size = os.path.getsize(file_path)
            if file_size > 500 * 1024 * 1024 or (file_size > 0 and file_size < 100):
                return True
            
            return False
        except Exception as e:
            logger.debug(f"Could not check if file suspicious: {e}")
            return False
    
    def _check_file_ownership(self, file_path: str) -> tuple:
        """
        Check file ownership to determine if owned by SYSTEM.
        
        Returns:
            Tuple of (owner_name, is_system_owned)
        """
        try:
            import subprocess
            import re
            
            # Use Windows wmic or PowerShell to get file owner
            try:
                # Try using PowerShell Get-Acl (more reliable on modern Windows)
                ps_cmd = f'Get-Acl -Path "{file_path}" | Select-Object -ExpandProperty Owner'
                result = subprocess.run(
                    ['powershell', '-Command', ps_cmd],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0:
                    owner = result.stdout.strip()
                    is_system = 'SYSTEM' in owner.upper() or 'NT AUTHORITY\\SYSTEM' in owner.upper()
                    return owner, is_system
            except Exception:
                pass
            
            # Fallback: use stat module (less reliable on Windows but works)
            try:
                file_stat = os.stat(file_path)
                # On Windows, this returns the numeric UID, not the name
                # We'll mark as potential SYSTEM if in protected directories
                if 'windows\\system32' in file_path.lower() or 'windows\\syswow64' in file_path.lower():
                    return 'SYSTEM', True
            except Exception:
                pass
            
            return 'Unknown', False
        except Exception as e:
            logger.debug(f"Error checking file ownership for {file_path}: {e}")
            return 'Unknown', False
    
        logger.info(f"YARA: {self.config.yara.enabled}, AI: {self.config.ai_model.enabled}, "
                   f"Sandbox: disabled, USB: Ready, Whitelist: Active")
    
    def scan_file(self, file_path: str) -> ScanResult:
        """
        Scan a single file through the complete pipeline.
        
        Args:
            file_path: Path to file to scan
            
        Returns:
            ScanResult with all findings
        """
        import time
        import hashlib
        
        start_time = time.time()
        
        # Check license activation
        if not self.product_key_manager.is_system_usable():
            logger.error("License expired or not activated - scan blocked")
            return ScanResult(
                file_path=str(file_path) if file_path else "unknown",
                file_hash="license_error",
                file_size=0,
                scan_timestamp=datetime.utcnow().isoformat(),
                risk_level='error'
            )
        
        # Validate input
        if not file_path or not isinstance(file_path, str):
            logger.error(f"Invalid file_path: {file_path}")
            return ScanResult(
                file_path=str(file_path) if file_path else "unknown",
                file_hash="invalid",
                file_size=0,
                scan_timestamp=datetime.utcnow().isoformat(),
                risk_level='error'
            )
        
        file_path = str(file_path).strip()
        
        # Log start of file processing
        logger.debug(f"[FILE] Processing: {file_path}")
        
        try:
            path_obj = Path(file_path)
            if not path_obj.exists():
                logger.debug(f"[FILE] Not found (skipping): {file_path}")
                return ScanResult(
                    file_path=file_path,
                    file_hash="not_found",
                    file_size=0,
                    scan_timestamp=datetime.utcnow().isoformat(),
                    risk_level='error'
                )
            
            if not path_obj.is_file():
                logger.debug(f"[FILE] Not a file (skipping): {file_path}")
                return ScanResult(
                    file_path=file_path,
                    file_hash="not_file",
                    file_size=0,
                    scan_timestamp=datetime.utcnow().isoformat(),
                    risk_level='error'
                )
            
            # Check whitelist
            if self.whitelist.should_whitelist(file_path):
                logger.debug(f"[FILE] Whitelisted (skipping): {file_path}")
                return ScanResult(
                    file_path=file_path,
                    file_hash="whitelisted",
                    file_size=0,
                    scan_timestamp=datetime.utcnow().isoformat(),
                    risk_level='clean'
                )
            
            # Check file ownership
            file_owner, is_system_owned = self._check_file_ownership(file_path)
            logger.debug(f"[FILE] Owner check - File: {file_path} | Owner: {file_owner} | System: {is_system_owned}")
            
            # Read file and calculate hash
            logger.debug(f"[FILE] Reading: {file_path}")
            with open(file_path, 'rb') as f:
                file_data = f.read()
                file_hash = hashlib.sha256(file_data).hexdigest()
            
            file_size = len(file_data)
            logger.debug(f"[FILE] Hash calculated ({file_size} bytes): {file_path} -> {file_hash[:16]}...")
            
            result = ScanResult(
                file_path=file_path,
                file_hash=file_hash,
                file_size=file_size,
                scan_timestamp=datetime.utcnow().isoformat(),
                detection_path=[],
                file_owner=file_owner,
                is_system_owned=is_system_owned
            )
            
            # STAGE 1: YARA Signature Scanning (ALL MATCHES)
            if self.config.yara.enabled:
                logger.debug(f"[FILE] Stage 1: YARA Scanning - {file_path}")
                yara_matches = self.yara_layer.scan_file(file_path)
                result.yara_matches = yara_matches
                
                if yara_matches:
                    result.yara_flagged = True
                    result.detection_path.append('YARA')
                    match_names = [m.rule_name for m in yara_matches]
                    
                    # If SYSTEM-owned file with YARA matches, raise concern instead of auto-quarantine
                    if is_system_owned:
                        result.threat_notification = True
                        result.risk_level = 'gray'  # Gray zone - needs manual review
                        logger.warning(f"[FILE] SYSTEM-OWNED FILE - YARA Match Alert ({len(yara_matches)} signatures): {match_names} @ {file_path} | NOTIFY USER")
                        # Continue to other stages for system files
                    else:
                        # YARA MATCH FOUND - QUARANTINE IMMEDIATELY FOR NON-SYSTEM FILES
                        result.is_malicious = True
                        result.risk_level = 'malicious'
                        logger.critical(f"[YARA HIT] Immediate quarantine triggered - YARA signatures matched ({len(yara_matches)}): {match_names} @ {file_path}")
                        
                        # Quarantine immediately without continuing to other stages
                        result.scan_duration = time.time() - start_time
                        quarantine_success = self.quarantine_from_scan_result(result)
                        result.quarantined = quarantine_success
                        if quarantine_success:
                            logger.critical(f"[QUARANTINE] File immediately quarantined on YARA match: {file_path} ({', '.join(match_names)})")
                        else:
                            logger.error(f"[QUARANTINE] Failed to quarantine file after YARA match: {file_path}")
                        
                        # Return early - don't continue to other stages
                        return result
                else:
                    logger.debug(f"[FILE] YARA: No matches - {file_path}")
            
            # STAGE 2: Non-AI Heuristics Analysis
            if self.config.heuristics.enabled if hasattr(self.config, 'heuristics') else True:
                logger.debug(f"[FILE] Stage 2: Non-AI Heuristics - {file_path}")
                try:
                    heuristics_result = self.heuristics_layer.analyze_file(file_path)
                    result.heuristics_score = heuristics_result.overall_heuristic_score
                    result.heuristics_flagged = heuristics_result.is_suspicious
                    result.heuristics_flags = heuristics_result.flags
                    
                    if heuristics_result.is_suspicious:
                        result.detection_path.append('Heuristics')
                        
                        # If SYSTEM-owned file with heuristic flags, raise concern
                        if is_system_owned and not result.threat_notification:
                            result.threat_notification = True
                            result.risk_level = 'gray'
                            logger.warning(f"[FILE] SYSTEM-OWNED FILE - Heuristic Alert: {heuristics_result.flags} @ {file_path} | NOTIFY USER")
                        elif not result.is_malicious:
                            result.is_malicious = True
                            result.risk_level = 'suspicious'
                            logger.warning(f"[FILE] Heuristic Analysis flagged suspicious behavior: {heuristics_result.flags} @ {file_path}")
                        
                        logger.debug(f"[FILE] Heuristic Score: {heuristics_result.overall_heuristic_score:.3f} - Flags: {heuristics_result.flags}")
                    else:
                        logger.debug(f"[FILE] Heuristics: No suspicious patterns - {file_path}")
                except Exception as e:
                    logger.error(f"[FILE] Heuristics analysis failed for {file_path}: {str(e)}")
                    result.heuristics_score = 0.0
                    result.heuristics_flagged = False
                    result.heuristics_flags = []
            
            # STAGE 3: AI/ML Analysis
            if self.config.ai_model.enabled:
                logger.debug(f"[FILE] Stage 3: AI Analysis - {file_path}")
                ai_score = self.ai_layer.predict(file_path)
                
                if ai_score:
                    result.ai_score = ai_score.maliciousness_score
                    
                    if self.ai_layer.is_definitely_malicious(ai_score):
                        result.ai_flagged = True
                        result.is_malicious = True
                        result.risk_level = 'malicious'
                        result.detection_path.append('AI')
                        logger.warning(f"[FILE] AI flagged MALICIOUS (score {ai_score.maliciousness_score:.4f}): {file_path}")
                    
                    elif self.ai_layer.needs_sandbox_escalation(ai_score):
                        result.needs_sandbox = True
                        result.risk_level = 'gray'
                        result.detection_path.append('AI_Gray_Zone')
                        logger.warning(f"[FILE] AI GRAY ZONE (score {ai_score.maliciousness_score:.4f}, escalating): {file_path}")
                    
                    else:
                        logger.debug(f"[FILE] AI clean (score {ai_score.maliciousness_score:.4f}): {file_path}")
                else:
                    logger.debug(f"[FILE] AI analysis unavailable: {file_path}")
            
            # STAGE 4: Rootkit Detection Analysis
            logger.debug(f"[FILE] Stage 4: Rootkit Detection - {file_path}")
            try:
                rootkit_result = self.rootkit_detector.scan_file(file_path)
                result.rootkit_score = rootkit_result.rootkit_confidence
                result.rootkit_flagged = rootkit_result.is_rootkit
                result.rootkit_confidence = rootkit_result.rootkit_confidence
                result.rootkit_indicators = rootkit_result.indicators
                
                if rootkit_result.is_rootkit:
                    result.detection_path.append('Rootkit_Detection')
                    result.is_malicious = True
                    result.risk_level = 'malicious'
                    logger.critical(f"[FILE] ROOTKIT DETECTED (confidence {rootkit_result.rootkit_confidence:.2%}): {file_path}")
                    for ind in rootkit_result.indicators:
                        logger.warning(f"  [ROOTKIT] {ind.indicator_type}: {ind.description}")
                elif rootkit_result.suspicious_behavior_count > 0:
                    result.detection_path.append('Rootkit_Suspicious')
                    result.risk_level = 'gray'
                    logger.warning(f"[FILE] Suspicious rootkit indicators: {file_path}")
                else:
                    logger.debug(f"[FILE] Rootkit scan clean: {file_path}")
            except Exception as e:
                logger.warning(f"[FILE] Rootkit detection error: {e}")
            
            # STAGE 5: Sandbox Escalation (Hybrid Analysis removed)
            if result.needs_sandbox:
                logger.debug(f"[FILE] Stage 4: Sandbox Escalation (local analysis): {file_path}")
                # Local Cuckoo sandbox or VirusTotal analysis can be added here
                result.sandbox_submitted = False
                # Commented out - Hybrid Analysis API removed (was causing 404 errors)
                # Code below would submit file to Hybrid Analysis for advanced analysis
                # submission_id = self.hybrid_analysis.submit_file(file_path)
                # if submission_id:
                #     result.sandbox_submitted = True
                #     report = self.hybrid_analysis.wait_for_analysis(submission_id)
                #     
                #     if report:
                #         result.sandbox_result = {
                #             'submission_id': submission_id,
                #             'verdict': report.verdict,
                #             'threat_score': report.threat_score,
                #             'status': report.status.value,
                #             'analysis_url': report.analysis_url,
                #             'file_hash': report.file_hash
                #         }
                #         
                #         # Update result based on sandbox verdict
                #         if report.verdict == 'malware' or report.threat_score > 75:
                #             result.is_malicious = True
                #             result.risk_level = 'malicious'
                #             if 'Sandbox' not in result.detection_path:
                #                 result.detection_path.append('Sandbox')
                #             logger.error(f"[FILE] Sandbox verdict: MALWARE (Score: {report.threat_score}): {file_path}")
                #         else:
                #             logger.info(f"[FILE] Sandbox verdict: {report.verdict} (Score: {report.threat_score}): {file_path}")
                #     else:
                #         logger.warning("Sandbox analysis timed out or failed")
            
            result.scan_duration = time.time() - start_time
            
            # 10-LAYER ADVANCED SCANNING FOR SUSPICIOUS FILES
            if result.is_malicious or result.risk_level in ['suspicious', 'gray']:
                logger.info(f"[10-LAYER] Triggering 10-layer advanced scanning for suspicious file: {file_path}")
                self._trigger_ten_layer_scan(file_path, origin="regular_scan")
            
            # Summary with full details
            if result.yara_matches:
                match_info = f" [YARA: {len(result.yara_matches)} signatures]"
            else:
                match_info = ""
            
            summary = (f"[FILE] Scan complete{match_info}: {file_path} | "
                      f"Risk: {result.risk_level.upper()} | "
                      f"Malicious: {result.is_malicious} | "
                      f"Hash: {file_hash[:16]}... | "
                      f"Duration: {result.scan_duration:.2f}s")
            
            if result.is_malicious:
                logger.error(summary)
            elif result.risk_level == 'gray':
                logger.warning(summary)
            else:
                logger.info(summary)
            
            # AUTOMATIC QUARANTINE: Quarantine malicious files from other detection stages (non-YARA)
            # Note: YARA matches are already quarantined immediately above
            if result.is_malicious and not result.quarantined:
                quarantine_success = self.quarantine_from_scan_result(result)
                result.quarantined = quarantine_success
                if quarantine_success:
                    logger.warning(f"[QUARANTINE] File successfully quarantined after heuristics/AI/rootkit detection: {file_path}")
                else:
                    logger.error(f"[QUARANTINE] Failed to quarantine file: {file_path}")
            
            return result
        
        except Exception as e:
            logger.error(f"Error scanning {file_path}: {e}")
            return ScanResult(
                file_path=file_path,
                file_hash="error",
                file_size=0,
                scan_timestamp=datetime.utcnow().isoformat(),
                risk_level='error'
            )
    
    def scan_directory(self, directory: str, recursive: bool = True, 
                      extensions: Optional[List[str]] = None) -> List[ScanResult]:
        """
        Scan all files in a directory.
        
        Args:
            directory: Directory path to scan
            recursive: Whether to scan subdirectories
            extensions: Optional list of file extensions to scan (e.g., ['.exe', '.dll'])
            
        Returns:
            List of ScanResult objects
        """
        results = []
        logger.info(f"[DIR] Starting directory scan: {directory} (recursive={recursive})")
        
        try:
            if extensions:
                file_generator = self.discovery_layer.discover_files_by_extension(extensions)
            else:
                file_generator = self.discovery_layer.discover_files()
            
            file_count = 0
            for file_info in file_generator:
                if extensions:
                    if file_info.extension not in [f'.{e.lower()}' if not e.startswith('.') 
                                                   else e.lower() for e in extensions]:
                        continue
                
                file_count += 1
                logger.debug(f"[DIR] File #{file_count}: {file_info.path}")
                result = self.scan_file(file_info.path)
                results.append(result)
            
            logger.info(f"[DIR] Scan complete: {directory} - Scanned {file_count} files, found {sum(1 for r in results if r.is_malicious)} detections")
        
        except Exception as e:
            logger.error(f"[DIR] Error scanning directory {directory}: {e}")
        
        return results
    
    def generate_report(self, results: List[ScanResult], output_path: Optional[str] = None) -> Dict:
        """
        Generate a summary report of scan results.
        
        Args:
            results: List of ScanResult objects
            output_path: Optional path to save report as JSON
            
        Returns:
            Dictionary with report data
        """
        malicious_count = sum(1 for r in results if r.is_malicious)
        gray_count = sum(1 for r in results if r.risk_level == 'gray')
        clean_count = sum(1 for r in results if r.risk_level == 'clean')
        
        report = {
            'scan_timestamp': datetime.utcnow().isoformat(),
            'total_files_scanned': len(results),
            'malicious_count': malicious_count,
            'gray_zone_count': gray_count,
            'clean_count': clean_count,
            'malicious_percentage': (malicious_count / len(results) * 100) if results else 0,
            'total_duration': sum(r.scan_duration for r in results),
            'findings': [asdict(r) for r in results if r.is_malicious or r.risk_level == 'gray']
        }
        
        # Save report if path provided
        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            logger.info(f"Report saved: {output_path}")
        
        return report
    
    def get_pipeline_status(self) -> Dict:
        """Get status of all pipeline components."""
        return {
            'timestamp': datetime.utcnow().isoformat(),
            'discovery': {
                'enabled': self.config.discovery.enabled,
                'target_paths': self.config.discovery.target_paths
            },
            'yara': self.yara_layer.get_signature_details(),
            'ai_model': self.ai_layer.get_model_info(),
            'hybrid_analysis': 'disabled',  # Hybrid Analysis API removed
            'usb_scanner': self.get_usb_status()
        }
    
    def get_usb_status(self) -> Dict:
        """Get USB scanner status."""
        try:
            devices = self.usb_scanner.get_usb_devices()
            return {
                'enabled': True,
                'device_count': len(devices),
                'devices': [
                    self.usb_scanner.get_device_info(d) for d in devices
                ]
            }
        except Exception as e:
            logger.error(f"Error getting USB status: {e}")
            return {'enabled': False, 'error': str(e)}
        except Exception as e:
            logger.error(f"Error getting USB status: {e}")
            return {
                'enabled': True,
                'device_count': 0,
                'devices': [],
                'error': str(e)
            }
    
    def scan_usb_device(self, device_letter: str) -> List[ScanResult]:
        """
        Scan a USB device for malware.
        
        Args:
            device_letter: Drive letter (e.g., 'D', 'E')
            
        Returns:
            List of ScanResult objects
        """
        results = []
        logger.info(f"[USB] Starting USB device scan: {device_letter}:")
        
        try:
            # Find the device
            devices = self.usb_scanner.get_usb_devices()
            target_device = None
            
            for device in devices:
                if device.drive_letter.upper() == device_letter.upper():
                    target_device = device
                    break
            
            if not target_device:
                logger.warning(f"[USB] Device not found: {device_letter}:")
                return results
            
            logger.info(f"[USB] Found device: {target_device.label} ({target_device.mount_path})")
            
            # Scan all files on the device
            file_count = 0
            for file_path in self.usb_scanner.scan_usb_device(target_device):
                try:
                    file_count += 1
                    logger.debug(f"[USB] File #{file_count}: {file_path}")
                    result = self.scan_file(file_path)
                    results.append(result)
                except Exception as e:
                    logger.warning(f"[USB] Error scanning file {file_path}: {e}")
            
            logger.info(f"[USB] Scan complete: {device_letter}: - Scanned {file_count} files, found {sum(1 for r in results if r.is_malicious)} detections")
        
        except Exception as e:
            logger.error(f"[USB] Error scanning device {device_letter}: {e}")
        
        return results
    
    def get_usb_devices(self) -> List[Dict]:
        """
        Get list of connected USB devices.
        
        Returns:
            List of USB device information dictionaries
        """
        try:
            devices = self.usb_scanner.get_usb_devices()
            return [self.usb_scanner.get_device_info(d) for d in devices]
        except Exception as e:
            logger.error(f"Error getting USB devices: {e}")
            return []
    
    def get_usb_devices_with_timestamps(self) -> List[Dict]:
        """
        Get USB devices from registry with full timestamp and connection count information.
        
        Returns:
            List of USB device dicts with timestamps and total connection counts
        """
        try:
            devices = self.registry_usb_scanner.get_connected_usb_devices()
            return devices
        except Exception as e:
            logger.error(f"Error getting USB devices with timestamps: {e}")
            return []
    
    def enable_network_sealing(self) -> bool:
        """
        Enable advanced network vulnerability sealing.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            logger.info("[NETWORK-SEALING] User enabled network sealing")
            self._network_sealing_enabled = True
            self.advanced_network_sealer.start_sealing()
            self.advanced_network_sealer.seal_all_vulnerabilities()
            logger.info("[NETWORK-SEALING] Network sealing activated successfully")
            return True
        except Exception as e:
            logger.error(f"[NETWORK-SEALING] Failed to enable: {e}")
            return False
    
    def quarantine_malicious_file(self, file_path: str, threat_type: str = "malware", 
                                   severity: str = "malicious", reason: str = "") -> bool:
        """
        Quarantine a malicious file automatically.
        
        Args:
            file_path: Path to the malicious file
            threat_type: Type of threat detected (malware, virus, rootkit, etc.)
            severity: Severity level (malicious, suspicious, network_threat)
            reason: Detailed reason for quarantine
            
        Returns:
            True if file was successfully quarantined, False otherwise
        """
        try:
            if not Path(file_path).exists():
                logger.warning(f"[QUARANTINE] File no longer exists (cannot quarantine): {file_path}")
                return False
            
            # Quarantine the file
            success = self.quarantine_manager.quarantine_file(
                file_path=file_path,
                threat_type=threat_type,
                severity=severity if severity in ['malicious', 'suspicious', 'network_threat'] else 'malicious',
                reason=reason
            )
            
            if success:
                logger.warning(f"[QUARANTINE] Successfully quarantined: {file_path} ({threat_type})")
                return True
            else:
                logger.error(f"[QUARANTINE] Failed to quarantine: {file_path}")
                return False
                
        except Exception as e:
            logger.error(f"[QUARANTINE] Error quarantining {file_path}: {e}")
            return False
    
    def quarantine_from_scan_result(self, scan_result: 'ScanResult') -> bool:
        """
        Quarantine a file based on scan results.
        
        Args:
            scan_result: ScanResult from a file scan
            
        Returns:
            True if file was successfully quarantined, False otherwise
        """
        try:
            if not scan_result.is_malicious:
                logger.debug(f"[QUARANTINE] File not marked as malicious, skipping quarantine: {scan_result.file_path}")
                return False
            
            # Determine threat type from detection path
            threat_type = "malware"
            if scan_result.rootkit_flagged:
                threat_type = "rootkit"
            elif scan_result.yara_flagged:
                threat_type = "signature_detected"
            elif scan_result.heuristics_flagged:
                threat_type = "heuristic_threat"
            elif scan_result.ai_flagged:
                threat_type = "ai_detected_malware"
            
            # Build detailed reason
            reasons = []
            if scan_result.yara_matches:
                reasons.append(f"YARA signatures: {', '.join([m.rule_name for m in scan_result.yara_matches[:3]])}")
            if scan_result.heuristics_flags:
                reasons.append(f"Heuristics: {', '.join(scan_result.heuristics_flags[:3])}")
            if scan_result.ai_score:
                reasons.append(f"AI Score: {scan_result.ai_score:.4f}")
            if scan_result.rootkit_indicators:
                reasons.append(f"Rootkit: {', '.join([ind.indicator_type for ind in scan_result.rootkit_indicators[:2]])}")
            
            reason = " | ".join(reasons) if reasons else "Multiple detection layers triggered"
            
            # Quarantine
            return self.quarantine_malicious_file(
                file_path=scan_result.file_path,
                threat_type=threat_type,
                severity=scan_result.risk_level,
                reason=reason
            )
            
        except Exception as e:
            logger.error(f"[QUARANTINE] Error processing scan result for quarantine: {e}")
            return False
    
    def disable_network_sealing(self) -> bool:
        """
        Disable advanced network vulnerability sealing and restore normal network access.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            logger.info("[NETWORK-SEALING] User disabled network sealing")
            self._network_sealing_enabled = False
            self.advanced_network_sealer.restore_network_access()
            logger.info("[NETWORK-SEALING] Network sealing deactivated - normal access restored")
            return True
        except Exception as e:
            logger.error(f"[NETWORK-SEALING] Failed to disable: {e}")
            return False
    
    def start_process_monitoring(self):
        """
        Start continuous background monitoring for Windows process hijacking.
        Called only when user explicitly enables it via GUI.
        """
        if self._process_monitoring_enabled:
            logger.warning("[PROCESS-HIJACKING] Already running")
            return
        
        import threading
        
        self._process_monitoring_enabled = True
        
        def monitor_loop():
            """Background monitoring loop"""
            while self._process_monitoring_enabled:
                try:
                    # Run process hijacking detection every 10 seconds
                    threats = self.rootkit_detector.continuous_process_hijacking_monitor()
                    
                    if threats['hijacked_processes_detected'] > 0:
                        logger.critical(
                            f"[PROCESS-HIJACKING] {threats['hijacked_processes_detected']} "
                            f"hijacked system process(es) detected and terminated!"
                        )
                    
                    time.sleep(10)  # Check every 10 seconds
                
                except Exception as e:
                    logger.error(f"[PROCESS-HIJACKING] Monitor error: {e}")
                    time.sleep(10)
        
        # Start monitor thread as daemon so it stops when main program exits
        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()
        logger.info("[PROCESS-HIJACKING] Continuous monitoring started (user-enabled)")
    
    def stop_process_monitoring(self):
        """Stop process hijacking monitoring."""
        self._process_monitoring_enabled = False
        logger.info("[PROCESS-HIJACKING] Monitoring stopped")
    
    # ===== Network Packet Capture Methods =====
    
    def start_packet_capture(self, interface: Optional[str] = None, simulate: bool = False) -> bool:
        """
        Start capturing network packets for analysis
        
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
    
    def is_packet_capture_active(self) -> bool:
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
        """Clear all captured packet logs"""
        if self.packet_capture:
            self.packet_capture.clear_logs()
    
    def is_sealing(self) -> bool:
        """
        Check if network sealing is currently enabled.
        
        Returns:
            True if network sealing is active, False otherwise
        """
        return self._network_sealing_enabled
    
    def get_license_status(self) -> Dict:
        """
        Get current license and trial status.
        
        Returns:
            Dictionary with activation status information
        """
        status = self.product_key_manager.get_status()
        return {
            'is_activated': status.is_activated,
            'is_trial': status.is_trial,
            'product_key': status.product_key,
            'activation_date': status.activation_date,
            'expiration_date': status.expiration_date,
            'trial_days_remaining': status.trial_days_remaining,
            'plan': status.plan,
            'plan_days_remaining': status.plan_days_remaining,
            'status_message': self.product_key_manager.get_status_message(),
            'is_usable': self.product_key_manager.is_system_usable()
        }
    
    def activate_license(self, product_key: str) -> bool:
        """
        Activate system with a product key.
        
        Args:
            product_key: Product key in format SENT-XXXX-XXXX-XXXX
            
        Returns:
            True if activation successful, False otherwise
        """
        if not self.product_key_manager.validate_product_key(product_key):
            logger.error(f"Invalid product key format: {product_key}")
            return False
        
        try:
            self.product_key_manager.activate(product_key)
            logger.info(f"System activated with product key: {product_key}")
            return True
        except Exception as e:
            logger.error(f"Activation failed: {e}")
            return False
    
    def start_trial(self) -> bool:
        """
        Start 30-day trial period (if not already running).
        
        Returns:
            True if trial started or already running, False otherwise
        """
        try:
            status = self.product_key_manager.get_status()
            
            if status.is_activated:
                logger.info("System already activated - trial not needed")
                return True
            
            if status.is_trial:
                logger.info(f"Trial already active - {status.trial_days_remaining} days remaining")
                return True
            
            # Start new trial
            self.product_key_manager.start_trial()
            logger.info("30-day trial period started")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start trial: {e}")
            return False
    
    # =========================================================================
    # NETWORK-WIDE EMERGENCY LOCKDOWN - For critical threats
    # =========================================================================
    
    def trigger_network_emergency_shutdown(self, threat_name: str, threat_type: str = "malware",
                                          severity: int = 10, description: str = None) -> bool:
        """
        Trigger emergency network-wide lockdown when critical threat is detected.
        
        Disables network access across ALL nodes in the network to prevent malware spread.
        Can be triggered from ANY node to protect the entire network.
        
        Args:
            threat_name: Name of detected threat
            threat_type: Type of threat (malware, ransomware, worm, etc.)
            severity: Severity level (1-10, typically 9-10 for emergency)
            description: Detailed threat description
            
        Returns:
            True if emergency shutdown initiated successfully
        """
        if not self.emergency_lockdown_manager:
            logger.error("Emergency lockdown manager not available")
            return False
        
        logger.critical("=" * 100)
        logger.critical("TRIGGERING NETWORK-WIDE EMERGENCY SHUTDOWN!")
        logger.critical("=" * 100)
        logger.critical(f"Threat detected: {threat_name}")
        logger.critical(f"Type: {threat_type} | Severity: {severity}/10")
        logger.critical(f"Taking immediate network-wide protective action...")
        logger.critical("=" * 100)
        
        try:
            # Trigger emergency shutdown through isolation manager
            result = self.emergency_lockdown_manager.trigger_emergency_shutdown(
                threat_type=threat_type,
                severity=severity,
                threat_name=threat_name,
                description=description or f"Critical {threat_type} detected"
            )
            
            logger.critical("Network-wide lockdown status: ACTIVE")
            logger.critical("All network nodes have been isolated")
            logger.critical("Awaiting administrator confirmation to restore connectivity")
            
            return result
            
        except Exception as e:
            logger.error(f"Error triggering network emergency shutdown: {e}")
            return False
    
    def release_network_lockdown(self) -> bool:
        """
        Release network lockdown and restore connectivity.
        
        Should only be called after the threat has been fully neutralized.
        
        Returns:
            True if lockdown released successfully
        """
        if not self.emergency_lockdown_manager:
            logger.warning("Emergency lockdown manager not available")
            return False
        
        logger.critical("Releasing network-wide lockdown...")
        result = self.emergency_lockdown_manager.release_network_lockdown()
        
        if result:
            logger.critical("Network lockdown released - connectivity restoration in progress")
        
        return result
    
    def get_network_emergency_status(self) -> Dict:
        """
        Get current network emergency and lockdown status.
        
        Returns:
            Dictionary with emergency status information
        """
        if not self.emergency_lockdown_manager:
            return {"available": False}
        
        return {
            "available": True,
            "lockdown_status": self.emergency_lockdown_manager.get_emergency_status()
        }
    
    def get_active_network_nodes(self) -> List[str]:
        """
        Get list of all active nodes on the network.
        
        Returns:
            List of active IP addresses
        """
        if not self.emergency_lockdown_manager:
            return []
        
        return self.emergency_lockdown_manager.get_network_nodes()

