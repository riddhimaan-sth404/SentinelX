"""
10-Layer Advanced File Scanning System for Suspicious Files
Implements enterprise-grade multi-layered file analysis with cascading detection
"""

import os
import json
import hashlib
import threading
import subprocess
import re
import yara
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple, Set
from enum import Enum
from collections import defaultdict
import struct

from sentinelx.utils.logger import logger


class ThreatLevel(Enum):
    """File threat classification"""
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALWARE = "malware"
    CRITICAL = "critical"


class ScanDecision(Enum):
    """Final decision on file"""
    ALLOW = "allow"
    BLOCK = "block"
    QUARANTINE = "quarantine"
    ISOLATE = "isolate"
    ESCALATE = "escalate_human_review"


@dataclass
class ScanScore:
    """Aggregated scan scoring"""
    layer1_yara_score: float = 0.0
    layer2_reputation_score: float = 0.0
    layer3_format_score: float = 0.0
    layer4_heuristics_score: float = 0.0
    layer5_context_score: float = 0.0
    layer6_behavior_score: float = 0.0
    layer7_memory_score: float = 0.0
    layer8_static_ml_score: float = 0.0
    layer9_dynamic_ml_score: float = 0.0
    
    final_risk_score: float = 0.0
    decision: ScanDecision = ScanDecision.ALLOW
    threat_level: ThreatLevel = ThreatLevel.CLEAN
    confidence: float = 0.0


@dataclass
class FileArtifact:
    """Extracted file artifact"""
    artifact_type: str  # 'yara_hit', 'string', 'opcode', 'network_call', etc.
    source: str  # 'static' or 'memory'
    value: str
    severity: str  # 'low', 'medium', 'high', 'critical'
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class ScanResult:
    """Complete 10-layer scan result"""
    file_path: str
    file_hash: str
    file_size: int
    scan_timestamp: datetime
    
    # Layer results
    layer1_yara_matches: List[Dict] = field(default_factory=list)
    layer2_reputation: Dict = field(default_factory=dict)
    layer3_format_analysis: Dict = field(default_factory=dict)
    layer4_static_heuristics: Dict = field(default_factory=dict)
    layer5_context_evaluation: Dict = field(default_factory=dict)
    layer6_behavior_analysis: Dict = field(default_factory=dict)
    layer7_memory_artifacts: List[FileArtifact] = field(default_factory=list)
    layer8_static_ml: Dict = field(default_factory=dict)
    layer9_dynamic_ml: Dict = field(default_factory=dict)
    
    # Final decision
    scores: ScanScore = field(default_factory=ScanScore)
    final_decision: ScanDecision = ScanDecision.ALLOW
    threat_level: ThreatLevel = ThreatLevel.CLEAN
    threats_detected: List[str] = field(default_factory=list)
    mitigation_actions: List[str] = field(default_factory=list)


class Layer1YaraScannerAdvanced:
    """Layer 1: YARA Rule Scanning - High-confidence detection"""
    
    def __init__(self):
        self.yara_rules = {}
        self.rule_priorities = {}
        self.malware_families = set()
        self._load_rules()
    
    def _load_rules(self):
        """Load YARA rules by category"""
        try:
            # Determine project root - this file is at: src/sentinelx/services/ten_layer_file_scanning.py
            # Going up: services -> sentinelx -> src -> project_root (4 levels)
            import sys
            from pathlib import Path
            project_root = Path(__file__).parent.parent.parent.parent
            
            # Try to load yara-rules-full.yar as primary source
            rules_path = project_root / "rules" / "yara-rules-full.yar"
            if rules_path.exists():
                self.yara_rules['primary'] = yara.compile(filepath=str(rules_path.absolute()))
                self.rule_priorities['primary'] = 10  # Highest priority
                logger.info(f"Layer 1: Loaded yara-rules-full.yar from {rules_path}")
            else:
                logger.warning(f"Layer 1: YARA rules file not found at {rules_path}")
        except Exception as e:
            logger.warning(f"Layer 1: Could not load primary YARA rules: {e}")
    
    def scan_file(self, file_path: str) -> Tuple[float, List[Dict], Set[str]]:
        """
        Scan file with high-confidence YARA rules
        Returns: (confidence_score, matches, detected_families)
        """
        matches = []
        families = set()
        confidence = 0.0
        
        try:
            if not os.path.exists(file_path):
                return 0.0, [], set()
            
            for rule_set_name, rules in self.yara_rules.items():
                try:
                    yara_matches = rules.match(file_path)
                    
                    for match in yara_matches:
                        rule_match = {
                            'rule_name': match.rule,
                            'tags': list(match.tags),
                            'matches': len(match.strings),
                            'priority': self.rule_priorities.get(rule_set_name, 5),
                            'timestamp': datetime.now().isoformat()
                        }
                        matches.append(rule_match)
                        
                        # Extract malware family
                        if 'malware' in match.tags or 'trojan' in match.tags:
                            families.add(match.rule)
                            confidence = min(0.95, confidence + 0.3)
                
                except Exception as e:
                    logger.debug(f"Layer 1: YARA rule error: {e}")
            
            logger.info(f"Layer 1: Scanned {file_path} - {len(matches)} YARA matches")
            return confidence, matches, families
        
        except Exception as e:
            logger.error(f"Layer 1: YARA scan failed: {e}")
            return 0.0, [], set()


class Layer2ReputationIntelligence:
    """Layer 2: Hash and Reputation Intelligence"""
    
    def __init__(self):
        self.known_good_hashes = set()
        self.known_bad_hashes = set()
        self.reputation_scores = {}  # hash -> score (0-100)
        self.reputation_sources = []
        self._initialize_threat_feeds()
    
    def _initialize_threat_feeds(self):
        """Initialize threat intelligence feeds"""
        self.reputation_sources = [
            'virustotal',
            'internal_database',
            'industry_feeds',
            'custom_signatures'
        ]
    
    def compute_file_hash(self, file_path: str) -> Tuple[str, str]:
        """Compute MD5 and SHA256 hashes"""
        try:
            md5_hash = hashlib.md5()
            sha256_hash = hashlib.sha256()
            
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    md5_hash.update(chunk)
                    sha256_hash.update(chunk)
            
            return md5_hash.hexdigest(), sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"Layer 2: Hash computation failed: {e}")
            return "", ""
    
    def check_reputation(self, file_hash: str) -> Tuple[float, Dict]:
        """Check file reputation against threat feeds"""
        confidence = 0.0
        details = {
            'hash': file_hash,
            'in_whitelist': False,
            'in_blacklist': False,
            'reputation_score': 0.0,
            'sources': []
        }
        
        # Check known-good
        if file_hash in self.known_good_hashes:
            details['in_whitelist'] = True
            confidence = 0.0  # Known good = low risk
            logger.info(f"Layer 2: File whitelisted (hash: {file_hash[:8]}...)")
        
        # Check known-bad
        elif file_hash in self.known_bad_hashes:
            details['in_blacklist'] = True
            confidence = 0.95  # Known bad = very high risk
            logger.warning(f"Layer 2: File blacklisted (hash: {file_hash[:8]}...)")
        
        # Check reputation score
        elif file_hash in self.reputation_scores:
            score = self.reputation_scores[file_hash]
            details['reputation_score'] = score
            confidence = score / 100.0  # Convert to 0-1 range
            
            if score > 70:
                details['sources'].append('malicious_reputation')
        
        return confidence, details


class Layer3FileTypeValidation:
    """Layer 3: File Type Validation and Format Sanity Checks"""
    
    def __init__(self):
        self.file_signatures = {
            b'\x4d\x5a\x90\x00': 'PE_EXECUTABLE',  # MZ header (EXE/DLL)
            b'\x50\x4b\x03\x04': 'ZIP',  # ZIP
            b'\x89\x50\x4e\x47': 'PNG',  # PNG
            b'\xff\xd8\xff\xe0': 'JPEG',  # JPEG (JFIF)
            b'\x25\x50\x44\x46': 'PDF',  # PDF
            b'\xd0\xcf\x11\xe0': 'OLE2',  # OLE2 (Office)
        }
        self.dangerous_combinations = []
    
    def validate_file_type(self, file_path: str) -> Tuple[float, Dict]:
        """Validate file type and format integrity"""
        confidence = 0.0
        details = {
            'declared_type': '',
            'actual_type': '',
            'type_match': False,
            'format_anomalies': [],
            'is_polyglot': False,
            'has_embedded_executables': False,
            'is_malformed': False
        }
        
        try:
            # Get declared type from extension
            _, ext = os.path.splitext(file_path)
            details['declared_type'] = ext.lower()
            
            # Read file header
            with open(file_path, 'rb') as f:
                header = f.read(512)
            
            # Detect actual type
            for signature, file_type in self.file_signatures.items():
                if header.startswith(signature):
                    details['actual_type'] = file_type
                    break
            
            # Check for type mismatch
            if details['declared_type'] and details['actual_type']:
                # Map extension to file type
                ext_map = {
                    '.exe': 'PE_EXECUTABLE',
                    '.dll': 'PE_EXECUTABLE',
                    '.zip': 'ZIP',
                    '.pdf': 'PDF',
                    '.png': 'PNG',
                    '.jpg': 'JPEG',
                }
                
                expected_type = ext_map.get(details['declared_type'])
                if expected_type and expected_type != details['actual_type']:
                    details['format_anomalies'].append(f"Type mismatch: {expected_type} vs {details['actual_type']}")
                    confidence = 0.7
                else:
                    details['type_match'] = True
            
            # Check for polyglot files (multiple file types)
            signature_count = sum(1 for sig in self.file_signatures.keys() if sig in header)
            if signature_count > 1:
                details['is_polyglot'] = True
                details['format_anomalies'].append("Polyglot file detected (multiple signatures)")
                confidence = max(confidence, 0.6)
            
            logger.info(f"Layer 3: Validated {file_path} - Type: {details['actual_type']}")
            return confidence, details
        
        except Exception as e:
            logger.error(f"Layer 3: File type validation failed: {e}")
            details['is_malformed'] = True
            return 0.5, details


class Layer4StaticHeuristics:
    """Layer 4: Static Structural Heuristics (non-ML)"""
    
    def __init__(self):
        self.entropy_threshold = 7.0  # High entropy = compression/encryption
        self.suspicious_strings = [
            b'WinExec',
            b'CreateProcessA',
            b'LoadLibrary',
            b'GetProcAddress',
            b'CreateRemoteThread',
            b'WriteProcessMemory',
            b'VirtualAllocEx',
            b'SetWindowsHookEx',
            b'CreateService',
        ]
    
    def analyze_entropy(self, file_path: str) -> Tuple[float, float]:
        """Calculate file entropy"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            if not data:
                return 0.0, 0.0
            
            # Calculate Shannon entropy
            entropy_dict = defaultdict(int)
            for byte in data:
                entropy_dict[byte] += 1
            
            entropy = 0.0
            for count in entropy_dict.values():
                probability = count / len(data)
                entropy -= probability * (probability and __import__('math').log2(probability) or 0)
            
            # High entropy indicates compression or encryption
            confidence = 0.0
            if entropy > self.entropy_threshold:
                confidence = 0.3  # Suspicious but not conclusive
            
            return confidence, entropy
        
        except Exception as e:
            logger.error(f"Layer 4: Entropy analysis failed: {e}")
            return 0.0, 0.0
    
    def analyze_structure(self, file_path: str) -> Tuple[float, Dict]:
        """Analyze PE file structure"""
        confidence = 0.0
        details = {
            'suspicious_imports': [],
            'suspicious_strings_found': [],
            'obfuscation_indicators': [],
            'section_anomalies': []
        }
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Check for suspicious strings
            for suspicious_str in self.suspicious_strings:
                if suspicious_str in data:
                    details['suspicious_strings_found'].append(suspicious_str.decode('utf-8', errors='ignore'))
                    confidence = max(confidence, 0.2)
            
            # Check for code obfuscation patterns
            if data.count(b'\x00') > len(data) * 0.1:  # >10% null bytes
                details['obfuscation_indicators'].append("High null byte density")
                confidence = max(confidence, 0.3)
            
            logger.info(f"Layer 4: Structural analysis complete - {len(details['suspicious_strings_found'])} suspicious indicators")
            return confidence, details
        
        except Exception as e:
            logger.error(f"Layer 4: Structure analysis failed: {e}")
            return 0.0, details


class Layer5ContextualEvaluation:
    """Layer 5: Policy and Context Evaluation"""
    
    def __init__(self):
        self.risk_contexts = defaultdict(float)
        self.high_risk_origins = [
            'email_attachment',
            'external_usb',
            'untrusted_network',
            'download_folder'
        ]
        self.execution_intents = {
            'script_execution': 0.5,
            'macro_execution': 0.6,
            'network_access': 0.4,
            'system_binary': 0.2
        }
    
    def evaluate_context(self, file_path: str, origin: str = None, user_privilege: str = 'user',
                        target_type: str = 'workstation', execution_intent: str = None) -> Tuple[float, Dict]:
        """Evaluate file in delivery and execution context"""
        confidence = 0.0
        details = {
            'origin': origin or 'unknown',
            'user_privilege': user_privilege,
            'target_type': target_type,
            'execution_intent': execution_intent or 'unknown',
            'risk_factors': [],
            'sandbox_depth_recommendation': 'shallow'
        }
        
        # Assess origin risk
        if origin in self.high_risk_origins:
            details['risk_factors'].append(f"High-risk origin: {origin}")
            confidence = max(confidence, 0.4)
        
        # Assess execution intent
        if execution_intent and execution_intent in self.execution_intents:
            intent_risk = self.execution_intents[execution_intent]
            details['risk_factors'].append(f"Execution intent: {execution_intent}")
            confidence = max(confidence, intent_risk)
        
        # Assess privilege level
        if user_privilege == 'admin':
            details['sandbox_depth_recommendation'] = 'deep'
            confidence = max(confidence, 0.3)
        
        logger.info(f"Layer 5: Context evaluated - origin={details['origin']}, intent={details['execution_intent']}")
        return confidence, details


class Layer6DynamicBehaviorAnalysis:
    """Layer 6: Rule-Based Dynamic Behavior Analysis"""
    
    def __init__(self):
        self.behavior_rules = self._initialize_behavior_rules()
        self.suspicious_behaviors = []
    
    def _initialize_behavior_rules(self) -> List[Dict]:
        """Initialize behavioral detection rules"""
        return [
            {'name': 'persistence_registry', 'pattern': 'HKCU\\Run', 'severity': 'high'},
            {'name': 'persistence_startup', 'pattern': 'Startup folder', 'severity': 'high'},
            {'name': 'process_injection', 'pattern': 'WriteProcessMemory', 'severity': 'critical'},
            {'name': 'credential_access', 'pattern': 'credential|password|token', 'severity': 'high'},
            {'name': 'network_cc', 'pattern': 'DNS lookup|HTTP POST|SMTP', 'severity': 'high'},
            {'name': 'privilege_escalation', 'pattern': 'UAC bypass|privilege', 'severity': 'critical'},
            {'name': 'environment_detection', 'pattern': 'vmware|virtualbox|debugger', 'severity': 'medium'},
        ]
    
    def analyze_behavior(self, file_path: str) -> Tuple[float, Dict, List[Dict]]:
        """Analyze file behavior in sandbox"""
        confidence = 0.0
        details = {
            'behaviors_detected': [],
            'persistence_found': False,
            'injection_detected': False,
            'credential_access': False,
            'c2_communication': False,
            'evasion_detected': False
        }
        behaviors = []
        
        # Simulate sandbox execution analysis
        logger.info(f"Layer 6: Analyzing behavior of {file_path}")
        
        # This would integrate with actual sandbox (Cuckoo, etc.)
        # For now, simulate behavior detection
        
        return confidence, details, behaviors


class Layer7MemoryArtifactExtraction:
    """Layer 7: Memory Dumping and Runtime Artifact Extraction"""
    
    def __init__(self):
        self.memory_artifacts = []
        self.unpacked_payloads = []
        self.injected_code_patterns = []
    
    def extract_memory_artifacts(self, process_id: int = None) -> Tuple[float, List[FileArtifact], Dict]:
        """Extract and analyze memory artifacts"""
        confidence = 0.0
        artifacts = []
        details = {
            'artifacts_extracted': 0,
            'unpacked_payloads_found': False,
            'injected_code_found': False,
            'reflective_dlls_found': False,
            'shellcode_detected': False
        }
        
        logger.info(f"Layer 7: Extracting memory artifacts (PID: {process_id})")
        
        # This would use real memory forensics tools
        # For now, provide framework for integration
        
        return confidence, artifacts, details


class Layer8StaticMLClassification:
    """Layer 8: AI-Assisted Static Malware Classification
    
    Integrates multiple ML models:
    1. EMBER (Endgame Malware BEnchmark) - LIEF-based static analysis
    2. LightGBM - Traditional gradient boosting model
    """
    
    def __init__(self):
        """Initialize Layer 8 with EMBER and LightGBM models"""
        self.feature_extractors = ['bytes', 'opcodes', 'strings', 'metadata']
        self.ml_model = None
        self.ember_model = None
        
        # Try to load EMBER
        try:
            from sentinelx.layers.ai_layer import EMBERLayer
            self.ember_model = EMBERLayer()
            logger.info("Layer 8: EMBER model initialized")
        except Exception as e:
            logger.warning(f"Layer 8: Could not initialize EMBER: {e}")
        
        # Try to load LightGBM
        try:
            from sentinelx.layers.ai_layer import LightGBMLayer
            self.lgbm_model = LightGBMLayer()
            logger.info("Layer 8: LightGBM model initialized")
        except Exception as e:
            logger.warning(f"Layer 8: Could not initialize LightGBM: {e}")
    
    def extract_static_features(self, file_path: str) -> Dict:
        """Extract static features for ML analysis"""
        features = {
            'file_size': 0,
            'entropy': 0.0,
            'import_count': 0,
            'string_patterns': [],
            'byte_patterns': [],
            'opcode_patterns': [],
            'section_count': 0
        }
        
        try:
            features['file_size'] = os.path.getsize(file_path)
            logger.info(f"Layer 8: Extracted static features from {file_path}")
        except Exception as e:
            logger.error(f"Layer 8: Feature extraction failed: {e}")
        
        return features
    
    def classify_file(self, file_path: str) -> Tuple[float, Dict]:
        """
        Classify file using ML models (EMBER + LightGBM ensemble)
        Returns: (confidence_score, details)
        """
        features = self.extract_static_features(file_path)
        
        confidence = 0.0
        ml_scores = {}
        
        # Try EMBER model first (higher priority for PE files)
        ember_score = None
        if self.ember_model is not None:
            try:
                ember_result = self.ember_model.predict(file_path)
                if ember_result:
                    ember_score = {
                        'score': ember_result.maliciousness_score,
                        'is_malicious': ember_result.is_malicious,
                        'confidence': ember_result.confidence,
                        'model': 'EMBER'
                    }
                    ml_scores['ember'] = ember_score
                    confidence = max(confidence, ember_result.confidence)
                    logger.info(f"Layer 8: EMBER score={ember_result.maliciousness_score:.4f} "
                              f"for {file_path}")
            except Exception as e:
                logger.debug(f"Layer 8: EMBER prediction failed: {e}")
        
        # Try LightGBM model as ensemble
        lgbm_score = None
        if hasattr(self, 'lgbm_model') and self.lgbm_model is not None:
            try:
                lgbm_result = self.lgbm_model.predict(file_path)
                if lgbm_result:
                    lgbm_score = {
                        'score': lgbm_result.maliciousness_score,
                        'is_malicious': lgbm_result.is_malicious,
                        'confidence': lgbm_result.confidence,
                        'model': 'LightGBM'
                    }
                    ml_scores['lgbm'] = lgbm_score
                    confidence = max(confidence, lgbm_result.confidence)
                    logger.info(f"Layer 8: LightGBM score={lgbm_result.maliciousness_score:.4f} "
                              f"for {file_path}")
            except Exception as e:
                logger.debug(f"Layer 8: LightGBM prediction failed: {e}")
        
        # Calculate ensemble score if both available
        ensemble_score = 0.5  # Default neutral
        if ember_score and lgbm_score:
            ensemble_score = (ember_score['score'] + lgbm_score['score']) / 2.0
            ml_scores['ensemble'] = {
                'score': ensemble_score,
                'models': ['EMBER', 'LightGBM']
            }
        elif ember_score:
            ensemble_score = ember_score['score']
        elif lgbm_score:
            ensemble_score = lgbm_score['score']
        
        details = {
            'features_extracted': len(features),
            'ml_score': ensemble_score,
            'predicted_class': 'malicious' if ensemble_score >= 0.5 else 'benign',
            'top_indicators': list(ml_scores.keys()),
            'model_scores': ml_scores,
            'models_used': list(ml_scores.keys())
        }
        
        logger.info(f"Layer 8: ML classification complete for {file_path} - final score={ensemble_score:.4f}")
        
        return confidence, details


class Layer9DynamicMLAnalysis:
    """Layer 9: AI-Assisted Dynamic and Memory Behavior Analysis"""
    
    def __init__(self):
        self.behavior_model = None  # Would load advanced ML model
        self.anomaly_detector = None
    
    def analyze_execution_traces(self, trace_data: List[Dict]) -> Tuple[float, Dict]:
        """Analyze execution traces using ML"""
        confidence = 0.0
        details = {
            'system_calls_analyzed': len(trace_data),
            'anomalies_detected': [],
            'process_graph_analysis': {},
            'memory_pattern_score': 0.0,
            'low_slow_attack_detected': False
        }
        
        logger.info(f"Layer 9: Analyzing execution traces ({len(trace_data)} calls)")
        
        return confidence, details


class Layer10CorrelationScoring:
    """Layer 10: Correlation, Scoring, and Response Orchestration"""
    
    def __init__(self):
        self.layer_weights = {
            1: 0.15,  # YARA
            2: 0.20,  # Reputation
            3: 0.10,  # Format
            4: 0.12,  # Heuristics
            5: 0.08,  # Context
            6: 0.12,  # Behavior
            7: 0.08,  # Memory
            8: 0.10,  # Static ML
            9: 0.05   # Dynamic ML
        }
        self.decision_thresholds = {
            'allow': 0.2,
            'quarantine': 0.5,
            'block': 0.7,
            'isolate': 0.85,
            'escalate': 0.95
        }
    
    def correlate_and_score(self, scores: ScanScore) -> Tuple[ScanDecision, float, ThreatLevel]:
        """Correlate all layer scores and make final decision"""
        
        # Aggregate weighted scores
        total_score = (
            scores.layer1_yara_score * self.layer_weights[1] +
            scores.layer2_reputation_score * self.layer_weights[2] +
            scores.layer3_format_score * self.layer_weights[3] +
            scores.layer4_heuristics_score * self.layer_weights[4] +
            scores.layer5_context_score * self.layer_weights[5] +
            scores.layer6_behavior_score * self.layer_weights[6] +
            scores.layer7_memory_score * self.layer_weights[7] +
            scores.layer8_static_ml_score * self.layer_weights[8] +
            scores.layer9_dynamic_ml_score * self.layer_weights[9]
        )
        
        # Determine decision
        decision = ScanDecision.ALLOW
        threat_level = ThreatLevel.CLEAN
        
        if total_score >= self.decision_thresholds['escalate']:
            decision = ScanDecision.ESCALATE
            threat_level = ThreatLevel.CRITICAL
        elif total_score >= self.decision_thresholds['isolate']:
            decision = ScanDecision.ISOLATE
            threat_level = ThreatLevel.CRITICAL
        elif total_score >= self.decision_thresholds['block']:
            decision = ScanDecision.BLOCK
            threat_level = ThreatLevel.MALWARE
        elif total_score >= self.decision_thresholds['quarantine']:
            decision = ScanDecision.QUARANTINE
            threat_level = ThreatLevel.SUSPICIOUS
        
        return decision, total_score, threat_level


class TenLayerFileScanner:
    """
    Complete 10-Layer Advanced File Scanner
    Cascading detection for maximum coverage
    """
    
    def __init__(self):
        self.layer1 = Layer1YaraScannerAdvanced()
        self.layer2 = Layer2ReputationIntelligence()
        self.layer3 = Layer3FileTypeValidation()
        self.layer4 = Layer4StaticHeuristics()
        self.layer5 = Layer5ContextualEvaluation()
        self.layer6 = Layer6DynamicBehaviorAnalysis()
        self.layer7 = Layer7MemoryArtifactExtraction()
        self.layer8 = Layer8StaticMLClassification()
        self.layer9 = Layer9DynamicMLAnalysis()
        self.layer10 = Layer10CorrelationScoring()
        
        self.scan_results = []
        self.threat_feed = []
        
        logger.info("=" * 80)
        logger.info("10-Layer Advanced File Scanner initialized")
        logger.info("Layers: YARA → Reputation → Format → Heuristics → Context →")
        logger.info("        Behavior → Memory → Static ML → Dynamic ML → Orchestration")
        logger.info("=" * 80)
    
    def scan_file(self, file_path: str, origin: str = None, user_privilege: str = 'user',
                  target_type: str = 'workstation', execution_intent: str = None) -> ScanResult:
        """
        Execute comprehensive 10-layer scan on file
        """
        logger.info(f"\n{'='*80}")
        logger.info(f"STARTING 10-LAYER SCAN: {file_path}")
        logger.info(f"{'='*80}")
        
        scan_start = datetime.now()
        
        # Get file info
        try:
            file_size = os.path.getsize(file_path)
        except:
            file_size = 0
        
        md5_hash, sha256_hash = self.layer2.compute_file_hash(file_path)
        
        # Initialize result
        result = ScanResult(
            file_path=file_path,
            file_hash=sha256_hash,
            file_size=file_size,
            scan_timestamp=datetime.now()
        )
        
        scores = ScanScore()
        
        # LAYER 1: YARA Scanning
        logger.info("\n[LAYER 1] YARA Rule Scanning...")
        l1_conf, l1_matches, l1_families = self.layer1.scan_file(file_path)
        scores.layer1_yara_score = l1_conf
        result.layer1_yara_matches = l1_matches
        logger.info(f"[LAYER 1] Confidence: {l1_conf:.2%} | Matches: {len(l1_matches)}")
        
        # LAYER 2: Reputation Intelligence
        logger.info("\n[LAYER 2] Hash & Reputation Intelligence...")
        l2_conf, l2_rep = self.layer2.check_reputation(sha256_hash)
        scores.layer2_reputation_score = l2_conf
        result.layer2_reputation = l2_rep
        logger.info(f"[LAYER 2] Confidence: {l2_conf:.2%} | Status: {'Blacklisted' if l2_rep['in_blacklist'] else 'Checking feeds'}")
        
        # LAYER 3: File Type Validation
        logger.info("\n[LAYER 3] File Type Validation...")
        l3_conf, l3_validation = self.layer3.validate_file_type(file_path)
        scores.layer3_format_score = l3_conf
        result.layer3_format_analysis = l3_validation
        logger.info(f"[LAYER 3] Confidence: {l3_conf:.2%} | Type: {l3_validation.get('actual_type', 'Unknown')}")
        
        # LAYER 4: Static Heuristics
        logger.info("\n[LAYER 4] Static Structural Heuristics...")
        l4_entropy_conf, l4_entropy = self.layer4.analyze_entropy(file_path)
        l4_struct_conf, l4_struct = self.layer4.analyze_structure(file_path)
        l4_conf = max(l4_entropy_conf, l4_struct_conf)
        scores.layer4_heuristics_score = l4_conf
        result.layer4_static_heuristics = {'entropy': l4_entropy, 'structure': l4_struct}
        logger.info(f"[LAYER 4] Confidence: {l4_conf:.2%} | Entropy: {l4_entropy:.2f} | Suspicious Strings: {len(l4_struct['suspicious_strings_found'])}")
        
        # LAYER 5: Context Evaluation
        logger.info("\n[LAYER 5] Policy & Context Evaluation...")
        l5_conf, l5_context = self.layer5.evaluate_context(
            file_path, origin, user_privilege, target_type, execution_intent
        )
        scores.layer5_context_score = l5_conf
        result.layer5_context_evaluation = l5_context
        logger.info(f"[LAYER 5] Confidence: {l5_conf:.2%} | Origin: {l5_context['origin']} | Sandbox Depth: {l5_context['sandbox_depth_recommendation']}")
        
        # LAYER 6: Dynamic Behavior Analysis
        logger.info("\n[LAYER 6] Dynamic Behavior Analysis...")
        l6_conf, l6_behavior, l6_behaviors = self.layer6.analyze_behavior(file_path)
        scores.layer6_behavior_score = l6_conf
        result.layer6_behavior_analysis = l6_behavior
        logger.info(f"[LAYER 6] Confidence: {l6_conf:.2%} | Behaviors: {len(l6_behaviors)}")
        
        # LAYER 7: Memory Artifact Extraction
        logger.info("\n[LAYER 7] Memory Artifact Extraction...")
        l7_conf, l7_artifacts, l7_memory = self.layer7.extract_memory_artifacts()
        scores.layer7_memory_score = l7_conf
        result.layer7_memory_artifacts = l7_artifacts
        logger.info(f"[LAYER 7] Confidence: {l7_conf:.2%} | Artifacts: {len(l7_artifacts)}")
        
        # LAYER 8: Static ML Classification
        logger.info("\n[LAYER 8] Static ML Classification...")
        l8_conf, l8_ml = self.layer8.classify_file(file_path)
        scores.layer8_static_ml_score = l8_conf
        result.layer8_static_ml = l8_ml
        logger.info(f"[LAYER 8] Confidence: {l8_conf:.2%} | ML Score: {l8_ml.get('ml_score', 0):.2%}")
        
        # LAYER 9: Dynamic ML Analysis
        logger.info("\n[LAYER 9] Dynamic ML Behavior Analysis...")
        l9_conf, l9_ml = self.layer9.analyze_execution_traces([])
        scores.layer9_dynamic_ml_score = l9_conf
        result.layer9_dynamic_ml = l9_ml
        logger.info(f"[LAYER 9] Confidence: {l9_conf:.2%} | Anomalies: {len(l9_ml.get('anomalies_detected', []))}")
        
        # LAYER 10: Correlation & Final Decision
        logger.info("\n[LAYER 10] Correlation, Scoring & Response Orchestration...")
        final_decision, final_score, threat_level = self.layer10.correlate_and_score(scores)
        
        scores.final_risk_score = final_score
        scores.decision = final_decision
        scores.threat_level = threat_level
        scores.confidence = final_score
        
        result.scores = scores
        result.final_decision = final_decision
        result.threat_level = threat_level
        
        # Generate threats and mitigations
        result.threats_detected = list(l1_families)
        if l2_rep['in_blacklist']:
            result.threats_detected.append("Known Malware (Blacklist)")
        if l3_validation['is_polyglot']:
            result.threats_detected.append("Polyglot File")
        if l4_struct['suspicious_strings_found']:
            result.threats_detected.append("Suspicious Imports/Strings")
        
        # Mitigation actions based on decision
        if final_decision == ScanDecision.BLOCK:
            result.mitigation_actions.append("BLOCK: File execution prevented")
            result.mitigation_actions.append("DELETE: Remove from system")
        elif final_decision == ScanDecision.QUARANTINE:
            result.mitigation_actions.append("QUARANTINE: Isolate in secure vault")
            result.mitigation_actions.append("MONITOR: Track for execution attempts")
        elif final_decision == ScanDecision.ISOLATE:
            result.mitigation_actions.append("ISOLATE: Quarantine host system")
            result.mitigation_actions.append("CONTAIN: Block network access")
        elif final_decision == ScanDecision.ESCALATE:
            result.mitigation_actions.append("ESCALATE: Send to human security team")
            result.mitigation_actions.append("ALERT: Create high-priority incident")
        
        scan_duration = (datetime.now() - scan_start).total_seconds()
        
        logger.info(f"\n{'='*80}")
        logger.info(f"10-LAYER SCAN COMPLETE")
        logger.info(f"File: {file_path}")
        logger.info(f"Hash: {sha256_hash[:16]}...")
        logger.info(f"Final Risk Score: {final_score:.2%}")
        logger.info(f"Threat Level: {threat_level.value.upper()}")
        logger.info(f"Decision: {final_decision.value.upper()}")
        logger.info(f"Scan Duration: {scan_duration:.2f} seconds")
        logger.info(f"Mitigations: {len(result.mitigation_actions)}")
        logger.info(f"{'='*80}\n")
        
        self.scan_results.append(result)
        return result
    
    def get_scan_summary(self, result: ScanResult) -> Dict:
        """Generate scan summary"""
        return {
            'file': result.file_path,
            'hash': result.file_hash[:16] + "...",
            'threat_level': result.threat_level.value,
            'final_decision': result.final_decision.value,
            'risk_score': result.scores.final_risk_score,
            'threats_found': len(result.threats_detected),
            'threat_list': result.threats_detected,
            'actions_taken': result.mitigation_actions,
            'scan_time': result.scan_timestamp.isoformat()
        }
    
    def export_scan_result(self, result: ScanResult, output_path: str):
        """Export detailed scan result to JSON"""
        try:
            export_data = {
                'file_path': result.file_path,
                'file_hash': result.file_hash,
                'file_size': result.file_size,
                'scan_timestamp': result.scan_timestamp.isoformat(),
                'layer_results': {
                    'layer1_yara': result.layer1_yara_matches,
                    'layer2_reputation': result.layer2_reputation,
                    'layer3_format': result.layer3_format_analysis,
                    'layer4_heuristics': result.layer4_static_heuristics,
                    'layer5_context': result.layer5_context_evaluation,
                    'layer6_behavior': result.layer6_behavior_analysis,
                },
                'final_decision': result.final_decision.value,
                'threat_level': result.threat_level.value,
                'risk_score': result.scores.final_risk_score,
                'threats_detected': result.threats_detected,
                'mitigations': result.mitigation_actions
            }
            
            with open(output_path, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            logger.info(f"Scan result exported to: {output_path}")
        except Exception as e:
            logger.error(f"Failed to export scan result: {e}")
