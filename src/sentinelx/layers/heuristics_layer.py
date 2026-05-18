"""
Non-AI Heuristics Layer: Behavioral and structural analysis without ML.
Detects suspicious patterns through static analysis, entropy, imports, and behaviors.
"""
import os
import struct
import math
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass
from sentinelx.utils.logger import get_logger

logger = get_logger(__name__)

# Import malwi for AI-based malware detection
try:
    from common.malwi_object import disassemble_file_ast
    from common.config import EXTENSION_TO_LANGUAGE
    MALWI_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    MALWI_AVAILABLE = False
    logger.debug("Malwi package not available, using basic heuristics only")


@dataclass
class HeuristicScore:
    """Heuristic analysis result."""
    entropy_score: float  # 0-1, higher = more suspicious
    import_score: float  # 0-1 based on dangerous imports
    section_score: float  # 0-1 based on PE sections
    behavior_score: float  # 0-1 based on behavioral patterns
    compression_score: float  # 0-1 if file appears packed/compressed
    overall_heuristic_score: float  # Weighted average
    flags: List[str]  # List of triggered heuristics
    is_suspicious: bool  # Overall verdict
    malwi_score: float = 0.0  # 0-1 malwi maliciousness score
    malwi_flagged: bool = False  # Whether malwi flagged the file


class NonAIHeuristicsLayer:
    """
    Heuristic-based malware detection without AI/ML.
    Analyzes file structure, imports, entropy, and behavior patterns.
    """
    
    def __init__(self):
        """Initialize heuristics layer."""
        self.dangerous_imports = {
            'CreateRemoteThread': 10,
            'WriteProcessMemory': 10,
            'VirtualAllocEx': 9,
            'SetWindowsHookEx': 8,
            'GetProcAddress': 7,
            'LoadLibrary': 6,
            'CreateProcess': 8,
            'WinExec': 9,
            'ShellExecute': 8,
            'RegOpenKey': 6,
            'RegSetValue': 7,
            'InternetConnect': 7,
            'InternetReadFile': 6,
            'CreateService': 10,
            'OpenService': 9,
            'StartService': 9,
            'SetFilePointer': 5,
            'ReadFile': 5,
            'WriteFile': 5,
            'FindFirst': 5,
            'GetSystemDirectory': 5,
            'GetWindowsDirectory': 5,
        }
        
        self.suspicious_strings = {
            'cmd.exe': 7,
            'powershell': 8,
            'WScript.Shell': 9,
            'CreateObject': 6,
            'rundll32': 8,
            'regsvr32': 8,
            'certutil': 7,
            'mshta': 8,
            'cscript': 8,
            'wscript': 8,
            'vbscript': 7,
            'javascript': 6,
            'CreateRemoteThread': 10,
            'inject': 9,
            'shellcode': 10,
            'exploit': 10,
            'backdoor': 10,
            'trojan': 9,
            'rootkit': 10,
            'ransomware': 10,
            'cryptolocker': 10,
            'bitcoin': 8,
            'monero': 8,
            # Keylogger-specific patterns
            'keylog': 10,
            'keystroke': 10,
            'keyboard': 9,
            'SetWindowsHookEx': 10,
            'WH_KEYBOARD_LL': 10,
            'GetAsyncKeyState': 9,
            'keylogger': 10,
            'key capture': 9,
            'keystroke logging': 10,
            'clipboard': 8,
            'screen capture': 9,
            'screenshot': 8,
            'hybrid-analysis': 7,
            'cuckoo': 6,
            # Credential theft patterns
            'password': 8,
            'credential': 9,
            'auth': 6,
            'login': 7,
            'browser': 7,
            'chrome': 6,
            'firefox': 6,
            'internet explorer': 6,
            'edge': 5,
        }
        
        self.pe_suspicious_sections = {
            '.text': 1,
            '.data': 2,
            '.rsrc': 1,
            '.code': 3,
            '.packed': 10,
            '.encrypted': 10,
            '.obfuscated': 10,
            '.upx': 8,
            '.aspack': 8,
            '.petite': 8,
        }
        
        logger.info("Non-AI Heuristics Layer initialized")
    
    def analyze_file(self, file_path: str) -> HeuristicScore:
        """
        Perform comprehensive heuristic analysis on file.
        
        Args:
            file_path: Path to file to analyze
            
        Returns:
            HeuristicScore with detailed analysis
        """
        flags = []
        scores = {}
        
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read(min(len(open(file_path, 'rb').read()), 10 * 1024 * 1024))  # First 10MB
            
            # Calculate entropy
            entropy_score = self._calculate_entropy(file_data)
            scores['entropy'] = entropy_score
            if entropy_score > 7.5:
                flags.append(f"HIGH_ENTROPY[{entropy_score:.2f}]")
            
            # Check for compression/packing
            compression_score = self._detect_compression(file_data)
            scores['compression'] = compression_score
            if compression_score > 0.7:
                flags.append(f"COMPRESSION_DETECTED[{compression_score:.2f}]")
            
            # Analyze file structure
            section_score = self._analyze_sections(file_data)
            scores['section'] = section_score
            if section_score > 0.6:
                flags.append(f"SUSPICIOUS_SECTIONS[{section_score:.2f}]")
            
            # Check imports and strings
            import_score, dangerous_imports = self._analyze_imports(file_data)
            scores['import'] = import_score
            if dangerous_imports:
                for imp in dangerous_imports[:3]:  # Top 3
                    flags.append(f"IMPORT[{imp}]")
            
            # Behavioral analysis
            behavior_score = self._analyze_behavior(file_data, file_path)
            scores['behavior'] = behavior_score
            if behavior_score > 0.5:
                flags.append(f"SUSPICIOUS_BEHAVIOR[{behavior_score:.2f}]")
            
            # Malwi AI-based analysis (if available)
            malwi_score = 0.0
            malwi_flagged = False
            if MALWI_AVAILABLE:
                malwi_score, malwi_flagged = self._analyze_with_malwi(file_path)
                scores['malwi'] = malwi_score
                if malwi_flagged:
                    flags.append(f"MALWI_FLAGGED[{malwi_score:.4f}]")
            
            # Calculate overall score (weighted average)
            # Include malwi if available and has high confidence
            if MALWI_AVAILABLE and malwi_score > 0.3:
                # Malwi is high-confidence, weight it heavily
                overall_score = (
                    entropy_score * 0.15 +
                    import_score * 0.20 +
                    section_score * 0.10 +
                    behavior_score * 0.10 +
                    compression_score * 0.05 +
                    malwi_score * 0.40  # Heavy weight on malwi when confident
                )
            else:
                # Normal weighting without strong malwi signal
                overall_score = (
                    entropy_score * 0.25 +
                    import_score * 0.35 +
                    section_score * 0.15 +
                    behavior_score * 0.15 +
                    compression_score * 0.10
                )
                if MALWI_AVAILABLE:
                    # Add small malwi boost if available
                    overall_score = min(0.99, overall_score + (malwi_score * 0.05))
            
            is_suspicious = overall_score > 0.6 or compression_score > 0.8 or (MALWI_AVAILABLE and malwi_flagged)
            
            logger.debug(f"[HEURISTICS] {file_path} - Overall: {overall_score:.4f} | Entropy: {entropy_score:.2f} | "
                        f"Imports: {import_score:.2f} | Sections: {section_score:.2f} | Behavior: {behavior_score:.2f} | "
                        f"Malwi: {malwi_score:.4f}")
            
            return HeuristicScore(
                entropy_score=entropy_score,
                import_score=import_score,
                section_score=section_score,
                behavior_score=behavior_score,
                compression_score=compression_score,
                overall_heuristic_score=overall_score,
                flags=flags,
                is_suspicious=is_suspicious,
                malwi_score=malwi_score,
                malwi_flagged=malwi_flagged
            )
            
        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {e}")
            return HeuristicScore(
                entropy_score=0.0,
                import_score=0.0,
                section_score=0.0,
                behavior_score=0.0,
                compression_score=0.0,
                overall_heuristic_score=0.0,
                flags=[f"ANALYSIS_ERROR[{str(e)}]"],
                is_suspicious=False,
                malwi_score=0.0,
                malwi_flagged=False
            )
    
    def _calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of file data.
        Higher entropy suggests compression, encryption, or obfuscation.
        Returns 0-8 scale.
        """
        if len(data) == 0:
            return 0.0
        
        # Calculate frequency of each byte
        frequency = {}
        for byte in data:
            frequency[byte] = frequency.get(byte, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        for count in frequency.values():
            probability = count / len(data)
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _detect_compression(self, data: bytes) -> float:
        """
        Detect if file is compressed or packed.
        Returns 0-1 confidence score.
        """
        if len(data) < 2:
            return 0.0
        
        score = 0.0
        
        # Check for common compression signatures
        compression_sigs = {
            b'PK': 0.8,  # ZIP
            b'\x1f\x8b': 0.8,  # GZIP
            b'BZh': 0.8,  # BZIP2
            b'7z': 0.8,  # 7z
            b'Rar': 0.8,  # RAR
            b'UPX': 0.9,  # UPX packer
            b'!<arch>': 0.7,  # Archive
        }
        
        for sig, sig_score in compression_sigs.items():
            if data.startswith(sig):
                score = max(score, sig_score)
        
        # Check entropy - high entropy suggests compression
        entropy = self._calculate_entropy(data)
        if entropy > 7.5:
            score = max(score, 0.7)
        
        return score
    
    def _analyze_sections(self, data: bytes) -> float:
        """
        Analyze PE file sections for suspicious characteristics.
        Returns 0-1 suspicion score.
        """
        if not data.startswith(b'MZ'):
            return 0.2  # Non-PE file, low section score
        
        try:
            # Simple PE header check
            if len(data) < 64:
                return 0.0
            
            # Get PE offset
            pe_offset = struct.unpack('<I', data[60:64])[0]
            if pe_offset > len(data) or pe_offset < 64:
                return 0.4
            
            # Check PE signature
            if data[pe_offset:pe_offset+2] != b'PE':
                return 0.5
            
            score = 0.0
            suspicious_count = 0
            
            # Look for suspicious section names in file
            suspicious_sections = ['.packed', '.encrypted', '.obfuscated', '.code', '.upx', '.aspack']
            for section in suspicious_sections:
                if section.encode() in data:
                    suspicious_count += 1
                    score += 0.2
            
            # Writable code section check
            if b'.text' in data and b'EXECUTE' in data:
                score += 0.15
            
            return min(score, 1.0)
            
        except Exception:
            return 0.1
    
    def _analyze_imports(self, data: bytes) -> tuple:
        """
        Analyze imported functions for dangerous ones.
        Returns (score, list_of_dangerous_imports).
        """
        dangerous_found = []
        total_score = 0.0
        
        # Search for import names in data
        for import_name, severity in self.dangerous_imports.items():
            if import_name.encode() in data:
                dangerous_found.append(import_name)
                total_score += severity
        
        # Normalize score to 0-1
        if dangerous_found:
            avg_score = total_score / (len(dangerous_found) * 10)
            return min(avg_score, 1.0), dangerous_found[:5]
        
        return 0.0, []
    
    def _analyze_behavior(self, data: bytes, file_path: str) -> float:
        """
        Analyze file for suspicious behavioral strings.
        Returns 0-1 suspicion score.
        """
        score = 0.0
        found_behaviors = []
        
        # Check file extension
        extension = Path(file_path).suffix.lower()
        if extension in ['.exe', '.dll', '.sys', '.scr', '.vbs', '.js', '.bat', '.cmd']:
            score += 0.1
        
        # Search for suspicious strings
        for behavior, severity in self.suspicious_strings.items():
            if behavior.encode().lower() in data.lower():
                found_behaviors.append(behavior)
                score += severity / 10
        
        # Multiple suspicious behaviors increase suspicion significantly
        if len(found_behaviors) > 3:
            score += 0.2
        elif len(found_behaviors) > 1:
            score += 0.1
        
        return min(score, 1.0)
    
    def _analyze_with_malwi(self, file_path: str) -> tuple:
        """
        Analyze file with Malwi AI-based malware detector.
        Returns (malwi_score, is_flagged) where score is 0-1 and flagged is boolean.
        """
        if not MALWI_AVAILABLE:
            return 0.0, False
        
        try:
            # Keep track of max maliciousness across all objects found
            max_maliciousness = 0.0
            flagged = False
            file_path_obj = Path(file_path)
            
            # Try to detect language and analyze
            try:
                source_code = file_path_obj.read_text(encoding='utf-8', errors='replace')
                file_extension = file_path_obj.suffix.lower()
                language = EXTENSION_TO_LANGUAGE.get(file_extension, 'python')
                
                # Disassemble and analyze the file's AST
                malwi_objects = disassemble_file_ast(
                    source_code, 
                    file_path=str(file_path), 
                    language=language
                )
                
                # Analyze each object and get maliciousness scores
                for obj in malwi_objects:
                    try:
                        # Use the predict method to get maliciousness
                        obj.predict()
                        if hasattr(obj, 'maliciousness') and obj.maliciousness:
                            maliciousness = obj.maliciousness
                            max_maliciousness = max(max_maliciousness, float(maliciousness))
                            
                            # Flag if any object is highly malicious
                            if maliciousness > 0.7:
                                flagged = True
                                logger.debug(f"[MALWI] {file_path} - Object '{obj.name}' flagged with maliciousness: {maliciousness:.4f}")
                    except Exception as obj_err:
                        logger.debug(f"[MALWI] Error predicting object maliciousness: {obj_err}")
                        continue
                
            except UnicodeDecodeError:
                logger.debug(f"[MALWI] Cannot decode file {file_path} - likely binary")
                return 0.0, False
            except SyntaxError:
                logger.debug(f"[MALWI] Syntax error in file {file_path}")
                return 0.0, False
            
            # Log results
            if max_maliciousness > 0:
                logger.debug(f"[MALWI] {file_path} - Max maliciousness score: {max_maliciousness:.4f}, Flagged: {flagged}")
            
            return max_maliciousness, flagged
            
        except Exception as e:
            logger.debug(f"[MALWI] Error analyzing {file_path}: {e}")
            return 0.0, False

