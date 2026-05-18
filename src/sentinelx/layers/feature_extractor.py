"""
Feature Extraction: Extract static features from PE files for ML analysis.
Uses pefile to analyze headers, entropy, section information, and imports.
"""
import pefile
import math
import hashlib
from pathlib import Path
from typing import Dict, Optional, Tuple
from dataclasses import dataclass
import numpy as np
from sentinelx.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class FileFeatures:
    """Extracted features from a file for ML analysis."""
    file_path: str
    file_hash: str
    is_pe: bool
    features: Dict[str, float] = None
    
    
class FeatureExtractor:
    """
    Extract static features from PE files for machine learning models.
    Features include entropy, section counts, import density, etc.
    """
    
    def __init__(self):
        """Initialize feature extractor."""
        self.feature_names = [
            'entropy',
            'section_count',
            'import_count',
            'export_count',
            'string_table_size',
            'debug_size',
            'overlay_size',
            'resource_size',
            'has_code_section',
            'has_writable_code',
            'has_executable_stack',
            'average_section_entropy',
            'suspicious_api_count'
        ]
    
    def _calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of data.
        
        Shannon entropy measures the randomness/disorder of bytes.
        Higher entropy values (>7) often indicate compressed/encrypted sections.
        
        Args:
            data: Bytes to analyze
            
        Returns:
            Entropy value (0.0 to 8.0)
        """
        if not data:
            return 0.0
        
        frequencies = {}
        for byte in data:
            frequencies[byte] = frequencies.get(byte, 0) + 1
        
        entropy = 0.0
        data_len = len(data)
        for count in frequencies.values():
            probability = count / data_len
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _get_section_entropy(self, pe_obj: pefile.PE, section_name: str) -> float:
        """
        Get entropy of a specific PE section.
        
        Args:
            pe_obj: pefile.PE object
            section_name: Name of section (e.g., '.text')
            
        Returns:
            Entropy value or 0 if section not found
        """
        for section in pe_obj.sections:
            if section.Name.decode().rstrip('\x00') == section_name:
                data = section.get_data()
                return self._calculate_entropy(data)
        return 0.0
    
    def _count_suspicious_imports(self, pe_obj: pefile.PE) -> int:
        """
        Count imports of suspicious APIs (code injection, persistence, etc).
        
        Args:
            pe_obj: pefile.PE object
            
        Returns:
            Count of suspicious imports
        """
        suspicious_apis = {
            'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
            'SetWindowsHookEx', 'RegSetValueEx', 'CreateProcess',
            'ShellExecute', 'InternetConnect', 'URLDownloadToFile',
            'WinExec', 'LoadLibrary', 'GetProcAddress',
            'SetTimer', 'CreateThread', 'ResumeThread'
        }
        
        count = 0
        if hasattr(pe_obj, 'DIRECTORY_ENTRY_IMPORT'):
            for dll in pe_obj.DIRECTORY_ENTRY_IMPORT:
                for func in dll.imports:
                    if func.name and func.name.decode().strip('\x00') in suspicious_apis:
                        count += 1
        
        return count
    
    def extract_features_from_file(self, file_path: str) -> Optional[FileFeatures]:
        """
        Extract features from a PE file.
        
        Args:
            file_path: Path to file
            
        Returns:
            FileFeatures object or None if extraction fails
        """
        try:
            # Calculate file hash
            with open(file_path, 'rb') as f:
                file_data = f.read()
                file_hash = hashlib.sha256(file_data).hexdigest()
            
            features = {
                'entropy': 0.0,
                'section_count': 0,
                'import_count': 0,
                'export_count': 0,
                'string_table_size': 0,
                'debug_size': 0,
                'overlay_size': 0,
                'resource_size': 0,
                'has_code_section': 0,
                'has_writable_code': 0,
                'has_executable_stack': 0,
                'average_section_entropy': 0.0,
                'suspicious_api_count': 0
            }
            
            # Try to parse as PE
            try:
                pe = pefile.PE(file_path)
                is_pe = True
            except pefile.PEFormatError:
                logger.debug(f"File is not a PE: {file_path}")
                # Return generic features for non-PE files
                features['entropy'] = self._calculate_entropy(file_data)
                return FileFeatures(
                    file_path=file_path,
                    file_hash=file_hash,
                    is_pe=False,
                    features=features
                )
            
            # Extract PE-specific features
            features['entropy'] = self._calculate_entropy(file_data)
            features['section_count'] = len(pe.sections)
            features['suspicious_api_count'] = self._count_suspicious_imports(pe)
            
            # Count imports and exports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for dll in pe.DIRECTORY_ENTRY_IMPORT:
                    features['import_count'] += len(dll.imports)
            
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                features['export_count'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
            
            # Check for various PE characteristics
            section_entropy_values = []
            for section in pe.sections:
                section_name = section.Name.decode().rstrip('\x00')
                entropy = self._calculate_entropy(section.get_data())
                section_entropy_values.append(entropy)
                
                # Check for writable code section
                if section_name == '.text':
                    features['has_code_section'] = 1
                    if section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE']:
                        features['has_writable_code'] = 1
            
            # Calculate average section entropy
            if section_entropy_values:
                features['average_section_entropy'] = np.mean(section_entropy_values)
            
            # Extract optional header features
            if hasattr(pe, 'OPTIONAL_HEADER'):
                opt_header = pe.OPTIONAL_HEADER
                
                # Check for debug directory
                if hasattr(opt_header, 'DATA_DIRECTORIES'):
                    for i, data_dir in enumerate(opt_header.DATA_DIRECTORIES):
                        if i == 6:  # Debug directory
                            features['debug_size'] = data_dir.Size
                        elif i == 2:  # Resource directory
                            features['resource_size'] = data_dir.Size
            
            # Calculate overlay size
            if hasattr(pe, 'sections'):
                last_section = pe.sections[-1]
                last_section_end = last_section.PointerToRawData + last_section.SizeOfRawData
                if len(file_data) > last_section_end:
                    features['overlay_size'] = len(file_data) - last_section_end
            
            return FileFeatures(
                file_path=file_path,
                file_hash=file_hash,
                is_pe=True,
                features=features
            )
        
        except Exception as e:
            logger.error(f"Error extracting features from {file_path}: {e}")
            return None
    
    def extract_features_as_vector(self, file_features: FileFeatures) -> np.ndarray:
        """
        Convert FileFeatures to feature vector for ML model.
        
        Args:
            file_features: FileFeatures object
            
        Returns:
            Numpy array of features in consistent order
        """
        if file_features.features is None:
            return np.zeros(len(self.feature_names))
        
        vector = []
        for feature_name in self.feature_names:
            value = file_features.features.get(feature_name, 0.0)
            vector.append(float(value))
        
        return np.array(vector)
    
    def get_feature_names(self) -> list:
        """Get list of feature names in extraction order."""
        return self.feature_names.copy()
