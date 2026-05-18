"""
Heuristic AI Layer: LightGBM-based malware classification.
Uses static features extracted from PE headers for maliciousness prediction.
"""
import lightgbm as lgb
import joblib
import numpy as np
from pathlib import Path
from typing import Tuple, Optional, Dict
from dataclasses import dataclass
from sentinelx.config.settings import get_config
from sentinelx.layers.feature_extractor import FeatureExtractor, FileFeatures
from sentinelx.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class AIScore:
    """Result from AI model prediction."""
    file_path: str
    maliciousness_score: float  # 0.0 to 1.0
    is_malicious: bool
    confidence: float
    feature_importance: Dict[str, float] = None


class LightGBMLayer:
    """
    Machine learning layer using LightGBM for malware classification.
    Performs static analysis based on file header features.
    """
    
    def __init__(self):
        """Initialize the LightGBM AI layer."""
        self.config = get_config().ai_model
        self.feature_extractor = FeatureExtractor()
        self.model = None
        self.normalizer = None
        self.feature_names = self.feature_extractor.get_feature_names()
        
        if self.config.enabled:
            self._load_model()
    
    def _load_model(self):
        """Load pre-trained LightGBM model."""
        model_path = Path(self.config.model_path)
        normalizer_path = Path(self.config.feature_normalizer_path)
        
        if not model_path.exists():
            logger.warning(f"Model file not found: {self.config.model_path}")
            logger.info("Creating a default random forest model for demonstration...")
            self._create_default_model()
            return
        
        try:
            self.model = joblib.load(model_path)
            logger.info(f"Model loaded successfully: {self.config.model_path}")
            
            if normalizer_path.exists():
                self.normalizer = joblib.load(normalizer_path)
                logger.info(f"Feature normalizer loaded: {self.config.feature_normalizer_path}")
        
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            self._create_default_model()
    
    def _create_default_model(self):
        """
        Create a simple default model for demonstration.
        Production systems should use a pre-trained model.
        """
        from sklearn.preprocessing import StandardScaler
        from sklearn.ensemble import RandomForestClassifier
        
        logger.info("Creating default demo model...")
        
        # Create a simple model
        X_dummy = np.random.randn(100, len(self.feature_names))
        y_dummy = np.random.randint(0, 2, 100)
        
        self.normalizer = StandardScaler().fit(X_dummy)
        X_normalized = self.normalizer.transform(X_dummy)
        
        self.model = RandomForestClassifier(n_estimators=50, random_state=42)
        self.model.fit(X_normalized, y_dummy)
        
        logger.info("Default demo model created (should be replaced with trained model)")
    
    def predict(self, file_path: str) -> Optional[AIScore]:
        """
        Predict maliciousness of a file.
        
        Args:
            file_path: Path to file to analyze
            
        Returns:
            AIScore object or None if prediction fails
        """
        if not self.config.enabled or self.model is None:
            return None
        
        try:
            # Check if it's a Python/script file first
            python_score = self._check_python_malware(file_path)
            if python_score is not None:
                return python_score
            
            # Extract features
            file_features = self.feature_extractor.extract_features_from_file(file_path)
            if file_features is None:
                logger.warning(f"Could not extract features from {file_path}")
                return None
            
            # Convert to feature vector
            feature_vector = self.feature_extractor.extract_features_as_vector(file_features)
            feature_vector = feature_vector.reshape(1, -1)
            
            # Normalize features if normalizer available
            if self.normalizer is not None:
                feature_vector = self.normalizer.transform(feature_vector)
            
            # Make prediction
            if hasattr(self.model, 'predict_proba'):
                probabilities = self.model.predict_proba(feature_vector)
                malicious_score = probabilities[0][1]  # Probability of class 1 (malicious)
            else:
                malicious_score = float(self.model.predict(feature_vector)[0])
            
            # Ensure score is in [0, 1]
            maliciousness_score = float(np.clip(malicious_score, 0.0, 1.0))
            
            # Determine if malicious based on threshold
            is_malicious = maliciousness_score >= self.config.malice_threshold
            
            # Calculate confidence
            confidence = max(maliciousness_score, 1.0 - maliciousness_score)
            
            # Get feature importance if available
            feature_importance = None
            if hasattr(self.model, 'feature_importances_'):
                importance_dict = {
                    name: float(importance)
                    for name, importance in zip(self.feature_names, self.model.feature_importances_)
                }
                feature_importance = dict(sorted(
                    importance_dict.items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:5])  # Top 5 features
            
            logger.debug(f"AI prediction for {file_path}: score={maliciousness_score:.4f}, "
                        f"malicious={is_malicious}, confidence={confidence:.4f}")
            
            return AIScore(
                file_path=file_path,
                maliciousness_score=maliciousness_score,
                is_malicious=is_malicious,
                confidence=confidence,
                feature_importance=feature_importance
            )
        
        except Exception as e:
            logger.error(f"Error predicting maliciousness for {file_path}: {e}")
            return None
    
    def _check_python_malware(self, file_path: str) -> Optional[AIScore]:
        """
        Check Python/script files for malicious patterns.
        
        Args:
            file_path: Path to file to check
            
        Returns:
            AIScore if file is Python, None otherwise
        """
        from pathlib import Path
        
        file_path_obj = Path(file_path)
        
        # Check if it's a Python/script file
        python_extensions = {'.py', '.pyw', '.pyx', '.pxd'}
        script_extensions = {'.sh', '.bash', '.ps1', '.vbs', '.js', '.rb', '.pl'}
        
        if file_path_obj.suffix.lower() not in python_extensions and file_path_obj.suffix.lower() not in script_extensions:
            return None  # Not a script file
        
        try:
            # Read file content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read().lower()
            
            malicious_patterns = [
                # Import/execution patterns
                ('__import__', 1.0),
                ('exec(', 0.9),
                ('eval(', 0.8),
                ('subprocess.call', 0.8),
                ('os.system', 0.8),
                ('system(', 0.7),
                ('popen(', 0.7),
                
                # Registry manipulation (Windows)
                ('winreg.', 0.7),
                ('registry', 0.6),
                ('HKEY_', 0.6),
                
                # Network operations (suspicious)
                ('socket.', 0.5),
                ('urllib.request', 0.3),  # Lower - legitimate use
                ('requests.get', 0.2),    # Lower - legitimate use
                ('http.client', 0.3),
                
                # File operations (suspicious)
                ('shutil.rmtree', 0.6),
                ('os.remove', 0.3),  # Lower - can be legitimate
                ('open(', 0.0),      # Too common
                
                # USB/Device manipulation
                ('usb', 0.7),
                ('device', 0.3),     # Too generic
                
                # Persistence
                ('startup', 0.7),
                ('scheduler', 0.6),
                ('service', 0.4),    # Can be legitimate
                ('cron', 0.5),
                
                # Obfuscation indicators
                ('base64', 0.6),
                ('hex(', 0.5),
                ('chr(', 0.3),       # Can be legitimate
                ('marshal', 0.8),
                ('compile(', 0.5),
                
                # Injection/hooking
                ('ctypes', 0.7),
                ('inject', 0.9),
                ('hook', 0.8),
                ('patch', 0.4),      # Lower - can be legitimate
                
                # Credentials/secrets
                ('password', 0.5),
                ('api_key', 0.5),
                ('secret', 0.5),
                ('token', 0.3),      # Can be legitimate
            ]
            
            risk_score = 0.0
            detected_patterns = []
            
            for pattern, weight in malicious_patterns:
                if pattern in content:
                    risk_score += weight
                    detected_patterns.append(pattern)
            
            # Normalize score to 0-1 range
            # If we found many patterns, score gets higher
            normalized_score = min(risk_score / 10.0, 1.0)
            
            # Boost if we found very suspicious patterns together
            if any(p in content for p in ['exec(', 'eval(', 'marshal']):
                normalized_score = min(normalized_score + 0.3, 1.0)
            
            if any(p in content for p in ['subprocess.call', 'os.system', 'popen(']):
                normalized_score = min(normalized_score + 0.2, 1.0)
            
            if any(p in content for p in ['ctypes', '__import__']):
                normalized_score = min(normalized_score + 0.15, 1.0)
            
            is_malicious = normalized_score >= self.config.malice_threshold
            confidence = abs(normalized_score - 0.5) * 2  # Higher if farther from middle
            
            if detected_patterns:
                logger.warning(f"Python/Script malware analysis for {file_path}: "
                              f"score={normalized_score:.4f}, patterns={', '.join(set(detected_patterns[:5]))}")
            
            return AIScore(
                file_path=file_path,
                maliciousness_score=normalized_score,
                is_malicious=is_malicious,
                confidence=confidence,
                feature_importance={'suspicious_patterns': len(detected_patterns)} if detected_patterns else None
            )
        
        except Exception as e:
            logger.debug(f"Could not analyze Python file {file_path}: {e}")
            return None
    
    def predict_batch(self, file_paths: list) -> list:
        """
        Predict maliciousness for multiple files.
        
        Args:
            file_paths: List of file paths
            
        Returns:
            List of AIScore objects
        """
        results = []
        for file_path in file_paths:
            score = self.predict(file_path)
            if score is not None:
                results.append(score)
        return results
    
    def needs_sandbox_escalation(self, ai_score: AIScore) -> bool:
        """
        Check if score warrants sandbox escalation.
        
        Args:
            ai_score: AIScore from prediction
            
        Returns:
            True if score is in escalation threshold range
        """
        return (ai_score.maliciousness_score > 0.5 and 
                ai_score.maliciousness_score < self.config.sandbox_escalation_threshold)
    
    def is_clear(self, ai_score: AIScore) -> bool:
        """Check if file appears clean."""
        return ai_score.maliciousness_score < 0.5
    
    def is_definitely_malicious(self, ai_score: AIScore) -> bool:
        """Check if file is definitely malicious."""
        return ai_score.maliciousness_score >= self.config.sandbox_escalation_threshold
    
    def get_model_info(self) -> Dict:
        """Get information about loaded model."""
        return {
            "enabled": self.config.enabled,
            "model_path": self.config.model_path,
            "feature_count": len(self.feature_names),
            "malice_threshold": self.config.malice_threshold,
            "sandbox_escalation_threshold": self.config.sandbox_escalation_threshold,
            "model_type": type(self.model).__name__ if self.model else None
        }


class EMBERLayer:
    """
    EMBER (Endgame Malware BEnchmark for Researchers) ML layer.
    Uses LIEF-based feature extraction for PE file malware classification.
    EMBER is a research-grade machine learning model for static PE analysis.
    Reference: https://github.com/elastic/ember
    Paper: Anderson & Roth (2018) - https://arxiv.org/abs/1804.04637
    """
    
    def __init__(self):
        """Initialize EMBER layer."""
        self.config = get_config().ai_model
        self.ember = None
        self.model = None
        self.feature_extractor = None
        
        if self.config.enabled:
            self._initialize_ember()
    
    def _initialize_ember(self):
        """Initialize EMBER module and feature extractor."""
        try:
            import ember
            self.ember = ember
            logger.info("EMBER module loaded successfully")
            
            # Initialize EMBER's PE feature extractor
            try:
                self.feature_extractor = ember.PEFeatureExtractor()
                logger.info("EMBER PEFeatureExtractor initialized")
            except Exception as e:
                logger.warning(f"Could not initialize PEFeatureExtractor: {e}")
            
            # Try to load pre-trained EMBER model
            # Look in multiple locations for flexibility
            possible_paths = [
                Path("models/ember/ember_trained.txt"),  # Primary location
                Path(self.config.model_path).parent / "ember_trained.txt",  # Config-based
                Path("models/ember/ember_model_2018.txt"),  # Alternative naming
            ]
            
            model_loaded = False
            for model_path in possible_paths:
                if model_path.exists():
                    try:
                        import lightgbm as lgb
                        self.model = lgb.Booster(model_file=str(model_path))
                        logger.info(f"EMBER pre-trained model loaded from {model_path}")
                        model_loaded = True
                        break
                    except Exception as e:
                        logger.debug(f"Could not load model from {model_path}: {e}")
                        continue
            
            if not model_loaded:
                logger.info("EMBER pre-trained model not found - using feature extraction heuristics")
                logger.info("To use trained model, run: python train_ember_model.py")
                
        except ImportError:
            logger.debug("EMBER module not available - install with: pip install git+https://github.com/elastic/ember.git")
            self.ember = None
    
    def predict(self, file_path: str) -> Optional[AIScore]:
        """
        Predict maliciousness using EMBER features.
        
        Args:
            file_path: Path to PE file to analyze
            
        Returns:
            AIScore object or None if prediction fails
        """
        if self.ember is None:
            return None
        
        try:
            # Read file
            file_path_obj = Path(file_path)
            if not file_path_obj.exists():
                logger.debug(f"File not found: {file_path}")
                return None
            
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Check if valid PE file
            if not file_data.startswith(b'MZ'):
                logger.debug(f"Not a PE file: {file_path}")
                return None
            
            # Extract EMBER features
            maliciousness_score = 0.5  # Default neutral score
            
            try:
                if self.feature_extractor:
                    # Use PEFeatureExtractor to extract features
                    features = self.feature_extractor.extract_raw(file_data)
                    
                    if features is not None:
                        # Try to vectorize features
                        feature_vector = self.ember.vectorize(features)
                        
                        if feature_vector is not None:
                            feature_vector = np.array([feature_vector])  # Make 2D
                            
                            # Make prediction if model available
                            if self.model is not None:
                                try:
                                    prediction = self.model.predict(feature_vector)
                                    maliciousness_score = float(np.clip(prediction[0], 0.0, 1.0))
                                    logger.debug(f"EMBER model prediction: {maliciousness_score:.4f}")
                                except Exception as e:
                                    logger.debug(f"Model prediction failed: {e}")
                                    maliciousness_score = self._heuristic_score(features)
                            else:
                                # Use heuristic scoring based on features
                                maliciousness_score = self._heuristic_score(features)
                        else:
                            # Vectorization failed, use heuristics
                            maliciousness_score = self._heuristic_score(features)
                    else:
                        # Feature extraction failed, use binary heuristics
                        maliciousness_score = self._binary_heuristic_score(file_data)
                else:
                    # No feature extractor, use binary heuristics
                    maliciousness_score = self._binary_heuristic_score(file_data)
                    
            except Exception as e:
                logger.debug(f"Feature extraction failed: {e}")
                maliciousness_score = self._binary_heuristic_score(file_data)
            
            # Determine if malicious
            is_malicious = maliciousness_score >= self.config.malice_threshold
            confidence = max(maliciousness_score, 1.0 - maliciousness_score)
            
            logger.debug(f"EMBER prediction for {file_path}: score={maliciousness_score:.4f}, is_malicious={is_malicious}")
            
            return AIScore(
                file_path=file_path,
                maliciousness_score=maliciousness_score,
                is_malicious=is_malicious,
                confidence=confidence,
                feature_importance=None
            )
        
        except Exception as e:
            logger.error(f"EMBER analysis failed for {file_path}: {e}")
            return None
    
    def _heuristic_score(self, features: Dict) -> float:
        """
        Calculate maliciousness score using extracted features.
        
        Args:
            features: Dictionary of PE features from EMBER
            
        Returns:
            Score between 0.0 (benign) and 1.0 (malicious)
        """
        score = 0.5  # Start neutral
        
        try:
            # Check suspicious API imports
            suspicious_apis = [
                'CreateRemoteThread', 'WriteProcessMemory', 'ReadProcessMemory',
                'VirtualAlloc', 'WinExec', 'ShellExecute', 'RegSetValue', 'RegOpenKey',
                'InternetOpen', 'InternetConnect', 'HttpOpenRequest'
            ]
            
            if isinstance(features, dict):
                # Check for suspicious imports in features
                if 'imports' in features:
                    imports = features.get('imports', [])
                    for api in suspicious_apis:
                        if api in str(imports):
                            score += 0.08
                
                # Check for suspicious characteristics
                if 'is_exe' in features and features['is_exe']:
                    score += 0.05
                
                if 'has_debug' in features and features['has_debug']:
                    score += 0.05
                
                # Check entropy (high entropy = suspicious)
                if 'entropy' in features:
                    entropy = float(features['entropy'])
                    if entropy > 7.5:
                        score += 0.1  # High entropy sections
                    elif entropy > 7.0:
                        score += 0.05
            
            score = float(np.clip(score, 0.0, 1.0))
            return score
            
        except Exception as e:
            logger.debug(f"Heuristic scoring failed: {e}")
            return 0.5
    
    def _binary_heuristic_score(self, file_data: bytes) -> float:
        """
        Calculate maliciousness score using raw binary heuristics.
        
        Args:
            file_data: Raw PE file bytes
            
        Returns:
            Score between 0.0 (benign) and 1.0 (malicious)
        """
        score = 0.5  # Start neutral
        
        # Check for common malware indicators in binary
        suspicious_indicators = [
            (b'WinExec', 0.1),
            (b'CreateRemoteThread', 0.15),
            (b'WriteProcessMemory', 0.15),
            (b'ReadProcessMemory', 0.1),
            (b'VirtualAlloc', 0.08),
            (b'LoadLibrary', 0.05),
            (b'GetProcAddress', 0.05),
            (b'ShellExecute', 0.1),
            (b'RegSetValue', 0.1),
            (b'RegOpenKey', 0.08),
            (b'InternetOpen', 0.08),
            (b'InternetConnect', 0.08),
            (b'HttpOpenRequest', 0.08),
        ]
        
        for indicator, weight in suspicious_indicators:
            if indicator in file_data:
                score += weight
        
        # Normalize to 0-1 range
        score = float(np.clip(score, 0.0, 1.0))
        return score
    
    def predict_batch(self, file_paths: list) -> list:
        """Predict multiple files."""
        results = []
        for file_path in file_paths:
            score = self.predict(file_path)
            if score is not None:
                results.append(score)
        return results
    
    def get_model_info(self) -> Dict:
        """Get information about EMBER layer."""
        return {
            "enabled": self.ember is not None,
            "model": "EMBER (Endgame Malware BEnchmark for Researchers)",
            "feature_source": "LIEF library (via PEFeatureExtractor)",
            "feature_version": 2,
            "pretrained_model": self.model is not None,
            "feature_extractor_available": self.feature_extractor is not None,
            "reference": {
                "paper": "Anderson & Roth (2018)",
                "arxiv": "https://arxiv.org/abs/1804.04637",
                "github": "https://github.com/elastic/ember"
            }
        }
