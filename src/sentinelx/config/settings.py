"""
Configuration management for SentinelX malware detection pipeline.
"""
from pathlib import Path
from pydantic import BaseModel, Field, field_validator
from typing import Optional
import os


class YaraConfig(BaseModel):
    """YARA scanning configuration."""
    enabled: bool = Field(default=True, description="Enable YARA scanning")
    rules_path: str = Field(default="rules/malware_signatures.yar", description="Path to YARA rules")
    timeout: int = Field(default=60, ge=5, le=300, description="YARA scan timeout in seconds")
    recursion_limit: int = Field(default=20, ge=1, le=100, description="Maximum recursion limit")


class AIModelConfig(BaseModel):
    """LightGBM AI model configuration."""
    enabled: bool = Field(default=True, description="Enable AI model scanning")
    model_path: str = Field(default="data/lightgbm_model.pkl", description="Path to trained model")
    feature_normalizer_path: str = Field(default="data/feature_normalizer.pkl", description="Path to feature normalizer")
    malice_threshold: float = Field(default=0.5, ge=0.0, le=1.0, description="Minimum score to flag as suspicious")
    sandbox_escalation_threshold: float = Field(default=0.85, ge=0.0, le=1.0, description="Score threshold for sandbox escalation")


class HybridAnalysisConfig(BaseModel):
    """Hybrid Analysis API configuration (DEPRECATED - use Cuckoo Sandbox instead)."""
    enabled: bool = Field(default=False, description="DEPRECATED - use cuckoo_sandbox instead")
    api_key: Optional[str] = Field(default=None, description="DEPRECATED")
    api_url: str = Field(default="https://www.hybrid-analysis.com/api/v2", description="DEPRECATED")
    submit_timeout: int = Field(default=30, ge=5, le=300, description="DEPRECATED")
    environment: int = Field(default=100, description="DEPRECATED")
    poll_interval: int = Field(default=5, ge=1, le=60, description="DEPRECATED")
    max_poll_attempts: int = Field(default=60, ge=1, le=600, description="DEPRECATED")


class CuckooSandboxConfig(BaseModel):
    """Cuckoo Sandbox configuration - open source malware analysis."""
    enabled: bool = Field(default=True, description="Enable Cuckoo Sandbox integration")
    host: str = Field(default="localhost", description="Cuckoo server hostname/IP")
    port: int = Field(default=8090, ge=1, le=65535, description="Cuckoo API port (default 8090)")
    submit_timeout: int = Field(default=30, ge=5, le=300, description="API request timeout in seconds")
    poll_interval: int = Field(default=5, ge=1, le=60, description="Polling interval in seconds")
    max_poll_attempts: int = Field(default=120, ge=1, le=600, description="Maximum polling attempts (longer for thorough analysis)")
    description: str = Field(
        default="Open source sandbox - https://github.com/cuckoosandbox/cuckoo. "
                "Get started: pip install cuckoo && cuckoo -d && python cuckoo.py",
        description="Setup instructions"
    )

class QuarantineConfig(BaseModel):
    """Quarantine configuration for suspicious files."""
    enabled: bool = Field(default=True, description="Enable file quarantine")
    quarantine_dir: str = Field(default="quarantine", description="Directory to store quarantined files")
    safe_ai_score: float = Field(default=0.3, ge=0.0, le=1.0, description="AI score threshold for safe files")
    suspicious_ai_score: float = Field(default=0.5, ge=0.0, le=1.0, description="AI score threshold for suspicious files")
    malicious_ai_score: float = Field(default=0.75, ge=0.0, le=1.0, description="AI score threshold for malicious files")
    auto_quarantine: bool = Field(default=True, description="Automatically quarantine suspicious files")


class DiscoveryConfig(BaseModel):
    """File discovery configuration."""
    enabled: bool = Field(default=True, description="Enable discovery layer")
    target_paths: list = Field(default=[r"C:\Users", r"C:\Windows\Temp"], description="Paths to scan")
    recursive: bool = Field(default=True, description="Recursively scan subdirectories")
    follow_symlinks: bool = Field(default=False, description="Follow symbolic links")
    excluded_patterns: list = Field(
        default=[r"\.git", r"node_modules", r"__pycache__"],
        description="Glob patterns to exclude"
    )
    file_size_limit_mb: int = Field(default=50, ge=1, le=500, description="Maximum file size to scan in MB")


class LoggingConfig(BaseModel):
    """Logging configuration."""
    level: str = Field(default="INFO", description="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)")
    log_file: str = Field(default="logs/sentinelx.log", description="Path to log file")
    max_bytes: int = Field(default=10485760, ge=1000000, description="Max log file size in bytes (10MB default)")
    backup_count: int = Field(default=5, ge=1, le=20, description="Number of backup log files to keep")
    
    @field_validator('level')
    @classmethod
    def validate_log_level(cls, v):
        """Validate log level."""
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if v.upper() not in valid_levels:
            raise ValueError(f'Log level must be one of {valid_levels}')
        return v.upper()


class SentinelXConfig(BaseModel):
    """Main SentinelX configuration."""
    yara: YaraConfig = YaraConfig()
    ai_model: AIModelConfig = AIModelConfig()
    hybrid_analysis: HybridAnalysisConfig = HybridAnalysisConfig()  # Deprecated
    cuckoo_sandbox: CuckooSandboxConfig = CuckooSandboxConfig()  # New open source sandbox
    quarantine: QuarantineConfig = QuarantineConfig()
    discovery: DiscoveryConfig = DiscoveryConfig()
    logging: LoggingConfig = LoggingConfig()
    
    # Pipeline behavior
    report_dir: str = Field(default="reports", description="Directory for storing scan reports")
    cache_results: bool = Field(default=True, description="Cache scan results")
    cache_dir: str = Field(default="data/cache", description="Cache directory")
    
    class Config:
        """Pydantic config."""
        extra = "allow"
        arbitrary_types_allowed = True
    
    def validate_paths(self) -> list:
        """Validate that required paths are accessible."""
        errors = []
        
        # Check logging directory
        log_dir = Path(self.logging.log_file).parent
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            errors.append(f"Cannot create log directory {log_dir}: {e}")
        
        # Check cache directory
        cache_dir = Path(self.cache_dir)
        try:
            cache_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            errors.append(f"Cannot create cache directory {cache_dir}: {e}")
        
        # Warn about missing YARA rules
        if self.yara.enabled:
            rules_path = Path(self.yara.rules_path)
            if not rules_path.exists():
                errors.append(f"YARA rules not found at {rules_path}")
        
        # Warn about missing model
        if self.ai_model.enabled:
            model_path = Path(self.ai_model.model_path)
            if not model_path.exists():
                errors.append(f"AI model not found at {model_path}")
        
        return errors


def load_config(config_path: Optional[str] = None) -> SentinelXConfig:
    """
    Load configuration from file or use defaults.
    
    Args:
        config_path: Path to JSON config file (optional)
        
    Returns:
        SentinelXConfig instance
    """
    # Load API key from environment variable
    hybrid_api_key = os.getenv("HYBRID_ANALYSIS_API_KEY")
    
    # If no path provided, try to find config.json automatically
    if not config_path:
        # Try multiple locations
        possible_paths = [
            "config/config.json",
            "./config/config.json",
            Path(__file__).parent.parent.parent / "config" / "config.json",  # Relative to this file
        ]
        for path in possible_paths:
            if Path(path).exists():
                config_path = str(path)
                break
    
    if config_path and Path(config_path).exists():
        import json
        with open(config_path, 'r') as f:
            config_dict = json.load(f)
        # Override with env var if present
        if hybrid_api_key:
            config_dict.setdefault('hybrid_analysis', {})['api_key'] = hybrid_api_key
        return SentinelXConfig(**config_dict)
    
    # Return default config with API key if available
    config = SentinelXConfig()
    if hybrid_api_key:
        config.hybrid_analysis.api_key = hybrid_api_key
    return config


def get_config() -> SentinelXConfig:
    """Get the global configuration instance."""
    if not hasattr(get_config, '_instance'):
        get_config._instance = load_config()
    return get_config._instance
