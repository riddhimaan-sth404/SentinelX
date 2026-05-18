"""SentinelX - Multi-stage Hybrid Malware Detection Pipeline with Live Monitoring"""

__version__ = "2.0.0"
__author__ = "SentinelX Security Team"

# Lazy imports to avoid blocking on GUI startup - users will import directly as needed
# from sentinelx.pipeline import MalwareDetectionPipeline, ScanResult
# from sentinelx.config.settings import get_config, load_config
# from sentinelx.utils.logger import setup_logging, get_logger
# from sentinelx.layers.usb_scanner import USBScanner, USBDevice

__all__ = [
    'MalwareDetectionPipeline',
    'ScanResult',
    'get_config',
    'load_config',
    'setup_logging',
    'get_logger',
    'USBScanner',
    'USBDevice'
]

