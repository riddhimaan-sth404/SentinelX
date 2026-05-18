"""
Alert System: Real-time threat notifications and alerts.
"""

import json
from pathlib import Path
from typing import List, Dict, Callable
from enum import Enum
from datetime import datetime
from dataclasses import dataclass, asdict

from sentinelx.utils.logger import get_logger

logger = get_logger(__name__)


class AlertSeverity(Enum):
    """Alert severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertType(Enum):
    """Types of alerts."""
    MALWARE_DETECTED = "malware_detected"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    NETWORK_THREAT = "network_threat"
    PROCESS_THREAT = "process_threat"
    FILE_THREAT = "file_threat"
    SYSTEM_THREAT = "system_threat"
    EXPLOIT_ATTEMPT = "exploit_attempt"
    DATA_EXFILTRATION = "data_exfiltration"
    RANSOMWARE_ACTIVITY = "ransomware_activity"


@dataclass
class Alert:
    """Alert object."""
    alert_type: str
    severity: str
    title: str
    description: str
    source: str
    timestamp: str
    details: Dict = None
    alert_id: str = None
    
    def __post_init__(self):
        if self.alert_id is None:
            import uuid
            self.alert_id = str(uuid.uuid4())[:8]


class AlertSystem:
    """Manage security alerts and notifications."""
    
    DEFAULT_ALERT_LEVEL = AlertSeverity.MEDIUM
    
    def __init__(self):
        self.alerts: List[Alert] = []
        self.alert_history = Path('logs/alerts.json')
        self.alert_callbacks = []
        self._load_alert_history()
    
    def register_alert_callback(self, callback: Callable):
        """Register callback for alert events."""
        self.alert_callbacks.append(callback)
    
    def trigger_alert(self, alert_type: AlertType, severity: AlertSeverity, 
                     title: str, description: str, source: str, details: Dict = None) -> Alert:
        """Trigger a new alert."""
        alert = Alert(
            alert_type=alert_type.value if isinstance(alert_type, AlertType) else alert_type,
            severity=severity.value if isinstance(severity, AlertSeverity) else severity,
            title=title,
            description=description,
            source=source,
            timestamp=datetime.now().isoformat(),
            details=details or {}
        )
        
        self.alerts.append(alert)
        self._save_alert_history()
        
        # Log based on severity
        if severity in [AlertSeverity.CRITICAL, AlertSeverity.HIGH]:
            logger.error(f"[ALERT] {severity.value.upper()}: {title} - {description}")
        elif severity == AlertSeverity.MEDIUM:
            logger.warning(f"[ALERT] {severity.value.upper()}: {title} - {description}")
        else:
            logger.info(f"[ALERT] {severity.value.upper()}: {title} - {description}")
        
        # Call registered callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"[ALERT] Callback error: {str(e)}")
        
        return alert
    
    def malware_detected(self, file_path: str, threat_type: str, severity: str, details: Dict = None):
        """Alert for malware detection."""
        return self.trigger_alert(
            AlertType.MALWARE_DETECTED,
            self._map_severity(severity),
            f"Malware Detected: {threat_type}",
            f"File: {file_path}",
            "yara_scanner",
            details
        )
    
    def suspicious_activity(self, activity: str, severity: str = 'medium', details: Dict = None):
        """Alert for suspicious activity."""
        return self.trigger_alert(
            AlertType.SUSPICIOUS_ACTIVITY,
            self._map_severity(severity),
            "Suspicious Activity Detected",
            activity,
            "behavior_monitor",
            details
        )
    
    def network_threat_detected(self, threat: str, severity: str = 'high', details: Dict = None):
        """Alert for network threats."""
        return self.trigger_alert(
            AlertType.NETWORK_THREAT,
            self._map_severity(severity),
            "Network Threat Detected",
            threat,
            "network_monitor",
            details
        )
    
    def process_threat_detected(self, process_name: str, threat: str, severity: str = 'high', details: Dict = None):
        """Alert for process threats."""
        return self.trigger_alert(
            AlertType.PROCESS_THREAT,
            self._map_severity(severity),
            f"Process Threat: {process_name}",
            threat,
            "process_monitor",
            details
        )
    
    def ransomware_activity_detected(self, activity: str, file_count: int = 0, details: Dict = None):
        """Alert for ransomware activity."""
        desc = f"Ransomware activity detected: {activity}"
        if file_count > 0:
            desc += f" ({file_count} files affected)"
        
        return self.trigger_alert(
            AlertType.RANSOMWARE_ACTIVITY,
            AlertSeverity.CRITICAL,
            "RANSOMWARE ACTIVITY DETECTED",
            desc,
            "network_monitor",
            details
        )
    
    def data_exfiltration_detected(self, protocol: str, target: str, details: Dict = None):
        """Alert for data exfiltration."""
        return self.trigger_alert(
            AlertType.DATA_EXFILTRATION,
            AlertSeverity.CRITICAL,
            "DATA EXFILTRATION DETECTED",
            f"Traffic detected: {protocol} -> {target}",
            "network_monitor",
            details
        )
    
    def exploit_attempt_detected(self, technique: str, target: str, details: Dict = None):
        """Alert for exploit attempts."""
        return self.trigger_alert(
            AlertType.EXPLOIT_ATTEMPT,
            AlertSeverity.HIGH,
            f"Exploit Attempt: {technique}",
            f"Target: {target}",
            "heuristics",
            details
        )
    
    def get_alerts_by_severity(self, severity: AlertSeverity) -> List[Alert]:
        """Get alerts filtered by severity."""
        return [a for a in self.alerts if a.severity == severity.value]
    
    def get_alerts_by_type(self, alert_type: AlertType) -> List[Alert]:
        """Get alerts filtered by type."""
        return [a for a in self.alerts if a.alert_type == alert_type.value]
    
    def get_critical_alerts(self) -> List[Alert]:
        """Get all critical alerts."""
        return self.get_alerts_by_severity(AlertSeverity.CRITICAL)
    
    def acknowledge_alert(self, alert_id: str):
        """Acknowledge an alert."""
        for alert in self.alerts:
            if alert.alert_id == alert_id:
                logger.info(f"[ALERT] Alert acknowledged: {alert_id}")
                return True
        return False
    
    def clear_old_alerts(self, hours: int = 24):
        """Remove alerts older than specified hours."""
        from datetime import timedelta
        cutoff = datetime.now() - timedelta(hours=hours)
        
        initial_count = len(self.alerts)
        self.alerts = [a for a in self.alerts 
                      if datetime.fromisoformat(a.timestamp) > cutoff]
        
        cleared = initial_count - len(self.alerts)
        if cleared > 0:
            logger.info(f"[ALERT] Cleared {cleared} old alerts")
            self._save_alert_history()
    
    def get_alert_summary(self) -> Dict:
        """Get summary of alerts."""
        summary = {
            'total_alerts': len(self.alerts),
            'by_severity': {},
            'by_type': {},
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0
        }
        
        for alert in self.alerts:
            severity = alert.severity
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            summary['by_type'][alert.alert_type] = summary['by_type'].get(alert.alert_type, 0) + 1
            
            if severity == 'critical':
                summary['critical_count'] += 1
            elif severity == 'high':
                summary['high_count'] += 1
            elif severity == 'medium':
                summary['medium_count'] += 1
            elif severity == 'low':
                summary['low_count'] += 1
        
        return summary
    
    def _map_severity(self, severity_str: str) -> AlertSeverity:
        """Map string to AlertSeverity."""
        severity_map = {
            'critical': AlertSeverity.CRITICAL,
            'high': AlertSeverity.HIGH,
            'medium': AlertSeverity.MEDIUM,
            'low': AlertSeverity.LOW,
            'info': AlertSeverity.INFO,
            'malicious': AlertSeverity.CRITICAL,
            'suspicious': AlertSeverity.HIGH,
        }
        return severity_map.get(severity_str.lower(), self.DEFAULT_ALERT_LEVEL)
    
    def _load_alert_history(self):
        """Load alert history from file."""
        try:
            if self.alert_history.exists():
                with open(self.alert_history, 'r') as f:
                    data = json.load(f)
                    for item in data.get('alerts', []):
                        self.alerts.append(Alert(**item))
        except Exception as e:
            logger.debug(f"[ALERT] Error loading history: {str(e)}")
    
    def _save_alert_history(self):
        """Save alert history to file."""
        try:
            self.alert_history.parent.mkdir(parents=True, exist_ok=True)
            with open(self.alert_history, 'w') as f:
                json.dump({
                    'timestamp': datetime.now().isoformat(),
                    'alerts': [asdict(a) for a in self.alerts[-100:]]  # Keep last 100
                }, f, indent=2)
        except Exception as e:
            logger.error(f"[ALERT] Error saving history: {str(e)}")
