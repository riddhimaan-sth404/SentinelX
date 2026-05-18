"""SentinelX Background Services Module."""

from sentinelx.services.network_vulnerability_sealer import (
    NetworkVulnerabilitySealer,
    VulnerabilityFinding
)

from sentinelx.services.network_vulnerability_sealer_advanced import (
    AdvancedNetworkVulnerabilitySealer,
    BlockedThreat
)

from sentinelx.services.network_monitor import (
    NetworkMonitor,
    NetworkEvent,
    DataBreachIndicator
)

from sentinelx.services.realtime_file_monitor import (
    RealtimeFileMonitor,
    FileChangeEvent
)

from sentinelx.services.process_monitor import (
    ProcessMonitor,
    ProcessAlert
)

from sentinelx.services.quarantine_manager import (
    QuarantineManager,
    QuarantineEntry
)

from sentinelx.services.scheduled_scan import (
    ScheduledScanService
)

from sentinelx.services.report_generator import (
    ReportGenerator
)

from sentinelx.services.alert_system import (
    AlertSystem,
    Alert,
    AlertSeverity,
    AlertType
)

from sentinelx.services.threat_intelligence import (
    ThreatIntelligenceAggregator
)

from sentinelx.services.system_hardening import (
    SystemHardening
)

from sentinelx.services.event_log_analyzer import (
    WindowsEventLogAnalyzer,
    EventLogEntry
)

from sentinelx.services.malware_prevention_engine import (
    MalwarePreventionEngine,
    PreventionEvent
)

from sentinelx.services.network_isolation import (
    NetworkIsolationManager,
    NetworkSegment
)

from sentinelx.services.auto_discovery_scanner import (
    AutoDiscoveryScannerService
)

from sentinelx.services.comprehensive_15_layer_firewall import (
    Comprehensive15LayerFirewall,
    Layer1PhysicalSecurity,
    Layer2EnvironmentalProtection,
    Layer3PerimeterRouting,
    Layer4NetworkFirewall,
    Layer5NetworkSegmentation,
    Layer6IntrusionDetection,
    Layer7DDoSProtection,
    Layer8SecureRemoteAccess,
    Layer9ApplicationLayerFirewall,
    Layer10AuthenticationIdentity,
    Layer11Authorization,
    Layer12EndpointHardening,
    Layer13DataProtection,
    Layer14MonitoringLogging,
    Layer15IncidentResponse,
    FirewallEvent,
    NetworkSegment as FirewallNetworkSegment,
    SecurityPolicy
)

from sentinelx.services.ten_layer_file_scanning import (
    TenLayerFileScanner,
    ScanResult,
    ScanScore,
    ThreatLevel,
    ScanDecision,
    FileArtifact
)

__all__ = [
    'NetworkVulnerabilitySealer',
    'VulnerabilityFinding',
    'AdvancedNetworkVulnerabilitySealer',
    'BlockedThreat',
    'NetworkMonitor',
    'NetworkEvent',
    'DataBreachIndicator',
    'RealtimeFileMonitor',
    'FileChangeEvent',
    'ProcessMonitor',
    'ProcessAlert',
    'QuarantineManager',
    'QuarantineEntry',
    'ScheduledScanService',
    'ReportGenerator',
    'AlertSystem',
    'Alert',
    'AlertSeverity',
    'AlertType',
    'ThreatIntelligenceAggregator',
    'SystemHardening',
    'WindowsEventLogAnalyzer',
    'EventLogEntry',
    'MalwarePreventionEngine',
    'PreventionEvent',
    'NetworkIsolationManager',
    'NetworkSegment',
    'AutoDiscoveryScannerService',
    'Comprehensive15LayerFirewall',
    'Layer1PhysicalSecurity',
    'Layer2EnvironmentalProtection',
    'Layer3PerimeterRouting',
    'Layer4NetworkFirewall',
    'Layer5NetworkSegmentation',
    'Layer6IntrusionDetection',
    'Layer7DDoSProtection',
    'Layer8SecureRemoteAccess',
    'Layer9ApplicationLayerFirewall',
    'Layer10AuthenticationIdentity',
    'Layer11Authorization',
    'Layer12EndpointHardening',
    'Layer13DataProtection',
    'Layer14MonitoringLogging',
    'Layer15IncidentResponse',
    'FirewallEvent',
    'SecurityPolicy',
    'TenLayerFileScanner',
    'ScanResult',
    'ScanScore',
    'ThreatLevel',
    'ScanDecision',
    'FileArtifact',
]
