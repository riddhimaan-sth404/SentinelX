"""
Windows Event Log Analyzer: Monitor and detect suspicious Windows events.
"""

import subprocess
import json
from pathlib import Path
from typing import List, Dict
from datetime import datetime, timedelta
from dataclasses import dataclass

from sentinelx.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class EventLogEntry:
    """Represents a Windows event log entry."""
    event_id: int
    level: str
    source: str
    timestamp: str
    description: str
    user: str = None
    computer: str = None


class WindowsEventLogAnalyzer:
    """Analyze Windows Event Logs for security threats."""
    
    SUSPICIOUS_EVENT_IDS = {
        # Security events
        540: "Failed login attempts",
        672: "Authentication ticket request failure",
        4625: "Account logon failure",
        4656: "Privileged object access",
        4672: "Special privileges assigned",
        4720: "Account created",
        4722: "Account enabled",
        4735: "Group modified",
        4782: "Password hash accessed",
        
        # System events
        7001: "Session disconnected without logoff",
        7002: "User session restart",
        
        # Process events
        1: "Image loaded",
        2: "Create remote thread",
        3: "Create process",
        4: "Create process set",
        5: "Process terminated",
        8: "Create remote thread",
        10: "Process accessed",
        11: "File created",
        13: "Registry object created or deleted",
        15: "File stream created",
        19: "WmiEvent (suspiciously deleted)",
        20: "WmiEvent (suspiciously deleted)",
        
        # Network events
        5156: "Network connection allowed",
        5157: "Network connection blocked",
        5158: "Network bind allowed",
        5159: "Network bind blocked",
    }
    
    def __init__(self):
        self.event_log_file = Path('logs/event_log_analysis.json')
        self.events = []
        self._load_events()
    
    def analyze_security_log(self, hours: int = 24) -> Dict:
        """Analyze Windows Security event log for suspicious activity."""
        logger.info(f"[EVENTLOG] Analyzing Security log for last {hours} hours...")
        
        suspicious_events = []
        time_filter = datetime.now() - timedelta(hours=hours)
        
        try:
            # Query Security event log using PowerShell
            ps_cmd = f'''
            $filter = @{{
                LogName = 'Security'
                StartTime = [datetime]::Now.AddHours(-{hours})
            }}
            Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue | 
            Select-Object ID, LevelDisplayName, TimeCreated, Message | 
            ConvertTo-Json -Depth 10
            '''
            
            result = subprocess.run(
                ['powershell', '-Command', ps_cmd],
                capture_output=True,
                text=True,
                check=False,
                timeout=30
            )
            
            if result.returncode == 0 and result.stdout:
                try:
                    events_data = json.loads(result.stdout)
                    
                    if isinstance(events_data, dict):
                        events_data = [events_data]
                    
                    for event in events_data:
                        event_id = event.get('ID', 0)
                        
                        if event_id in self.SUSPICIOUS_EVENT_IDS:
                            suspicious_events.append({
                                'event_id': event_id,
                                'type': self.SUSPICIOUS_EVENT_IDS[event_id],
                                'level': event.get('LevelDisplayName', 'Unknown'),
                                'time': event.get('TimeCreated', 'Unknown'),
                                'description': event.get('Message', '')[:256]
                            })
                except json.JSONDecodeError:
                    logger.debug("[EVENTLOG] Could not parse event log JSON")
        
        except subprocess.TimeoutExpired:
            logger.warning("[EVENTLOG] Event log query timed out")
        except Exception as e:
            logger.error(f"[EVENTLOG] Error analyzing Security log: {str(e)}")
        
        return {
            'total_suspicious_events': len(suspicious_events),
            'events': suspicious_events[:50],  # Limit to last 50 events
            'analyzed_hours': hours
        }
    
    def analyze_system_log(self, hours: int = 24) -> Dict:
        """Analyze Windows System event log."""
        logger.info(f"[EVENTLOG] Analyzing System log for last {hours} hours...")
        
        critical_events = []
        
        try:
            ps_cmd = f'''
            $filter = @{{
                LogName = 'System'
                Level = 1, 2
                StartTime = [datetime]::Now.AddHours(-{hours})
            }}
            Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue | 
            Select-Object ID, LevelDisplayName, TimeCreated, Message | 
            ConvertTo-Json -Depth 10
            '''
            
            result = subprocess.run(
                ['powershell', '-Command', ps_cmd],
                capture_output=True,
                text=True,
                check=False,
                timeout=30
            )
            
            if result.returncode == 0 and result.stdout:
                try:
                    events_data = json.loads(result.stdout)
                    
                    if isinstance(events_data, dict):
                        events_data = [events_data]
                    
                    for event in events_data:
                        critical_events.append({
                            'event_id': event.get('ID', 0),
                            'level': event.get('LevelDisplayName', 'Unknown'),
                            'time': event.get('TimeCreated', 'Unknown'),
                            'message': event.get('Message', '')[:256]
                        })
                except json.JSONDecodeError:
                    logger.debug("[EVENTLOG] Could not parse system log JSON")
        
        except Exception as e:
            logger.error(f"[EVENTLOG] Error analyzing System log: {str(e)}")
        
        return {
            'critical_events': len(critical_events),
            'events': critical_events[:50],
            'analyzed_hours': hours
        }
    
    def detect_brute_force_attempts(self, threshold: int = 5) -> Dict:
        """Detect brute force login attempts."""
        logger.info(f"[EVENTLOG] Detecting brute force attempts (threshold: {threshold})...")
        
        failed_ips = {}
        failed_users = {}
        
        try:
            ps_cmd = f'''
            $events = Get-WinEvent -FilterHashtable @{{
                LogName = 'Security'
                ID = 4625
                StartTime = [datetime]::Now.AddHours(-1)
            }} -ErrorAction SilentlyContinue
            
            $events | ForEach-Object {{
                $xml = [xml]$_.ToXml()
                Select-Object -InputObject $_ -Property @{{
                    IpAddress = $xml.Event.EventData.Data | Where-Object Name -eq 'IpAddress' | Select-Object -ExpandProperty '#text'
                    AccountName = $xml.Event.EventData.Data | Where-Object Name -eq 'TargetUserName' | Select-Object -ExpandProperty '#text'
                    TimeCreated = $_.TimeCreated
                }}
            }} | ConvertTo-Json -Depth 10
            '''
            
            result = subprocess.run(
                ['powershell', '-Command', ps_cmd],
                capture_output=True,
                text=True,
                check=False,
                timeout=30
            )
            
            if result.returncode == 0 and result.stdout:
                try:
                    attempts = json.loads(result.stdout)
                    
                    if isinstance(attempts, dict):
                        attempts = [attempts]
                    
                    for attempt in attempts:
                        ip = attempt.get('IpAddress', 'Unknown')
                        user = attempt.get('AccountName', 'Unknown')
                        
                        if ip:
                            failed_ips[ip] = failed_ips.get(ip, 0) + 1
                        if user:
                            failed_users[user] = failed_users.get(user, 0) + 1
                
                except json.JSONDecodeError:
                    logger.debug("[EVENTLOG] Could not parse brute force data")
        
        except Exception as e:
            logger.error(f"[EVENTLOG] Error detecting brute force: {str(e)}")
        
        suspicious_ips = {ip: count for ip, count in failed_ips.items() if count >= threshold}
        suspicious_users = {user: count for user, count in failed_users.items() if count >= threshold}
        
        return {
            'suspicious_ips': suspicious_ips,
            'suspicious_users': suspicious_users,
            'total_failed_attempts': sum(failed_ips.values()),
            'threshold_exceeded_ips': len(suspicious_ips),
            'threshold_exceeded_users': len(suspicious_users),
        }
    
    def detect_privilege_escalation(self) -> Dict:
        """Detect privilege escalation attempts."""
        logger.info("[EVENTLOG] Detecting privilege escalation attempts...")
        
        escalation_events = []
        
        try:
            # Events 4672 and 4673 indicate privilege use
            ps_cmd = '''
            $events = Get-WinEvent -FilterHashtable @{
                LogName = 'Security'
                ID = 4672
                StartTime = [datetime]::Now.AddHours(-24)
            } -ErrorAction SilentlyContinue
            
            $events | Select-Object -Property @{Name='Time'; Expression={$_.TimeCreated}}, 
                @{Name='PrivilegeList'; Expression={($_.Properties[2].Value)}} | 
                ConvertTo-Json -Depth 10
            '''
            
            result = subprocess.run(
                ['powershell', '-Command', ps_cmd],
                capture_output=True,
                text=True,
                check=False,
                timeout=30
            )
            
            if result.returncode == 0 and result.stdout:
                try:
                    events = json.loads(result.stdout)
                    
                    if isinstance(events, dict):
                        events = [events]
                    
                    escalation_events = events[:20]  # Limit to 20 events
                except json.JSONDecodeError:
                    pass
        
        except Exception as e:
            logger.error(f"[EVENTLOG] Error detecting privilege escalation: {str(e)}")
        
        return {
            'escalation_events': len(escalation_events),
            'events': escalation_events,
        }
    
    def _load_events(self):
        """Load event log analysis history."""
        try:
            if self.event_log_file.exists():
                with open(self.event_log_file, 'r') as f:
                    data = json.load(f)
                    self.events = data.get('events', [])
        except Exception as e:
            logger.debug(f"[EVENTLOG] Error loading event history: {str(e)}")
    
    def get_event_summary(self) -> Dict:
        """Get summary of recent event log analysis."""
        return {
            'timestamp': datetime.now().isoformat(),
            'total_analyzed_events': len(self.events),
            'latest_analysis': self.events[-1] if self.events else None
        }
