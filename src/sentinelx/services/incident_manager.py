"""
Incident Management System for SentinelX
Tracks security incidents, assigns them to analysts, and manages response playbooks
"""
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

class IncidentManager:
    """Manages security incidents"""
    
    INCIDENT_TYPES = ["Malware", "Network_Breach", "Data_Exfiltration", "Ransomware", "Supply_Chain", "Unauthorized_Access"]
    SEVERITY_LEVELS = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    INCIDENT_STATUS = ["Open", "In_Progress", "Resolved", "Closed"]
    
    PLAYBOOKS = {
        "Malware": {
            "steps": [
                "Isolate infected system",
                "Capture memory dump",
                "Analyze malware behavior",
                "Identify C2 communication",
                "Remove malware",
                "Update signatures"
            ],
            "estimated_time": "4-8 hours"
        },
        "Network_Breach": {
            "steps": [
                "Enable full network logging",
                "Identify entry point",
                "Trace attacker path",
                "Contain lateral movement",
                "Reset credentials",
                "Deploy additional monitoring"
            ],
            "estimated_time": "6-12 hours"
        },
        "Data_Exfiltration": {
            "steps": [
                "Identify data scope",
                "Block exfiltration channels",
                "Review access logs",
                "Notify affected parties",
                "Deploy DLP rules",
                "Monitor for selling"
            ],
            "estimated_time": "2-4 hours"
        },
        "Ransomware": {
            "steps": [
                "Network isolation",
                "Backup verification",
                "System snapshot",
                "Malware analysis",
                "Decryption key search",
                "System restoration"
            ],
            "estimated_time": "8-24 hours"
        },
        "Supply_Chain": {
            "steps": [
                "Identify affected vendors",
                "Assess impact scope",
                "Patch all systems",
                "Monitor for indicators",
                "Notify supply chain",
                "Enhanced monitoring"
            ],
            "estimated_time": "24-72 hours"
        }
    }
    
    def __init__(self, db_path: str = "logs/incidents.json"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.load_incidents()
    
    def load_incidents(self):
        """Load incidents from file"""
        if self.db_path.exists():
            with open(self.db_path, 'r') as f:
                self.incidents = json.load(f)
        else:
            self.incidents = {}
    
    def save_incidents(self):
        """Save incidents to file"""
        with open(self.db_path, 'w') as f:
            json.dump(self.incidents, f, indent=2)
    
    def create_incident(self, inc_type: str, severity: str, source: str, title: str, 
                       description: str, assigned_to: str = None) -> str:
        """Create new incident"""
        if inc_type not in self.INCIDENT_TYPES or severity not in self.SEVERITY_LEVELS:
            return None
        
        incident_id = f"INC-{str(uuid.uuid4())[:8].upper()}"
        
        incident = {
            "id": incident_id,
            "type": inc_type,
            "severity": severity,
            "source": source,
            "title": title,
            "description": description,
            "status": "Open",
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "assigned_to": assigned_to,
            "timeline": [],
            "evidence": [],
            "playbook": self.PLAYBOOKS.get(inc_type, {}),
            "playbook_progress": 0
        }
        
        self.incidents[incident_id] = incident
        self.save_incidents()
        return incident_id
    
    def get_incident(self, incident_id: str) -> Optional[Dict]:
        """Get incident details"""
        return self.incidents.get(incident_id)
    
    def update_incident(self, incident_id: str, **kwargs) -> bool:
        """Update incident details"""
        if incident_id not in self.incidents:
            return False
        
        incident = self.incidents[incident_id]
        
        # Only allow updating certain fields
        allowed_fields = ["status", "assigned_to", "severity", "description"]
        for key, value in kwargs.items():
            if key in allowed_fields:
                incident[key] = value
        
        incident["updated_at"] = datetime.now().isoformat()
        self.save_incidents()
        return True
    
    def add_timeline_entry(self, incident_id: str, analyst: str, action: str, notes: str) -> bool:
        """Add entry to incident timeline"""
        if incident_id not in self.incidents:
            return False
        
        entry = {
            "timestamp": datetime.now().isoformat(),
            "analyst": analyst,
            "action": action,
            "notes": notes
        }
        
        self.incidents[incident_id]["timeline"].append(entry)
        self.save_incidents()
        return True
    
    def add_evidence(self, incident_id: str, evidence_type: str, description: str, data: str) -> bool:
        """Add evidence to incident"""
        if incident_id not in self.incidents:
            return False
        
        evidence = {
            "id": str(uuid.uuid4())[:8],
            "type": evidence_type,  # file, network, process, registry, etc
            "description": description,
            "data": data,
            "added_at": datetime.now().isoformat()
        }
        
        self.incidents[incident_id]["evidence"].append(evidence)
        self.save_incidents()
        return True
    
    def escalate_incident(self, incident_id: str, escalated_to: str, reason: str) -> bool:
        """Escalate incident to higher authority"""
        if incident_id not in self.incidents:
            return False
        
        incident = self.incidents[incident_id]
        incident["escalated_to"] = escalated_to
        incident["escalation_reason"] = reason
        incident["escalated_at"] = datetime.now().isoformat()
        
        self.add_timeline_entry(incident_id, "system", "escalated", f"Escalated to {escalated_to}: {reason}")
        return True
    
    def list_incidents(self, status: str = None, severity: str = None, assigned_to: str = None) -> List[Dict]:
        """List incidents with optional filtering"""
        incidents_list = []
        
        for incident_id, incident in self.incidents.items():
            if status and incident["status"] != status:
                continue
            if severity and incident["severity"] != severity:
                continue
            if assigned_to and incident["assigned_to"] != assigned_to:
                continue
            
            incidents_list.append({
                "id": incident["id"],
                "type": incident["type"],
                "severity": incident["severity"],
                "source": incident["source"],
                "title": incident["title"],
                "status": incident["status"],
                "created_at": incident["created_at"],
                "assigned_to": incident["assigned_to"]
            })
        
        return sorted(incidents_list, key=lambda x: x["created_at"], reverse=True)
    
    def get_incident_stats(self) -> Dict:
        """Get incident statistics"""
        stats = {
            "total": len(self.incidents),
            "open": 0,
            "in_progress": 0,
            "resolved": 0,
            "critical": 0,
            "by_type": {}
        }
        
        for incident in self.incidents.values():
            stats[incident["status"].lower().replace(" ", "_")] += 1
            if incident["severity"] == "CRITICAL":
                stats["critical"] += 1
            
            inc_type = incident["type"]
            if inc_type not in stats["by_type"]:
                stats["by_type"][inc_type] = 0
            stats["by_type"][inc_type] += 1
        
        return stats
    
    def close_incident(self, incident_id: str, resolution: str) -> bool:
        """Close incident"""
        if incident_id not in self.incidents:
            return False
        
        incident = self.incidents[incident_id]
        incident["status"] = "Closed"
        incident["resolution"] = resolution
        incident["closed_at"] = datetime.now().isoformat()
        
        self.save_incidents()
        return True
