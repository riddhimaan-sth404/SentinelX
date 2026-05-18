"""
Compliance Management System for SentinelX
Tracks compliance with various standards and regulations
"""
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

class ComplianceManager:
    """Manages compliance tracking and reporting"""
    
    STANDARDS = {
        "HIPAA": {
            "full_name": "Health Insurance Portability and Accountability Act",
            "requirements": ["encryption", "access_control", "audit_logs", "breach_notification"],
            "audit_frequency": "quarterly"
        },
        "PCI-DSS": {
            "full_name": "Payment Card Industry Data Security Standard",
            "requirements": ["encryption", "vulnerability_management", "access_control", "monitoring"],
            "audit_frequency": "annually"
        },
        "GDPR": {
            "full_name": "General Data Protection Regulation",
            "requirements": ["data_protection", "privacy_controls", "dpia", "breach_notification"],
            "audit_frequency": "continuous"
        },
        "SOC2": {
            "full_name": "Service Organization Control 2",
            "requirements": ["availability", "security", "integrity", "confidentiality", "privacy"],
            "audit_frequency": "annually"
        },
        "ISO27001": {
            "full_name": "Information Security Management",
            "requirements": ["risk_assessment", "access_control", "encryption", "incident_response"],
            "audit_frequency": "annually"
        },
        "NIST": {
            "full_name": "NIST Cybersecurity Framework",
            "requirements": ["identify", "protect", "detect", "respond", "recover"],
            "audit_frequency": "quarterly"
        }
    }
    
    def __init__(self, db_path: str = "logs/compliance.json"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.load_compliance()
    
    def load_compliance(self):
        """Load compliance data from file"""
        if self.db_path.exists():
            with open(self.db_path, 'r') as f:
                self.compliance_data = json.load(f)
        else:
            self.compliance_data = {
                "standards": {},
                "audit_logs": [],
                "violations": []
            }
            # Initialize standards with default values
            for standard in self.STANDARDS.keys():
                self.compliance_data["standards"][standard] = {
                    "compliance_percentage": 100,
                    "last_audit": datetime.now().isoformat(),
                    "next_audit": (datetime.now() + timedelta(days=90)).isoformat(),
                    "findings": [],
                    "status": "compliant"
                }
    
    def save_compliance(self):
        """Save compliance data to file"""
        with open(self.db_path, 'w') as f:
            json.dump(self.compliance_data, f, indent=2)
    
    def get_standard_status(self, standard: str) -> Optional[Dict]:
        """Get compliance status for a standard"""
        return self.compliance_data["standards"].get(standard)
    
    def update_compliance_status(self, standard: str, compliance_pct: int, status: str = "compliant") -> bool:
        """Update compliance percentage for a standard"""
        if standard not in self.STANDARDS:
            return False
        
        if standard not in self.compliance_data["standards"]:
            self.compliance_data["standards"][standard] = {}
        
        self.compliance_data["standards"][standard]["compliance_percentage"] = compliance_pct
        self.compliance_data["standards"][standard]["status"] = status
        self.compliance_data["standards"][standard]["last_updated"] = datetime.now().isoformat()
        
        self.save_compliance()
        return True
    
    def record_audit(self, standard: str, auditor: str, findings: List[str], notes: str = "") -> bool:
        """Record compliance audit"""
        if standard not in self.STANDARDS:
            return False
        
        audit_record = {
            "id": f"AUDIT-{len(self.compliance_data['audit_logs'])+ 1}",
            "standard": standard,
            "date": datetime.now().isoformat(),
            "auditor": auditor,
            "findings": findings,
            "notes": notes,
            "status": "non-compliant" if findings else "compliant"
        }
        
        self.compliance_data["audit_logs"].append(audit_record)
        
        # Update standard status
        if standard in self.compliance_data["standards"]:
            self.compliance_data["standards"][standard]["last_audit"] = datetime.now().isoformat()
            self.compliance_data["standards"][standard]["next_audit"] = (
                datetime.now() + timedelta(days=90)
            ).isoformat()
        
        self.save_compliance()
        return True
    
    def record_violation(self, standard: str, violation_type: str, description: str, severity: str) -> bool:
        """Record compliance violation"""
        if standard not in self.STANDARDS:
            return False
        
        violation = {
            "id": f"VIO-{len(self.compliance_data['violations']) + 1}",
            "standard": standard,
            "type": violation_type,
            "description": description,
            "severity": severity,
            "date": datetime.now().isoformat(),
            "status": "open",
            "remediation": None
        }
        
        self.compliance_data["violations"].append(violation)
        
        # Update status
        if standard in self.compliance_data["standards"]:
            self.compliance_data["standards"][standard]["status"] = "non-compliant"
        
        self.save_compliance()
        return True
    
    def remediate_violation(self, violation_id: str, remediation_description: str) -> bool:
        """Mark violation as remediated"""
        for violation in self.compliance_data["violations"]:
            if violation["id"] == violation_id:
                violation["status"] = "resolved"
                violation["remediation"] = remediation_description
                violation["resolved_at"] = datetime.now().isoformat()
                self.save_compliance()
                return True
        
        return False
    
    def get_compliance_summary(self) -> Dict:
        """Get overall compliance summary across all standards"""
        standards = self.compliance_data["standards"]
        
        if not standards:
            return {"overall_compliance": 0, "standards": {}}
        
        total_compliance = sum(s.get("compliance_percentage", 0) for s in standards.values())
        overall = total_compliance / len(standards)
        
        summary = {
            "overall_compliance": round(overall, 1),
            "standards": {},
            "total_violations": len([v for v in self.compliance_data["violations"] if v["status"] == "open"]),
            "total_audit_logs": len(self.compliance_data["audit_logs"])
        }
        
        for standard, data in standards.items():
            summary["standards"][standard] = {
                "compliance_percentage": data.get("compliance_percentage", 0),
                "status": data.get("status", "unknown"),
                "last_audit": data.get("last_audit")
            }
        
        return summary
    
    def list_audit_logs(self, standard: str = None) -> List[Dict]:
        """List audit logs with optional filtering"""
        logs = self.compliance_data["audit_logs"]
        
        if standard:
            logs = [l for l in logs if l["standard"] == standard]
        
        return sorted(logs, key=lambda x: x["date"], reverse=True)
    
    def list_violations(self, status: str = None) -> List[Dict]:
        """List violations with optional filtering"""
        violations = self.compliance_data["violations"]
        
        if status:
            violations = [v for v in violations if v["status"] == status]
        
        return sorted(violations, key=lambda x: x["date"], reverse=True)
    
    def generate_compliance_report(self, output_path: str = None) -> Dict:
        """Generate comprehensive compliance report"""
        summary = self.get_compliance_summary()
        
        report = {
            "generated_at": datetime.now().isoformat(),
            "summary": summary,
            "standard_details": {},
            "audit_logs": self.list_audit_logs(),
            "open_violations": self.list_violations("open"),
            "resolved_violations": self.list_violations("resolved")
        }
        
        for standard in self.STANDARDS.keys():
            status = self.compliance_data["standards"].get(standard, {})
            report["standard_details"][standard] = {
                "compliance_percentage": status.get("compliance_percentage", 0),
                "status": status.get("status", "unknown"),
                "last_audit": status.get("last_audit"),
                "next_audit": status.get("next_audit")
            }
        
        if output_path:
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2)
        
        return report
