"""
Asset Management System for SentinelX
Tracks network assets, vulnerabilities, and compliance status
Integrates with auto-discovery and vulnerability scanning
"""
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional
import uuid

class AssetManager:
    """Manages network assets and their security posture"""
    
    def __init__(self, db_path: str = "logs/assets.json"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.load_assets()
    
    def load_assets(self):
        """Load asset inventory from file"""
        if self.db_path.exists():
            with open(self.db_path, 'r') as f:
                self.assets = json.load(f)
        else:
            self.assets = {}
    
    def save_assets(self):
        """Save asset inventory to file"""
        with open(self.db_path, 'w') as f:
            json.dump(self.assets, f, indent=2)
    
    def discover_asset(self, hostname: str, ip: str, asset_type: str, os: str, 
                      mac_address: str = None, description: str = "") -> str:
        """Discover or register new asset"""
        asset_id = f"ASSET-{str(uuid.uuid4())[:8].upper()}"
        
        asset = {
            "id": asset_id,
            "hostname": hostname,
            "ip": ip,
            "type": asset_type,  # workstation, server, printer, etc
            "os": os,
            "mac_address": mac_address,
            "description": description,
            "discovered_at": datetime.now().isoformat(),
            "last_scan": None,
            "last_seen": datetime.now().isoformat(),
            "status": "active",
            "vulnerabilities": [],
            "compliance_status": "unknown",
            "compliance_percentage": 0,
            "security_score": 100,
            "patches_available": 0,
            "missing_patches": [],
            "antivirus_status": "unknown",
            "firewall_status": "unknown",
            "disk_encryption": False,
            "mfa_enabled": False
        }
        
        # Check if asset already exists
        for existing_id, existing_asset in self.assets.items():
            if existing_asset["ip"] == ip or existing_asset["hostname"].lower() == hostname.lower():
                # Update existing asset
                existing_asset["last_seen"] = datetime.now().isoformat()
                self.save_assets()
                return existing_id
        
        self.assets[asset_id] = asset
        self.save_assets()
        return asset_id
    
    def add_vulnerability(self, asset_id: str, cve: str, severity: str, 
                         description: str, remediation: str = None) -> bool:
        """Add vulnerability to asset"""
        if asset_id not in self.assets:
            return False
        
        vulnerability = {
            "id": f"VUL-{str(uuid.uuid4())[:8]}",
            "cve": cve,
            "severity": severity,
            "description": description,
            "remediation": remediation,
            "discovered_at": datetime.now().isoformat(),
            "status": "open",
            "patch_available": True
        }
        
        self.assets[asset_id]["vulnerabilities"].append(vulnerability)
        self.update_security_score(asset_id)
        self.save_assets()
        return True
    
    def update_security_score(self, asset_id: str) -> int:
        """Calculate and update asset security score (0-100)"""
        if asset_id not in self.assets:
            return 0
        
        asset = self.assets[asset_id]
        score = 100
        
        # Deduct points for vulnerabilities
        critical = sum(1 for v in asset["vulnerabilities"] if v["severity"] == "CRITICAL")
        high = sum(1 for v in asset["vulnerabilities"] if v["severity"] == "HIGH")
        medium = sum(1 for v in asset["vulnerabilities"] if v["severity"] == "MEDIUM")
        
        score -= critical * 15
        score -= high * 8
        score -= medium * 3
        
        # Deduct for missing patches
        score -= asset.get("patches_available", 0) * 2
        
        # Deduct if antivirus not active
        if asset["antivirus_status"] != "active":
            score -= 20
        
        # Deduct if firewall not enabled
        if asset["firewall_status"] != "enabled":
            score -= 15
        
        # Bonus for disk encryption
        if asset["disk_encryption"]:
            score += 5
        
        # Bonus for MFA
        if asset["mfa_enabled"]:
            score += 5
        
        score = max(0, min(100, score))
        asset["security_score"] = score
        self.save_assets()
        return score
    
    def scan_asset(self, asset_id: str, scan_type: str = "full") -> Dict:
        """Perform security scan on asset"""
        if asset_id not in self.assets:
            return None
        
        asset = self.assets[asset_id]
        
        scan_result = {
            "scan_id": f"SCAN-{str(uuid.uuid4())[:8]}",
            "asset_id": asset_id,
            "hostname": asset["hostname"],
            "scan_type": scan_type,
            "started_at": datetime.now().isoformat(),
            "completed_at": None,
            "status": "in_progress",
            "vulnerabilities_found": 0,
            "patches_needed": 0,
            "security_issues": []
        }
        
        # Update last scan time
        asset["last_scan"] = datetime.now().isoformat()
        
        # Simulate scan completion
        scan_result["completed_at"] = datetime.now().isoformat()
        scan_result["status"] = "completed"
        scan_result["vulnerabilities_found"] = len(asset["vulnerabilities"])
        scan_result["patches_needed"] = asset.get("patches_available", 0)
        
        self.save_assets()
        return scan_result
    
    def update_patch_status(self, asset_id: str, patches_available: int, 
                           missing_patches: List[str] = None) -> bool:
        """Update patch availability for asset"""
        if asset_id not in self.assets:
            return False
        
        asset = self.assets[asset_id]
        asset["patches_available"] = patches_available
        asset["missing_patches"] = missing_patches or []
        
        self.update_security_score(asset_id)
        self.save_assets()
        return True
    
    def update_antivirus_status(self, asset_id: str, status: str, version: str = None) -> bool:
        """Update antivirus status on asset"""
        if asset_id not in self.assets:
            return False
        
        asset = self.assets[asset_id]
        asset["antivirus_status"] = status  # active, outdated, disabled
        if version:
            asset["antivirus_version"] = version
        
        self.update_security_score(asset_id)
        self.save_assets()
        return True
    
    def update_firewall_status(self, asset_id: str, status: str) -> bool:
        """Update firewall status on asset"""
        if asset_id not in self.assets:
            return False
        
        asset = self.assets[asset_id]
        asset["firewall_status"] = status  # enabled, disabled, custom
        
        self.update_security_score(asset_id)
        self.save_assets()
        return True
    
    def update_encryption_status(self, asset_id: str, encrypted: bool, method: str = None) -> bool:
        """Update disk encryption status"""
        if asset_id not in self.assets:
            return False
        
        asset = self.assets[asset_id]
        asset["disk_encryption"] = encrypted
        if method:
            asset["encryption_method"] = method
        
        self.update_security_score(asset_id)
        self.save_assets()
        return True
    
    def enable_mfa(self, asset_id: str, enabled: bool) -> bool:
        """Update MFA status"""
        if asset_id not in self.assets:
            return False
        
        asset = self.assets[asset_id]
        asset["mfa_enabled"] = enabled
        
        self.update_security_score(asset_id)
        self.save_assets()
        return True
    
    def list_assets(self, status: str = None, asset_type: str = None) -> List[Dict]:
        """List assets with optional filtering"""
        assets_list = []
        
        for asset_id, asset in self.assets.items():
            if status and asset["status"] != status:
                continue
            if asset_type and asset["type"] != asset_type:
                continue
            
            assets_list.append({
                "id": asset["id"],
                "hostname": asset["hostname"],
                "ip": asset["ip"],
                "type": asset["type"],
                "os": asset["os"],
                "status": asset["status"],
                "security_score": asset["security_score"],
                "vulnerabilities": len(asset["vulnerabilities"]),
                "patches_available": asset.get("patches_available", 0),
                "last_scan": asset["last_scan"],
                "antivirus_status": asset["antivirus_status"],
                "firewall_status": asset["firewall_status"]
            })
        
        return sorted(assets_list, key=lambda x: x["security_score"])
    
    def get_asset(self, asset_id: str) -> Optional[Dict]:
        """Get detailed asset information"""
        return self.assets.get(asset_id)
    
    def get_vulnerability_summary(self, asset_id: str = None) -> Dict:
        """Get vulnerability summary"""
        summary = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "total": 0
        }
        
        if asset_id:
            if asset_id in self.assets:
                for vuln in self.assets[asset_id]["vulnerabilities"]:
                    severity = vuln["severity"].lower()
                    if severity in summary:
                        summary[severity] += 1
                    summary["total"] += 1
        else:
            # Summary across all assets
            for asset in self.assets.values():
                for vuln in asset["vulnerabilities"]:
                    severity = vuln["severity"].lower()
                    if severity in summary:
                        summary[severity] += 1
                    summary["total"] += 1
        
        return summary
    
    def get_asset_stats(self) -> Dict:
        """Get asset statistics"""
        stats = {
            "total_assets": len(self.assets),
            "active_assets": 0,
            "inactive_assets": 0,
            "by_type": {},
            "by_os": {},
            "average_security_score": 0,
            "assets_with_critical_vulns": 0,
            "total_vulnerabilities": 0,
            "total_patches_needed": 0
        }
        
        total_score = 0
        
        for asset in self.assets.values():
            if asset["status"] == "active":
                stats["active_assets"] += 1
            else:
                stats["inactive_assets"] += 1
            
            # Count by type
            asset_type = asset["type"]
            if asset_type not in stats["by_type"]:
                stats["by_type"][asset_type] = 0
            stats["by_type"][asset_type] += 1
            
            # Count by OS
            os = asset["os"]
            if os not in stats["by_os"]:
                stats["by_os"][os] = 0
            stats["by_os"][os] += 1
            
            total_score += asset["security_score"]
            
            # Count critical vulnerabilities
            critical_count = sum(1 for v in asset["vulnerabilities"] if v["severity"] == "CRITICAL")
            if critical_count > 0:
                stats["assets_with_critical_vulns"] += 1
            
            stats["total_vulnerabilities"] += len(asset["vulnerabilities"])
            stats["total_patches_needed"] += asset.get("patches_available", 0)
        
        if stats["total_assets"] > 0:
            stats["average_security_score"] = round(total_score / stats["total_assets"], 1)
        
        return stats
