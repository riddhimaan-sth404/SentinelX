"""
Remote Access Management System for SentinelX
Enables secure remote access to any PC running SentinelX
Supports RDP, SSH, and custom secure tunnel connections
"""
import json
import socket
import secrets
import ssl
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional
import hashlib

class RemoteAccessManager:
    """Manages remote access to SentinelX-enabled PCs"""
    
    ACCESS_TYPES = ["RDP", "SSH", "SECURE_TUNNEL", "VNC", "HTTP"]
    
    def __init__(self, db_path: str = "logs/remote_access.json", cert_path: str = "config"):
        self.db_path = Path(db_path)
        self.cert_path = Path(cert_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.cert_path.mkdir(parents=True, exist_ok=True)
        self.load_access_rules()
    
    def load_access_rules(self):
        """Load remote access rules from file"""
        if self.db_path.exists():
            with open(self.db_path, 'r') as f:
                self.access_data = json.load(f)
        else:
            self.access_data = {
                "enabled": True,
                "sessions": [],
                "approved_users": [],
                "access_logs": [],
                "blocked_ips": []
            }
            self.save_access_rules()
    
    def save_access_rules(self):
        """Save remote access rules to file"""
        with open(self.db_path, 'w') as f:
            json.dump(self.access_data, f, indent=2)
    
    def get_system_info(self) -> Dict:
        """Get local system information for remote connection"""
        try:
            import platform
            import socket as sock
            import psutil
            
            hostname = sock.gethostname()
            local_ip = sock.gethostbyname(hostname)
            
            return {
                "hostname": hostname,
                "local_ip": local_ip,
                "os": platform.system(),
                "os_version": platform.release(),
                "processor": platform.processor(),
                "machine": platform.machine(),
                "cpu_cores": psutil.cpu_count(),
                "total_memory_gb": psutil.virtual_memory().total // (1024**3),
                "available_memory_gb": psutil.virtual_memory().available // (1024**3)
            }
        except:
            return {
                "hostname": "unknown",
                "local_ip": "127.0.0.1",
                "os": "Windows",
                "cpu_cores": 4,
                "total_memory_gb": 8
            }
    
    def generate_access_token(self, duration_hours: int = 24) -> str:
        """Generate secure access token for remote connection"""
        token = secrets.token_urlsafe(64)
        return token
    
    def create_remote_session(self, requester: str, access_type: str, target_ip: str, 
                            target_hostname: str, duration_hours: int = 8) -> Dict:
        """Create new remote access session"""
        if access_type not in self.ACCESS_TYPES:
            return None
        
        session_id = f"RS-{secrets.token_hex(8).upper()}"
        access_token = self.generate_access_token(duration_hours)
        
        session = {
            "session_id": session_id,
            "requester": requester,
            "access_type": access_type,
            "target_ip": target_ip,
            "target_hostname": target_hostname,
            "access_token": hashlib.sha256(access_token.encode()).hexdigest(),  # Store hash
            "access_token_plain": access_token,  # For one-time display
            "created_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(hours=duration_hours)).isoformat(),
            "status": "active",
            "connection_logs": []
        }
        
        self.access_data["sessions"].append(session)
        self.save_access_rules()
        
        return {
            "session_id": session_id,
            "access_token": access_token,  # Send to requester once
            "target": f"{target_hostname} ({target_ip})",
            "access_type": access_type,
            "expires_at": session["expires_at"]
        }
    
    def verify_access_token(self, session_id: str, token: str) -> bool:
        """Verify access token for a session"""
        for session in self.access_data["sessions"]:
            if session["session_id"] == session_id:
                token_hash = hashlib.sha256(token.encode()).hexdigest()
                if token_hash == session["access_token"] and session["status"] == "active":
                    # Check expiration
                    expires = datetime.fromisoformat(session["expires_at"])
                    if datetime.now() > expires:
                        session["status"] = "expired"
                        self.save_access_rules()
                        return False
                    return True
        return False
    
    def log_connection(self, session_id: str, event: str, details: str = "") -> bool:
        """Log connection event"""
        for session in self.access_data["sessions"]:
            if session["session_id"] == session_id:
                log_entry = {
                    "timestamp": datetime.now().isoformat(),
                    "event": event,
                    "details": details
                }
                session["connection_logs"].append(log_entry)
                
                # Also log to main access logs
                self.access_data["access_logs"].append({
                    "session_id": session_id,
                    "timestamp": datetime.now().isoformat(),
                    "event": event,
                    "details": details
                })
                
                self.save_access_rules()
                return True
        return False
    
    def approve_user(self, username: str, user_email: str, permissions: List[str]) -> bool:
        """Approve user for remote access"""
        user = {
            "username": username,
            "email": user_email,
            "permissions": permissions,
            "approved_at": datetime.now().isoformat(),
            "last_used": None,
            "use_count": 0
        }
        
        # Check if already approved
        for approved_user in self.access_data["approved_users"]:
            if approved_user["username"] == username:
                return False
        
        self.access_data["approved_users"].append(user)
        self.save_access_rules()
        return True
    
    def is_user_approved(self, username: str) -> bool:
        """Check if user is approved for remote access"""
        for user in self.access_data["approved_users"]:
            if user["username"] == username:
                return True
        return False
    
    def block_ip(self, ip: str, reason: str = "") -> bool:
        """Block IP from remote access"""
        if ip not in self.access_data["blocked_ips"]:
            self.access_data["blocked_ips"].append({
                "ip": ip,
                "blocked_at": datetime.now().isoformat(),
                "reason": reason
            })
            self.save_access_rules()
            
            # Terminate any active sessions from this IP
            for session in self.access_data["sessions"]:
                if session.get("source_ip") == ip and session["status"] == "active":
                    session["status"] = "terminated"
            
            self.save_access_rules()
            return True
        return False
    
    def is_ip_blocked(self, ip: str) -> bool:
        """Check if IP is blocked"""
        return any(blocked["ip"] == ip for blocked in self.access_data["blocked_ips"])
    
    def list_sessions(self, status: str = None) -> List[Dict]:
        """List remote access sessions"""
        sessions = self.access_data["sessions"]
        
        if status:
            sessions = [s for s in sessions if s["status"] == status]
        
        return sessions
    
    def end_session(self, session_id: str) -> bool:
        """Terminate active session"""
        for session in self.access_data["sessions"]:
            if session["session_id"] == session_id:
                session["status"] = "terminated"
                self.log_connection(session_id, "session_terminated", "User manually ended session")
                self.save_access_rules()
                return True
        return False
    
    def get_access_logs(self, session_id: str = None, limit: int = 100) -> List[Dict]:
        """Get access logs"""
        logs = self.access_data["access_logs"]
        
        if session_id:
            logs = [l for l in logs if l["session_id"] == session_id]
        
        return sorted(logs, key=lambda x: x["timestamp"], reverse=True)[:limit]
    
    def create_access_token_for_pc(self, machine_id: str, hostname: str, duration_days: int = 30) -> str:
        """Create persistent access token for a SentinelX-enabled PC"""
        token = {
            "token_id": f"SENT-PC-{secrets.token_hex(16).upper()}",
            "machine_id": machine_id,
            "hostname": hostname,
            "created_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(days=duration_days)).isoformat(),
            "is_active": True,
            "access_key": secrets.token_urlsafe(64)
        }
        
        # Save to config
        config_path = self.cert_path / f"pc_token_{machine_id}.json"
        with open(config_path, 'w') as f:
            json.dump(token, f, indent=2)
        
        return token["access_key"]
    
    def verify_pc_token(self, machine_id: str, access_key: str) -> bool:
        """Verify PC access token"""
        config_path = self.cert_path / f"pc_token_{machine_id}.json"
        
        if not config_path.exists():
            return False
        
        with open(config_path, 'r') as f:
            token = json.load(f)
        
        if token["access_key"] != access_key or not token["is_active"]:
            return False
        
        # Check expiration
        expires = datetime.fromisoformat(token["expires_at"])
        return datetime.now() < expires
    
    def enable_remote_access_on_pc(self) -> Dict:
        """Enable remote access on current PC"""
        system_info = self.get_system_info()
        machine_id = hashlib.md5(system_info["hostname"].encode()).hexdigest()[:16]
        
        access_key = self.create_access_token_for_pc(machine_id, system_info["hostname"])
        
        return {
            "machine_id": machine_id,
            "hostname": system_info["hostname"],
            "local_ip": system_info["local_ip"],
            "access_key": access_key,
            "registration_code": f"{system_info['hostname']}-{machine_id[:8]}".upper(),
            "system_info": system_info
        }
    
    def generate_access_report(self) -> Dict:
        """Generate remote access report"""
        active_sessions = [s for s in self.access_data["sessions"] if s["status"] == "active"]
        
        report = {
            "generated_at": datetime.now().isoformat(),
            "remote_access_enabled": self.access_data["enabled"],
            "active_sessions": len(active_sessions),
            "total_sessions": len(self.access_data["sessions"]),
            "approved_users": len(self.access_data["approved_users"]),
            "blocked_ips": len(self.access_data["blocked_ips"]),
            "total_access_logs": len(self.access_data["access_logs"]),
            "access_methods": list(set(s["access_type"] for s in self.access_data["sessions"])),
            "recent_activity": self.get_access_logs(limit=10)
        }
        
        return report
