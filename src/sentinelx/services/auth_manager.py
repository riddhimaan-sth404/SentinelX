"""
Authentication and User Management System for SentinelX
Handles user login, role-based access control, and session management
"""
import json
import hashlib
import secrets
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional, List, Tuple

class AuthManager:
    """Manages user authentication and authorization"""
    
    ROLES = {
        "Administrator": {
            "permissions": ["view_all", "edit_all", "manage_users", "manage_settings", "export_data"],
            "level": 5
        },
        "Analyst_Senior": {
            "permissions": ["view_all", "investigate", "remediate", "manage_incidents"],
            "level": 4
        },
        "Analyst_Junior": {
            "permissions": ["view_incidents", "create_tickets", "view_reports"],
            "level": 2
        },
        "System_Admin": {
            "permissions": ["manage_settings", "apply_patches", "configure_firewall", "manage_updates"],
            "level": 3
        },
        "Viewer": {
            "permissions": ["view_reports", "view_dashboard"],
            "level": 1
        }
    }
    
    def __init__(self, db_path: str = "config/users.json"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.sessions = {}  # {session_token: {user_id, username, role, created_at, last_activity}}
        self.load_users()
    
    def load_users(self):
        """Load user database from file"""
        if self.db_path.exists():
            try:
                with open(self.db_path, 'r') as f:
                    self.users = json.load(f)
            except:
                self.users = {}
        else:
            self.users = {}
            # Create default admin user
            self.create_user("admin", "admin@sentinelx.local", "Administrator", "default_hash")
    
    def save_users(self):
        """Save user database to file"""
        with open(self.db_path, 'w') as f:
            json.dump(self.users, f, indent=2)
    
    def hash_password(self, password: str, salt: str = None) -> Tuple[str, str]:
        """Hash password with salt"""
        if salt is None:
            salt = secrets.token_hex(16)
        hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return hash_obj.hex(), salt
    
    def create_user(self, username: str, email: str, role: str, password: str) -> bool:
        """Create new user"""
        if username in self.users:
            return False
        
        if role not in self.ROLES:
            return False
        
        password_hash, salt = self.hash_password(password)
        
        self.users[username] = {
            "email": email,
            "role": role,
            "password_hash": password_hash,
            "salt": salt,
            "created_at": datetime.now().isoformat(),
            "last_login": None,
            "mfa_enabled": False,
            "mfa_secret": None,
            "is_active": True
        }
        self.save_users()
        return True
    
    def authenticate(self, username: str, password: str) -> Optional[str]:
        """Authenticate user and return session token"""
        if username not in self.users:
            return None
        
        user = self.users[username]
        if not user["is_active"]:
            return None
        
        # Verify password
        password_hash, _ = self.hash_password(password, user["salt"])
        if password_hash != user["password_hash"]:
            return None
        
        # Create session token
        session_token = secrets.token_urlsafe(32)
        self.sessions[session_token] = {
            "user_id": username,
            "username": username,
            "role": user["role"],
            "created_at": time.time(),
            "last_activity": time.time(),
            "ip": "127.0.0.1"
        }
        
        # Update last login
        user["last_login"] = datetime.now().isoformat()
        self.save_users()
        
        return session_token
    
    def verify_session(self, session_token: str, timeout: int = 3600) -> bool:
        """Verify if session is valid"""
        if session_token not in self.sessions:
            return False
        
        session = self.sessions[session_token]
        if time.time() - session["last_activity"] > timeout:
            del self.sessions[session_token]
            return False
        
        session["last_activity"] = time.time()
        return True
    
    def get_user_from_session(self, session_token: str) -> Optional[Dict]:
        """Get user info from session token"""
        if not self.verify_session(session_token):
            return None
        
        session = self.sessions[session_token]
        username = session["user_id"]
        user = self.users[username]
        
        return {
            "username": username,
            "email": user["email"],
            "role": user["role"],
            "permissions": self.ROLES[user["role"]]["permissions"],
            "last_login": user["last_login"]
        }
    
    def check_permission(self, session_token: str, permission: str) -> bool:
        """Check if user has specific permission"""
        user = self.get_user_from_session(session_token)
        if not user:
            return False
        
        return permission in user["permissions"]
    
    def list_users(self) -> List[Dict]:
        """List all users with their info"""
        users_list = []
        for username, user_data in self.users.items():
            users_list.append({
                "username": username,
                "email": user_data["email"],
                "role": user_data["role"],
                "last_login": user_data["last_login"],
                "mfa_enabled": user_data["mfa_enabled"],
                "is_active": user_data["is_active"],
                "created_at": user_data["created_at"]
            })
        return users_list
    
    def delete_user(self, username: str) -> bool:
        """Delete user"""
        if username in self.users:
            del self.users[username]
            self.save_users()
            return True
        return False
    
    def update_user_role(self, username: str, new_role: str) -> bool:
        """Update user's role"""
        if username not in self.users or new_role not in self.ROLES:
            return False
        
        self.users[username]["role"] = new_role
        self.save_users()
        return True
    
    def enable_mfa(self, username: str) -> str:
        """Enable MFA for user (returns secret for QR code)"""
        if username not in self.users:
            return None
        
        mfa_secret = secrets.token_urlsafe(32)
        self.users[username]["mfa_enabled"] = True
        self.users[username]["mfa_secret"] = mfa_secret
        self.save_users()
        return mfa_secret
    
    def logout(self, session_token: str) -> bool:
        """Logout user"""
        if session_token in self.sessions:
            del self.sessions[session_token]
            return True
        return False
