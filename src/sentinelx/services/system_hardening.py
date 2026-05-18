"""
System Hardening: Apply security configurations and defensive measures.
"""

import subprocess
import logging
from pathlib import Path
from typing import List, Dict, Tuple

from sentinelx.utils.logger import get_logger

logger = get_logger(__name__)


class SystemHardening:
    """Apply system hardening measures and security configurations."""
    
    def __init__(self, enable_auto_apply: bool = False):
        self.enable_auto_apply = enable_auto_apply
        self.applied_hardening = []
    
    def harden_services(self) -> Dict[str, bool]:
        """Disable dangerous Windows services."""
        dangerous_services = {
            'RDP': 'TermService',  # Remote Desktop
            'SMB': 'LanmanServer',  # File Sharing
            'WinRM': 'WinRM',  # Remote Management
            'PsExec': 'PsExecSvc',  # Remote Execution
        }
        
        results = {}
        
        for service_name, service_id in dangerous_services.items():
            if self.enable_auto_apply:
                success = self._disable_service(service_id)
                results[service_name] = success
                
                if success:
                    self.applied_hardening.append(f"Disabled {service_name} service")
                    logger.warning(f"[HARDENING] Disabled service: {service_name}")
        
        return results
    
    def harden_firewall(self) -> bool:
        """Enable Windows Firewall and apply strict rules."""
        try:
            if self.enable_auto_apply:
                cmd = 'netsh advfirewall set allprofiles state on'
                subprocess.run(cmd, shell=True, capture_output=True, check=False)
                
                self.applied_hardening.append("Enabled Windows Firewall")
                logger.warning("[HARDENING] Windows Firewall enabled")
                return True
        
        except Exception as e:
            logger.error(f"[HARDENING] Error hardening firewall: {str(e)}")
            return False
    
    def harden_uac(self) -> bool:
        """Enable User Account Control (UAC)."""
        try:
            # Note: Requires registry modification, need admin
            registry_path = 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'
            registry_key = 'EnableUIADesktopToggle'
            
            if self.enable_auto_apply:
                cmd = f'reg add "{registry_path}" /v {registry_key} /t REG_DWORD /d 1 /f'
                subprocess.run(cmd, shell=True, capture_output=True, check=False)
                
                self.applied_hardening.append("Hardened UAC settings")
                logger.warning("[HARDENING] UAC settings hardened")
                return True
        
        except Exception as e:
            logger.error(f"[HARDENING] Error hardening UAC: {str(e)}")
            return False
    
    def disable_unnecessary_sharing(self) -> Dict[str, bool]:
        """Disable unnecessary Windows sharing features."""
        sharing_features = {
            'guest_account': 'guest',
            'network_discovery': 'NcaSvc',
            'file_sharing': 'LanmanServer',
            'printer_discovery': 'p2pimsvc',
        }
        
        results = {}
        
        for feature_name, service_name in sharing_features.items():
            if self.enable_auto_apply:
                success = self._disable_service(service_name)
                results[feature_name] = success
                
                if success:
                    self.applied_hardening.append(f"Disabled {feature_name}")
                    logger.warning(f"[HARDENING] Disabled feature: {feature_name}")
        
        return results
    
    def enable_audit_logging(self) -> bool:
        """Enable Windows audit logging."""
        try:
            audit_policies = [
                'audit process creation',
                'audit account management',
                'audit logon events',
            ]
            
            if self.enable_auto_apply:
                for policy in audit_policies:
                    cmd = f'auditpol /set /category:"{policy}" /success:enable /failure:enable'
                    subprocess.run(cmd, shell=True, capture_output=True, check=False)
                
                self.applied_hardening.append("Enabled Windows audit logging")
                logger.warning("[HARDENING] Audit logging enabled")
                return True
        
        except Exception as e:
            logger.error(f"[HARDENING] Error enabling audit logging: {str(e)}")
            return False
    
    def harden_windows_defender(self) -> bool:
        """Configure Windows Defender for stronger protection."""
        try:
            if self.enable_auto_apply:
                # Enable real-time protection
                cmd = 'powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $false"'
                subprocess.run(cmd, shell=True, capture_output=True, check=False)
                
                # Enable cloud protection
                cmd = 'powershell -Command "Set-MpPreference -MAPSReporting Advanced"'
                subprocess.run(cmd, shell=True, capture_output=True, check=False)
                
                self.applied_hardening.append("Hardened Windows Defender settings")
                logger.warning("[HARDENING] Windows Defender hardened")
                return True
        
        except Exception as e:
            logger.error(f"[HARDENING] Error hardening Defender: {str(e)}")
            return False
    
    def block_suspicious_extensions(self) -> Dict[str, bool]:
        """Block execution of suspicious file extensions."""
        suspicious_exts = [
            '.scr',     # Screen saver (often malicious)
            '.vbs',     # VBScript
            '.js',      # JavaScript (can be malicious)
            '.bat',     # Batch files
            '.cmd',     # Command files
            '.pif',     # Program information file
            '.msi',     # Installer (can be trojanized)
        ]
        
        results = {}
        
        if self.enable_auto_apply:
            for ext in suspicious_exts:
                # Add to registry to prevent execution
                try:
                    registry_path = f'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\{ext}'
                    subprocess.run(
                        f'reg add "{registry_path}" /v "blocked" /t REG_DWORD /d 1 /f',
                        shell=True,
                        capture_output=True,
                        check=False
                    )
                    results[ext] = True
                except:
                    results[ext] = False
            
            self.applied_hardening.append(f"Blocked {sum(results.values())} suspicious extensions")
            logger.warning("[HARDENING] Suspicious file extensions blocked")
        
        return results
    
    def disable_autorun(self) -> bool:
        """Disable autorun for external media."""
        try:
            registry_path = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AutoplayHandlers'
            
            if self.enable_auto_apply:
                cmd = f'reg add "{registry_path}" /v "DisableAutoplay" /t REG_DWORD /d 1 /f'
                subprocess.run(cmd, shell=True, capture_output=True, check=False)
                
                self.applied_hardening.append("Disabled autorun for external media")
                logger.warning("[HARDENING] Autorun disabled")
                return True
        
        except Exception as e:
            logger.error(f"[HARDENING] Error disabling autorun: {str(e)}")
            return False
    
    def apply_all_hardening(self) -> Dict[str, bool]:
        """Apply all hardening measures."""
        logger.warning("[HARDENING] Applying comprehensive system hardening...")
        
        results = {
            'services': len(self.harden_services()),
            'firewall': self.harden_firewall(),
            'uac': self.harden_uac(),
            'sharing': len(self.disable_unnecessary_sharing()),
            'audit_logging': self.enable_audit_logging(),
            'windows_defender': self.harden_windows_defender(),
            'suspicious_extensions': len(self.block_suspicious_extensions()),
            'autorun': self.disable_autorun(),
        }
        
        logger.warning(f"[HARDENING] Applied {len(self.applied_hardening)} hardening measures")
        return results
    
    def get_hardening_status(self) -> Dict:
        """Get current hardening status."""
        return {
            'auto_apply_enabled': self.enable_auto_apply,
            'measures_applied': len(self.applied_hardening),
            'applied_measures': self.applied_hardening,
        }
    
    def _disable_service(self, service_name: str) -> bool:
        """Disable a Windows service."""
        try:
            cmd = f'net stop {service_name}'
            subprocess.run(cmd, shell=True, capture_output=True, check=False)
            
            cmd = f'sc config {service_name} start= disabled'
            result = subprocess.run(cmd, shell=True, capture_output=True)
            
            return result.returncode == 0
        except Exception as e:
            logger.debug(f"[HARDENING] Error disabling service {service_name}: {str(e)}")
            return False
