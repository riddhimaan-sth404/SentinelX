"""
Quarantine Manager: Manage quarantined files with encryption and recovery options.
"""

import json
import shutil
import os
from pathlib import Path
from typing import List, Dict
from dataclasses import dataclass, asdict
from datetime import datetime

from sentinelx.utils.logger import get_logger

logger = get_logger(__name__)

# Import encryption
try:
    from cryptography.fernet import Fernet
    ENCRYPTION_AVAILABLE = True
except ImportError:
    ENCRYPTION_AVAILABLE = False
    logger.warning("[QUARANTINE] cryptography library not installed - files will not be encrypted")


@dataclass
class QuarantineEntry:
    """Represents a quarantined file."""
    original_path: str
    quarantine_path: str
    file_hash: str
    quarantine_date: str
    threat_type: str
    severity: str
    reason: str
    is_encrypted: bool = False


class QuarantineManager:
    """Manage quarantined malicious files with encryption."""
    
    QUARANTINE_DIRS = {
        'malicious': Path('quarantine/malicious'),
        'suspicious': Path('quarantine/suspicious'),
        'network': Path('quarantine/network_downloads'),
    }
    
    def __init__(self):
        self.quarantine_log = Path('logs/quarantine.json')
        self.encryption_key_file = Path('config/.quarantine_key')
        self._init_quarantine_dirs()
        self.entries: List[QuarantineEntry] = []
        self._load_or_create_encryption_key()
        self._load_quarantine_log()
        
        # Auto-recover any orphaned quarantine entries
        recovered = self.resync_quarantine_log()
        if recovered > 0:
            logger.info(f"[QUARANTINE] Auto-recovered {recovered} orphaned entries on startup")
    
    def _load_or_create_encryption_key(self):
        """Load or create encryption key for quarantine files."""
        if not ENCRYPTION_AVAILABLE:
            logger.warning("[QUARANTINE] Encryption library not available - files will NOT be encrypted")
            self.cipher = None
            return
        
        try:
            # Create config directory if needed
            self.encryption_key_file.parent.mkdir(parents=True, exist_ok=True)
            
            if self.encryption_key_file.exists():
                # Load existing key
                with open(self.encryption_key_file, 'rb') as f:
                    key = f.read()
                self.cipher = Fernet(key)
                logger.debug("[QUARANTINE] Encryption key loaded")
            else:
                # Generate new key
                key = Fernet.generate_key()
                with open(self.encryption_key_file, 'wb') as f:
                    f.write(key)
                # Set restrictive permissions on key file
                os.chmod(str(self.encryption_key_file), 0o600)
                self.cipher = Fernet(key)
                logger.info("[QUARANTINE] New encryption key generated")
        except Exception as e:
            logger.error(f"[QUARANTINE] Failed to setup encryption: {str(e)}")
            self.cipher = None
    
    def _encrypt_file(self, file_path: Path) -> bool:
        """Encrypt a file in place."""
        if not self.cipher:
            return False
        
        try:
            # Read original file
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Encrypt data
            encrypted_data = self.cipher.encrypt(data)
            
            # Write encrypted data back
            with open(file_path, 'wb') as f:
                f.write(encrypted_data)
            
            logger.debug(f"[QUARANTINE] File encrypted: {file_path}")
            return True
        except Exception as e:
            logger.error(f"[QUARANTINE] Encryption failed for {file_path}: {str(e)}")
            return False
    
    def _decrypt_file(self, file_path: Path) -> bool:
        """Decrypt a file in place."""
        if not self.cipher:
            return False
        
        try:
            # Read encrypted file
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt data
            decrypted_data = self.cipher.decrypt(encrypted_data)
            
            # Write decrypted data back
            with open(file_path, 'wb') as f:
                f.write(decrypted_data)
            
            logger.debug(f"[QUARANTINE] File decrypted: {file_path}")
            return True
        except Exception as e:
            logger.error(f"[QUARANTINE] Decryption failed for {file_path}: {str(e)}")
            return False
    
    def _init_quarantine_dirs(self):
        """Initialize quarantine directories."""
        for qdir in self.QUARANTINE_DIRS.values():
            qdir.mkdir(parents=True, exist_ok=True)
    
    def quarantine_file(self, file_path: str, threat_type: str, severity: str, reason: str) -> bool:
        """Move file to quarantine and encrypt it."""
        try:
            source = Path(file_path)
            if not source.exists():
                return False
            
            category = severity  # Use severity as quarantine category
            dest_dir = self.QUARANTINE_DIRS.get(category, self.QUARANTINE_DIRS['suspicious'])
            
            quarantine_name = f"{source.stem}_QUARANTINED_{datetime.now().strftime('%Y%m%d_%H%M%S')}{source.suffix}"
            quarantine_path = dest_dir / quarantine_name
            
            # Move file to quarantine
            shutil.move(str(source), str(quarantine_path))
            logger.info(f"[QUARANTINE] File moved to quarantine: {quarantine_path}")
            
            # Encrypt the quarantined file
            is_encrypted = False
            if ENCRYPTION_AVAILABLE and self.cipher:
                is_encrypted = self._encrypt_file(quarantine_path)
                if is_encrypted:
                    logger.critical(f"[QUARANTINE] File encrypted to prevent execution: {quarantine_path}")
                else:
                    logger.warning(f"[QUARANTINE] Encryption failed, file remains unencrypted: {quarantine_path}")
            
            # Log entry to quarantine database
            import hashlib
            file_hash = hashlib.sha256(open(quarantine_path, 'rb').read() if not is_encrypted else b'').hexdigest()
            
            entry = QuarantineEntry(
                original_path=str(source),
                quarantine_path=str(quarantine_path),
                file_hash=file_hash,
                quarantine_date=datetime.now().isoformat(),
                threat_type=threat_type,
                severity=severity,
                reason=reason,
                is_encrypted=is_encrypted
            )
            
            self.entries.append(asdict(entry))
            self._save_quarantine_log()
            
            logger.info(f"[QUARANTINE] File successfully quarantined: {quarantine_path}")
            return True
        
        except Exception as e:
            logger.error(f"[QUARANTINE] Error quarantining file: {str(e)}")
            return False
    
    def restore_file(self, quarantine_path: str, original_path: str) -> bool:
        """Restore file from quarantine (decrypt and move to original location)."""
        try:
            source = Path(quarantine_path)
            dest = Path(original_path)
            
            if not source.exists():
                logger.warning(f"[QUARANTINE] File not found: {quarantine_path}")
                return False
            
            # Decrypt the file before restoring
            if ENCRYPTION_AVAILABLE and self.cipher:
                decrypt_success = self._decrypt_file(source)
                if decrypt_success:
                    logger.info(f"[QUARANTINE] File decrypted for restoration: {source}")
                else:
                    logger.error(f"[QUARANTINE] Failed to decrypt file: {source}")
                    return False
            
            # Restore to original location
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(source), str(dest))
            
            # Remove entry from quarantine log
            self.entries = [e for e in self.entries if e.get('quarantine_path') != str(source)]
            self._save_quarantine_log()
            
            logger.warning(f"[QUARANTINE] File restored to original location: {original_path}")
            return True
        
        except Exception as e:
            logger.error(f"[QUARANTINE] Error restoring file: {str(e)}")
            return False
    
    def permanently_delete(self, quarantine_path: str) -> bool:
        """Permanently delete quarantined file."""
        try:
            path = Path(quarantine_path)
            if path.exists():
                path.unlink()
                
                # Remove entry from quarantine log
                self.entries = [e for e in self.entries if e.get('quarantine_path') != str(path)]
                self._save_quarantine_log()
                
                logger.info(f"[QUARANTINE] File permanently deleted: {quarantine_path}")
                return True
            return False
        
        except Exception as e:
            logger.error(f"[QUARANTINE] Error deleting file: {str(e)}")
            return False
    
    def get_quarantine_stats(self) -> dict:
        """Get statistics on quarantined files."""
        stats = {'total': 0, 'by_severity': {}, 'by_type': {}}
        
        for category, qdir in self.QUARANTINE_DIRS.items():
            if not qdir.exists():
                continue
            
            count = len(list(qdir.glob('*')))
            stats['total'] += count
            stats['by_severity'][category] = count
        
        return stats
    
    def get_quarantined_files(self) -> list:
        """Get list of all quarantined files from log."""
        return self.entries
    
    def get_quarantined_file(self, quarantine_path: str) -> dict:
        """Get details of a specific quarantined file."""
        for entry in self.entries:
            if entry.get('quarantine_path') == str(quarantine_path):
                return entry
        return None
    
    def list_quarantine_directory(self, severity: str = None) -> list:
        """List files in quarantine directory."""
        files = []
        
        if severity:
            dirs = [self.QUARANTINE_DIRS.get(severity)]
        else:
            dirs = list(self.QUARANTINE_DIRS.values())
        
        for qdir in dirs:
            if qdir.exists():
                for file_path in qdir.glob('*'):
                    if file_path.is_file():
                        # Find matching quarantine entry for details
                        entry = self.get_quarantined_file(str(file_path))
                        files.append({
                            'path': str(file_path),
                            'filename': file_path.name,
                            'size': file_path.stat().st_size,
                            'entry': entry
                        })
        
        return files
    
    def resync_quarantine_log(self) -> int:
        """
        Rescan quarantine directories and recover missing entries.
        Returns the number of entries recovered.
        """
        import hashlib
        recovered = 0
        
        # Track which files we've logged
        logged_paths = set(e.get('quarantine_path') for e in self.entries)
        
        # Scan all quarantine directories
        for severity, qdir in self.QUARANTINE_DIRS.items():
            if not qdir.exists():
                continue
            
            for file_path in qdir.glob('*'):
                if not file_path.is_file():
                    continue
                
                file_path_str = str(file_path)
                
                # Check if this file is already logged
                if file_path_str in logged_paths:
                    continue
                
                # File found on disk but not in log - recover it
                logger.warning(f"[QUARANTINE] Recovering orphaned quarantine entry: {file_path}")
                
                try:
                    # Try to extract original path from filename
                    filename = file_path.name
                    # Format: filename_QUARANTINED_TIMESTAMP.ext
                    parts = filename.rsplit('_QUARANTINED_', 1)
                    original_name = parts[0] if parts else filename
                    
                    # Create recovery entry
                    entry = QuarantineEntry(
                        original_path=f"[RECOVERED] {original_name}",
                        quarantine_path=file_path_str,
                        file_hash="",
                        quarantine_date=datetime.fromtimestamp(file_path.stat().st_mtime).isoformat(),
                        threat_type="unknown",
                        severity=severity,
                        reason="[RECOVERED] Entry was missing from log",
                        is_encrypted=False  # Unknown if encrypted
                    )
                    
                    self.entries.append(asdict(entry))
                    recovered += 1
                    logger.info(f"[QUARANTINE] Recovered entry for: {file_path_str}")
                    
                except Exception as e:
                    logger.error(f"[QUARANTINE] Failed to recover entry for {file_path}: {e}")
        
        # Save the updated log
        if recovered > 0:
            self._save_quarantine_log()
            logger.warning(f"[QUARANTINE] Recovered {recovered} missing quarantine entries")
        
        return recovered
    
    def _load_quarantine_log(self):
        """Load quarantine log from file."""
        try:
            if self.quarantine_log.exists():
                with open(self.quarantine_log, 'r') as f:
                    data = json.load(f)
                    self.entries = data.get('entries', [])
        except Exception as e:
            logger.debug(f"[QUARANTINE] Error loading log: {str(e)}")
    
    def _save_quarantine_log(self):
        """Save quarantine log to file."""
        try:
            self.quarantine_log.parent.mkdir(parents=True, exist_ok=True)
            with open(self.quarantine_log, 'w') as f:
                json.dump({
                    'timestamp': datetime.now().isoformat(),
                    'entries': self.entries
                }, f, indent=2)
        except Exception as e:
            logger.error(f"[QUARANTINE] Error saving log: {str(e)}")
