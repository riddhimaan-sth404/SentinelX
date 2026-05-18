"""
Windows Whitelist Module - Safe system files and processes
Prevents false positives by excluding trusted Windows applications and system files.
"""
import os
from pathlib import Path
from typing import Set
import logging

logger = logging.getLogger(__name__)


class WindowsWhitelist:
    """Manages whitelist of trusted Windows system files and applications."""
    
    # Core Windows system folders (always safe)
    SAFE_FOLDERS = {
        'c:\\windows\\',
        'c:\\program files\\',
        'c:\\program files (x86)\\',
        'c:\\programdata\\microsoft\\',
        'c:\\winnt\\',
    }
    
    # Safe processes and executables (case-insensitive)
    SAFE_EXECUTABLES = {
        # Windows Core
        'svchost.exe', 'services.exe', 'lsass.exe', 'smss.exe',
        'csrss.exe', 'wininit.exe', 'conhost.exe', 'explorer.exe',
        'dwm.exe', 'taskhostw.exe', 'rundll32.exe', 'regsvcs.exe',
        'regsvc.exe', 'regsvr32.exe', 'rundll.exe', 'dllhost.exe',
        
        # Windows Updates
        'wuauclt.exe', 'nuget.exe', 'wusa.exe', 'TiWorker.exe',
        'sihclient.exe', 'WinDefend.exe', 'MsMpEng.exe', 'SecurityHealthService.exe',
        
        # Windows Defender / Security
        'winlogon.exe', 'userinit.exe', 'ProtectedModuleHost.exe',
        'SecurityHealthSystray.exe', 'WmiPrvSE.exe', 'wmiprvse.exe',
        
        # Network Services
        'tcpsvcs.exe', 'SNMPService.exe', 'DHCP.exe', 'DNS.exe',
        'ipconfig.exe', 'nslookup.exe', 'ping.exe', 'netstat.exe',
        'tasklist.exe', 'taskkill.exe', 'net.exe', 'netsh.exe',
        
        # Windows Kernel & System
        'smss.exe', 'csrss.exe', 'ntoskrnl.exe', 'hal.dll',
        'kernel32.dll', 'ntdll.dll', 'user32.dll', 'advapi32.dll',
        
        # Administrative Tools
        'devenv.exe', 'msiexec.exe', 'winrar.exe', 'notepad.exe',
        'cmd.exe', 'powershell.exe', 'taskmgr.exe', 'diskmgmt.msc',
        'compmgmt.msc', 'devmgmt.msc', 'services.msc', 'eventvwr.msc',
        
        # Windows Networking
        'iexplore.exe', 'firefox.exe', 'chrome.exe', 'msedge.exe',
        'outlook.exe', 'thunderbird.exe', 'putty.exe', 'winscp.exe',
        
        # Windows Updates & Maintenance
        'nltest.exe', 'dcdiag.exe', 'repadmin.exe', 'fsutil.exe',
        'chkdsk.exe', 'defrag.exe', 'diskpart.exe', 'format.exe',
        
        # Safe Microsoft Tools
        'msdt.exe', 'mstsc.exe', 'mmc.exe', 'control.exe',
        'calc.exe', 'paint.exe', 'wordpad.exe', 'clipbrd.exe',
        'charmap.exe', 'sndvol.exe', 'perfmon.exe', 'eventvwr.exe',
        
        # Windows Diagnostics
        'perfmon.exe', 'logman.exe', 'wevtutil.exe', 'wmi.exe',
        'WMIDiag.exe', 'diagnhost.exe', 'DiagnosticWorker.exe',
        
        # Windows Update Engine
        'WindowsUpdate.exe', 'UpdateOrchestrator.exe', 'MusNotifyIcon.exe',
        'SetupHost.exe', 'newdev.exe', 'drvinst.exe', 'hdwwiz.exe',
        
        # Common Safe Applications (user-installable)
        'acrobat.exe', 'adobeupdate.exe', 'java.exe', 'javaw.exe',
        'javaupdate.exe', 'ITProConsole.exe', 'TeamViewer.exe',
        'AnyDesk.exe', 'skype.exe', 'slack.exe', 'zoom.exe',
        'discord.exe', 'spotify.exe', 'vlc.exe', 'ffmpeg.exe',
        'python.exe', 'pythonw.exe', 'node.exe', 'npm.exe',
        'docker.exe', 'git.exe', 'svn.exe', 'mercurial.exe',
        'matlab.exe', 'mathematica.exe', 'r.exe', 'rstudio.exe',
        
        # Microsoft Office
        'winword.exe', 'excel.exe', 'powerpnt.exe', 'msaccess.exe',
        'mspub.exe', 'onenote.exe', 'infopath.exe', 'visio.exe',
        
        # Microsoft Teams, OneDrive, Sync
        'teams.exe', 'onedrive.exe', 'groove.exe', 'synchost.exe',
        'onenotemsaddin.exe', 'iCloudServices.exe', 'Dropbox.exe',
        'GoogleDriveSync.exe', 'Copy.exe', 'sync.exe',
        
        # Windows Component Stores
        'tiworker.exe', 'PendingRenames.exe', 'cbscore.exe',
        'serviceshell.exe', 'setupcln.exe',
    }
    
    # Safe file extensions (case-insensitive)
    SAFE_EXTENSIONS = {
        # Documents
        '.txt', '.docx', '.doc', '.xlsx', '.xls', '.pptx', '.ppt',
        '.pdf', '.odt', '.ods', '.odp', '.rtf', '.csv', '.json',
        '.xml', '.html', '.htm', '.md', '.rst', '.tex',
        
        # Media
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.tiff',
        '.mp3', '.wav', '.flac', '.aac', '.ogg', '.m4a', '.wma',
        '.mp4', '.avi', '.mkv', '.mov', '.flv', '.wmv', '.webm',
        
        # Archives
        '.zip', '.rar', '.7z', '.gz', '.tar', '.bz2', '.iso',
        '.cab', '.exe', '.msi', '.msu', '.inf',
        
        # Source Code - REMOVED: .py (malware-prone language)
        '.java', '.cpp', '.c', '.cs', '.js', '.ts', '.go',
        '.rs', '.php', '.rb', '.pl', '.sh', '.bash', '.bat', '.ps1',
        '.sql', '.html', '.css', '.scss', '.less', '.vue', '.jsx',
        
        # Config/Data
        '.yaml', '.yml', '.toml', '.cfg', '.conf', '.ini', '.env',
        '.properties', '.gradle', '.maven', '.npm', '.package',
        
        # Libraries & Headers
        '.dll', '.so', '.dylib', '.a', '.lib', '.h', '.hpp', '.idl',
        
        # System & Other Safe
        '.sys', '.drv', '.inf', '.cat', '.crl', '.cer', '.pem',
        '.key', '.crt', '.pfx', '.p12', '.ico', '.cur', '.ani',
    }
    
    def __init__(self):
        """Initialize the whitelist."""
        self.safe_folders_lower = {folder.lower() for folder in self.SAFE_FOLDERS}
        self.safe_executables_lower = {exe.lower() for exe in self.SAFE_EXECUTABLES}
        self.safe_extensions_lower = {ext.lower() for ext in self.SAFE_EXTENSIONS}
        logger.info(f"Windows Whitelist initialized with {len(self.safe_executables_lower)} safe executables")
    
    def is_safe_folder(self, file_path: str) -> bool:
        """Check if file is in a safe folder."""
        path_lower = file_path.lower()
        return any(path_lower.startswith(folder) for folder in self.safe_folders_lower)
    
    def is_safe_executable(self, file_path: str) -> bool:
        """Check if executable is in the safe list."""
        try:
            filename = Path(file_path).name.lower()
            return filename in self.safe_executables_lower
        except Exception as e:
            logger.debug(f"Error checking executable: {e}")
            return False
    
    def is_safe_extension(self, file_path: str) -> bool:
        """Check if file extension is in the safe list."""
        try:
            ext = Path(file_path).suffix.lower()
            return ext in self.safe_extensions_lower
        except Exception as e:
            logger.debug(f"Error checking extension: {e}")
            return False
    
    def should_whitelist(self, file_path: str) -> bool:
        """
        Determine if a file should be whitelisted.
        
        Args:
            file_path: Path to the file to check
            
        Returns:
            True if the file is in the whitelist, False otherwise
        """
        try:
            # Check if in safe folder
            if self.is_safe_folder(file_path):
                return True
            
            # Check if is safe executable
            if self.is_safe_executable(file_path):
                return True
            
            # Check if has safe extension
            if self.is_safe_extension(file_path):
                return True
            
            return False
        except Exception as e:
            logger.debug(f"Error in whitelist check: {e}")
            return False
    
    def add_safe_executable(self, executable_name: str):
        """Add a custom executable to the safe list."""
        try:
            self.safe_executables_lower.add(executable_name.lower())
            logger.debug(f"Added {executable_name} to safe executables")
        except Exception as e:
            logger.error(f"Error adding safe executable: {e}")
    
    def add_safe_folder(self, folder_path: str):
        """Add a custom folder to the safe list."""
        try:
            folder_lower = folder_path.lower()
            if not folder_lower.endswith('\\'):
                folder_lower += '\\'
            self.safe_folders_lower.add(folder_lower)
            logger.debug(f"Added {folder_path} to safe folders")
        except Exception as e:
            logger.error(f"Error adding safe folder: {e}")


# Global whitelist instance
_whitelist_instance = None


def get_whitelist() -> WindowsWhitelist:
    """Get or create the global whitelist instance."""
    global _whitelist_instance
    if _whitelist_instance is None:
        _whitelist_instance = WindowsWhitelist()
    return _whitelist_instance
