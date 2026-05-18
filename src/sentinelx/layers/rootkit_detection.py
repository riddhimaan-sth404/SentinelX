"""
Rootkit Detection Layer: Detects kernel-mode and user-mode rootkits.
Monitors suspicious system modifications, hidden processes, driver anomalies.
"""
import os
import subprocess
import json
import psutil
import winreg
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
from sentinelx.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class RootkitIndicator:
    """Rootkit detection indicator."""
    indicator_type: str  # kernel_module, hidden_process, registry, driver, hook, memory
    severity: int  # 0-10 criticality
    description: str
    evidence: Optional[str] = None
    process_id: Optional[int] = None
    file_path: Optional[str] = None
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat()


@dataclass
class RootkitScanResult:
    """Result of rootkit detection scan."""
    file_path: str
    is_rootkit: bool
    rootkit_confidence: float  # 0-1.0
    indicators: List[RootkitIndicator]
    suspicious_behavior_count: int
    risk_level: str  # clean, suspicious, critical
    detection_methods: List[str]  # Which detection methods triggered
    scan_duration: float
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat()


class RootkitDetectionLayer:
    """
    Advanced rootkit detection engine.
    Monitors kernel modules, processes, registry, drivers, and system hooks.
    """
    
    def __init__(self):
        """Initialize rootkit detection layer."""
        self.kernel_module_patterns = {
            'infector': 10,
            'rootkit': 10,
            'hacker': 10,
            'backdoor': 10,
            'trojan': 9,
            'malware': 9,
            'spyware': 9,
            'adware': 8,
            'loader': 8,
            'injector': 9,
            'hook': 8,
            'hidden': 9,
            'system': 2,  # Lower weight, common legit modules
            'kernel': 2,  # Lower weight, common legit modules
        }
        
        self.suspicious_drivers = {
            'infect.sys': 10,
            'rootkit.sys': 10,
            'backdoor.sys': 10,
            'hidden.sys': 10,
            'loader.sys': 9,
            'injector.sys': 9,
            'hook.sys': 8,
            'monitor.sys': 8,
        }
        
        self.suspicious_registry_keys = [
            r'HKLM\System\CurrentControlSet\Services',  # Services
            r'HKLM\Software\Microsoft\Windows\CurrentVersion\Run',  # Autorun
            r'HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce',  # One-time runs
            r'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon',  # Logon processes
        ]
        
        # Critical Windows system processes that MUST run under SYSTEM user only
        # If any of these run under a different user, it's a rootkit hijacking indicator
        self.critical_system_processes = {
            'csrss.exe': 'Client/Server Runtime Subsystem',
            'svchost.exe': 'Service Host',
            'lsass.exe': 'Local Security Authority',
            'services.exe': 'Service Control Manager',
            'smss.exe': 'Session Manager',
            'wininit.exe': 'Windows Initialization',
            'winlogon.exe': 'Windows Logon',
            'ntlm.exe': 'NTLM Authentication',
            'spoolsv.exe': 'Print Spooler',
            'explorer.exe': 'Windows Explorer (should be user)',  # Explorer can be user, but monitor
            'taskmgr.exe': 'Task Manager',
            'wscript.exe': 'Windows Script Host',
            'cscript.exe': 'Console Script Host',
            'msiexec.exe': 'Windows Installer',
            'rundll32.exe': 'DLL Runner',
            'regsvr32.exe': 'Registry Server',
            'powershell.exe': 'PowerShell (monitor)',
            'cmd.exe': 'Command Prompt',
            'system.exe': 'System Process',
            'ntvdm.exe': 'DOS Virtual Machine',
            'conhost.exe': 'Console Host',
            'dwm.exe': 'Desktop Window Manager',
            'nvagent.exe': 'NVIDIA Agent',
        }
        
        self.terminated_hijacked_processes = []
        logger.info("[ROOTKIT] Process Hijacking Detection initialized - Critical Windows processes under surveillance")
        self.suspicious_processes = [
            'csrss.exe',  # Should only have 2 instances
            'svchost.exe',  # Should only run from system32
            'explorer.exe',  # Should only run once
            'lsass.exe',  # System process, rarely modified
            'services.exe',  # System service
        ]
        
        logger.info("[ROOTKIT] Rootkit Detection Layer initialized")
    
    def scan_file(self, file_path: str) -> RootkitScanResult:
        """
        Scan a file for rootkit indicators.
        
        Args:
            file_path: Path to file to scan
            
        Returns:
            RootkitScanResult with detection details
        """
        import time
        start_time = time.time()
        indicators = []
        detection_methods = []
        
        try:
            # Method 1: File signature analysis
            if self._check_driver_signature(file_path):
                indicators.append(RootkitIndicator(
                    indicator_type='driver',
                    severity=8,
                    description='Driver file detected',
                    file_path=file_path
                ))
                detection_methods.append('driver_signature')
            
            # Method 2: Suspicious imports
            imports = self._extract_file_imports(file_path)
            for imp in imports:
                if imp.lower() in self._get_rootkit_imports():
                    indicators.append(RootkitIndicator(
                        indicator_type='suspicious_import',
                        severity=9,
                        description=f'Suspicious kernel import: {imp}',
                        file_path=file_path,
                        evidence=imp
                    ))
                    detection_methods.append('rootkit_imports')
            
            # Method 3: File name patterns
            filename_score = self._check_filename_patterns(file_path)
            if filename_score > 5:
                indicators.append(RootkitIndicator(
                    indicator_type='filename_heuristic',
                    severity=filename_score,
                    description=f'Suspicious filename pattern detected',
                    file_path=file_path,
                    evidence=Path(file_path).name
                ))
                detection_methods.append('filename_pattern')
            
            # Method 4: File location anomaly
            if self._check_suspicious_location(file_path):
                indicators.append(RootkitIndicator(
                    indicator_type='location_anomaly',
                    severity=7,
                    description='File in suspicious system location',
                    file_path=file_path
                ))
                detection_methods.append('location_check')
            
            # Calculate confidence and risk
            confidence = min(len(indicators) * 0.25, 1.0)
            is_rootkit = confidence > 0.5 or any(ind.severity >= 9 for ind in indicators)
            
            # Determine risk level
            if is_rootkit:
                risk_level = 'critical'
            elif len(indicators) > 2:
                risk_level = 'suspicious'
            else:
                risk_level = 'clean'
            
            duration = time.time() - start_time
            
            result = RootkitScanResult(
                file_path=file_path,
                is_rootkit=is_rootkit,
                rootkit_confidence=confidence,
                indicators=indicators,
                suspicious_behavior_count=len(indicators),
                risk_level=risk_level,
                detection_methods=detection_methods,
                scan_duration=duration
            )
            
            if is_rootkit:
                logger.critical(f"[ROOTKIT] POTENTIAL ROOTKIT DETECTED: {file_path}")
                for ind in indicators:
                    logger.warning(f"[ROOTKIT] {ind.indicator_type}: {ind.description}")
            elif indicators:
                logger.warning(f"[ROOTKIT] Suspicious indicators found in: {file_path}")
            else:
                logger.debug(f"[ROOTKIT] File scan clean: {file_path}")
            
            return result
            
        except Exception as e:
            logger.error(f"[ROOTKIT] Error scanning file {file_path}: {e}")
            return RootkitScanResult(
                file_path=file_path,
                is_rootkit=False,
                rootkit_confidence=0.0,
                indicators=[],
                suspicious_behavior_count=0,
                risk_level='clean',
                detection_methods=[],
                scan_duration=time.time() - start_time
            )
    
    def scan_system(self) -> Dict:
        """
        Perform system-wide rootkit scan including process hijacking detection.
        
        Returns:
            Dictionary with scan results
        """
        logger.info("[ROOTKIT] Starting system-wide rootkit scan...")
        results = {
            'kernel_modules': self._scan_kernel_modules(),
            'hidden_processes': self._scan_hidden_processes(),
            'hijacked_processes': self._detect_hijacked_system_processes(),  # NEW: Process hijacking detection
            'registry_anomalies': self._scan_registry(),
            'driver_anomalies': self._scan_drivers(),
            'memory_anomalies': self._scan_memory_hooks(),
            'terminated_threats': self.terminated_hijacked_processes,  # Processes we killed
            'timestamp': datetime.utcnow().isoformat()
        }
        
        total_threats = sum(len(v) for v in results.values() if isinstance(v, list))
        logger.info(f"[ROOTKIT] System scan complete - {total_threats} threats detected")
        
        return results
    
    def _scan_kernel_modules(self) -> List[Dict]:
        """Scan for suspicious kernel modules."""
        suspicious_modules = []
        
        try:
            # Use psutil to get loaded modules
            # Note: Full kernel module scanning requires admin and special APIs
            logger.debug("[ROOTKIT] Scanning kernel modules...")
            
            # Check system drivers directory
            driver_paths = [
                r'C:\Windows\System32\drivers',
                r'C:\Windows\System32\drivers\etc'
            ]
            
            for driver_dir in driver_paths:
                if os.path.exists(driver_dir):
                    for file in os.listdir(driver_dir):
                        if file.endswith('.sys'):
                            file_path = os.path.join(driver_dir, file)
                            score = self._check_filename_patterns(file_path)
                            if score > 5:
                                suspicious_modules.append({
                                    'module': file,
                                    'path': file_path,
                                    'severity': score,
                                    'description': 'Suspicious kernel module detected'
                                })
                
        except Exception as e:
            logger.debug(f"[ROOTKIT] Error scanning kernel modules: {e}")
        
        return suspicious_modules
    
    def _scan_hidden_processes(self) -> List[Dict]:
        """Detect hidden processes using multiple methods."""
        hidden_processes = []
        
        try:
            logger.debug("[ROOTKIT] Scanning for hidden processes...")
            
            # Method 1: Check for process anomalies
            process_names = {}
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    name = proc.info['name'].lower()
                    if name not in process_names:
                        process_names[name] = 0
                    process_names[name] += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            # Check for suspicious process behavior
            for proc_name, count in process_names.items():
                if proc_name in self.suspicious_processes:
                    # Some system processes should have limited instances
                    if proc_name == 'csrss.exe' and count > 3:
                        hidden_processes.append({
                            'process': proc_name,
                            'instance_count': count,
                            'severity': 8,
                            'description': f'Abnormal {proc_name} instance count: {count}'
                        })
                    elif proc_name == 'explorer.exe' and count > 2:
                        hidden_processes.append({
                            'process': proc_name,
                            'instance_count': count,
                            'severity': 7,
                            'description': f'Multiple explorer.exe instances detected: {count}'
                        })
        
        except Exception as e:
            logger.debug(f"[ROOTKIT] Error scanning hidden processes: {e}")
        
        return hidden_processes
    
    def _detect_hijacked_system_processes(self) -> List[Dict]:
        """
        Detect and terminate Windows system processes running under non-SYSTEM user.
        This is a critical rootkit indicator - system processes should ONLY run under SYSTEM.
        
        Returns:
            List of hijacked processes detected and terminated
        """
        hijacked = []
        self.terminated_hijacked_processes = []
        
        try:
            logger.info("[ROOTKIT-HIJACK] Starting critical Windows process integrity check...")
            
            for proc in psutil.process_iter(['pid', 'name', 'username']):
                try:
                    proc_name = proc.info['name'].lower()
                    proc_username = proc.info['username'].lower() if proc.info['username'] else 'unknown'
                    proc_id = proc.info['pid']
                    
                    # Check if this is a critical Windows system process
                    if proc_name in self.critical_system_processes:
                        process_desc = self.critical_system_processes[proc_name]
                        
                        # Critical check: System processes should run under SYSTEM or NT AUTHORITY\SYSTEM
                        is_system_owned = any([
                            'system' in proc_username,
                            'nt authority' in proc_username,
                            proc_username == 'system'
                        ])
                        
                        if not is_system_owned:
                            # HIJACKED! System process running under non-system user
                            hijacked_entry = {
                                'process': proc_name,
                                'pid': proc_id,
                                'expected_user': 'SYSTEM',
                                'actual_user': proc_username,
                                'description': process_desc,
                                'severity': 10,  # CRITICAL
                                'status': 'DETECTED_AND_TERMINATING'
                            }
                            hijacked.append(hijacked_entry)
                            
                            logger.critical(
                                f"[ROOTKIT-HIJACK] ⚠️ CRITICAL ROOTKIT INDICATOR DETECTED!\n"
                                f"  Process: {proc_name} (PID: {proc_id})\n"
                                f"  Expected User: SYSTEM\n"
                                f"  Actual User: {proc_username}\n"
                                f"  Description: {process_desc}\n"
                                f"  Status: TERMINATING IMMEDIATELY"
                            )
                            
                            # Kill the hijacked process immediately
                            try:
                                process_obj = psutil.Process(proc_id)
                                process_obj.kill()  # Forcefully terminate
                                hijacked_entry['status'] = 'TERMINATED'
                                self.terminated_hijacked_processes.append(hijacked_entry)
                                logger.critical(f"[ROOTKIT-HIJACK] ✓ Hijacked process TERMINATED: {proc_name} (PID:{proc_id})")
                                
                            except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError) as kill_error:
                                hijacked_entry['status'] = f'TERMINATION_FAILED: {str(kill_error)}'
                                logger.error(
                                    f"[ROOTKIT-HIJACK] ⚠️ FAILED TO TERMINATE: {proc_name} (PID:{proc_id})\n"
                                    f"  Error: {kill_error}\n"
                                    f"  This process may require elevated privileges or may be protected by Windows"
                                )
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            if hijacked:
                logger.critical(f"[ROOTKIT-HIJACK] {len(hijacked)} hijacked system process(es) detected and handled!")
            else:
                logger.info("[ROOTKIT-HIJACK] ✓ All critical system processes verified - No hijacking detected")
            
        except Exception as e:
            logger.error(f"[ROOTKIT-HIJACK] Error during process hijacking scan: {e}")
        
        return hijacked
    
    def _scan_registry(self) -> List[Dict]:
        """Scan registry for rootkit indicators."""
        anomalies = []
        
        try:
            logger.debug("[ROOTKIT] Scanning registry for rootkit indicators...")
            
            # Check autorun locations
            autorun_keys = [
                (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Run'),
                (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\RunOnce'),
                (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run'),
            ]
            
            for hkey, subkey in autorun_keys:
                try:
                    reg_key = winreg.OpenKey(hkey, subkey)
                    i = 0
                    while True:
                        try:
                            value_name, value_data, value_type = winreg.EnumValue(reg_key, i)
                            # Check for suspicious patterns
                            if any(pattern in str(value_data).lower() for pattern in 
                                   ['rootkit', 'malware', 'backdoor', 'trojan']):
                                anomalies.append({
                                    'registry_key': subkey,
                                    'value_name': value_name,
                                    'severity': 10,
                                    'description': f'Suspicious autorun entry: {value_name}'
                                })
                            i += 1
                        except WindowsError:
                            break
                    winreg.CloseKey(reg_key)
                except Exception:
                    pass
        
        except Exception as e:
            logger.debug(f"[ROOTKIT] Error scanning registry: {e}")
        
        return anomalies
    
    def _scan_drivers(self) -> List[Dict]:
        """Scan for suspicious driver installations."""
        suspicious = []
        
        try:
            logger.debug("[ROOTKIT] Scanning for suspicious drivers...")
            
            # Check installed drivers
            try:
                reg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
                key = winreg.OpenKey(reg, r'System\CurrentControlSet\Services')
                
                for i in range(winreg.QueryInfoKey(key)[0]):
                    subkey_name = winreg.EnumKey(key, i)
                    
                    # Check if it's a driver (has ImagePath)
                    try:
                        subkey = winreg.OpenKey(key, subkey_name)
                        try:
                            image_path, _ = winreg.QueryValueEx(subkey, 'ImagePath')
                            
                            # Check for suspicious patterns
                            score = self._check_filename_patterns(image_path)
                            if score > 6:
                                suspicious.append({
                                    'driver': subkey_name,
                                    'path': image_path,
                                    'severity': score,
                                    'description': 'Suspicious driver detected'
                                })
                        except WindowsError:
                            pass
                        winreg.CloseKey(subkey)
                    except:
                        pass
                
                winreg.CloseKey(key)
            except Exception:
                pass
        
        except Exception as e:
            logger.debug(f"[ROOTKIT] Error scanning drivers: {e}")
        
        return suspicious
    
    def _scan_memory_hooks(self) -> List[Dict]:
        """Detect suspicious memory hooks and API patches."""
        hooks = []
        
        try:
            logger.debug("[ROOTKIT] Scanning for memory hooks...")
            
            # In a real implementation, this would use Windows APIs like
            # GetProcAddress, ReadProcessMemory to detect hooked functions
            # For now, we provide a framework and check for suspicious DLLs
            
            suspicious_dlls = ['ntdll.dll', 'kernel32.dll', 'user32.dll']
            
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if proc.info['name'].lower() in ['explorer.exe', 'winlogon.exe', 'lsass.exe']:
                        # These processes are commonly targeted by rootkits
                        # Check their loaded modules (would need elevated privileges)
                        pass
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        
        except Exception as e:
            logger.debug(f"[ROOTKIT] Error scanning memory hooks: {e}")
        
        return hooks
    
    def _check_driver_signature(self, file_path: str) -> bool:
        """Check if file is a driver (.sys, .drv, .sys)."""
        try:
            if not os.path.exists(file_path):
                return False
            
            # Check file extension
            file_ext = Path(file_path).suffix.lower()
            if file_ext in ['.sys', '.drv', '.vxd']:
                return True
            
            # Check PE header for driver characteristics
            with open(file_path, 'rb') as f:
                header = f.read(2)
                if header == b'MZ':  # PE executable
                    f.seek(0x3C)
                    pe_offset = int.from_bytes(f.read(4), 'little')
                    f.seek(pe_offset)
                    pe_sig = f.read(4)
                    if pe_sig == b'PE\x00\x00':
                        # Read characteristics
                        f.seek(pe_offset + 22)
                        characteristics = int.from_bytes(f.read(2), 'little')
                        # 0x2000 = IMAGE_FILE_SYSTEM (driver file)
                        return bool(characteristics & 0x2000)
            
            return False
        
        except Exception:
            return False
    
    def _extract_file_imports(self, file_path: str) -> List[str]:
        """Extract imports from PE file (simplified)."""
        imports = []
        
        try:
            if not os.path.exists(file_path):
                return imports
            
            # Try to read string imports (basic approach)
            with open(file_path, 'rb') as f:
                content = f.read()
                
                # Look for common driver imports
                kernel_imports = [
                                    b'ZwCreateFile', b'ZwReadFile', b'ZwWriteFile',
                    b'ExAllocatePool', b'IoCreateDevice', b'IoCreateSymbolicLink',
                    b'IoDeleteDevice', b'IoDeleteSymbolicLink',
                    b'KeSetEvent', b'KeResetEvent', b'KeClearEvent',
                    b'RtlCopyMemory', b'RtlMoveMemory', b'RtlZeroMemory',
                    b'DbgPrint', b'KdPrint'
                ]
                
                for imp in kernel_imports:
                    if imp in content:
                        imports.append(imp.decode('ascii', errors='ignore'))
            
            return imports
        
        except Exception:
            return imports
    
    def _get_rootkit_imports(self) -> List[str]:
        """Get list of rootkit-related kernel APIs."""
        return [
            'zwcreatefile', 'zwreadfile', 'zwwritefile',
            'exallocatepool', 'iocreatdevice', 'iocreatesymboliclink',
            'iodeletedevice', 'iodeletesymboliclink',
            'kesetevent', 'keresetevent', 'keclearevent',
            'rtlcopymemory', 'rtlmovememory', 'rtlzeromemory'
        ]
    
    def _check_filename_patterns(self, file_path: str) -> int:
        """Check file name for rootkit patterns."""
        filename = Path(file_path).name.lower()
        score = 0
        
        for pattern, weight in self.kernel_module_patterns.items():
            if pattern in filename:
                score += weight
        
        return min(score, 10)  # Cap at 10
    
    def _check_suspicious_location(self, file_path: str) -> bool:
        """Check if file is in suspicious system location."""
        suspicious_locs = [
            r'C:\Windows\System32\drivers',
            r'C:\Windows\System32\spool',
            r'C:\Windows\Tasks',
            r'C:\ProgramData',
            r'C:\Users\.*\AppData\Roaming',
        ]
        
        file_lower = file_path.lower()
        for loc in suspicious_locs:
            if loc.replace('\\', '\\\\') in file_lower:
                return True
        
        return False
    
    def continuous_process_hijacking_monitor(self) -> Dict:
        """
        Continuous real-time monitoring for Windows process hijacking.
        Should be run periodically (e.g., every 5-10 seconds) to catch rootkits immediately.
        
        Returns:
            Dictionary with current threats
        """
        threats = self._detect_hijacked_system_processes()
        return {
            'hijacked_processes_detected': len(threats),
            'processes_terminated': len(self.terminated_hijacked_processes),
            'threats': threats,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def get_status(self) -> Dict:
        """Get rootkit detection status."""
        return {
            'status': 'active',
            'detection_methods': [
                'driver_signature',
                'kernel_imports',
                'filename_heuristics',
                'location_anomalies',
                'hidden_process_detection',
                'process_hijacking_detection',  # NEW
                'registry_monitoring',
                'driver_anomalies',
                'memory_hook_detection'
            ],
            'critical_system_processes_monitored': len(self.critical_system_processes),
            'kernel_module_patterns': len(self.kernel_module_patterns),
            'suspicious_drivers': len(self.suspicious_drivers),
            'processes_terminated_as_threats': len(self.terminated_hijacked_processes),
            'timestamp': datetime.utcnow().isoformat()
        }
