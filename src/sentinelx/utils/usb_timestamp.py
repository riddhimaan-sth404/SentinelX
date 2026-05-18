"""
USB Timestamp Utility - Detects and displays USB device timestamps
Retrieves insertion, removal, and mount timestamps from registry and event logs
"""
import winreg
from datetime import datetime
from pathlib import Path
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)


class USBTimestampExtractor:
    """Extract USB device timestamps from Windows registry and event logs"""
    
    def __init__(self):
        """Initialize USB timestamp extractor"""
        logger.info("USB Timestamp Extractor initialized")
    
    def get_total_connection_count(self, device_vendor: str, device_product: str) -> int:
        """
        Get total number of times a device has been connected
        Counts all instances of a device with same vendor/product in USBSTOR registry
        
        Args:
            device_vendor: Device vendor ID
            device_product: Device product ID
            
        Returns:
            Total count of device connections
        """
        connection_count = 0
        
        try:
            usbstor_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Enum\USBSTOR")
            
            i = 0
            while True:
                try:
                    entry = winreg.EnumKey(usbstor_key, i)
                    i += 1
                    
                    # Check if vendor and product match
                    if f"Ven_{device_vendor}" in entry and f"Prod_{device_product}" in entry:
                        connection_count += 1
                except WindowsError:
                    break
            
            winreg.CloseKey(usbstor_key)
            logger.info(f"Device {device_vendor}_{device_product} connected {connection_count} times")
            
        except Exception as e:
            logger.warning(f"Could not count connections: {e}")
        
        return connection_count
    
    def get_device_timestamps(self, device_key_path: str) -> Dict[str, str]:
        """
        Get all available timestamps for a USB device from registry
        
        Args:
            device_key_path: Full registry path to the USB device
            
        Returns:
            Dictionary with timestamp information
        """
        timestamps = {
            'first_install': 'Unknown',
            'last_write': 'Unknown',
            'last_removal': 'Unknown',
            'last_insertion': 'Unknown'
        }
        
        try:
            # Get device registry key
            device_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, device_key_path)
            
            # Get LastWrite timestamp (when device was last written to registry)
            try:
                reg_stat = winreg.QueryInfoKey(device_key)
                if reg_stat and len(reg_stat) > 2 and reg_stat[2] is not None:
                    try:
                        last_write_timestamp = datetime.fromtimestamp(reg_stat[2]).isoformat()
                        timestamps['last_write'] = last_write_timestamp
                    except (ValueError, OSError, OverflowError) as te:
                        logger.debug(f"Invalid timestamp value from registry: {te}")
                else:
                    logger.debug("Registry timestamp not available")
            except Exception as e:
                logger.debug(f"Could not get LastWrite timestamp: {e}")
            
            # Try to get FirstInstall timestamp from device properties
            try:
                first_install = winreg.QueryValueEx(device_key, "FirstInstallDate")[0]
                if first_install:
                    timestamps['first_install'] = self._convert_registry_timestamp(first_install)
            except WindowsError:
                pass
            
            # Check for custom timestamps in device properties
            try:
                device_properties = winreg.OpenKey(device_key, "Device Parameters")
                # Some devices store insertion/removal times here
                for value_name in self._get_registry_values(device_properties):
                    if 'insert' in value_name.lower():
                        try:
                            value = winreg.QueryValueEx(device_properties, value_name)[0]
                            timestamps['last_insertion'] = str(value)
                        except:
                            pass
                    elif 'removal' in value_name.lower() or 'remove' in value_name.lower():
                        try:
                            value = winreg.QueryValueEx(device_properties, value_name)[0]
                            timestamps['last_removal'] = str(value)
                        except:
                            pass
            except WindowsError:
                pass
            
            winreg.CloseKey(device_key)
            
        except Exception as e:
            logger.error(f"Error extracting device timestamps: {e}")
        
        return timestamps
    
    def get_usb_mount_history(self) -> List[Dict]:
        """
        Get USB device mount history from registry MountPoints2
        
        Returns:
            List of dicts with device letter, volume info, and last access time
        """
        mount_history = []
        
        try:
            # Check HKEY_CURRENT_USER MountPoints2
            mp2_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"
            mp2_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, mp2_path)
            
            i = 0
            while True:
                try:
                    volume_guid = winreg.EnumKey(mp2_key, i)
                    i += 1
                    
                    # Check if it's a GUID-based mount point (USB)
                    if volume_guid.startswith('{') and volume_guid.endswith('}'):
                        try:
                            volume_key = winreg.OpenKey(mp2_key, volume_guid)
                            
                            # Get LastWrite timestamp for this mount
                            try:
                                reg_stat = winreg.QueryInfoKey(volume_key)
                                last_mount_time = datetime.fromtimestamp(reg_stat[2]).isoformat()
                                
                                # Try to get the label
                                try:
                                    label = winreg.QueryValueEx(volume_key, "_LabelFromReg")[0]
                                except:
                                    label = "Unknown"
                                
                                mount_history.append({
                                    'volume_guid': volume_guid,
                                    'label': label,
                                    'last_mount_time': last_mount_time
                                })
                            except:
                                pass
                            
                            winreg.CloseKey(volume_key)
                        except:
                            pass
                except WindowsError:
                    break
            
            winreg.CloseKey(mp2_key)
            logger.info(f"Found {len(mount_history)} USB mount points")
            
        except Exception as e:
            logger.warning(f"Could not access MountPoints2: {e}")
        
        return mount_history
    
    def get_device_file_timestamps(self, device_drive_letter: str) -> Dict[str, str]:
        """
        Get timestamps from USB device root by checking file metadata
        
        Args:
            device_drive_letter: Drive letter (e.g., 'D' or 'E')
            
        Returns:
            Dictionary with file timestamps from the device
        """
        timestamps = {
            'drive_root_created': 'Unknown',
            'drive_root_modified': 'Unknown',
            'drive_root_accessed': 'Unknown'
        }
        
        try:
            drive_path = Path(f"{device_drive_letter}:\\")
            
            if drive_path.exists():
                stat_info = drive_path.stat()
                timestamps['drive_root_created'] = datetime.fromtimestamp(stat_info.st_ctime).isoformat()
                timestamps['drive_root_modified'] = datetime.fromtimestamp(stat_info.st_mtime).isoformat()
                timestamps['drive_root_accessed'] = datetime.fromtimestamp(stat_info.st_atime).isoformat()
        except Exception as e:
            logger.warning(f"Could not get file timestamps for {device_drive_letter}: {e}")
        
        return timestamps
    
    def get_all_device_events(self, friendly_name: str) -> Dict[str, List[str]]:
        """
        Get all available timestamp events for a USB device
        
        Args:
            friendly_name: Friendly name of the USB device
            
        Returns:
            Dictionary with various timestamp events
        """
        events = {
            'insertions': [],
            'removals': [],
            'mount_times': [],
            'registry_updates': []
        }
        
        # Try to get information from Windows Event Log
        try:
            import subprocess
            
            # Look for USB device insertion events in Event Log
            # Event ID 20001 = Device inserted
            # Event ID 20002 = Device removed
            # Event ID 20003 = Device enumerated
            
            cmd = f'wevtutil query-events "System" /q:"(*[EventData[Data[@Name=\'ProviderName\']=\'Disk\']])" /f:text /c:50'
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                # Parse event log results if available
                if result.stdout:
                    for line in result.stdout.split('\n'):
                        if 'Device' in line and friendly_name.split()[0] in line:
                            events['insertions'].append(line.strip())
            except Exception as e:
                logger.debug(f"Could not retrieve event logs: {e}")
        
        except Exception as e:
            logger.warning(f"Event log access failed: {e}")
        
        return events
    
    def _convert_registry_timestamp(self, timestamp_value: str) -> str:
        """
        Convert registry timestamp to ISO format
        
        Args:
            timestamp_value: Timestamp value from registry
            
        Returns:
            ISO formatted timestamp string
        """
        try:
            # Registry FirstInstallDate is typically in format: timestamp or FILETIME
            if isinstance(timestamp_value, int):
                return datetime.fromtimestamp(timestamp_value).isoformat()
            elif isinstance(timestamp_value, str):
                # Try to parse if it's already a timestamp string
                try:
                    timestamp = int(timestamp_value)
                    return datetime.fromtimestamp(timestamp).isoformat()
                except:
                    return str(timestamp_value)
            return str(timestamp_value)
        except Exception as e:
            logger.debug(f"Could not convert timestamp: {e}")
            return "Unknown"
    
    def _get_registry_values(self, registry_key) -> List[str]:
        """Get all value names from a registry key"""
        values = []
        try:
            i = 0
            while True:
                try:
                    value_name = winreg.EnumValue(registry_key, i)[0]
                    values.append(value_name)
                    i += 1
                except WindowsError:
                    break
        except:
            pass
        return values


def get_usb_timestamp_info(device_friendly_name: str, device_registry_path: str = None, 
                           device_drive_letter: str = None) -> Dict:
    """
    Get comprehensive USB device timestamp information
    
    Args:
        device_friendly_name: Friendly name of the USB device
        device_registry_path: Optional registry path to the device
        device_drive_letter: Optional drive letter if device is currently mounted
        
    Returns:
        Comprehensive dictionary with all available timestamp information
    """
    extractor = USBTimestampExtractor()
    
    timestamp_info = {
        'device_name': device_friendly_name,
        'registry_timestamps': {},
        'mount_history': extractor.get_usb_mount_history(),
        'file_timestamps': {},
        'event_logs': {}
    }
    
    # Get registry timestamps if path provided
    if device_registry_path:
        try:
            timestamp_info['registry_timestamps'] = extractor.get_device_timestamps(device_registry_path)
        except Exception as e:
            logger.warning(f"Could not get registry timestamps: {e}")
    
    # Get file timestamps if drive letter provided
    if device_drive_letter:
        try:
            timestamp_info['file_timestamps'] = extractor.get_device_file_timestamps(device_drive_letter)
        except Exception as e:
            logger.warning(f"Could not get file timestamps: {e}")
    
    # Get event log information
    try:
        timestamp_info['event_logs'] = extractor.get_all_device_events(device_friendly_name)
    except Exception as e:
        logger.warning(f"Could not get event logs: {e}")
    
    return timestamp_info
