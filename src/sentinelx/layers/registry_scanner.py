r"""
Registry Scanner - Detects USB devices from Windows registry HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR
Provides comprehensive USB history and device information
"""
import winreg
from typing import List, Dict
from datetime import datetime
import logging
from sentinelx.utils.usb_timestamp import USBTimestampExtractor

logger = logging.getLogger(__name__)


class RegistryUSBScanner:
    """Scan Windows registry for USB storage devices ever connected"""
    
    # Registry path for USB storage devices
    USBSTOR_PATH = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
    
    def __init__(self):
        """Initialize registry USB scanner"""
        logger.info("Registry USB Scanner initialized")
    
    def get_all_usb_devices(self) -> List[Dict]:
        """
        Get all USB storage devices ever connected to the system from registry
        
        Returns:
            List of dicts with USB device information
        """
        devices = []
        try:
            # Open the HKEY_LOCAL_MACHINE registry hive
            registry_key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                self.USBSTOR_PATH
            )
            
            # Enumerate all subkeys (each represents a USB device)
            subkey_count = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(registry_key, subkey_count)
                    subkey_count += 1
                    
                    # Open each device subkey
                    device_key = winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE,
                        f"{self.USBSTOR_PATH}\\{subkey_name}"
                    )
                    
                    # Extract device information
                    device_info = self._parse_device_info(subkey_name, device_key)
                    if device_info:
                        devices.append(device_info)
                    
                    winreg.CloseKey(device_key)
                    
                except WindowsError:
                    break
            
            winreg.CloseKey(registry_key)
            logger.info(f"Found {len(devices)} USB devices in registry")
            
        except Exception as e:
            logger.error(f"Error scanning registry for USB devices: {e}")
        
        return devices
    
    def _parse_device_info(self, subkey_name: str, device_key) -> Dict:
        """
        Parse USB device information from registry subkey
        
        Args:
            subkey_name: Registry subkey name (e.g., "Disk&Ven_Kingston&Prod_DataTraveler&Rev_3.0")
            device_key: Registry key handle
            
        Returns:
            Dictionary with device information
        """
        try:
            # Get FriendlyName if available
            try:
                friendly_name = winreg.QueryValueEx(device_key, "FriendlyName")[0]
            except WindowsError:
                friendly_name = "Unknown USB Device"
            
            # Clean up friendly name - replace underscores with spaces
            friendly_name = self._format_device_name(friendly_name)
            
            # Parse the subkey name to extract device details
            parts = subkey_name.split("&")
            device_type = parts[0] if parts else "Unknown"
            
            device_info = {
                'registry_key': subkey_name,
                'friendly_name': friendly_name,
                'device_type': device_type,
                'vendor_id': self._format_device_name(self._extract_usb_value(subkey_name, 'Ven')),
                'product_id': self._format_device_name(self._extract_usb_value(subkey_name, 'Prod')),
                'revision': self._extract_usb_value(subkey_name, 'Rev'),
                'connection_count': self._get_connection_count(subkey_name, device_key),
                'last_connection_date': self._get_last_connection_date(device_key, subkey_name),
                'detected_at': datetime.now().isoformat()
            }
            
            # Extract timestamp information using USBTimestampExtractor
            try:
                device_registry_path = f"{self.USBSTOR_PATH}\\{subkey_name}"
                timestamp_extractor = USBTimestampExtractor()
                timestamps = timestamp_extractor.get_device_timestamps(device_registry_path)
                device_info['timestamps'] = timestamps
                
                # Get accurate total connection count
                vendor_id = self._extract_usb_value(subkey_name, 'Ven')
                product_id = self._extract_usb_value(subkey_name, 'Prod')
                total_connections = timestamp_extractor.get_total_connection_count(vendor_id, product_id)
                device_info['total_connections'] = total_connections
                
            except Exception as e:
                logger.debug(f"Could not extract timestamps for {friendly_name}: {e}")
                device_info['timestamps'] = {
                    'first_install': 'Unknown',
                    'last_write': 'Unknown',
                    'last_removal': 'Unknown',
                    'last_insertion': 'Unknown'
                }
                device_info['total_connections'] = device_info.get('connection_count', 'Unknown')
            
            return device_info
            
        except Exception as e:
            logger.error(f"Error parsing device info for {subkey_name}: {e}")
            return None
    
    def _format_device_name(self, name: str) -> str:
        """Format device name by replacing underscores with spaces"""
        if name and name != "Unknown":
            return name.replace("_", " ")
        return name
    
    def _extract_usb_value(self, subkey_name: str, prefix: str) -> str:
        """Extract USB value from registry key name"""
        try:
            for part in subkey_name.split("&"):
                if part.startswith(prefix):
                    return part[len(prefix):]
        except:
            pass
        return "Unknown"
    
    def _get_connection_count(self, subkey_name: str, device_key) -> str:
        """Get the number of times this USB device has been connected"""
        try:
            # Extract the device identifier (Disk&Ven_xxx&Prod_yyy&Rev_zzz)
            # This matches all connections of the same device, ignoring serial numbers
            parts = subkey_name.split("&")
            
            # Find where the serial number starts (after Rev)
            # Format: Disk&Ven_xxx&Prod_yyy&Rev_zzz&SERIAL
            device_identifier = "&".join(parts[:4]) if len(parts) >= 4 else "&".join(parts[:3])
            
            # Count matching entries in USBSTOR registry
            count = 0
            try:
                usbstor_key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
                )
                
                i = 0
                while True:
                    try:
                        entry = winreg.EnumKey(usbstor_key, i)
                        # Extract identifier parts from this entry
                        entry_parts = entry.split("&")
                        entry_identifier = "&".join(entry_parts[:4]) if len(entry_parts) >= 4 else "&".join(entry_parts[:3])
                        
                        # Check if this entry matches our device (same vendor/product/revision)
                        if entry_identifier.lower() == device_identifier.lower():
                            count += 1
                        i += 1
                    except WindowsError:
                        break
                
                winreg.CloseKey(usbstor_key)
            except:
                count = 1
            
            # Check if currently connected (counts as active connection)
            if self._is_device_currently_connected(subkey_name):
                return f"Connected {count} time(s) - Currently online"
            else:
                return f"Connected {count} time(s)"
                
        except Exception as e:
            logger.error(f"Error getting connection count: {e}")
            return "Unknown"
    
    def _get_last_connection_date(self, device_key, subkey_name: str) -> str:
        """Get the date of the last connection"""
        try:
            # Try to get LastArrivalDate (most reliable)
            try:
                last_arrival = winreg.QueryValueEx(device_key, "LastArrivalDate")[0]
                if last_arrival and last_arrival != "Unknown" and last_arrival != "0":
                    return self._format_timestamp(str(last_arrival))
            except WindowsError:
                pass
            
            # Try LastRemovalDate if device was previously connected
            try:
                last_removal = winreg.QueryValueEx(device_key, "LastRemovalDate")[0]
                if last_removal and last_removal != "Unknown" and last_removal != "0":
                    return self._format_timestamp(str(last_removal))
            except WindowsError:
                pass
            
            # If currently connected, try to get connection time
            if self._is_device_currently_connected(subkey_name):
                try:
                    # Get the registry key modification time (when device was mounted)
                    device_params_key = winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE,
                        f"SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\{subkey_name}\\Device Parameters"
                    )
                    file_time = winreg.QueryInfoKey(device_params_key)[4]
                    winreg.CloseKey(device_params_key)
                    
                    if file_time:
                        return self._convert_filetime_to_datetime(file_time)
                except:
                    pass
                
                # If we can't determine exact time, return today's date
                return datetime.now().strftime("%Y-%m-%d")
            
            # Try to get from registry key metadata
            try:
                parent_key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    f"SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\{subkey_name}"
                )
                file_time = winreg.QueryInfoKey(parent_key)[4]
                winreg.CloseKey(parent_key)
                
                if file_time:
                    return self._convert_filetime_to_datetime(file_time)
            except:
                pass
            
            return "Unknown"
            
        except Exception as e:
            logger.error(f"Error getting last connection date: {e}")
            return "Unknown"
    
    def _is_device_currently_connected(self, subkey_name: str) -> bool:
        """Check if a device is currently connected by looking in active USB enum"""
        try:
            # Method 1: Check if device appears in MountedDevices
            try:
                mounted_devices_key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\MountedDevices"
                )
                i = 0
                while True:
                    try:
                        value_name = winreg.EnumValue(mounted_devices_key, i)[0]
                        # Check if this USBSTOR device is in MountedDevices
                        if subkey_name.split('&')[0].lower() in value_name.lower():
                            winreg.CloseKey(mounted_devices_key)
                            return True
                        i += 1
                    except WindowsError:
                        break
                winreg.CloseKey(mounted_devices_key)
            except:
                pass
            
            # Method 2: Check if device key has CurrentPresent value set to 1
            try:
                device_key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    f"SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\{subkey_name}"
                )
                
                try:
                    present_value = winreg.QueryValueEx(device_key, "Present")[0]
                    winreg.CloseKey(device_key)
                    
                    # Present = 1 means currently connected in some systems
                    if int(present_value) == 1:
                        return True
                except:
                    pass
                
                winreg.CloseKey(device_key)
            except:
                pass
            
            # Method 3: Check Device Parameters subkey - active devices have this
            try:
                params_key_path = f"SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\{subkey_name}\\Device Parameters"
                device_params_key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    params_key_path
                )
                
                # If Device Parameters key exists and contains active values, device is likely connected
                try:
                    partition_style = winreg.QueryValueEx(device_params_key, "PartitionStyle")[0]
                    winreg.CloseKey(device_params_key)
                    if partition_style:
                        return True
                except WindowsError:
                    pass
                
                winreg.CloseKey(device_params_key)
            except WindowsError:
                # This key doesn't exist - device likely not currently connected
                pass
            except:
                pass
            
            # Method 4: Check against active USB enum in real-time
            try:
                # Get the vendor and product IDs from USBSTOR key
                parts = subkey_name.split('&')
                vendor_prod = None
                for part in parts:
                    if part.startswith('Prod_'):
                        vendor_prod = part
                        break
                
                if vendor_prod:
                    # Check active USB devices for this vendor/product combo
                    active_usb_key = winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE,
                        r"SYSTEM\CurrentControlSet\Enum\USB"
                    )
                    
                    i = 0
                    while True:
                        try:
                            usb_key_name = winreg.EnumKey(active_usb_key, i)
                            
                            # Open the USB key to check if it's the same device
                            try:
                                sub_key = winreg.OpenKey(
                                    winreg.HKEY_LOCAL_MACHINE,
                                    f"SYSTEM\\CurrentControlSet\\Enum\\USB\\{usb_key_name}"
                                )
                                
                                # Check if device is present (connected)
                                try:
                                    present = winreg.QueryValueEx(sub_key, "Present")[0]
                                    if int(present) == 1:
                                        # Check friendly name or device description match
                                        try:
                                            friendly = winreg.QueryValueEx(sub_key, "FriendlyName")[0]
                                            # If friendly name contains product info, it's a match
                                            for part in parts:
                                                if part.lower() in friendly.lower():
                                                    winreg.CloseKey(sub_key)
                                                    winreg.CloseKey(active_usb_key)
                                                    return True
                                        except:
                                            pass
                                except:
                                    pass
                                
                                winreg.CloseKey(sub_key)
                            except:
                                pass
                            
                            i += 1
                        except WindowsError:
                            break
                    
                    winreg.CloseKey(active_usb_key)
            except:
                pass
            
            return False
            
        except Exception as e:
            logger.warning(f"Error checking device connection status: {e}")
            return False
    
    def _format_timestamp(self, timestamp_str: str) -> str:
        """Format timestamp string to human-readable format"""
        try:
            # Handle various timestamp formats
            if len(timestamp_str) == 14 and timestamp_str.isdigit():
                # Format: YYYYMMDDHHMMSS
                return f"{timestamp_str[0:4]}-{timestamp_str[4:6]}-{timestamp_str[6:8]} {timestamp_str[8:10]}:{timestamp_str[10:12]}:{timestamp_str[12:14]}"
            elif "T" in timestamp_str:
                # Already formatted (ISO format)
                return timestamp_str.split("T")[0] + " " + timestamp_str.split("T")[1].split(".")[0] if "." in timestamp_str else timestamp_str
            else:
                return str(timestamp_str)
        except:
            return str(timestamp_str)
    
    def _convert_filetime_to_datetime(self, filetime: int) -> str:
        """Convert Windows FILETIME to human-readable datetime"""
        try:
            # Windows FILETIME epoch is January 1, 1601
            # Unix epoch is January 1, 1970
            # Difference is 11644473600 seconds
            windows_epoch = 11644473600
            unix_timestamp = (filetime / 10000000.0) - windows_epoch
            
            if unix_timestamp > 0:
                from datetime import datetime as dt
                dt_obj = dt.fromtimestamp(unix_timestamp)
                return dt_obj.strftime("%Y-%m-%d %H:%M:%S")
        except:
            pass
        return "Unknown"
    
    def get_device_by_friendly_name(self, friendly_name: str) -> Dict:
        """Get specific device by friendly name"""
        devices = self.get_all_usb_devices()
        for device in devices:
            if device['friendly_name'].lower() == friendly_name.lower():
                return device
        return None
    
    def get_devices_by_vendor(self, vendor_id: str) -> List[Dict]:
        """Get all devices from specific vendor"""
        devices = self.get_all_usb_devices()
        return [d for d in devices if d['vendor_id'].lower() == vendor_id.lower()]
    
    def get_connected_usb_devices(self) -> List[Dict]:
        """
        Get only currently connected USB devices (filters out historical entries)
        Checks device status in registry to determine if currently connected
        
        Returns:
            List of currently connected USB devices
        """
        all_devices = self.get_all_usb_devices()
        connected_devices = []
        seen_serials = set()
        
        try:
            # Check the active USB enum path for currently connected devices
            active_usb_key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Enum\USB"
            )
            
            # Get list of currently active USB device serial numbers
            active_serials = set()
            i = 0
            while True:
                try:
                    serial = winreg.EnumKey(active_usb_key, i)
                    active_serials.add(serial.lower())
                    i += 1
                except WindowsError:
                    break
            
            winreg.CloseKey(active_usb_key)
            
            # Filter USBSTOR devices - check if serial appears in active USB list
            for device in all_devices:
                registry_key = device.get('registry_key', '').lower()
                
                # Extract serial/product ID from registry key
                parts = registry_key.split('&')
                device_serial = parts[-1] if parts else ""
                
                # Check if this device's serial is in the active USB list
                is_active = False
                for active_serial in active_serials:
                    if device_serial.lower() in active_serial.lower() or active_serial.lower() in device_serial.lower():
                        is_active = True
                        break
                
                # Also check device state flag in registry (0 = connected)
                try:
                    device_key = winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE,
                        f"SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\{device['registry_key']}"
                    )
                    try:
                        config_flags = winreg.QueryValueEx(device_key, "ConfigFlags")[0]
                        # If ConfigFlags = 0, device is connected
                        if config_flags == 0:
                            is_active = True
                    except:
                        pass
                    winreg.CloseKey(device_key)
                except:
                    pass
                
                # Deduplicate - only add if we haven't seen this device
                device_id = f"{device.get('vendor_id', 'unknown')}_{device.get('product_id', 'unknown')}"
                
                if is_active and device_id not in seen_serials:
                    connected_devices.append(device)
                    seen_serials.add(device_id)
        
        except Exception as e:
            logger.warning(f"Could not determine active USB devices, returning all: {e}")
            return all_devices
        
        logger.info(f"Found {len(connected_devices)} currently connected USB devices")
        return connected_devices if connected_devices else all_devices
    
    def get_suspicious_usb_devices(self) -> List[Dict]:
        """
        Get potentially suspicious USB devices based on characteristics
        
        Returns:
            List of suspicious device dicts
        """
        devices = self.get_all_usb_devices()
        suspicious = []
        
        # Common malware vendors/products to watch for
        suspicious_keywords = [
            'generic', 'removable', 'kingston', 'sandisk',  # These are common
            'usb', 'device'
        ]
        
        for device in devices:
            is_suspicious = False
            
            # Check for unknown or generic naming
            if device['friendly_name'] == "Unknown USB Device" or device['friendly_name'] == "USB Device":
                is_suspicious = True
            
            # Check for suspicious keywords in product info
            product = device.get('product_id', '').lower()
            if any(keyword in product for keyword in ['boot', 'firmware', 'backdoor', 'trojan']):
                is_suspicious = True
            
            if is_suspicious:
                suspicious.append(device)
        
        return suspicious


def get_registry_usb_scanner() -> RegistryUSBScanner:
    """Factory function to get registry USB scanner instance"""
    return RegistryUSBScanner()
