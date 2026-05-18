"""
USB Scanner: Detect and scan USB/removable media devices
"""
import os
import subprocess
import win32api
import win32file
from pathlib import Path
from typing import List, Dict, Generator, Optional
from dataclasses import dataclass
from datetime import datetime
from sentinelx.utils.logger import get_logger
from sentinelx.config.settings import get_config

logger = get_logger(__name__)


@dataclass
class USBDevice:
    """Information about a USB/removable device."""
    drive_letter: str
    label: str
    total_space: int
    free_space: int
    file_system: str
    is_removable: bool
    mount_path: str


class USBScanner:
    """
    Scanner for USB and removable media devices.
    Detects connected drives and performs scanning.
    """
    
    def __init__(self):
        """Initialize USB scanner."""
        self.config = get_config()
        logger.info("USB Scanner initialized")
    
    def get_usb_devices(self) -> List[USBDevice]:
        """
        Get list of connected USB/removable devices.
        
        Returns:
            List of USBDevice objects
        """
        devices = []
        
        try:
            # Get all drive letters
            drives = win32api.GetLogicalDriveStrings()
            drives = drives.split('\0')[:-1]  # Remove empty strings
            
            for drive in drives:
                # Skip if not removable
                drive_type = win32file.GetDriveType(drive)
                
                # DRIVE_REMOVABLE = 2
                if drive_type != 2:
                    continue
                
                try:
                    # Get drive info
                    label = win32api.GetVolumeInformation(drive)[0]
                    
                    # Get space info
                    space_info = win32api.GetDiskFreeSpaceEx(drive)
                    free_space = space_info[0]  # Free bytes available to user
                    total_space = space_info[1]  # Total bytes on disk
                    file_system = win32api.GetVolumeInformation(drive)[4]
                    
                    device = USBDevice(
                        drive_letter=drive[0],
                        label=label or "Unknown",
                        total_space=total_space,
                        free_space=free_space,
                        file_system=file_system,
                        is_removable=True,
                        mount_path=drive
                    )
                    
                    devices.append(device)
                    logger.info(f"Detected USB device: {drive} ({label})")
                
                except Exception as e:
                    logger.warning(f"Error reading drive {drive}: {e}")
                    continue
        
        except Exception as e:
            logger.error(f"Error enumerating USB devices: {e}")
        
        return devices
    
    def scan_usb_device(self, device: USBDevice) -> Generator[str, None, None]:
        """
        Get all scannable files from USB device.
        
        Args:
            device: USBDevice to scan
            
        Yields:
            File paths on the device
        """
        try:
            path = device.mount_path
            
            if not os.path.exists(path):
                logger.warning(f"USB device not accessible: {path}")
                return
            
            # Walk through directory tree
            for root, dirs, files in os.walk(path):
                # Skip certain directories
                skip_dirs = {'.Recycle.Bin', 'System Volume Information', '$RECYCLE.BIN'}
                dirs[:] = [d for d in dirs if d not in skip_dirs]
                
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Skip certain file types (media, documents, etc.)
                    skip_extensions = {
                        '.jpg', '.jpeg', '.png', '.gif', '.mp4', '.mp3',
                        '.docx', '.xlsx', '.pdf', '.txt', '.pptx'
                    }
                    
                    file_ext = Path(file).suffix.lower()
                    if file_ext not in skip_extensions:
                        yield file_path
        
        except Exception as e:
            logger.error(f"Error scanning USB device {device.mount_path}: {e}")
    
    def get_device_info(self, device: USBDevice) -> Dict:
        """
        Get detailed information about a USB device.
        
        Args:
            device: USBDevice to inspect
            
        Returns:
            Dictionary with device details
        """
        used_space = device.total_space - device.free_space
        used_percent = (used_space / device.total_space * 100) if device.total_space > 0 else 0
        
        return {
            'drive_letter': device.drive_letter,
            'label': device.label,
            'mount_path': device.mount_path,
            'total_space_gb': round(device.total_space / (1024**3), 2),
            'free_space_gb': round(device.free_space / (1024**3), 2),
            'used_space_gb': round(used_space / (1024**3), 2),
            'used_percent': round(used_percent, 2),
            'file_system': device.file_system,
            'detected_at': datetime.utcnow().isoformat()
        }
    
    def monitor_usb_changes(self, callback=None) -> None:
        """
        Monitor for USB device changes (plug/unplug).
        
        Args:
            callback: Function to call when changes detected
        """
        import time
        
        previous_devices = set()
        
        try:
            while True:
                current_devices = {d.mount_path for d in self.get_usb_devices()}
                
                # Check for new devices
                new_devices = current_devices - previous_devices
                removed_devices = previous_devices - current_devices
                
                if new_devices:
                    logger.info(f"New USB devices detected: {new_devices}")
                    if callback:
                        callback('attached', list(new_devices))
                
                if removed_devices:
                    logger.info(f"USB devices removed: {removed_devices}")
                    if callback:
                        callback('removed', list(removed_devices))
                
                previous_devices = current_devices
                time.sleep(2)  # Check every 2 seconds
        
        except KeyboardInterrupt:
            logger.info("USB monitoring stopped")
        except Exception as e:
            logger.error(f"Error monitoring USB devices: {e}")
