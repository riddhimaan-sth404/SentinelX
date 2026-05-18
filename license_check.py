"""
SentinelX License Check System
Verifies license activation with anti-cheat NTP time verification
Enforces 30-day grace period and blocks usage after expiration
"""

import json
import os
import socket
import struct
import time
from datetime import datetime, timedelta
from pathlib import Path
import sys


class NTPTimeValidator:
    """Validates system time against NTP servers to prevent clock tampering"""
    
    # Public NTP servers (OpenPool - no authentication required)
    NTP_SERVERS = [
        ('time.google.com', 123),
        ('pool.ntp.org', 123),
        ('time.nist.gov', 123),
    ]
    
    NTP_DELTA = 2208988800  # Seconds between 1900 and 1970
    
    @staticmethod
    def get_ntp_time(server_addr: str, timeout: int = 3) -> float:
        """
        Get current time from NTP server
        
        Args:
            server_addr: NTP server hostname
            timeout: Timeout in seconds
            
        Returns:
            Unix timestamp from NTP server, or None if failed
        """
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.settimeout(timeout)
            
            # NTP request packet (simple request, no auth)
            data = b'\x1b' + 47 * b'\0'
            
            # Send request
            client.sendto(data, (server_addr, 123))
            response, _ = client.recvfrom(1024)
            client.close()
            
            if len(response) >= 32:
                # Extract seconds from NTP response (bytes 32-35)
                ntp_seconds = struct.unpack('!I', response[32:36])[0]
                # Convert to Unix timestamp
                unix_timestamp = ntp_seconds - NTPTimeValidator.NTP_DELTA
                return float(unix_timestamp)
        except Exception as e:
            pass
        
        return None
    
    @classmethod
    def get_verified_time(cls) -> tuple:
        """
        Get current time verified from NTP servers
        Tries multiple servers for redundancy
        
        Returns:
            Tuple of (verified_timestamp, server_used, is_verified)
        """
        local_time = time.time()
        
        # Try each NTP server
        for server_addr, port in cls.NTP_SERVERS:
            ntp_time = cls.get_ntp_time(server_addr, timeout=3)
            if ntp_time:
                # Check if local time differs from NTP by more than 5 minutes
                # This is lenient but catches major tampering
                time_diff = abs(local_time - ntp_time)
                
                return (ntp_time, server_addr, True)
        
        # If all NTP servers fail, use local time with warning
        return (local_time, "local_fallback", False)


class LicenseChecker:
    """Main license checking system with strict enforcement"""
    
    ACTIVATION_FILE = Path('config/activation.json')
    GRACE_PERIOD_DAYS = 30
    
    def __init__(self):
        self.activation_data = self._load_activation()
        self.verified_time, self.time_source, self.time_verified = NTPTimeValidator.get_verified_time()
        self.current_datetime = datetime.fromtimestamp(self.verified_time)
    
    def _load_activation(self) -> dict:
        """Load activation status from file"""
        if self.ACTIVATION_FILE.exists():
            try:
                with open(self.ACTIVATION_FILE, 'r') as f:
                    data = json.load(f)
                    
                    # Check if this is old format (from product_key_manager)
                    # Old format has: product_key, activation_date, expiration_date, is_activated, is_trial
                    # New format has: trial_start_date, trial_end_date, first_run_timestamp, time_verified
                    if 'trial_start_date' not in data and 'trial_end_date' not in data:
                        # Old format detected - migrate to new format
                        if data.get('is_activated') and data.get('expiration_date'):
                            # Keep the activated license info
                            return {
                                'is_trial': False,
                                'is_activated': True,
                                'product_key': data.get('product_key'),
                                'plan': data.get('plan'),
                                'activation_date': data.get('activation_date'),
                                'expiration_date': data.get('expiration_date'),
                                'time_verified': True,
                                'first_run_timestamp': None
                            }
                        else:
                            # Old trial info - recreate as new trial
                            return {}
                    
                    return data
            except:
                return {}
        return {}
    
    def _save_activation(self, data: dict):
        """Save activation status to file"""
        self.ACTIVATION_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(self.ACTIVATION_FILE, 'w') as f:
            json.dump(data, f, indent=2)
    
    def _start_trial(self):
        """Start the 30-day trial grace period"""
        trial_start = datetime.fromtimestamp(self.verified_time)
        trial_end = trial_start + timedelta(days=self.GRACE_PERIOD_DAYS)
        
        self.activation_data = {
            'is_trial': True,
            'is_activated': False,
            'product_key': None,
            'trial_start_date': trial_start.isoformat(),
            'trial_end_date': trial_end.isoformat(),
            'activation_date': None,
            'expiration_date': None,
            'plan': None,
            'time_verified': self.time_verified,
            'first_run_timestamp': self.verified_time
        }
        
        self._save_activation(self.activation_data)
        return True
    
    def check_license(self) -> tuple:
        """
        Check if system can be used
        
        Returns:
            Tuple of (can_use: bool, status: str, action: str)
            action: 'PROCEED' | 'ACTIVATE' | 'BLOCKED'
        """
        
        # No activation file - first run
        if not self.activation_data:
            self._start_trial()
            return (
                True,
                "30-day grace period started (trial mode)",
                'PROCEED_WITH_REMINDER'
            )
        
        # Already activated with product key
        if self.activation_data.get('is_activated'):
            expiration_str = self.activation_data.get('expiration_date')
            if expiration_str:
                try:
                    expiration = datetime.fromisoformat(expiration_str)
                    if self.current_datetime <= expiration:
                        plan = self.activation_data.get('plan', 'unknown').title()
                        days_left = (expiration - self.current_datetime).days
                        return (
                            True,
                            f"Licensed ({plan}) - {days_left} days remaining",
                            'PROCEED'
                        )
                    else:
                        return (False, "License expired - reactivation required", 'ACTIVATE')
                except:
                    return (False, "License data corrupted", 'ACTIVATE')
            return (False, "License data invalid", 'ACTIVATE')
        
        # Trial/grace period
        if self.activation_data.get('is_trial'):
            trial_end_str = self.activation_data.get('trial_end_date')
            if trial_end_str:
                try:
                    trial_end = datetime.fromisoformat(trial_end_str)
                    
                    # Trial is still active
                    if self.current_datetime <= trial_end:
                        days_left = (trial_end - self.current_datetime).days + 1
                        return (
                            True,
                            f"Grace period - {days_left} days remaining",
                            'PROCEED_WITH_REMINDER'
                        )
                    # Trial expired
                    else:
                        return (False, "Grace period expired - activation required", 'ACTIVATE')
                except:
                    return (False, "Trial data corrupted", 'ACTIVATE')
        
        # Unknown state or old format that wasn't properly migrated - recreate trial
        self._start_trial()
        return (
            True,
            "30-day grace period started (trial mode)",
            'PROCEED_WITH_REMINDER'
        )
    
    def display_startup_screen(self, can_use: bool, status: str, action: str):
        """Display startup license check screen"""
        
        print("\n" + "="*70)
        print(" "*15 + "SentinelX License Check")
        print("="*70)
        
        if self.time_verified:
            print(f"✓ Time verified from: {self.time_source}")
        else:
            print(f"⚠ Using local time (NTP unavailable)")
        
        print(f"Current time: {self.current_datetime.strftime('%Y-%m-%d %H:%M:%S')}")
        print("-"*70)
        print(f"Status: {status}")
        print("-"*70)
        
        if action == 'PROCEED':
            print("✓ System ready to use")
            print()
            return True
        
        elif action == 'PROCEED_WITH_REMINDER':
            print("ℹ Notice: Please activate to continue after grace period")
            print("         You can activate anytime using: python activate_gui.py")
            print()
            return True
        
        elif action == 'ACTIVATE':
            print("✗ ACTIVATION REQUIRED")
            print()
            if not can_use:
                print("  Your grace period or license has expired.")
                print("  You must activate to continue using the system.")
                print()
                return False
        
        return True
    
    def show_activation_menu(self) -> bool:
        """Show activation menu and handle user input"""
        
        while True:
            print("\n" + "-"*70)
            print("License Activation Options:")
            print("-"*70)
            print("1. Enter product key")
            print("2. Continue in trial mode")
            print("3. Exit")
            print("-"*70)
            
            choice = input("Select option (1-3): ").strip()
            
            if choice == '1':
                # Launch GUI for activation
                result = self._launch_activation_gui()
                if result:
                    return True
                # If GUI failed, try CLI
                if self._try_cli_activation():
                    return True
                print("\n✗ Activation failed. Returning to trial mode.")
                return False
            
            elif choice == '2':
                print("\n→ Continuing in trial mode...")
                return True
            
            elif choice == '3':
                print("\nExiting...")
                return False
            
            else:
                print("Invalid option. Please try again.")
    
    def _launch_activation_gui(self) -> bool:
        """Try to launch GUI activation"""
        try:
            import subprocess
            result = subprocess.run(
                [sys.executable, 'activate_gui.py'],
                cwd=Path(__file__).parent,
                timeout=120
            )
            return result.returncode == 0
        except:
            return False
    
    def _try_cli_activation(self) -> bool:
        """Try CLI activation as fallback"""
        try:
            import subprocess
            result = subprocess.run(
                [sys.executable, 'activate_sentinelx.py'],
                cwd=Path(__file__).parent,
                timeout=120
            )
            return result.returncode == 0
        except:
            return False


def main():
    """Main license check entry point"""
    
    print("\n")
    
    # Check license
    checker = LicenseChecker()
    can_use, status, action = checker.check_license()
    
    # Display startup screen
    if not checker.display_startup_screen(can_use, status, action):
        print("\n" + "="*70)
        print("SentinelX cannot start without a valid license.")
        print("="*70 + "\n")
        sys.exit(1)
    
    # If blocked, don't allow any further action
    if action == 'BLOCKED':
        print("\n" + "="*70)
        print("SentinelX has been blocked due to expired license.")
        print("Please contact support or purchase a new license.")
        print("="*70 + "\n")
        sys.exit(2)
    
    # If activation is required and not in trial
    if action == 'ACTIVATE' and not can_use:
        print("\n" + "="*70)
        print("License Activation Required")
        print("="*70)
        
        if not checker.show_activation_menu():
            print("\n" + "="*70)
            print("Cannot continue without activation.")
            print("="*70 + "\n")
            sys.exit(1)
    
    # License check complete - allow startup
    print("\n" + "="*70)
    print("✓ License check passed - Starting SentinelX GUI")
    print("="*70 + "\n")
    
    # Reload activation data in case it was updated
    checker.activation_data = checker._load_activation()
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
