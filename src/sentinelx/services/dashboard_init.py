"""
Dashboard Data Initialization
Populates managers with sample data for demo purposes
"""

def initialize_demo_data(auth_mgr, incident_mgr, compliance_mgr, asset_mgr, remote_access_mgr):
    """Initialize managers with demo data"""
    
    # Initialize users
    if auth_mgr:
        try:
            # Create demo users
            auth_mgr.create_user("john_analyst", "john@sentinelx.local", "Analyst_Senior", "password123")
            auth_mgr.create_user("jane_admin", "jane@sentinelx.local", "Administrator", "password123")
            auth_mgr.create_user("bob_viewer", "bob@sentinelx.local", "Viewer", "password123")
        except:
            pass
    
    # Initialize compliance data
    if compliance_mgr:
        try:
            compliance_mgr.update_compliance_status("HIPAA", 95, "compliant")
            compliance_mgr.update_compliance_status("PCI-DSS", 85, "compliant")
            compliance_mgr.update_compliance_status("GDPR", 100, "compliant")
            compliance_mgr.update_compliance_status("SOC2", 98, "compliant")
            compliance_mgr.update_compliance_status("ISO27001", 92, "compliant")
            compliance_mgr.update_compliance_status("NIST", 100, "compliant")
        except:
            pass
    
    # Initialize assets
    if asset_mgr:
        try:
            asset_mgr.discover_asset("WORKSTATION-01", "192.168.1.100", "workstation", "Windows 11", "AA:BB:CC:DD:EE:01")
            asset_mgr.discover_asset("SERVER-PROD", "192.168.1.50", "server", "Windows Server 2022", "AA:BB:CC:DD:EE:02")
            asset_mgr.discover_asset("WORKSTATION-02", "192.168.1.101", "workstation", "Windows 10", "AA:BB:CC:DD:EE:03")
            asset_mgr.discover_asset("FILESERVER", "192.168.1.51", "server", "Windows Server 2022", "AA:BB:CC:DD:EE:04")
            asset_mgr.discover_asset("DB-SERVER", "192.168.1.52", "server", "Ubuntu 22.04", "AA:BB:CC:DD:EE:05")
            
            # Update asset statuses
            for asset_id in list(asset_mgr.assets.keys())[:3]:
                asset_mgr.update_antivirus_status(asset_id, "active")
                asset_mgr.update_firewall_status(asset_id, "enabled")
                asset_mgr.update_patch_status(asset_id, 2)
        except:
            pass
    
    # Initialize incidents
    if incident_mgr:
        try:
            incident_mgr.create_incident(
                "Malware", "CRITICAL", "WORKSTATION-01", 
                "Trojan Detection", "Detected suspicious process with known malware signature",
                "john_analyst"
            )
            incident_mgr.create_incident(
                "Network_Breach", "HIGH", "SERVER-PROD",
                "Unauthorized Network Access", "Detected brute force attack on RDP port",
                "john_analyst"
            )
            incident_mgr.create_incident(
                "Ransomware", "CRITICAL", "FILESERVER",
                "Ransomware Activity Detected", "Detected file encryption activity",
                "jane_admin"
            )
        except:
            pass
    
    # Initialize remote access
    if remote_access_mgr:
        try:
            remote_access_mgr.approve_user("john_analyst", "john@sentinelx.local", ["rdp", "ssh", "view_logs"])
            remote_access_mgr.approve_user("jane_admin", "jane@sentinelx.local", ["rdp", "ssh", "view_logs", "manage_systems"])
            
            # Enable remote access on current PC
            pc_info = remote_access_mgr.enable_remote_access_on_pc()
        except:
            pass
