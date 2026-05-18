"""
Mock Cuckoo Sandbox for Testing - Simulates analysis responses without real Cuckoo instance.
Useful for GUI testing and development without VM/Docker requirements.
"""

import time
import random
from pathlib import Path
from typing import Dict, Optional

from sentinelx.utils.logger import get_logger

logger = get_logger(__name__)


class MockCuckooAnalysisReport:
    """Mock analysis report simulating Cuckoo response."""
    
    def __init__(self, task_id: int, file_name: str, is_malicious: bool = False):
        self.task_id = task_id
        self.file_hash = f"{random.randint(100000, 999999):x}"
        self.file_name = file_name
        self.analysis_status = "reported"
        self.timestamp = time.time()
        self.is_malicious = is_malicious
        
        # Generate mock behaviors/signatures
        if is_malicious:
            self.confidence_score = round(random.uniform(0.65, 0.99), 2)
            self.signatures = [
                "Modifies system registry",
                "Suspicious registry access",
                "Creates process with hidden window",
                "Injects code into running process",
                "Connects to suspicious domain",
                "Suspicious file write detected",
            ]
            self.behaviors = [
                {"api": "RegOpenKeyExA", "count": 12, "category": "Registry"},
                {"api": "CreateProcessA", "count": 3, "category": "Process"},
                {"api": "WinHttpConnect", "count": 5, "category": "Network"},
                {"api": "WriteFile", "count": 8, "category": "File"},
            ]
            self.dropped_files = [
                {"name": "payload.exe", "type": "executable", "size": 45000},
                {"name": "config.bin", "type": "data", "size": 1024},
            ]
        else:
            self.confidence_score = round(random.uniform(0.0, 0.3), 2)
            self.signatures = []
            self.behaviors = [
                {"api": "CreateWindowA", "count": 2, "category": "GUI"},
                {"api": "GetProcAddress", "count": 1, "category": "System"},
            ]
            self.dropped_files = []
        
        self.network_connections = []


class MockCuckooSandboxClient:
    """
    Mock Cuckoo Sandbox client for testing/development.
    Simulates file submission and analysis without requiring actual Cuckoo instance.
    """
    
    def __init__(self, host: str = "localhost", port: int = 8090, timeout: int = 300, mock_mode: bool = True):
        """
        Initialize mock Cuckoo client.
        
        Args:
            host: Cuckoo server hostname (ignored in mock mode)
            port: Cuckoo API port (ignored in mock mode)
            timeout: Analysis timeout in seconds
            mock_mode: If True, uses mock responses; if False, tries real connection
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self.is_available = True  # Always available in mock mode
        self.task_counter = 1000
        self.active_tasks = {}  # Store mock task states
        
        logger.info(f"[MOCK-CUCKOO] Initialized in mock mode - no real Cuckoo required")
    
    def submit_file(self, file_path: str, timeout: int = None) -> Optional[int]:
        """
        Mock file submission - returns immediately with fake task ID.
        
        Args:
            file_path: Path to file to analyze
            timeout: Optional custom analysis timeout
            
        Returns:
            Mock task ID
        """
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                logger.warning(f"[MOCK-CUCKOO] File not found: {file_path}")
                return None
            
            # Generate fake but consistent task ID
            task_id = self.task_counter
            self.task_counter += 1
            
            # Determine if "malicious" based on file size (for demo purposes)
            file_size = file_path.stat().st_size
            is_malicious = file_size > 100000  # Files > 100KB are "suspicious"
            
            # Store in active tasks (simulates API state)
            self.active_tasks[task_id] = {
                'status': 'submitted',
                'file': file_path.name,
                'start_time': time.time(),
                'is_malicious': is_malicious,
            }
            
            logger.info(f"[MOCK-CUCKOO] Submitted file: {file_path.name} (Task {task_id})")
            return task_id
        
        except Exception as e:
            logger.error(f"[MOCK-CUCKOO] Submission error: {str(e)}")
            return None
    
    def get_analysis_status(self, task_id: int) -> Optional[str]:
        """
        Mock status check - simulates analysis progression.
        
        Args:
            task_id: Task ID to check
            
        Returns:
            Status: 'running' or 'reported'
        """
        try:
            if task_id not in self.active_tasks:
                logger.warning(f"[MOCK-CUCKOO] Task not found: {task_id}")
                return None
            
            task = self.active_tasks[task_id]
            elapsed = time.time() - task['start_time']
            
            # Simulate analysis taking 10 seconds
            if elapsed < 10:
                task['status'] = 'running'
                return 'running'
            else:
                task['status'] = 'reported'
                return 'reported'
        
        except Exception as e:
            logger.error(f"[MOCK-CUCKOO] Status check error: {str(e)}")
            return None
    
    def get_analysis_report(self, task_id: int) -> Optional[MockCuckooAnalysisReport]:
        """
        Mock report generation - returns simulated analysis results.
        
        Args:
            task_id: Task ID to get report for
            
        Returns:
            MockCuckooAnalysisReport with simulated data
        """
        try:
            if task_id not in self.active_tasks:
                logger.warning(f"[MOCK-CUCKOO] Task not found: {task_id}")
                return None
            
            task = self.active_tasks[task_id]
            
            # Generate mock report
            report = MockCuckooAnalysisReport(
                task_id=task_id,
                file_name=task['file'],
                is_malicious=task['is_malicious']
            )
            
            logger.info(f"[MOCK-CUCKOO] Report retrieved - Task {task_id}: "
                       f"{'MALICIOUS' if report.is_malicious else 'CLEAN'} "
                       f"(Score: {report.confidence_score})")
            
            return report
        
        except Exception as e:
            logger.error(f"[MOCK-CUCKOO] Report error: {str(e)}")
            return None
    
    def cleanup_task(self, task_id: int) -> bool:
        """
        Mock cleanup - remove task from active list.
        
        Args:
            task_id: Task ID to clean up
            
        Returns:
            True if successful
        """
        try:
            if task_id in self.active_tasks:
                del self.active_tasks[task_id]
                logger.info(f"[MOCK-CUCKOO] Cleaned up task {task_id}")
                return True
            return False
        except Exception as e:
            logger.error(f"[MOCK-CUCKOO] Cleanup error: {str(e)}")
            return False
