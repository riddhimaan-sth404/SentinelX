"""
Cuckoo Sandbox Integration: Open-source malware analysis sandbox.
"""

import requests
import json
from pathlib import Path
from typing import Dict, Optional
from enum import Enum
from dataclasses import dataclass
from datetime import datetime

from sentinelx.utils.logger import get_logger

logger = get_logger(__name__)


class AnalysisStatus(Enum):
    """Status of sandbox analysis."""
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


@dataclass
class CuckooAnalysisReport:
    """Cuckoo Sandbox analysis report."""
    task_id: int
    file_hash: str
    file_name: str
    analysis_status: str
    timestamp: str
    behaviors: list = None
    signatures: list = None
    dropped_files: list = None
    network_connections: list = None
    is_malicious: bool = False
    confidence_score: float = 0.0


class CuckooSandboxClient:
    """Interface to Cuckoo Sandbox for dynamic malware analysis."""
    
    def __init__(self, host: str = "localhost", port: int = 8090, timeout: int = 300, force_mock: bool = False):
        """
        Initialize Cuckoo Sandbox client.
        
        Args:
            host: Cuckoo server hostname/IP
            port: Cuckoo API port
            timeout: Analysis timeout in seconds
            force_mock: If True, always use mock mode (for testing)
        """
        self.host = host
        self.port = port
        self.base_url = f"http://{host}:{port}/api"
        self.timeout = timeout
        self.headers = {"User-Agent": "SentinelX"}
        self.session = requests.Session()
        self.is_available = False
        self.use_mock = force_mock
        self.mock_client = None
        
        if force_mock:
            # Directly enable mock mode if requested
            self._enable_mock_mode(host, port, timeout)
        else:
            # Try to connect to real Cuckoo server
            self._check_connectivity()
            
            # Fall back to mock mode if real server not available
            if not self.is_available:
                logger.info(f"[CUCKOO] Cuckoo Sandbox not available at {host}:{port} - switching to MOCK MODE for testing")
                self._enable_mock_mode(host, port, timeout)
    
    def _check_connectivity(self) -> bool:
        """Check if Cuckoo server is reachable."""
        try:
            response = self.session.get(
                f"{self.base_url}/cuckoo/status",
                timeout=5,
                headers=self.headers
            )
            
            if response.status_code == 200:
                self.is_available = True
                logger.info(f"[CUCKOO] Connected to Cuckoo Sandbox at {self.host}:{self.port}")
                return True
            
        except requests.ConnectionError:
            logger.debug(f"[CUCKOO] Connection refused at {self.host}:{self.port} - not running")
            self.is_available = False
        except requests.Timeout:
            logger.debug(f"[CUCKOO] Connection timeout at {self.host}:{self.port}")
            self.is_available = False
        except Exception as e:
            logger.debug(f"[CUCKOO] Unable to connect to Cuckoo Sandbox: {type(e).__name__}")
            self.is_available = False
    
    def _enable_mock_mode(self, host: str, port: int, timeout: int):
        """Enable mock mode for testing without real Cuckoo instance."""
        try:
            from sentinelx.api.mock_sandbox import MockCuckooSandboxClient
            self.mock_client = MockCuckooSandboxClient(host, port, timeout, mock_mode=True)
            self.is_available = True
            self.use_mock = True
            logger.info(f"[CUCKOO] Mock mode enabled - sandbox features available for testing")
        except Exception as e:
            logger.error(f"[CUCKOO] Failed to enable mock mode: {e}")
            self.is_available = False
            return False
    
    def submit_file(self, file_path: str, timeout: int = None) -> Optional[int]:
        """
        Submit a file to Cuckoo for analysis.
        
        Args:
            file_path: Path to file to analyze
            timeout: Optional custom analysis timeout
            
        Returns:
            Task ID if successful, None otherwise
        """
        if not self.is_available:
            logger.warning("[CUCKOO] Cuckoo Sandbox not available")
            return None
        
        # Use mock mode if real server is unavailable
        if self.use_mock and self.mock_client:
            return self.mock_client.submit_file(file_path, timeout)
        
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                logger.error(f"[CUCKOO] File not found: {file_path}")
                return None
            
            with open(file_path, 'rb') as f:
                files = {'file': f}
                response = self.session.post(
                    f"{self.base_url}/tasks/create/file",
                    files=files,
                    timeout=10,
                    headers=self.headers
                )
            
            if response.status_code == 200:
                task_data = response.json()
                task_id = task_data.get('task_id')
                logger.info(f"[CUCKOO] File submitted - Task ID: {task_id}")
                return task_id
            else:
                logger.error(f"[CUCKOO] Submission failed: {response.status_code}")
                return None
        
        except Exception as e:
            logger.error(f"[CUCKOO] Error submitting file: {str(e)}")
            return None
    
    def get_analysis_status(self, task_id: int) -> str:
        """
        Get current analysis status.
        
        Args:
            task_id: Cuckoo task ID
            
        Returns:
            Status string (queued, running, completed, failed)
        """
        if not self.is_available:
            return AnalysisStatus.FAILED.value
        
        # Use mock mode if real server is unavailable
        if self.use_mock and self.mock_client:
            return self.mock_client.get_analysis_status(task_id)
        
        try:
            response = self.session.get(
                f"{self.base_url}/tasks/view/{task_id}",
                timeout=10,
                headers=self.headers
            )
            
            if response.status_code == 200:
                task_data = response.json()
                status = task_data.get('task', {}).get('status', 'unknown')
                return status
            
        except Exception as e:
            logger.error(f"[CUCKOO] Error getting status: {str(e)}")
        
        return AnalysisStatus.FAILED.value
    
    def get_analysis_report(self, task_id: int, file_hash: str = None) -> Optional[CuckooAnalysisReport]:
        """
        Retrieve analysis report.
        
        Args:
            task_id: Cuckoo task ID
            file_hash: Original file hash for reference
            
        Returns:
            CuckooAnalysisReport or None
        """
        if not self.is_available:
            return None
        
        # Use mock mode if real server is unavailable
        if self.use_mock and self.mock_client:
            mock_report = self.mock_client.get_analysis_report(task_id)
            if mock_report:
                # Convert mock report to CuckooAnalysisReport
                report = CuckooAnalysisReport(
                    task_id=mock_report.task_id,
                    file_hash=mock_report.file_hash,
                    file_name=mock_report.file_name,
                    analysis_status=mock_report.analysis_status,
                    timestamp=datetime.fromtimestamp(mock_report.timestamp).isoformat(),
                    behaviors=mock_report.behaviors,
                    signatures=mock_report.signatures,
                    dropped_files=mock_report.dropped_files,
                    network_connections=mock_report.network_connections,
                    is_malicious=mock_report.is_malicious,
                    confidence_score=mock_report.confidence_score
                )
                return report
            return None
        
        try:
            # Get task info
            response = self.session.get(
                f"{self.base_url}/tasks/view/{task_id}",
                timeout=10,
                headers=self.headers
            )
            
            if response.status_code != 200:
                return None
            
            task_data = response.json()
            task = task_data.get('task', {})
            status = task.get('status', 'unknown')
            
            if status != 'reported':
                return None
            
            # Get full report
            response = self.session.get(
                f"{self.base_url}/tasks/report/{task_id}",
                timeout=30,
                headers=self.headers
            )
            
            if response.status_code != 200:
                return None
            
            report_data = response.json()['report']
            
            # Parse report
            behaviors = report_data.get('behavior', {}).get('processes', [])
            signatures = report_data.get('signatures', [])
            dropped = report_data.get('dropped', [])
            network_data = report_data.get('network', {})
            
            # Determine if malicious
            is_malicious = len(signatures) > 0
            confidence = min(len(signatures) / 10.0, 1.0)  # Score based on signature count
            
            report = CuckooAnalysisReport(
                task_id=task_id,
                file_hash=file_hash or report_data.get('info', {}).get('md5', 'unknown'),
                file_name=task.get('target', {}).get('file', 'unknown'),
                analysis_status=status,
                timestamp=datetime.now().isoformat(),
                behaviors=behaviors,
                signatures=[sig.get('name') for sig in signatures],
                dropped_files=dropped,
                network_connections=network_data.get('tcp', []) + network_data.get('dns', []),
                is_malicious=is_malicious,
                confidence_score=confidence
            )
            
            logger.info(f"[CUCKOO] Report retrieved - Task {task_id}: {len(signatures)} signatures")
            return report
        
        except Exception as e:
            logger.error(f"[CUCKOO] Error getting report: {str(e)}")
            return None
    
    def analyze_file(self, file_path: str) -> Optional[CuckooAnalysisReport]:
        """
        Submit file and wait for analysis to complete.
        
        Args:
            file_path: Path to file to analyze
            
        Returns:
            CuckooAnalysisReport or None
        """
        import time
        
        task_id = self.submit_file(file_path)
        if task_id is None:
            return None
        
        # Wait for analysis to complete
        start_time = time.time()
        while time.time() - start_time < self.timeout:
            status = self.get_analysis_status(task_id)
            
            if status == 'reported':
                # Analysis complete
                return self.get_analysis_report(task_id)
            elif status == 'failed':
                logger.error(f"[CUCKOO] Analysis failed for task {task_id}")
                return None
            
            time.sleep(5)  # Check every 5 seconds
        
        logger.error(f"[CUCKOO] Analysis timeout for task {task_id}")
        return None
    
    def get_statistics(self) -> Dict:
        """Get Cuckoo server statistics."""
        if not self.is_available:
            return {}
        
        try:
            response = self.session.get(
                f"{self.base_url}/cuckoo/status",
                timeout=10,
                headers=self.headers
            )
            
            if response.status_code == 200:
                return response.json()
        
        except Exception as e:
            logger.error(f"[CUCKOO] Error getting statistics: {str(e)}")
        
        return {}
    
    def cleanup_task(self, task_id: int) -> bool:
        """Clean up task and analysis data."""
        if not self.is_available:
            return False
        
        try:
            response = self.session.delete(
                f"{self.base_url}/tasks/{task_id}",
                timeout=10,
                headers=self.headers
            )
            
            return response.status_code == 200
        
        except Exception as e:
            logger.error(f"[CUCKOO] Error cleaning up task: {str(e)}")
            return False
