"""
Online Malware Analysis Services - VirusTotal, Any.run, Joe Sandbox, etc.
No local Cuckoo needed - uses existing cloud analysis services.
Free tiers available for all services.
"""

import requests
import json
import time
import hashlib
from pathlib import Path
from typing import Optional, Dict, List
from dataclasses import dataclass
from enum import Enum

from sentinelx.utils.logger import get_logger

logger = get_logger(__name__)


class AnalysisStatus(Enum):
    """Status of online submission."""
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class OnlineAnalysisReport:
    """Report from online analysis service."""
    task_id: str
    file_hash: str
    file_name: str
    verdict: str  # "MALICIOUS", "SUSPICIOUS", "CLEAN", "UNDETECTED"
    confidence_score: float  # 0.0 to 1.0
    signatures: List[str]
    engines_detected: int  # Number of engines that detected malware
    engines_total: int  # Total engines used
    analysis_date: str
    is_malicious: bool
    dropped_files: List[str]
    behaviors: List[Dict]
    service: str  # Which service performed analysis


class VirusTotalClient:
    """VirusTotal free API integration."""
    
    def __init__(self, api_key: str = None):
        """
        Initialize VirusTotal client.
        
        Free tier available - no API key needed for basic lookups.
        Get free API key: https://www.virustotal.com/gui/home/upload
        """
        self.api_key = api_key or ""
        self.base_url = "https://www.virustotal.com/api/v3"
        self.session = requests.Session()
        self.is_available = False
        self._check_connectivity()
    
    def _check_connectivity(self) -> bool:
        """Check if VirusTotal is reachable."""
        try:
            response = self.session.get(
                f"{self.base_url}/domains/google.com",
                headers={"x-apikey": self.api_key} if self.api_key else {},
                timeout=5
            )
            # API returns 200 or 403 (rate limited) - both mean service is reachable
            self.is_available = response.status_code in [200, 403, 401]
            
            if self.is_available:
                logger.info("[VT] VirusTotal service is reachable")
            return self.is_available
        
        except Exception as e:
            logger.warning(f"[VT] VirusTotal connection check failed: {e}")
            return False
    
    def submit_file(self, file_path: str) -> Optional[str]:
        """
        Submit file to VirusTotal.
        Free tier: 4 files per minute, 500 files per day.
        """
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                return None
            
            # First check if file hash already exists (no upload needed)
            file_hash = self._get_file_hash(file_path)
            if file_hash:
                logger.info(f"[VT] File hash {file_hash}: attempting lookup")
                return file_hash
            
            # Upload file if API key provided
            if not self.api_key:
                logger.warning("[VT] No API key - using free hash lookup only")
                return None
            
            with open(file_path, 'rb') as f:
                files = {'file': (file_path.name, f)}
                response = self.session.post(
                    f"{self.base_url}/files",
                    files=files,
                    headers={"x-apikey": self.api_key},
                    timeout=30
                )
            
            if response.status_code == 200:
                result = response.json()
                file_id = result.get('data', {}).get('id')
                logger.info(f"[VT] File submitted - ID: {file_id}")
                return file_id
            elif response.status_code == 400:
                logger.warning("[VT] File too large (>650MB) or invalid format")
                return None
            else:
                logger.error(f"[VT] Upload failed: {response.status_code}")
                return None
        
        except Exception as e:
            logger.error(f"[VT] Submission error: {e}")
            return None
    
    def _get_file_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of file."""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"[VT] Hash calculation error: {e}")
            return None
    
    def get_analysis_status(self, file_id: str) -> str:
        """Check file analysis status."""
        try:
            response = self.session.get(
                f"{self.base_url}/files/{file_id}",
                headers={"x-apikey": self.api_key} if self.api_key else {},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                # If we got data, analysis is complete
                return "completed"
            else:
                return "pending"
        
        except Exception as e:
            logger.error(f"[VT] Status check error: {e}")
            return "failed"
    
    def get_analysis_report(self, file_id: str, file_name: str = "unknown") -> Optional[OnlineAnalysisReport]:
        """Retrieve analysis results from VirusTotal."""
        try:
            response = self.session.get(
                f"{self.base_url}/files/{file_id}",
                headers={"x-apikey": self.api_key} if self.api_key else {},
                timeout=10
            )
            
            if response.status_code != 200:
                logger.warning(f"[VT] No analysis data available")
                return None
            
            data = response.json().get('data', {})
            attributes = data.get('attributes', {})
            
            # Extract detection stats
            last_analysis = attributes.get('last_analysis_stats', {})
            undetected = last_analysis.get('undetected', 0)
            malicious = last_analysis.get('malicious', 0)
            suspicious = last_analysis.get('suspicious', 0)
            total = undetected + malicious + suspicious + last_analysis.get('harmless', 0)
            
            # Determine verdict
            if malicious > 0:
                verdict = "MALICIOUS"
                is_malicious = True
            elif suspicious > 0:
                verdict = "SUSPICIOUS"
                is_malicious = True
            else:
                verdict = "CLEAN"
                is_malicious = False
            
            # Calculate confidence (engines detecting / total engines)
            confidence = (malicious + suspicious) / total if total > 0 else 0.0
            
            # Extract detected signatures
            signatures = []
            last_analysis_results = attributes.get('last_analysis_results', {})
            for engine, result in last_analysis_results.items():
                if result.get('category') == 'malicious':
                    signatures.append(f"{engine}: {result.get('engine_name', '')}")
            
            report = OnlineAnalysisReport(
                task_id=file_id,
                file_hash=attributes.get('sha256', file_id),
                file_name=file_name,
                verdict=verdict,
                confidence_score=confidence,
                signatures=signatures[:20],  # Limit to 20
                engines_detected=malicious + suspicious,
                engines_total=total,
                analysis_date=attributes.get('last_analysis_date', ''),
                is_malicious=is_malicious,
                dropped_files=[],
                behaviors=[],
                service="VirusTotal"
            )
            
            logger.info(f"[VT] Report retrieved - {verdict} ({malicious}/{total} engines)")
            return report
        
        except Exception as e:
            logger.error(f"[VT] Report retrieval error: {e}")
            return None


class AnyRunClient:
    """Any.run sandbox integration (https://any.run)."""
    
    def __init__(self, api_key: str = None):
        """
        Initialize Any.run client.
        
        Get free API key: https://app.any.run/register
        Free tier: 45 submissions/month, unlimited lookups
        """
        self.api_key = api_key or ""
        self.base_url = "https://api.any.run/v1"
        self.session = requests.Session()
        self.is_available = False
        self._check_connectivity()
    
    def _check_connectivity(self) -> bool:
        """Check if Any.run API is reachable."""
        try:
            response = self.session.get(
                f"{self.base_url}/tasks",
                headers={"Authorization": f"Bearer {self.api_key}"} if self.api_key else {},
                timeout=5
            )
            self.is_available = response.status_code in [200, 401, 403]
            
            if self.is_available:
                logger.info("[ANYRUN] Any.run service is reachable")
            return self.is_available
        
        except Exception as e:
            logger.warning(f"[ANYRUN] Connection check failed: {e}")
            return False
    
    def submit_file(self, file_path: str) -> Optional[str]:
        """Submit file to Any.run (requires API key)."""
        if not self.api_key:
            logger.warning("[ANYRUN] No API key configured")
            return None
        
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                return None
            
            with open(file_path, 'rb') as f:
                files = {'file': (file_path.name, f)}
                response = self.session.post(
                    f"{self.base_url}/tasks",
                    files=files,
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    timeout=30
                )
            
            if response.status_code == 201:
                result = response.json()
                task_id = result.get('data', {}).get('taskId')
                logger.info(f"[ANYRUN] File submitted - Task ID: {task_id}")
                return task_id
            else:
                logger.error(f"[ANYRUN] Submission failed: {response.status_code}")
                return None
        
        except Exception as e:
            logger.error(f"[ANYRUN] Submission error: {e}")
            return None
    
    def get_analysis_status(self, task_id: str) -> str:
        """Check task status."""
        if not self.api_key:
            return "pending"
        
        try:
            response = self.session.get(
                f"{self.base_url}/tasks/{task_id}",
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=10
            )
            
            if response.status_code == 200:
                status = response.json().get('data', {}).get('status', 'pending')
                return "completed" if status == "done" else "pending"
            return "pending"
        
        except Exception as e:
            logger.error(f"[ANYRUN] Status check error: {e}")
            return "pending"
    
    def get_analysis_report(self, task_id: str, file_name: str = "unknown") -> Optional[OnlineAnalysisReport]:
        """Retrieve analysis results from Any.run."""
        if not self.api_key:
            return None
        
        try:
            response = self.session.get(
                f"{self.base_url}/tasks/{task_id}/report",
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=30
            )
            
            if response.status_code != 200:
                return None
            
            data = response.json().get('data', {})
            
            # Parse verdict
            verdict = data.get('verdict', 'undetected').upper()
            is_malicious = verdict in ["MALICIOUS", "SUSPICIOUS"]
            
            # Extract behaviors/indicators
            indicators = data.get('indicators', [])
            signatures = [ind.get('name', '') for ind in indicators[:20]]
            
            report = OnlineAnalysisReport(
                task_id=task_id,
                file_hash=data.get('hashes', {}).get('sha256', task_id),
                file_name=file_name,
                verdict=verdict,
                confidence_score=0.8 if is_malicious else 0.2,
                signatures=signatures,
                engines_detected=1 if is_malicious else 0,
                engines_total=1,
                analysis_date=data.get('createdAt', ''),
                is_malicious=is_malicious,
                dropped_files=data.get('artifacts', []),
                behaviors=data.get('behaviors', []),
                service="Any.run"
            )
            
            logger.info(f"[ANYRUN] Report retrieved - {verdict}")
            return report
        
        except Exception as e:
            logger.error(f"[ANYRUN] Report retrieval error: {e}")
            return None


class CuckooOnlineClient:
    """
    Meta-client for online analysis services.
    Automatically detects and uses available services.
    """
    
    def __init__(self, service: str = "virusTotal", api_key: str = None):
        """
        Initialize online client.
        
        Args:
            service: "virusTotal", "anyrun", or "auto" to detect
            api_key: API key for the service (optional for VirusTotal)
        """
        self.service_name = service
        self.api_key = api_key
        self.client = None
        self.is_available = False
        
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize the appropriate service client."""
        try:
            if self.service_name.lower() in ["virustotal", "vt"]:
                self.client = VirusTotalClient(self.api_key)
            elif self.service_name.lower() in ["anyrun", "any.run"]:
                self.client = AnyRunClient(self.api_key)
            else:
                # Default to VirusTotal
                self.client = VirusTotalClient(self.api_key)
            
            self.is_available = self.client.is_available
            logger.info(f"[ONLINE] Using {self.service_name} for online analysis")
        
        except Exception as e:
            logger.error(f"[ONLINE] Client initialization error: {e}")
            self.is_available = False
    
    def submit_file(self, file_path: str) -> Optional[str]:
        """Submit file to online service."""
        if not self.is_available or not self.client:
            logger.warning("[ONLINE] Online service not available")
            return None
        
        return self.client.submit_file(file_path)
    
    def get_analysis_status(self, task_id: str) -> str:
        """Check analysis status."""
        if not self.is_available or not self.client:
            return "failed"
        
        return self.client.get_analysis_status(task_id)
    
    def get_analysis_report(self, task_id: str, file_name: str = "unknown") -> Optional[OnlineAnalysisReport]:
        """Get analysis report."""
        if not self.is_available or not self.client:
            return None
        
        return self.client.get_analysis_report(task_id, file_name)
