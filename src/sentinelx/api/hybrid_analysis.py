"""
Hybrid Analysis API Client: Integration with Hybrid Analysis sandbox service.
Handles file submission, status checking, and report retrieval.
"""
import requests
import time
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass
from enum import Enum
from sentinelx.config.settings import get_config
from sentinelx.utils.logger import get_logger

logger = get_logger(__name__)


class AnalysisStatus(Enum):
    """Status of submitted analysis."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAILED = "failed"
    NOT_FOUND = "not_found"


@dataclass
class AnalysisReport:
    """Report from Hybrid Analysis."""
    submission_id: str
    file_hash: str
    status: AnalysisStatus
    verdict: Optional[str] = None  # malware, clean, unknown
    threat_score: float = 0.0  # 0-100
    analysis_url: Optional[str] = None
    extracted_behaviors: list = None
    

class HybridAnalysisClient:
    """
    Client for Hybrid Analysis API v2.
    Handles submission and retrieval of malware behavioral analysis.
    """
    
    def __init__(self):
        """Initialize Hybrid Analysis client."""
        self.config = get_config().hybrid_analysis
        self.session = requests.Session()
        
        logger.info(f"Hybrid Analysis Client initialized")
        logger.info(f"  - Enabled: {self.config.enabled}")
        logger.info(f"  - API Key Present: {bool(self.config.api_key)}")
        logger.info(f"  - API Endpoint: {self.config.api_url}")
        
        if self.config.api_key:
            self._setup_headers()
            logger.info(f"  - API Key configured (length: {len(self.config.api_key)})")
        else:
            logger.warning("No Hybrid Analysis API key configured - sandbox analysis disabled")
    
    def _setup_headers(self):
        """Setup request headers with API key."""
        self.session.headers.update({
            'User-Agent': 'SentinelX/1.0',
            'api-key': self.config.api_key,
            'Content-Type': 'application/x-www-form-urlencoded'
        })
        logger.debug(f"API headers configured with key: {self.config.api_key[:20]}...")
    
    def submit_file(self, file_path: str) -> Optional[str]:
        """
        Submit file to Hybrid Analysis for analysis.
        
        Args:
            file_path: Path to file to submit
            
        Returns:
            Submission ID or None if submission fails
        """
        if not self.config.enabled:
            logger.warning("Hybrid Analysis is disabled in configuration")
            return None
        
        if not self.config.api_key:
            logger.error("Hybrid Analysis enabled but no API key configured")
            return None
        
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                logger.error(f"File not found: {file_path}")
                return None
            
            # Validate it's a file
            if not file_path.is_file():
                logger.error(f"Path is not a file: {file_path}")
                return None
            
            # Check file size (Hybrid Analysis limits)
            file_size_mb = file_path.stat().st_size / (1024 * 1024)
            if file_size_mb > 100:
                logger.warning(f"File too large for Hybrid Analysis ({file_size_mb}MB)")
                return None
            
            logger.info(f"Submitting file to Hybrid Analysis: {file_path} ({file_size_mb:.2f}MB)")
            
            submit_url = f"{self.config.api_url}/submit/file"
            logger.debug(f"[DEBUG] POST URL: {submit_url}")
            logger.debug(f"[DEBUG] Headers: User-Agent={self.session.headers.get('User-Agent')}, api-key present={bool(self.config.api_key)}")
            logger.debug(f"[DEBUG] Environment ID: {self.config.environment}")
            
            with open(file_path, 'rb') as f:
                files = {'file': f}
                payload = {
                    'environment_id': self.config.environment,
                    'action_script': '0',
                    'private': '0',
                    'hybrid-analysis': '1'
                }
                
                response = self.session.post(
                    submit_url,
                    files=files,
                    data=payload,
                    timeout=self.config.submit_timeout
                )
            
            logger.debug(f"Submission response status: {response.status_code}")
            
            if response.status_code in [200, 201]:
                result = response.json()
                submission_id = result.get('submission_id') or result.get('job_id')
                if submission_id:
                    logger.info(f"[OK] File submitted successfully: {submission_id}")
                    return submission_id
                else:
                    logger.error(f"[FAILED] No submission ID in response: {result}")
                    return None
            elif response.status_code == 404:
                logger.error(f"[ERROR] API endpoint not found (404) - Check API URL and API key")
                logger.error(f"[DEBUG] Endpoint: {self.config.api_url}/submit/file")
                logger.error(f"[DEBUG] Response: {response.text[:200]}")
                return None
            else:
                logger.error(f"[FAILED] Submission failed: HTTP {response.status_code}")
                logger.error(f"[DEBUG] Response: {response.text[:500]}")
                return None
        
        except requests.exceptions.Timeout:
            logger.error(f"[TIMEOUT] Submission timeout (>{self.config.submit_timeout}s) for {file_path}")
            return None
        except requests.exceptions.ConnectionError as e:
            logger.error(f"[CONNECTION] Connection error: {e}")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"[REQUEST] Request error submitting file: {e}")
            return None
        except OSError as e:
            logger.error(f"[IOERROR] File access error: {e}")
            return None
        except Exception as e:
            logger.error(f"[ERROR] Unexpected error submitting file: {e}")
            return None
    
    def get_report(self, submission_id: str) -> Optional[AnalysisReport]:
        """
        Retrieve analysis report from Hybrid Analysis.
        
        Args:
            submission_id: ID returned from submit_file
            
        Returns:
            AnalysisReport object or None
        """
        if not self.config.enabled or not self.config.api_key:
            return None
        
        try:
            logger.debug(f"Fetching report for submission: {submission_id}")
            
            response = self.session.get(
                f"{self.config.api_url}/report/{submission_id}",
                timeout=self.config.submit_timeout
            )
            
            if response.status_code == 404:
                return AnalysisReport(
                    submission_id=submission_id,
                    file_hash="unknown",
                    status=AnalysisStatus.NOT_FOUND
                )
            
            if response.status_code != 200:
                logger.warning(f"Failed to get report: {response.status_code}")
                return None
            
            data = response.json()
            
            # Parse response
            status_str = data.get('state', 'unknown').lower()
            if 'succ' in status_str:
                status = AnalysisStatus.SUCCESS
            elif 'fail' in status_str:
                status = AnalysisStatus.FAILED
            else:
                status = AnalysisStatus.IN_PROGRESS
            
            # Extract verdict
            verdict = None
            verdict_raw = data.get('verdict', 'unknown').lower()
            if 'mal' in verdict_raw:
                verdict = 'malware'
            elif 'clean' in verdict_raw:
                verdict = 'clean'
            else:
                verdict = 'unknown'
            
            # Extract threat score
            threat_score = float(data.get('threat_score', 0))
            
            # Extract file hash
            file_hash = data.get('sha256', data.get('sha1', data.get('md5', 'unknown')))
            
            # Extract behaviors
            behaviors = data.get('extracted_behaviors', [])
            
            report = AnalysisReport(
                submission_id=submission_id,
                file_hash=file_hash,
                status=status,
                verdict=verdict,
                threat_score=threat_score,
                analysis_url=data.get('analysis_url'),
                extracted_behaviors=behaviors
            )
            
            logger.info(f"Report retrieved: {submission_id} - Verdict: {verdict} (Score: {threat_score})")
            
            return report
        
        except Exception as e:
            logger.error(f"Error fetching report: {e}")
            return None
    
    def wait_for_analysis(self, submission_id: str) -> Optional[AnalysisReport]:
        """
        Poll for analysis completion with timeout.
        
        Args:
            submission_id: ID returned from submit_file
            
        Returns:
            AnalysisReport when complete or None if timeout
        """
        if not self.config.enabled:
            return None
        
        logger.info(f"Waiting for analysis: {submission_id}")
        
        for attempt in range(self.config.max_poll_attempts):
            report = self.get_report(submission_id)
            
            if report is None:
                logger.warning(f"Could not fetch report (attempt {attempt + 1})")
            elif report.status == AnalysisStatus.SUCCESS:
                logger.info(f"Analysis completed: {submission_id}")
                return report
            elif report.status == AnalysisStatus.FAILED:
                logger.error(f"Analysis failed: {submission_id}")
                return report
            elif report.status == AnalysisStatus.NOT_FOUND:
                logger.warning(f"Submission not found: {submission_id}")
                return report
            
            # Wait before next poll
            logger.debug(f"Analysis still in progress, wait {self.config.poll_interval}s...")
            time.sleep(self.config.poll_interval)
        
        logger.warning(f"Analysis timed out after {self.config.max_poll_attempts} attempts")
        return None
    
    def test_connection(self) -> bool:
        """
        Test if Hybrid Analysis API is accessible.
        
        Returns:
            True if API is reachable, False otherwise
        """
        if not self.config.api_key:
            logger.error("Cannot test connection - no API key configured")
            return False
        
        try:
            logger.info("[TEST] Testing Hybrid Analysis API connection...")
            
            # Try a simple GET request to test endpoint
            test_url = f"{self.config.api_url}/overview"
            logger.debug(f"[TEST] Making request to: {test_url}")
            
            response = self.session.get(test_url, timeout=10)
            
            logger.info(f"[TEST] Connection test response: HTTP {response.status_code}")
            
            if response.status_code in [200, 401, 403]:
                logger.info("[TEST] API is reachable (authentication may be required)")
                return True
            elif response.status_code == 404:
                logger.warning("[TEST] API endpoint not found (404) - Check API URL")
                return False
            else:
                logger.warning(f"[TEST] Unexpected response: {response.status_code}")
                return response.status_code < 500
        
        except requests.exceptions.ConnectionError:
            logger.error("[TEST] Cannot connect to API - check network and API URL")
            return False
        except requests.exceptions.Timeout:
            logger.error("[TEST] Connection timeout - API not responding")
            return False
        except Exception as e:
            logger.error(f"[TEST] Connection test failed: {e}")
            return False
    
        """Check if Hybrid Analysis is properly configured."""
        return self.config.enabled and bool(self.config.api_key)
    
    def get_status(self) -> Dict[str, Any]:
        """Get status information."""
        return {
            "enabled": self.config.enabled,
            "api_configured": bool(self.config.api_key),
            "api_url": self.config.api_url,
            "environment": self.config.environment
        }
