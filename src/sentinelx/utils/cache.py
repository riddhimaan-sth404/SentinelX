"""
Result Caching for SentinelX
Caches scan results to avoid re-scanning identical files
"""
import json
import hashlib
from pathlib import Path
from typing import Optional, Dict
from datetime import datetime, timedelta
from sentinelx.config.settings import get_config
from sentinelx.utils.logger import get_logger

logger = get_logger(__name__)


class ResultCache:
    """
    Cache scan results based on file hash.
    Reduces unnecessary re-scans of unchanged files.
    """
    
    def __init__(self):
        """Initialize result cache."""
        self.config = get_config()
        self.cache_dir = Path(self.config.cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl_hours = 24  # Cache time-to-live
    
    def _get_cache_path(self, file_hash: str) -> Path:
        """Get cache file path for a given hash."""
        return self.cache_dir / f"{file_hash}.json"
    
    def get(self, file_hash: str) -> Optional[Dict]:
        """
        Get cached result if available and not expired.
        
        Args:
            file_hash: SHA256 hash of file
            
        Returns:
            Cached result dict or None
        """
        if not self.config.cache_results:
            return None
        
        cache_file = self._get_cache_path(file_hash)
        if not cache_file.exists():
            return None
        
        try:
            with open(cache_file, 'r') as f:
                cached = json.load(f)
            
            # Check if cache is expired
            cached_time = datetime.fromisoformat(cached.get('timestamp', ''))
            if datetime.utcnow() - cached_time > timedelta(hours=self.ttl_hours):
                logger.debug(f"Cache expired for {file_hash}")
                cache_file.unlink()  # Delete expired cache
                return None
            
            logger.debug(f"Cache hit for {file_hash}")
            return cached['result']
        
        except Exception as e:
            logger.error(f"Error reading cache: {e}")
            return None
    
    def set(self, file_hash: str, result: Dict):
        """
        Cache a scan result.
        
        Args:
            file_hash: SHA256 hash of file
            result: Result dictionary to cache
        """
        if not self.config.cache_results:
            return
        
        try:
            cache_file = self._get_cache_path(file_hash)
            
            cache_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'result': result
            }
            
            with open(cache_file, 'w') as f:
                json.dump(cache_data, f)
            
            logger.debug(f"Cached result for {file_hash}")
        
        except Exception as e:
            logger.error(f"Error caching result: {e}")
    
    def clear(self):
        """Clear all cached results."""
        if not self.config.cache_results:
            return
        
        try:
            for cache_file in self.cache_dir.glob("*.json"):
                cache_file.unlink()
            logger.info("Cache cleared")
        except Exception as e:
            logger.error(f"Error clearing cache: {e}")
    
    def clear_expired(self):
        """Remove expired cache entries."""
        if not self.config.cache_results:
            return
        
        try:
            removed_count = 0
            for cache_file in self.cache_dir.glob("*.json"):
                try:
                    with open(cache_file, 'r') as f:
                        cached = json.load(f)
                    
                    cached_time = datetime.fromisoformat(cached.get('timestamp', ''))
                    if datetime.utcnow() - cached_time > timedelta(hours=self.ttl_hours):
                        cache_file.unlink()
                        removed_count += 1
                
                except Exception:
                    continue
            
            if removed_count > 0:
                logger.info(f"Removed {removed_count} expired cache entries")
        
        except Exception as e:
            logger.error(f"Error clearing expired cache: {e}")
