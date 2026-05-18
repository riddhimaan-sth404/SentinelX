"""
Discovery Layer: High-performance file scanning using os.scandir and Windows API.
Implements efficient file crawling with exclusion patterns and size filtering.
"""
import os
import fnmatch
from pathlib import Path
from typing import Generator, List
from dataclasses import dataclass
from sentinelx.config.settings import get_config
from sentinelx.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class FileInfo:
    """Information about a discovered file."""
    path: str
    size: int
    is_directory: bool
    stat_result: os.stat_result
    
    @property
    def extension(self) -> str:
        """Get file extension."""
        return Path(self.path).suffix.lower()


class DiscoveryLayer:
    """
    High-performance file discovery using os.scandir.
    Leverages efficient Win32 FindFirstFileW for Windows systems.
    """
    
    def __init__(self):
        """Initialize discovery layer with configuration."""
        self.config = get_config().discovery
        self.excluded_patterns = self.config.excluded_patterns
        self.size_limit_bytes = self.config.file_size_limit_mb * 1024 * 1024
        logger.info(f"Discovery layer initialized with targets: {self.config.target_paths}")
    
    def should_exclude(self, path: str) -> bool:
        """
        Check if path matches exclusion patterns.
        
        Args:
            path: File or directory path
            
        Returns:
            True if path should be excluded
        """
        path_lower = path.lower()
        for pattern in self.excluded_patterns:
            if fnmatch.fnmatch(path_lower, f"*{pattern}*"):
                return True
        return False
    
    def scan_directory(
        self,
        directory: str,
        recursive: bool = True,
        depth: int = 0,
        max_depth: int = 50
    ) -> Generator[FileInfo, None, None]:
        """
        Scan directory for files using os.scandir for efficiency.
        
        Args:
            directory: Directory path to scan
            recursive: Whether to recurse into subdirectories
            depth: Current recursion depth
            max_depth: Maximum recursion depth
            
        Yields:
            FileInfo objects for discovered files
        """
        if depth >= max_depth:
            logger.warning(f"Max recursion depth {max_depth} reached at {directory}")
            return
        
        if self.should_exclude(directory):
            logger.debug(f"Excluding directory: {directory}")
            return
        
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    if self.should_exclude(entry.path):
                        logger.debug(f"Excluding: {entry.path}")
                        continue
                    
                    try:
                        stat = entry.stat(follow_symlinks=self.config.follow_symlinks)
                        
                        if entry.is_file(follow_symlinks=self.config.follow_symlinks):
                            # Check size limit
                            if stat.st_size <= self.size_limit_bytes:
                                yield FileInfo(
                                    path=entry.path,
                                    size=stat.st_size,
                                    is_directory=False,
                                    stat_result=stat
                                )
                            else:
                                logger.debug(f"File exceeds size limit: {entry.path} ({stat.st_size} bytes)")
                        
                        elif entry.is_dir(follow_symlinks=self.config.follow_symlinks) and recursive:
                            # Recursively scan subdirectories
                            yield from self.scan_directory(
                                entry.path,
                                recursive=True,
                                depth=depth + 1,
                                max_depth=max_depth
                            )
                    
                    except (PermissionError, OSError) as e:
                        logger.debug(f"Error accessing {entry.path}: {e}")
                        continue
        
        except PermissionError as e:
            logger.warning(f"Permission denied scanning {directory}: {e}")
        except OSError as e:
            logger.error(f"OS error scanning {directory}: {e}")
    
    def discover_files(self) -> Generator[FileInfo, None, None]:
        """
        Discover all files from configured target paths.
        
        Yields:
            FileInfo objects for each discovered file
        """
        for target_path in self.config.target_paths:
            if not target_path:
                logger.warning("Skipping empty target path")
                continue
            
            target = Path(target_path)
            
            if not target.exists():
                logger.warning(f"Target path does not exist: {target_path}")
                continue
            
            if target.is_file():
                logger.info(f"Scanning single file: {target_path}")
                try:
                    stat = target.stat()
                    if stat.st_size <= self.size_limit_bytes:
                        yield FileInfo(
                            path=str(target),
                            size=stat.st_size,
                            is_directory=False,
                            stat_result=stat
                        )
                    else:
                        logger.debug(f"File exceeds size limit: {target_path}")
                except OSError as e:
                    logger.error(f"Error accessing file {target_path}: {e}")
            
            else:
                if not target.is_dir():
                    logger.warning(f"Target is neither file nor directory: {target_path}")
                    continue
                    
                logger.info(f"Scanning directory: {target_path}")
                yield from self.scan_directory(str(target), self.config.recursive)
    
    def discover_files_by_extension(self, extensions: List[str]) -> Generator[FileInfo, None, None]:
        """
        Discover files filtered by extensions.
        
        Args:
            extensions: List of extensions to filter (e.g., ['.exe', '.dll'])
            
        Yields:
            FileInfo objects matching specified extensions
        """
        extensions = [ext.lower() if ext.startswith('.') else f'.{ext.lower()}' for ext in extensions]
        
        for file_info in self.discover_files():
            if file_info.extension in extensions:
                yield file_info
