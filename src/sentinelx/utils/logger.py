"""
Logging utilities for SentinelX.
"""
import logging
import logging.handlers
from pathlib import Path
from sentinelx.config.settings import get_config


def setup_logging():
    """Configure logging for the entire application."""
    config = get_config()
    log_config = config.logging
    
    # Create logs directory if it doesn't exist
    log_dir = Path(log_config.log_file).parent
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Create logger
    logger = logging.getLogger("sentinelx")
    logger.setLevel(getattr(logging, log_config.level))
    
    # Create rotating file handler
    handler = logging.handlers.RotatingFileHandler(
        log_config.log_file,
        maxBytes=log_config.max_bytes,
        backupCount=log_config.backup_count
    )
    
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(getattr(logging, log_config.level))
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    # Add handlers to logger
    if not logger.handlers:
        logger.addHandler(handler)
        logger.addHandler(console_handler)
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance.
    
    Args:
        name: Logger name (typically __name__)
        
    Returns:
        Logger instance
    """
    return logging.getLogger(f"sentinelx.{name}")


# Module-level logger instance for direct import
logger = logging.getLogger("sentinelx")
