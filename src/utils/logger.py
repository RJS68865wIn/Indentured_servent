"""
Logging utility for Indentured Servant
"""
import logging
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional

def setup_logger(name: str = "IndenturedServant", 
                log_level: int = logging.INFO,
                log_to_file: bool = True,
                log_to_console: bool = True) -> logging.Logger:
    """
    Setup and configure logger
    
    Args:
        name: Logger name
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_to_file: Whether to log to file
        log_to_console: Whether to log to console
        
    Returns:
        Configured logger instance
    """
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(log_level)
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Create formatters
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    console_formatter = logging.Formatter(
        '%(levelname)s: %(message)s',
        datefmt='%H:%M:%S'
    )
    
    # File handler
    if log_to_file:
        try:
            # Create logs directory
            log_dir = Path("data/logs")
            log_dir.mkdir(parents=True, exist_ok=True)
            
            # Create log file with date
            log_file = log_dir / f"indentured_{datetime.now().strftime('%Y%m%d')}.log"
            
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            file_handler.setLevel(log_level)
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            print(f"Failed to setup file logging: {e}")
    
    # Console handler
    if log_to_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
    
    return logger

def log_function_call(func):
    """Decorator to log function calls"""
    def wrapper(*args, **kwargs):
        logger = logging.getLogger("IndenturedServant")
        logger.debug(f"Calling {func.__name__} with args={args}, kwargs={kwargs}")
        try:
            result = func(*args, **kwargs)
            logger.debug(f"{func.__name__} returned: {result}")
            return result
        except Exception as e:
            logger.error(f"{func.__name__} failed: {e}", exc_info=True)
            raise
    return wrapper

def log_exception(logger: logging.Logger, exception: Exception, context: str = ""):
    """Log exception with context"""
    logger.error(f"{context}: {exception}", exc_info=True)

def get_log_file_path(date: Optional[str] = None) -> Path:
    """
    Get path to log file
    
    Args:
        date: Date in YYYYMMDD format, defaults to today
        
    Returns:
        Path to log file
    """
    if date is None:
        date = datetime.now().strftime('%Y%m%d')
    
    return Path("data/logs") / f"indentured_{date}.log"

def clear_old_logs(days_to_keep: int = 30):
    """Clear log files older than specified days"""
    import os
    from datetime import datetime, timedelta
    
    log_dir = Path("data/logs")
    if not log_dir.exists():
        return
    
    cutoff_date = datetime.now() - timedelta(days=days_to_keep)
    
    for log_file in log_dir.glob("indentured_*.log"):
        try:
            # Extract date from filename
            date_str = log_file.stem.split('_')[1]
            file_date = datetime.strptime(date_str, '%Y%m%d')
            
            if file_date < cutoff_date:
                log_file.unlink()
                print(f"Deleted old log: {log_file.name}")
        except (ValueError, IndexError):
            # Skip files that don't match naming pattern
            continue

if __name__ == "__main__":
    # Test the logger
    logger = setup_logger()
    
    logger.debug("This is a debug message")
    logger.info("This is an info message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")
    
    # Test exception logging
    try:
        raise ValueError("Test exception")
    except Exception as e:
        log_exception(logger, e, "Testing exception logging")
    
    print(f"\nLog file: {get_log_file_path()}")