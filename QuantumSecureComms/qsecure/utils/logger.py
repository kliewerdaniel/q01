"""
Logging utilities for QuantumSecureComms.
"""

import logging
import sys
from typing import Optional

# Configure root logger
def setup_logging(level: str = 'INFO', log_file: Optional[str] = None):
    """
    Setup logging configuration.
    
    Args:
        level (str): Logging level (DEBUG, INFO, WARNING, ERROR)
        log_file (str): Optional log file path
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(formatter)
    
    # File handler if specified
    file_handler = None
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(formatter)
    
    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    
    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Add handlers
    root_logger.addHandler(console_handler)
    if file_handler:
        root_logger.addHandler(file_handler)

def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance.
    
    Args:
        name (str): Logger name
        
    Returns:
        logging.Logger: Configured logger
    """
    return logging.getLogger(name)

# Initial setup with INFO level
setup_logging()
