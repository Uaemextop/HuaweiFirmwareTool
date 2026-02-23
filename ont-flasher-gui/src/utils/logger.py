"""
Logger - Centralized logging for the application
"""

import logging
import os
from datetime import datetime

_logger = None

def setup_logger():
    """Setup application logger"""
    global _logger

    if _logger is not None:
        return _logger

    # Create logger
    _logger = logging.getLogger('ONTFlasher')
    _logger.setLevel(logging.DEBUG)

    # Create logs directory if it doesn't exist
    log_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'logs')
    os.makedirs(log_dir, exist_ok=True)

    # Create file handler
    log_file = os.path.join(
        log_dir,
        f'ont_flasher_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
    )
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)

    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    # Add handlers
    _logger.addHandler(file_handler)
    _logger.addHandler(console_handler)

    _logger.info("Logger initialized")

    return _logger

def get_logger():
    """Get application logger"""
    global _logger

    if _logger is None:
        return setup_logger()

    return _logger
