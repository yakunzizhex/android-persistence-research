"""
Logging utility module for consistent logging across the framework.

Provides configured loggers with standard formatting and multiple output handlers.

Author: Security Research Team
License: Apache-2.0
"""

import logging
import sys
from pathlib import Path
from typing import Optional


class LoggerConfig:
    """Configure and manage application logging."""

    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    DEBUG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'

    def __init__(self, log_dir: Optional[str] = None):
        """
        Initialize logger configuration.
        
        Args:
            log_dir: Optional directory to store log files
        """
        self.log_dir = Path(log_dir) if log_dir else None
        if self.log_dir:
            self.log_dir.mkdir(parents=True, exist_ok=True)

    def get_logger(
        self,
        name: str,
        level: str = "INFO",
        log_file: bool = False
    ) -> logging.Logger:
        """
        Get configured logger.
        
        Args:
            name: Logger name
            level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_file: Whether to also log to file
            
        Returns:
            Configured logger instance
        """
        logger = logging.getLogger(name)
        logger.setLevel(getattr(logging, level))

        # Remove existing handlers to avoid duplicates
        logger.handlers.clear()

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(getattr(logging, level))
        
        formatter = logging.Formatter(
            self.DEBUG_FORMAT if level == "DEBUG" else self.LOG_FORMAT
        )
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        # File handler (optional)
        if log_file and self.log_dir:
            file_path = self.log_dir / f"{name}.log"
            file_handler = logging.FileHandler(file_path)
            file_handler.setLevel(getattr(logging, level))
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

        return logger
