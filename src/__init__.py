"""
Android Persistence Research Framework - Core analysis package.

This package provides comprehensive tools for analyzing Android persistence
mechanisms, including detection, analysis, and mitigation strategies.

Version: 1.0.0
License: Apache-2.0
Author: Security Research Team
"""

__version__ = "1.0.0"
__author__ = "Security Research Team"

from src.persistence_detector import PersistenceDetector
from src.defensive_mitigations import MitigationStrategies

__all__ = [
    "PersistenceDetector",
    "MitigationStrategies",
]
