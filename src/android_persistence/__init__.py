"""
Android Persistence Research Framework - Core analysis package.

This package provides comprehensive tools for analyzing Android persistence
mechanisms, including detection, analysis, and mitigation strategies.

Version: 1.0.0
License: MIT
Author: Zyekh Abdul Qadir Jailani
"""

__version__ = "1.0.0"
__author__ = "Zyekh Abdul Qadir Jailani"

from .persistence_detector import PersistenceDetector, PersistenceFinding, PersistenceType, SeverityLevel
from .defensive_mitigations import MitigationStrategies
from .data_parser import DataParser, APKMetadata
from .report_generator import ReportGenerator

__all__ = [
    "PersistenceDetector",
    "PersistenceFinding",
    "PersistenceType",
    "SeverityLevel",
    "MitigationStrategies",
    "DataParser",
    "APKMetadata",
    "ReportGenerator",
]
