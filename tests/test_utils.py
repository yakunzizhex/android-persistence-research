"""
Unit tests for utility modules.

Tests hex analysis, manifest parsing, and signature matching.
"""

import pytest
from android_persistence.utils.logger import LoggerConfig
from android_persistence.utils.signature_matcher import SignatureMatcher, SignatureSeverity
from android_persistence.utils.manifest_parser import ManifestParser


class TestLoggerConfig:
    """Test suite for LoggerConfig."""

    def test_logger_creation(self):
        """Test logger creation."""
        config = LoggerConfig()
        logger = config.get_logger("test", level="INFO")
        assert logger.name == "test"

    def test_logger_levels(self):
        """Test different logging levels."""
        config = LoggerConfig()
        for level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            logger = config.get_logger(f"test_{level}", level=level)
            assert logger is not None


class TestSignatureMatcher:
    """Test suite for SignatureMatcher."""

    def setup_method(self):
        """Set up test fixtures."""
        self.matcher = SignatureMatcher()

    def test_matcher_initialization(self):
        """Test matcher initialization."""
        assert len(self.matcher.signatures) > 0

    def test_signature_matching(self):
        """Test signature pattern matching."""
        test_data = "This contains android.intent.action.BOOT_COMPLETED action"
        matches = self.matcher.match_signatures(test_data)
        assert len(matches) > 0

    def test_boot_receiver_detection(self):
        """Test BOOT_COMPLETED receiver detection."""
        data = "Intent filter contains android.intent.action.BOOT_COMPLETED"
        matches = self.matcher.match_signatures(data)
        assert any("Boot" in m[0].name for m in matches)

    def test_risk_score_calculation(self):
        """Test risk score calculation."""
        test_data = "android.intent.action.BOOT_COMPLETED ptrace syscall"
        matches = self.matcher.match_signatures(test_data)
        score = self.matcher.get_risk_score(matches)
        assert 0 <= score <= 100

    def test_report_generation(self):
        """Test report generation."""
        test_data = "Contains BOOT_COMPLETED and native execution"
        matches = self.matcher.match_signatures(test_data)
        report = self.matcher.generate_report(matches)
        assert "Signature Matching Report" in report
        assert len(report) > 0


class TestManifestParser:
    """Test suite for ManifestParser."""

    def test_parser_initialization(self):
        """Test manifest parser initialization."""
        parser = ManifestParser()
        assert parser is not None

    def test_parser_with_empty_data(self):
        """Test parser with empty manifest data."""
        parser = ManifestParser(manifest_data=b"")
        result = parser.parse()
        # Should handle gracefully
        assert parser is not None

    def test_component_filtering(self):
        """Test component filtering."""
        parser = ManifestParser()
        # Should return empty list before parsing
        components = parser.get_components("activity")
        assert isinstance(components, list)

    def test_boot_receiver_check(self):
        """Test boot receiver detection."""
        parser = ManifestParser()
        has_boot = parser.has_boot_receiver()
        assert isinstance(has_boot, bool)

    def test_permission_handling(self):
        """Test permission handling."""
        parser = ManifestParser()
        permissions = parser.get_permissions()
        assert isinstance(permissions, list)


class TestSignatureSeverity:
    """Test suite for SignatureSeverity enum."""

    def test_severity_values(self):
        """Test severity value levels."""
        assert SignatureSeverity.CRITICAL.value == 5
        assert SignatureSeverity.HIGH.value == 4
        assert SignatureSeverity.MEDIUM.value == 3
        assert SignatureSeverity.LOW.value == 2
        assert SignatureSeverity.INFO.value == 1
