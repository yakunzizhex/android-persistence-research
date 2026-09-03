"""
Unit tests for persistence detector module.

Tests core functionality of the PersistenceDetector class including:
- Finding creation and management
- Risk score calculation
- Report export functionality
"""

import pytest
import json
import tempfile
from pathlib import Path
from android_persistence.persistence_detector import (
    PersistenceDetector,
    PersistenceType,
    SeverityLevel,
    PersistenceFinding,
)


class TestPersistenceDetector:
    """Test suite for PersistenceDetector class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.detector = PersistenceDetector()

    def test_detector_initialization(self):
        """Test detector initialization."""
        assert self.detector is not None
        assert len(self.detector.findings) == 0
        assert self.detector.apk_path is None

    def test_add_finding(self):
        """Test adding a persistence finding."""
        self.detector._add_finding(
            component_name="TestComponent",
            persistence_type=PersistenceType.BROADCAST_RECEIVER,
            severity=SeverityLevel.HIGH,
            description="Test finding",
        )

        assert len(self.detector.findings) == 1
        assert self.detector.findings[0].component_name == "TestComponent"
        assert self.detector.findings[0].severity == SeverityLevel.HIGH

    def test_multiple_findings(self):
        """Test adding multiple findings."""
        for i in range(5):
            self.detector._add_finding(
                component_name=f"Component{i}",
                persistence_type=PersistenceType.SERVICE,
                severity=SeverityLevel.MEDIUM,
                description=f"Finding {i}",
            )

        assert len(self.detector.findings) == 5

    def test_risk_score_calculation(self):
        """Test risk score calculation."""
        # No findings
        assert self.detector.get_risk_score() == 0.0

        # Add critical finding
        self.detector._add_finding(
            component_name="Critical",
            persistence_type=PersistenceType.NATIVE_LIBRARY,
            severity=SeverityLevel.CRITICAL,
            description="Critical issue",
        )
        score = self.detector.get_risk_score()
        assert score > 80  # Should be high

    def test_finding_export_json(self):
        """Test JSON export of findings."""
        self.detector._add_finding(
            component_name="TestComponent",
            persistence_type=PersistenceType.BROADCAST_RECEIVER,
            severity=SeverityLevel.HIGH,
            description="Test finding",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "findings.json"
            success = self.detector.export_findings_json(str(output_path))

            assert success
            assert output_path.exists()

            with open(output_path) as f:
                data = json.load(f)
                assert data["total_findings"] == 1
                assert len(data["findings"]) == 1

    def test_finding_to_dict(self):
        """Test finding to dictionary conversion."""
        finding = PersistenceFinding(
            finding_id="test123",
            app_name="TestApp",
            persistence_type=PersistenceType.BROADCAST_RECEIVER,
            severity=SeverityLevel.HIGH,
            component_name="TestComponent",
            description="Test description",
            confidence=90,
        )

        data = finding.to_dict()
        assert data["finding_id"] == "test123"
        assert data["persistence_type"] == PersistenceType.BROADCAST_RECEIVER.value
        assert data["severity"] == "HIGH"

    def test_severity_levels(self):
        """Test severity level values."""
        assert SeverityLevel.CRITICAL.value == 5
        assert SeverityLevel.HIGH.value == 4
        assert SeverityLevel.MEDIUM.value == 3
        assert SeverityLevel.LOW.value == 2

    def test_persistence_types(self):
        """Test persistence type enumeration."""
        assert PersistenceType.BROADCAST_RECEIVER.value == "broadcast_receiver"
        assert PersistenceType.SERVICE.value == "service"
        assert PersistenceType.NATIVE_LIBRARY.value == "native_library"

    def test_default_mitigations(self):
        """Test default mitigations generation."""
        mitigations = self.detector._get_default_mitigations(
            PersistenceType.BROADCAST_RECEIVER
        )
        assert len(mitigations) > 0
        assert any("broadcast" in m.lower() for m in mitigations)

    def test_print_summary(self, capsys):
        """Test summary printing."""
        self.detector._add_finding(
            component_name="Test",
            persistence_type=PersistenceType.BROADCAST_RECEIVER,
            severity=SeverityLevel.HIGH,
            description="Test",
        )

        self.detector.print_summary()
        captured = capsys.readouterr()
        assert "ANDROID PERSISTENCE ANALYSIS SUMMARY" in captured.out
        assert "Total Findings: 1" in captured.out


class TestPersistenceFinding:
    """Test suite for PersistenceFinding dataclass."""

    def test_finding_creation(self):
        """Test finding creation."""
        finding = PersistenceFinding(
            finding_id="test1",
            app_name="TestApp",
            persistence_type=PersistenceType.SERVICE,
            severity=SeverityLevel.MEDIUM,
            component_name="TestService",
            description="Test service finding",
        )

        assert finding.finding_id == "test1"
        assert finding.app_name == "TestApp"
        assert finding.persistence_type == PersistenceType.SERVICE

    def test_finding_with_evidence(self):
        """Test finding with evidence data."""
        evidence = {"key": "value", "count": 42}
        finding = PersistenceFinding(
            finding_id="test2",
            app_name="App",
            persistence_type=PersistenceType.NATIVE_LIBRARY,
            severity=SeverityLevel.HIGH,
            component_name="Component",
            description="Description",
            evidence=evidence,
        )

        assert finding.evidence == evidence

    def test_finding_default_values(self):
        """Test finding default values."""
        finding = PersistenceFinding(
            finding_id="test3",
            app_name="App",
            persistence_type=PersistenceType.JOB_SCHEDULER,
            severity=SeverityLevel.LOW,
            component_name="Component",
            description="Description",
        )

        assert finding.confidence == 85
        assert len(finding.mitigations) == 0
