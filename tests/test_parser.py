"""
Unit tests for data parser module.

Tests APK parsing, metadata extraction, and file handling.
"""

import pytest
import tempfile
from pathlib import Path
from android_persistence.data_parser import DataParser, APKMetadata


class TestAPKMetadata:
    """Test suite for APKMetadata dataclass."""

    def test_metadata_creation(self):
        """Test metadata creation."""
        metadata = APKMetadata(
            filename="test.apk",
            size=1024000,
            file_count=50,
            dex_count=1,
            lib_count=3,
            resource_count=20,
        )

        assert metadata.filename == "test.apk"
        assert metadata.size == 1024000
        assert metadata.dex_count == 1
        assert metadata.lib_count == 3


class TestDataParser:
    """Test suite for DataParser class."""

    def test_parser_initialization(self):
        """Test parser initialization."""
        parser = DataParser("test.apk")
        assert parser.apk_path.name == "test.apk"

    def test_list_files_empty(self):
        """Test listing files on non-existent APK."""
        parser = DataParser("nonexistent.apk")
        files = parser.list_files()
        assert files == []

    def test_hex_analysis(self):
        """Test binary analysis utilities."""
        from android_persistence.utils.hex_analyzer import HexAnalyzer

        test_data = b"Hello World"
        hex_dump = HexAnalyzer.hex_dump(test_data)
        assert "Hello" in hex_dump

    def test_string_extraction(self):
        """Test extracting strings from binary data."""
        from android_persistence.utils.hex_analyzer import HexAnalyzer

        test_data = b"Hello\x00World\x00\x00Test"
        strings = HexAnalyzer.extract_strings(test_data, min_length=4)
        assert "Hello" in strings
        assert "World" in strings

    def test_magic_bytes_detection(self):
        """Test magic bytes detection."""
        from android_persistence.utils.hex_analyzer import HexAnalyzer

        # ZIP magic bytes
        test_data = b"\x50\x4b\x03\x04" + b"rest of file"
        matches = HexAnalyzer.find_magic_bytes(test_data)
        assert len(matches) > 0
        assert matches[0][1] == "ZIP Archive"

    def test_pattern_finding(self):
        """Test pattern matching in binary data."""
        from android_persistence.utils.hex_analyzer import HexAnalyzer

        test_data = b"PATTERN_HERE_AND_PATTERN_HERE"
        matches = HexAnalyzer.find_pattern(test_data, b"PATTERN", all_matches=True)
        assert len(matches) == 2

    def test_xor_analysis(self):
        """Test XOR analysis."""
        from android_persistence.utils.hex_analyzer import HexAnalyzer

        test_data = b"test data for analysis"
        results = HexAnalyzer.xor_analysis(test_data, key_size=1)
        assert len(results) > 0
