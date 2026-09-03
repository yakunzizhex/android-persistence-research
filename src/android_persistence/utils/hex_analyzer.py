"""
Hex and Binary Analysis utilities for examining binary data from APK files.

Provides utilities for analyzing binary data, including hex dumps, pattern matching,
and binary format identification.

Author: Security Research Team
License: Apache-2.0
"""

import struct
from typing import List, Tuple, Optional
import re


class HexAnalyzer:
    """Utility class for hex and binary data analysis."""

    @staticmethod
    def hex_dump(data: bytes, width: int = 16) -> str:
        """
        Generate hex dump of binary data.
        
        Args:
            data: Binary data to dump
            width: Number of bytes per line
            
        Returns:
            Formatted hex dump string
        """
        lines = []
        for i in range(0, len(data), width):
            chunk = data[i:i+width]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(f'{i:08x}  {hex_part:<{width*3}}  {ascii_part}')
        return '\n'.join(lines)

    @staticmethod
    def find_pattern(data: bytes, pattern: bytes, all_matches: bool = False) -> List[int]:
        """
        Find pattern in binary data.
        
        Args:
            data: Data to search
            pattern: Pattern to find
            all_matches: If True, return all matches; if False, return first
            
        Returns:
            List of offsets where pattern is found
        """
        matches = []
        offset = 0
        while True:
            offset = data.find(pattern, offset)
            if offset == -1:
                break
            matches.append(offset)
            if not all_matches:
                return matches
            offset += 1
        return matches

    @staticmethod
    def find_magic_bytes(data: bytes) -> List[Tuple[int, str, bytes]]:
        """
        Identify common file format magic bytes in data.
        
        Args:
            data: Data to analyze
            
        Returns:
            List of (offset, type, bytes) tuples
        """
        MAGIC_SIGNATURES = {
            b'\x50\x4b\x03\x04': 'ZIP Archive',
            b'\x50\x4b\x05\x06': 'ZIP End of Central Directory',
            b'\x64\x65\x78\x0a': 'DEX File',
            b'\x7fELF': 'ELF Binary',
            b'\xca\xfe\xba\xbe': 'Java Class File',
            b'\xff\xd8\xff': 'JPEG Image',
            b'\x89PNG': 'PNG Image',
            b'\x42\x4d': 'BMP Image',
        }
        
        matches = []
        for sig, name in MAGIC_SIGNATURES.items():
            offset = data.find(sig)
            if offset != -1:
                matches.append((offset, name, sig))
        
        return sorted(matches, key=lambda x: x[0])

    @staticmethod
    def extract_strings(data: bytes, min_length: int = 4) -> List[str]:
        """
        Extract ASCII strings from binary data.
        
        Args:
            data: Binary data
            min_length: Minimum string length
            
        Returns:
            List of extracted strings
        """
        strings = []
        current = []
        
        for byte in data:
            if 32 <= byte < 127:  # Printable ASCII
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append(''.join(current))
                current = []
        
        if len(current) >= min_length:
            strings.append(''.join(current))
        
        return strings

    @staticmethod
    def find_regex_pattern(data: bytes, pattern: str) -> List[Tuple[int, bytes]]:
        """
        Find data matching regex pattern.
        
        Args:
            data: Binary data
            pattern: Regex pattern (will be applied to string representation)
            
        Returns:
            List of (offset, match) tuples
        """
        matches = []
        regex = re.compile(pattern.encode() if isinstance(pattern, str) else pattern)
        
        for match in regex.finditer(data):
            matches.append((match.start(), match.group()))
        
        return matches

    @staticmethod
    def xor_analysis(data: bytes, key_size: int = 1) -> List[Tuple[int, bytes]]:
        """
        Perform XOR analysis on data for potential encryption/obfuscation.
        
        Args:
            data: Data to analyze
            key_size: Size of XOR key to try
            
        Returns:
            List of (key, decrypted_sample) tuples
        """
        results = []
        
        if key_size == 1:
            for key in range(256):
                decrypted = bytes(b ^ key for b in data[:min(100, len(data))])
                if decrypted.count(0) < len(decrypted) // 4:  # Not too many nulls
                    results.append((bytes([key]), decrypted))
        
        return results[:10]  # Return top 10 results
