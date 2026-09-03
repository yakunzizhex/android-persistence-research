"""
Data Parser - Binary and APK data extraction and parsing utilities.

This module provides comprehensive parsing capabilities for Android APK files,
including ZIP archive inspection, resource extraction, and binary format handling.

Features:
- APK file structure parsing
- Resource extraction (strings, assets, etc.)
- Binary format identification
- Manifest XML parsing and extraction
- Certificate chain extraction

Author: Security Research Team
License: Apache-2.0
"""

import zipfile
import struct
import io
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
import logging


@dataclass
class APKMetadata:
    """Metadata extracted from APK file."""
    filename: str
    size: int
    file_count: int
    dex_count: int
    lib_count: int
    resource_count: int
    cert_sha256: Optional[str] = None


class DataParser:
    """
    Main data parsing engine for APK analysis.
    
    Handles extraction and parsing of various data formats found in APK files,
    including DEX bytecode, XML manifests, and resource files.
    
    Example:
        >>> parser = DataParser("sample.apk")
        >>> metadata = parser.get_metadata()
        >>> manifest = parser.extract_manifest()
    """

    def __init__(self, apk_path: str):
        """
        Initialize data parser.
        
        Args:
            apk_path: Path to APK file
        """
        self.apk_path = Path(apk_path)
        self.logger = logging.getLogger(__name__)
        self.apk_zip = None
        self.metadata = None

    def open(self) -> bool:
        """
        Open and validate APK file.
        
        Returns:
            True if APK is valid and opened successfully
        """
        try:
            self.apk_zip = zipfile.ZipFile(self.apk_path, 'r')
            self.logger.info(f"Opened APK: {self.apk_path.name}")
            return True
        except zipfile.BadZipFile:
            self.logger.error("Invalid APK file format")
            return False
        except Exception as e:
            self.logger.error(f"Error opening APK: {str(e)}")
            return False

    def close(self) -> None:
        """Close APK file."""
        if self.apk_zip:
            self.apk_zip.close()

    def get_metadata(self) -> Optional[APKMetadata]:
        """
        Extract APK metadata.
        
        Returns:
            APKMetadata object with file information
        """
        if not self.apk_zip:
            self.open()

        if not self.apk_zip:
            return None

        try:
            file_list = self.apk_zip.namelist()
            dex_files = [f for f in file_list if f.endswith('.dex')]
            lib_files = [f for f in file_list if f.startswith('lib/')]
            resource_files = [f for f in file_list if f.startswith('res/')]

            metadata = APKMetadata(
                filename=self.apk_path.name,
                size=self.apk_path.stat().st_size,
                file_count=len(file_list),
                dex_count=len(dex_files),
                lib_count=len(lib_files),
                resource_count=len(resource_files),
            )

            self.metadata = metadata
            return metadata
        except Exception as e:
            self.logger.error(f"Error extracting metadata: {str(e)}")
            return None

    def list_files(self, prefix: str = None) -> List[str]:
        """
        List files in APK.
        
        Args:
            prefix: Optional prefix to filter files
            
        Returns:
            List of file paths
        """
        if not self.apk_zip:
            self.open()

        if not self.apk_zip:
            return []

        all_files = self.apk_zip.namelist()
        if prefix:
            return [f for f in all_files if f.startswith(prefix)]
        return all_files

    def extract_manifest(self) -> Optional[bytes]:
        """
        Extract AndroidManifest.xml (binary format).
        
        Returns:
            Raw manifest bytes or None if not found
        """
        if not self.apk_zip:
            self.open()

        try:
            manifest_data = self.apk_zip.read('AndroidManifest.xml')
            self.logger.debug(f"Extracted AndroidManifest.xml ({len(manifest_data)} bytes)")
            return manifest_data
        except KeyError:
            self.logger.warning("AndroidManifest.xml not found in APK")
            return None

    def extract_dex_files(self, output_dir: str = None) -> List[bytes]:
        """
        Extract all DEX files from APK.
        
        Args:
            output_dir: Optional directory to save DEX files
            
        Returns:
            List of DEX file contents
        """
        if not self.apk_zip:
            self.open()

        dex_files = []
        try:
            for file_info in self.apk_zip.filelist:
                if file_info.filename.endswith('.dex'):
                    dex_data = self.apk_zip.read(file_info.filename)
                    dex_files.append(dex_data)
                    
                    if output_dir:
                        output_path = Path(output_dir) / file_info.filename
                        output_path.parent.mkdir(parents=True, exist_ok=True)
                        with open(output_path, 'wb') as f:
                            f.write(dex_data)
                        self.logger.debug(f"Saved {file_info.filename}")

            self.logger.info(f"Extracted {len(dex_files)} DEX files")
            return dex_files
        except Exception as e:
            self.logger.error(f"Error extracting DEX files: {str(e)}")
            return []

    def extract_resources(self, output_dir: str = None) -> Dict[str, bytes]:
        """
        Extract resource files from APK.
        
        Args:
            output_dir: Optional directory to save resources
            
        Returns:
            Dictionary mapping resource paths to content
        """
        if not self.apk_zip:
            self.open()

        resources = {}
        try:
            for file_info in self.apk_zip.filelist:
                if file_info.filename.startswith('res/'):
                    resource_data = self.apk_zip.read(file_info.filename)
                    resources[file_info.filename] = resource_data
                    
                    if output_dir:
                        output_path = Path(output_dir) / file_info.filename
                        output_path.parent.mkdir(parents=True, exist_ok=True)
                        with open(output_path, 'wb') as f:
                            f.write(resource_data)

            self.logger.info(f"Extracted {len(resources)} resource files")
            return resources
        except Exception as e:
            self.logger.error(f"Error extracting resources: {str(e)}")
            return {}

    def extract_native_libs(self, output_dir: str = None) -> Dict[str, bytes]:
        """
        Extract native libraries (SO files).
        
        Args:
            output_dir: Optional directory to save libraries
            
        Returns:
            Dictionary mapping library paths to content
        """
        if not self.apk_zip:
            self.open()

        libraries = {}
        try:
            for file_info in self.apk_zip.filelist:
                if file_info.filename.startswith('lib/') and file_info.filename.endswith('.so'):
                    lib_data = self.apk_zip.read(file_info.filename)
                    libraries[file_info.filename] = lib_data
                    
                    if output_dir:
                        output_path = Path(output_dir) / file_info.filename
                        output_path.parent.mkdir(parents=True, exist_ok=True)
                        with open(output_path, 'wb') as f:
                            f.write(lib_data)

            self.logger.info(f"Extracted {len(libraries)} native libraries")
            return libraries
        except Exception as e:
            self.logger.error(f"Error extracting native libraries: {str(e)}")
            return {}

    def get_certificates(self) -> List[Dict[str, Any]]:
        """
        Extract certificate information from APK.
        
        Returns:
            List of certificate dictionaries
        """
        if not self.apk_zip:
            self.open()

        certificates = []
        try:
            cert_files = [f for f in self.apk_zip.namelist() 
                         if f.startswith('META-INF/') and f.endswith('.RSA')]
            
            for cert_file in cert_files:
                cert_data = self.apk_zip.read(cert_file)
                certificates.append({
                    'filename': cert_file,
                    'size': len(cert_data),
                    'data': cert_data[:32],  # First 32 bytes for identification
                })

            self.logger.debug(f"Found {len(certificates)} certificate files")
            return certificates
        except Exception as e:
            self.logger.error(f"Error extracting certificates: {str(e)}")
            return []

    def get_apk_size_breakdown(self) -> Dict[str, int]:
        """
        Get breakdown of APK size by component type.
        
        Returns:
            Dictionary with size information per component
        """
        if not self.apk_zip:
            self.open()

        breakdown = {
            'dex': 0,
            'resources': 0,
            'libraries': 0,
            'manifest': 0,
            'metadata': 0,
            'other': 0,
        }

        try:
            for file_info in self.apk_zip.filelist:
                size = file_info.file_size
                
                if file_info.filename.endswith('.dex'):
                    breakdown['dex'] += size
                elif file_info.filename.startswith('res/'):
                    breakdown['resources'] += size
                elif file_info.filename.startswith('lib/'):
                    breakdown['libraries'] += size
                elif file_info.filename == 'AndroidManifest.xml':
                    breakdown['manifest'] += size
                elif file_info.filename.startswith('META-INF/'):
                    breakdown['metadata'] += size
                else:
                    breakdown['other'] += size

            return breakdown
        except Exception as e:
            self.logger.error(f"Error calculating size breakdown: {str(e)}")
            return breakdown
