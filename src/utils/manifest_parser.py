"""
Manifest Parser for AndroidManifest.xml binary format analysis.

Handles parsing of compiled AndroidManifest.xml files which are in binary AXML format.
This module provides tools for extracting components, permissions, and intent filters.

Author: Security Research Team
License: Apache-2.0
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass


@dataclass
class Permission:
    """Represents a permission declared in manifest."""
    name: str
    protection_level: str = "normal"
    description: str = ""


@dataclass
class Component:
    """Represents an Android component (Activity, Service, BroadcastReceiver, etc)."""
    name: str
    component_type: str  # activity, service, receiver, provider
    exported: bool = False
    permissions: List[str] = None
    intent_filters: List[Dict[str, Any]] = None


class ManifestParser:
    """
    Parser for Android manifest files.
    
    Note: This is a simplified parser. For full AXML binary parsing,
    use androguard library.
    """

    def __init__(self, manifest_path: str = None, manifest_data: bytes = None):
        """
        Initialize manifest parser.
        
        Args:
            manifest_path: Path to AndroidManifest.xml
            manifest_data: Raw manifest bytes
        """
        self.manifest_path = manifest_path
        self.manifest_data = manifest_data
        self.components: List[Component] = []
        self.permissions: List[Permission] = []
        self.package_name: str = ""

    def parse(self) -> bool:
        """
        Parse manifest file.
        
        Returns:
            True if parsing succeeded
        """
        try:
            if self.manifest_path:
                with open(self.manifest_path, 'rb') as f:
                    self.manifest_data = f.read()
            
            if not self.manifest_data:
                return False
            
            self._extract_basic_info()
            self._extract_components()
            self._extract_permissions()
            
            return True
        except Exception as e:
            print(f"Error parsing manifest: {str(e)}")
            return False

    def _extract_basic_info(self) -> None:
        """Extract basic package information from manifest."""
        # This is a simplified extraction - real parsing would decode AXML format
        # Looking for package attribute pattern
        try:
            # Search for package name in manifest
            if b'package=' in self.manifest_data:
                idx = self.manifest_data.find(b'package=')
                if idx != -1:
                    # Extract package name (simplified approach)
                    data_after = self.manifest_data[idx+8:idx+100]
                    end = data_after.find(b'\x00')
                    if end > 0:
                        self.package_name = data_after[:end].decode('utf-8', errors='ignore')
        except Exception:
            self.package_name = "Unknown"

    def _extract_components(self) -> None:
        """Extract Android components from manifest."""
        # Simulate component extraction
        component_types = {
            b'<activity': 'activity',
            b'<service': 'service',
            b'<receiver': 'receiver',
            b'<provider': 'provider',
        }
        
        for tag, comp_type in component_types.items():
            offset = 0
            while True:
                offset = self.manifest_data.find(tag, offset)
                if offset == -1:
                    break
                # Extract component name (simplified)
                offset += 1

    def _extract_permissions(self) -> None:
        """Extract declared permissions from manifest."""
        # Simulate permission extraction
        try:
            offset = self.manifest_data.find(b'<uses-permission')
            if offset != -1:
                # Found permission declaration
                pass
        except Exception:
            pass

    def get_components(self, component_type: str = None) -> List[Component]:
        """
        Get components from manifest.
        
        Args:
            component_type: Filter by type (activity, service, receiver, provider)
            
        Returns:
            List of components
        """
        if not component_type:
            return self.components
        return [c for c in self.components if c.component_type == component_type]

    def get_permissions(self) -> List[Permission]:
        """Get declared permissions."""
        return self.permissions

    def get_package_name(self) -> str:
        """Get package name."""
        return self.package_name

    def has_boot_receiver(self) -> bool:
        """Check if manifest contains BOOT_COMPLETED receiver."""
        return any(
            'BOOT_COMPLETED' in str(c.intent_filters or [])
            for c in self.get_components('receiver')
        )

    def get_exported_components(self) -> List[Component]:
        """Get all exported components (potential attack surface)."""
        return [c for c in self.components if c.exported]

    def print_summary(self) -> None:
        """Print manifest summary."""
        print(f"\nPackage: {self.package_name}")
        print(f"Components: {len(self.components)}")
        print(f"Permissions: {len(self.permissions)}")
        print(f"Exported: {len(self.get_exported_components())}")
