"""
Signature Matcher for identifying known persistence patterns and attack signatures.

Provides pattern matching capabilities to identify known Android persistence
techniques, malware signatures, and suspicious code patterns.

Author: Security Research Team
License: Apache-2.0
"""

from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum


class SignatureSeverity(Enum):
    """Severity levels for matched signatures."""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1


@dataclass
class Signature:
    """Pattern signature definition."""
    name: str
    pattern: str  # Regex or string pattern
    description: str
    severity: SignatureSeverity
    cve: Optional[str] = None
    references: List[str] = None


class SignatureMatcher:
    """
    Matcher for code and binary signatures.
    
    Maintains a database of known persistence patterns and suspicious signatures
    to identify potential threats during APK analysis.
    """

    def __init__(self):
        """Initialize signature matcher with known patterns."""
        self.signatures = self._load_signatures()

    def _load_signatures(self) -> List[Signature]:
        """
        Load known persistence signatures.
        
        Returns:
            List of Signature objects
        """
        return [
            Signature(
                name="BootReceiver",
                pattern="android.intent.action.BOOT_COMPLETED",
                description="Broadcast receiver triggered on device boot",
                severity=SignatureSeverity.HIGH,
            ),
            Signature(
                name="AutoStartService",
                pattern="startForeground|startService",
                description="Auto-starting service detected",
                severity=SignatureSeverity.MEDIUM,
            ),
            Signature(
                name="ScreenOnReceiver",
                pattern="android.intent.action.SCREEN_ON",
                description="Receiver triggered on screen activation",
                severity=SignatureSeverity.MEDIUM,
            ),
            Signature(
                name="JobScheduler",
                pattern="JobScheduler|JobService",
                description="Job scheduling mechanism for background tasks",
                severity=SignatureSeverity.MEDIUM,
            ),
            Signature(
                name="WorkManager",
                pattern="WorkManager|Worker",
                description="WorkManager background task execution",
                severity=SignatureSeverity.MEDIUM,
            ),
            Signature(
                name="NativeExecution",
                pattern="System\\.load|Runtime\\.exec",
                description="Native code or shell command execution",
                severity=SignatureSeverity.HIGH,
            ),
            Signature(
                name="HiddenComponent",
                pattern="android:enabled=\"false\"",
                description="Disabled component that could be enabled at runtime",
                severity=SignatureSeverity.MEDIUM,
            ),
            Signature(
                name="KernelHook",
                pattern="ptrace|syscall|mmap.*exec",
                description="Potential kernel-level hook or manipulation",
                severity=SignatureSeverity.CRITICAL,
            ),
            Signature(
                name="ObfuscationIndicator",
                pattern="aaaa|bbbb|cccc|\\u[0-9a-f]{4}",
                description="Code obfuscation indicators",
                severity=SignatureSeverity.MEDIUM,
            ),
            Signature(
                name="ReflectionUsage",
                pattern="reflect|getMethod|invoke|forName",
                description="Reflection-based code execution",
                severity=SignatureSeverity.MEDIUM,
            ),
        ]

    def match_signatures(self, data: str) -> List[Tuple[Signature, List[str]]]:
        """
        Match signatures in provided data.
        
        Args:
            data: Text data to scan
            
        Returns:
            List of (Signature, matches) tuples
        """
        results = []
        
        for signature in self.signatures:
            matches = self._find_pattern(data, signature.pattern)
            if matches:
                results.append((signature, matches))
        
        return results

    def _find_pattern(self, text: str, pattern: str) -> List[str]:
        """
        Find all occurrences of pattern in text.
        
        Args:
            text: Text to search
            pattern: Pattern to find
            
        Returns:
            List of matching strings
        """
        import re
        try:
            matches = re.findall(pattern, text, re.IGNORECASE)
            return matches
        except re.error:
            # If regex fails, try literal string match
            if pattern in text:
                return [pattern]
            return []

    def get_risk_score(self, matches: List[Tuple[Signature, List[str]]]) -> float:
        """
        Calculate risk score based on signature matches.
        
        Args:
            matches: Matched signatures
            
        Returns:
            Risk score from 0 to 100
        """
        if not matches:
            return 0.0
        
        max_severity = max(m[0].severity.value for m in matches)
        match_count = sum(len(m[1]) for m in matches)
        
        base_score = (max_severity / 5) * 100
        bonus = min(match_count * 5, 30)  # Cap bonus at 30
        
        return min(base_score + bonus, 100)

    def generate_report(self, matches: List[Tuple[Signature, List[str]]]) -> str:
        """
        Generate human-readable report of matches.
        
        Args:
            matches: Matched signatures
            
        Returns:
            Formatted report string
        """
        lines = ["Signature Matching Report", "=" * 50]
        
        risk_score = self.get_risk_score(matches)
        lines.append(f"Overall Risk Score: {risk_score:.1f}/100")
        lines.append("")
        
        if not matches:
            lines.append("No suspicious signatures detected.")
        else:
            lines.append(f"Found {len(matches)} signature matches:\n")
            
            for signature, match_list in sorted(
                matches,
                key=lambda x: x[0].severity.value,
                reverse=True
            ):
                lines.append(f"[{signature.severity.name}] {signature.name}")
                lines.append(f"  Description: {signature.description}")
                lines.append(f"  Matches: {len(match_list)}")
                if len(match_list) <= 3:
                    for match in match_list:
                        lines.append(f"    - {match}")
                else:
                    for match in match_list[:3]:
                        lines.append(f"    - {match}")
                    lines.append(f"    ... and {len(match_list) - 3} more")
                lines.append("")
        
        return "\n".join(lines)
