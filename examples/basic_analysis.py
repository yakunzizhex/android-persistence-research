"""
Basic APK Analysis Example

This script demonstrates basic usage of the Android Persistence Analysis Framework.
It shows how to analyze a single APK file for persistence mechanisms.

DISCLAIMER: Use only for authorized security research and analysis. Unauthorized
analysis of applications without permission may violate laws and ethical standards.

Usage:
    python examples/basic_analysis.py path/to/your/app.apk
"""

import sys
import json
from pathlib import Path

# Add src directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.persistence_detector import PersistenceDetector
from src.report_generator import ReportGenerator
from src.defensive_mitigations import MitigationStrategies


def analyze_apk_basic(apk_path: str) -> None:
    """
    Perform basic APK analysis and generate report.
    
    Args:
        apk_path: Path to APK file to analyze
    """
    print("\n" + "="*70)
    print("ANDROID PERSISTENCE ANALYSIS - BASIC EXAMPLE")
    print("="*70 + "\n")

    # Initialize detector
    print("[*] Initializing detector...")
    detector = PersistenceDetector(log_level="INFO")

    # Analyze APK
    print(f"[*] Analyzing APK: {apk_path}")
    if not detector.analyze_apk(apk_path):
        print("[!] Analysis failed")
        return

    # Print findings summary
    detector.print_summary()

    # Get and display findings
    findings = detector.get_findings()
    if findings:
        print("\n[*] Detailed Findings:\n")
        for i, finding in enumerate(findings, 1):
            print(f"{i}. {finding.persistence_type.value.upper()}")
            print(f"   Component: {finding.component_name}")
            print(f"   Severity: {finding.severity.name}")
            print(f"   Description: {finding.description}")
            print(f"   Confidence: {finding.confidence}%")
            if finding.mitigations:
                print(f"   Mitigations:")
                for mitigation in finding.mitigations[:2]:
                    print(f"     - {mitigation}")
            print()

    # Generate reports
    print("\n[*] Generating reports...")
    generator = ReportGenerator(title=f"Analysis Report for {Path(apk_path).name}")
    generator.add_findings(findings)

    # Export as JSON
    json_output = Path("findings.json")
    if generator.generate_json_report(str(json_output)):
        print(f"[+] JSON report: {json_output}")

    # Export as HTML
    html_output = Path("findings.html")
    if generator.generate_html_report(str(html_output)):
        print(f"[+] HTML report: {html_output}")

    # Generate mitigation recommendations
    print("\n[*] Generating mitigation recommendations...")
    threats = [f.persistence_type.value for f in findings]
    mitigations = MitigationStrategies()
    print(mitigations.generate_mitigation_report(threats))


def example_with_mock_apk() -> None:
    """
    Run example with mock APK (for demonstration).
    
    This example creates a detector and analyzes it without a real APK file.
    """
    print("\n" + "="*70)
    print("ANDROID PERSISTENCE ANALYSIS - MOCK EXAMPLE")
    print("="*70 + "\n")

    # Initialize detector
    detector = PersistenceDetector(log_level="INFO")

    # Simulate APK analysis by manually adding findings
    print("[*] Simulating APK analysis...")
    
    detector._add_finding(
        component_name="com.example.BootReceiver",
        persistence_type="broadcast_receiver",
        severity="HIGH",
        description="Broadcast receiver responding to BOOT_COMPLETED",
        evidence={"action": "android.intent.action.BOOT_COMPLETED"},
        confidence=95,
    )

    detector._add_finding(
        component_name="com.example.PersistentService",
        persistence_type="service",
        severity="MEDIUM",
        description="Service with auto-start capability",
        evidence={"flags": "START_STICKY"},
        confidence=85,
    )

    # Print summary
    detector.print_summary()

    # Generate recommendations
    print("\n[*] Mitigation Recommendations:\n")
    mitigations = MitigationStrategies()
    for finding in detector.get_findings():
        threat_type = finding.persistence_type.value
        applicable_mitigations = mitigations.get_mitigations_for_threat(threat_type)
        
        if applicable_mitigations:
            print(f"For {threat_type}:")
            best = mitigations.get_highest_effectiveness_mitigation(threat_type)
            if best:
                print(f"  Best mitigation: {best.name}")
                print(f"  Effectiveness: {best.effectiveness}%")
            print()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Analyze provided APK
        apk_file = sys.argv[1]
        analyze_apk_basic(apk_file)
    else:
        # Run mock example
        print("No APK path provided. Running mock example...")
        example_with_mock_apk()
        
        print("\n[!] To analyze a real APK, run:")
        print("    python examples/basic_analysis.py /path/to/your/app.apk")
