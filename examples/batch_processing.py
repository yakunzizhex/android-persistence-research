"""
Batch APK Processing Example

This script demonstrates batch processing of multiple APK files, suitable for
analyzing collections of apps or APK repositories.

DISCLAIMER: Use only for authorized security research. Batch analysis must be
performed only on systems where you have proper authorization.

Features:
- Process multiple APKs in a directory
- Generate summary statistics across all APKs
- Export aggregate findings
- Identify common persistence patterns
"""

import sys
import json
from pathlib import Path
from typing import List, Dict
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.persistence_detector import PersistenceDetector
from src.report_generator import ReportGenerator


class BatchAnalyzer:
    """
    Batch analyzer for processing multiple APK files.
    """

    def __init__(self, output_dir: str = "batch_results"):
        """
        Initialize batch analyzer.
        
        Args:
            output_dir: Directory to store results
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.results: List[Dict] = []
        self.statistics = defaultdict(int)

    def analyze_directory(self, directory: str, pattern: str = "*.apk") -> None:
        """
        Analyze all APK files in a directory.
        
        Args:
            directory: Path to directory containing APKs
            pattern: File pattern to match (default: *.apk)
        """
        apk_dir = Path(directory)
        if not apk_dir.exists():
            print(f"[!] Directory not found: {directory}")
            return

        apk_files = list(apk_dir.glob(pattern))
        print(f"\n[*] Found {len(apk_files)} APK files to analyze\n")

        for i, apk_file in enumerate(apk_files, 1):
            print(f"[{i}/{len(apk_files)}] Analyzing: {apk_file.name}")
            self._analyze_single_apk(str(apk_file))

        self._generate_aggregate_report()

    def _analyze_single_apk(self, apk_path: str) -> None:
        """
        Analyze a single APK file.
        
        Args:
            apk_path: Path to APK file
        """
        try:
            detector = PersistenceDetector(log_level="WARNING")
            
            if detector.analyze_apk(apk_path):
                findings = detector.get_findings()
                
                result = {
                    "apk": Path(apk_path).name,
                    "path": apk_path,
                    "findings_count": len(findings),
                    "risk_score": detector.get_risk_score(),
                    "findings": [f.to_dict() for f in findings],
                }
                
                self.results.append(result)
                
                # Update statistics
                for finding in findings:
                    self.statistics[finding.persistence_type.value] += 1
                
                print(f"  [+] Found {len(findings)} findings (Risk: {result['risk_score']:.1f})")
            else:
                print(f"  [!] Analysis failed")
        except Exception as e:
            print(f"  [!] Error: {str(e)}")

    def _generate_aggregate_report(self) -> None:
        """Generate aggregate report for all analyzed APKs."""
        print("\n" + "="*70)
        print("BATCH ANALYSIS SUMMARY")
        print("="*70)

        if not self.results:
            print("[!] No results to report")
            return

        total_apks = len(self.results)
        total_findings = sum(r["findings_count"] for r in self.results)
        avg_risk = sum(r["risk_score"] for r in self.results) / total_apks

        print(f"\nTotal APKs analyzed: {total_apks}")
        print(f"Total findings: {total_findings}")
        print(f"Average risk score: {avg_risk:.1f}/100")

        print("\nFindings Distribution:")
        for ptype, count in sorted(
            self.statistics.items(),
            key=lambda x: x[1],
            reverse=True
        ):
            percentage = (count / total_findings * 100) if total_findings > 0 else 0
            print(f"  {ptype}: {count} ({percentage:.1f}%)")

        # High-risk APKs
        high_risk = [r for r in self.results if r["risk_score"] >= 70]
        if high_risk:
            print(f"\nHigh-Risk APKs ({len(high_risk)}):")
            for result in sorted(high_risk, key=lambda x: x["risk_score"], reverse=True):
                print(f"  {result['apk']}: {result['risk_score']:.1f}")

        # Export results
        self._export_results()

    def _export_results(self) -> None:
        """Export batch analysis results."""
        # JSON export
        json_path = self.output_dir / "batch_findings.json"
        with open(json_path, 'w') as f:
            json.dump({
                "total_apks": len(self.results),
                "total_findings": sum(r["findings_count"] for r in self.results),
                "statistics": dict(self.statistics),
                "results": self.results,
            }, f, indent=2)

        print(f"\n[+] Results exported to: {json_path}")

        # Summary CSV
        csv_path = self.output_dir / "summary.csv"
        with open(csv_path, 'w') as f:
            f.write("APK Name,Findings Count,Risk Score\n")
            for result in self.results:
                f.write(f"{result['apk']},{result['findings_count']},{result['risk_score']:.1f}\n")

        print(f"[+] Summary exported to: {csv_path}")


def example_batch_analysis() -> None:
    """Run batch analysis example with mock data."""
    print("\n" + "="*70)
    print("BATCH ANALYSIS EXAMPLE - Mock Data")
    print("="*70 + "\n")

    analyzer = BatchAnalyzer()

    # Simulate analyzing multiple APKs
    mock_apks = [
        ("app1.apk", 3, 65.5),
        ("app2.apk", 5, 78.2),
        ("app3.apk", 2, 45.3),
        ("app4.apk", 7, 82.1),
    ]

    for apk_name, findings_count, risk_score in mock_apks:
        print(f"Analyzing: {apk_name}")
        
        detector = PersistenceDetector()
        for i in range(findings_count):
            detector._add_finding(
                component_name=f"Component{i}",
                persistence_type="service" if i % 2 == 0 else "broadcast_receiver",
                severity="HIGH" if risk_score > 70 else "MEDIUM",
                description=f"Finding {i}",
            )

        analyzer.results.append({
            "apk": apk_name,
            "path": f"/path/to/{apk_name}",
            "findings_count": findings_count,
            "risk_score": risk_score,
            "findings": [f.to_dict() for f in detector.get_findings()],
        })

        for finding in detector.get_findings():
            analyzer.statistics[finding.persistence_type.value] += 1

        print(f"  [+] Found {findings_count} findings (Risk: {risk_score:.1f})")

    analyzer._generate_aggregate_report()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        directory = sys.argv[1]
        analyzer = BatchAnalyzer()
        analyzer.analyze_directory(directory)
    else:
        print("No directory provided. Running example with mock data...")
        example_batch_analysis()
        print("\n[!] To analyze APKs in a directory, run:")
        print("    python examples/batch_processing.py /path/to/apk/directory")
