# Usage Guide

## Quick Start

### Basic Analysis

```bash
python -m src.persistence_detector /path/to/app.apk
```

### Analyze with Report Export

```bash
python -m src.persistence_detector /path/to/app.apk -o findings.json
```

### Batch Analysis

```bash
python examples/batch_processing.py /path/to/apk/directory
```

## Command-Line Interface

### Syntax

```
python -m src.persistence_detector <apk_path> [OPTIONS]
```

### Options

| Option | Short | Description | Example |
|--------|-------|-------------|---------|
| `--output` | `-o` | Output JSON file | `-o findings.json` |
| `--verbose` | `-v` | Verbose output | `-v` |
| `--format` | `-f` | Report format (json/html/pdf) | `-f html` |
| `--config` | `-c` | Configuration file | `-c config.json` |

### Examples

**Verbose analysis with JSON output**:
```bash
python -m src.persistence_detector app.apk -o report.json -v
```

**Generate HTML report**:
```bash
python -m src.persistence_detector app.apk -f html -o report.html
```

## Python API Usage

### 1. Basic APK Analysis

```python
from src.persistence_detector import PersistenceDetector

# Initialize detector
detector = PersistenceDetector(log_level="INFO")

# Analyze APK
if detector.analyze_apk("myapp.apk"):
    # Get findings
    findings = detector.get_findings()
    
    # Display summary
    detector.print_summary()
    
    # Get risk score
    score = detector.get_risk_score()
    print(f"Risk Score: {score:.1f}/100")
```

### 2. Generate Reports

```python
from src.report_generator import ReportGenerator

# Create generator
generator = ReportGenerator(title="My App Analysis")
generator.add_findings(findings)

# Export to JSON
generator.generate_json_report("findings.json")

# Export to HTML
generator.generate_html_report("findings.html")

# Export to PDF (requires reportlab)
generator.generate_pdf_report("findings.pdf")
```

### 3. Get Mitigation Recommendations

```python
from src.defensive_mitigations import MitigationStrategies

mitigations = MitigationStrategies()

# Get mitigations for specific threat
threat_mitigations = mitigations.get_mitigations_for_threat("broadcast_receiver")

for mitigation in threat_mitigations:
    print(f"Name: {mitigation.name}")
    print(f"Effectiveness: {mitigation.effectiveness}%")
    print(f"Implementation: {mitigation.implementation}")
```

### 4. Data Parsing

```python
from src.data_parser import DataParser

# Initialize parser
parser = DataParser("myapp.apk")
parser.open()

# Get metadata
metadata = parser.get_metadata()
print(f"File size: {metadata.size} bytes")
print(f"DEX files: {metadata.dex_count}")
print(f"Native libs: {metadata.lib_count}")

# Extract components
dex_files = parser.extract_dex_files("output_dir/")
resources = parser.extract_resources("output_dir/resources/")
libraries = parser.extract_native_libs("output_dir/libs/")

parser.close()
```

### 5. Manifest Parsing

```python
from src.utils.manifest_parser import ManifestParser

parser = ManifestParser(manifest_data=manifest_bytes)
parser.parse()

# Get information
package = parser.get_package_name()
components = parser.get_components()
permissions = parser.get_permissions()
exported = parser.get_exported_components()
has_boot = parser.has_boot_receiver()
```

### 6. Signature Matching

```python
from src.utils.signature_matcher import SignatureMatcher

matcher = SignatureMatcher()

# Analyze code/manifest text
code_snippet = """
    startService(intent);
    registerReceiver(..., BOOT_COMPLETED);
"""

matches = matcher.match_signatures(code_snippet)

# Get risk score
risk_score = matcher.get_risk_score(matches)
print(f"Risk Score: {risk_score:.1f}/100")

# Generate report
report = matcher.generate_report(matches)
print(report)
```

### 7. Hex Analysis

```python
from src.utils.hex_analyzer import HexAnalyzer

# Binary data
data = b"\x50\x4b\x03\x04..." # ZIP header example

# Generate hex dump
dump = HexAnalyzer.hex_dump(data)
print(dump)

# Find patterns
matches = HexAnalyzer.find_pattern(data, b"\x50\x4b", all_matches=True)
print(f"Found ZIP headers at: {matches}")

# Extract strings
strings = HexAnalyzer.extract_strings(data, min_length=4)
for s in strings:
    print(f"String: {s}")

# Detect magic bytes
magic = HexAnalyzer.find_magic_bytes(data)
for offset, file_type, signature in magic:
    print(f"At {offset:#x}: {file_type}")
```

## Advanced Usage

### Custom Analysis Workflow

```python
from src.persistence_detector import PersistenceDetector
from src.data_parser import DataParser
from src.report_generator import ReportGenerator
from src.defensive_mitigations import MitigationStrategies

# Step 1: Parse APK
parser = DataParser("app.apk")
parser.open()
metadata = parser.get_metadata()
print(f"Analyzing {metadata.filename}")

# Step 2: Detect persistence
detector = PersistenceDetector()
detector.analyze_apk("app.apk")
findings = detector.get_findings()

# Step 3: Get mitigations
mitigations = MitigationStrategies()
threat_types = [f.persistence_type.value for f in findings]

# Step 4: Generate reports
generator = ReportGenerator()
generator.add_findings(findings)
generator.generate_json_report("analysis_result.json")
generator.print_summary()

# Step 5: Mitigation recommendations
print("\nMitigation Recommendations:")
for threat in threat_types:
    best = mitigations.get_highest_effectiveness_mitigation(threat)
    if best:
        print(f"{threat}: {best.name} ({best.effectiveness}%)")

parser.close()
```

### Batch Processing with Custom Filter

```python
from pathlib import Path
from src.persistence_detector import PersistenceDetector

def analyze_high_risk_apps(directory, min_risk_score=70):
    """Analyze only high-risk apps"""
    apk_files = Path(directory).glob("*.apk")
    high_risk_apps = []
    
    for apk_file in apk_files:
        detector = PersistenceDetector(log_level="WARNING")
        if detector.analyze_apk(str(apk_file)):
            score = detector.get_risk_score()
            if score >= min_risk_score:
                high_risk_apps.append({
                    "app": apk_file.name,
                    "score": score,
                    "findings": len(detector.get_findings())
                })
    
    return sorted(high_risk_apps, key=lambda x: x['score'], reverse=True)

# Usage
high_risk = analyze_high_risk_apps("apks/", min_risk_score=75)
for app in high_risk:
    print(f"{app['app']}: {app['score']:.1f} ({app['findings']} findings)")
```

## Output Formats

### JSON Output Structure

```json
{
  "apk_hash": "a1b2c3d4e5f6...",
  "total_findings": 3,
  "risk_score": 75.5,
  "findings": [
    {
      "finding_id": "abc123",
      "app_name": "sample_app",
      "persistence_type": "broadcast_receiver",
      "severity": "HIGH",
      "component_name": "com.example.BootReceiver",
      "description": "...",
      "confidence": 95,
      "mitigations": [...]
    }
  ]
}
```

### HTML Report Features

- Interactive findings table
- Severity color-coding
- Statistics dashboard
- Exportable summary

### PDF Report Contents

- Executive summary
- Risk metrics
- Detailed findings
- Recommendations
- Appendices

## Error Handling

### Common Error Messages

**"Invalid APK file format"**
```python
try:
    detector.analyze_apk("app.apk")
except ValueError as e:
    print(f"Invalid APK: {e}")
```

**"APK file not found"**
```python
from pathlib import Path

apk_path = "app.apk"
if not Path(apk_path).exists():
    print(f"File not found: {apk_path}")
```

**"Module not found"**
```bash
pip install --upgrade androguard
```

## Performance Tips

1. **Use verbose=False** for faster analysis:
   ```python
   detector = PersistenceDetector(log_level="WARNING")
   ```

2. **Cache results** for batch operations:
   ```python
   import json
   results = {}
   for apk in apks:
       detector.analyze_apk(apk)
       results[apk] = detector.get_findings()
   ```

3. **Use WorkManager instead of Services** for modern apps

4. **Limit analysis scope** for large APK files

## Best Practices

✅ **DO**:
- Use explicit intents
- Implement proper permission checks
- Regular security audits
- Keep dependencies updated
- Test on representative APK samples

❌ **DON'T**:
- Analyze without authorization
- Use implicit intents
- Export unnecessary components
- Ignore warnings
- Run analysis on untrusted APKs without sandboxing

## Next Steps

- Review [API_REFERENCE.md](API_REFERENCE.md) for detailed API docs
- Check [RESEARCH_METHODOLOGY.md](RESEARCH_METHODOLOGY.md) for research approach
- Explore [examples/](../examples/) for more code samples
