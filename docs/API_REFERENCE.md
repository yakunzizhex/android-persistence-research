# API Reference

## Core Classes

### PersistenceDetector

Main persistence analysis engine.

#### Initialization

```python
from src.persistence_detector import PersistenceDetector

detector = PersistenceDetector(log_level: str = "INFO")
```

**Parameters**:
- `log_level` (str): Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)

#### Methods

##### analyze_apk

```python
def analyze_apk(self, apk_path: str) -> bool
```

Analyze an APK file for persistence mechanisms.

**Parameters**:
- `apk_path` (str): Path to APK file

**Returns**: `bool` - True if analysis succeeded

**Raises**:
- `FileNotFoundError`: If APK file doesn't exist
- `ValueError`: If file is not a valid APK

**Example**:
```python
if detector.analyze_apk("app.apk"):
    print("Analysis successful")
else:
    print("Analysis failed")
```

##### get_findings

```python
def get_findings(self) -> List[PersistenceFinding]
```

Get all detected findings.

**Returns**: `List[PersistenceFinding]` - List of findings

**Example**:
```python
findings = detector.get_findings()
for finding in findings:
    print(f"{finding.persistence_type.value}: {finding.component_name}")
```

##### get_risk_score

```python
def get_risk_score(self) -> float
```

Calculate overall risk score.

**Returns**: `float` - Risk score (0-100)

**Example**:
```python
score = detector.get_risk_score()
print(f"Risk: {score:.1f}/100")
```

##### export_findings_json

```python
def export_findings_json(self, output_path: str) -> bool
```

Export findings to JSON file.

**Parameters**:
- `output_path` (str): Output file path

**Returns**: `bool` - True if export succeeded

##### print_summary

```python
def print_summary(self) -> None
```

Print analysis summary to console.

---

### PersistenceFinding

Data class representing a persistence finding.

#### Attributes

```python
@dataclass
class PersistenceFinding:
    finding_id: str                    # Unique identifier
    app_name: str                      # Application name
    persistence_type: PersistenceType  # Type of persistence
    severity: SeverityLevel            # Risk severity
    component_name: str                # Component name
    description: str                   # Detailed description
    mitigations: List[str]            # Mitigation strategies
    evidence: Dict[str, Any]          # Supporting evidence
    confidence: int                    # Detection confidence (0-100)
    cve_references: List[str]         # Associated CVEs
```

#### Methods

##### to_dict

```python
def to_dict(self) -> Dict[str, Any]
```

Convert finding to dictionary.

**Returns**: `dict` - Dictionary representation

---

## Utility Classes

### ReportGenerator

Generate analysis reports in multiple formats.

#### Initialization

```python
from src.report_generator import ReportGenerator

generator = ReportGenerator(title: str = "Android Persistence Analysis Report")
```

#### Methods

##### add_findings

```python
def add_findings(self, findings: List[Any]) -> None
```

Add findings to report.

**Parameters**:
- `findings` (List): List of finding objects

##### generate_json_report

```python
def generate_json_report(self, output_path: str) -> bool
```

Generate JSON report.

**Parameters**:
- `output_path` (str): Output file path

**Returns**: `bool` - Success status

##### generate_html_report

```python
def generate_html_report(self, output_path: str) -> bool
```

Generate HTML report.

**Parameters**:
- `output_path` (str): Output file path

**Returns**: `bool` - Success status

##### generate_pdf_report

```python
def generate_pdf_report(self, output_path: str) -> bool
```

Generate PDF report (requires reportlab).

**Parameters**:
- `output_path` (str): Output file path

**Returns**: `bool` - Success status

---

### DataParser

Parse APK files and extract components.

#### Initialization

```python
from src.data_parser import DataParser

parser = DataParser(apk_path: str)
```

#### Methods

##### open

```python
def open(self) -> bool
```

Open and validate APK file.

**Returns**: `bool` - True if opened successfully

##### close

```python
def close(self) -> None
```

Close APK file.

##### get_metadata

```python
def get_metadata(self) -> Optional[APKMetadata]
```

Extract APK metadata.

**Returns**: `APKMetadata` or `None`

##### list_files

```python
def list_files(self, prefix: str = None) -> List[str]
```

List files in APK.

**Parameters**:
- `prefix` (str): Optional prefix filter

**Returns**: `List[str]` - File paths

##### extract_dex_files

```python
def extract_dex_files(self, output_dir: str = None) -> List[bytes]
```

Extract DEX files from APK.

**Parameters**:
- `output_dir` (str): Optional output directory

**Returns**: `List[bytes]` - DEX file contents

##### extract_native_libs

```python
def extract_native_libs(self, output_dir: str = None) -> Dict[str, bytes]
```

Extract native libraries.

**Parameters**:
- `output_dir` (str): Optional output directory

**Returns**: `Dict[str, bytes]` - Library paths and contents

---

### MitigationStrategies

Defensive mitigation recommendations.

#### Initialization

```python
from src.defensive_mitigations import MitigationStrategies

mitigations = MitigationStrategies()
```

#### Methods

##### get_mitigations_for_threat

```python
def get_mitigations_for_threat(self, threat_type: str) -> List[Mitigation]
```

Get mitigations for specific threat.

**Parameters**:
- `threat_type` (str): Threat type (e.g., 'broadcast_receiver')

**Returns**: `List[Mitigation]` - Applicable mitigations

**Example**:
```python
mitigations = strategy.get_mitigations_for_threat("broadcast_receiver")
for m in mitigations:
    print(f"{m.name}: {m.effectiveness}%")
```

##### get_highest_effectiveness_mitigation

```python
def get_highest_effectiveness_mitigation(self, threat_type: str) -> Optional[Mitigation]
```

Get most effective mitigation.

**Parameters**:
- `threat_type` (str): Threat type

**Returns**: `Mitigation` or `None`

##### generate_mitigation_report

```python
def generate_mitigation_report(self, threats: List[str]) -> str
```

Generate mitigation recommendations report.

**Parameters**:
- `threats` (List[str]): List of threat types

**Returns**: `str` - Formatted report

---

### SignatureMatcher

Pattern and signature matching.

#### Initialization

```python
from src.utils.signature_matcher import SignatureMatcher

matcher = SignatureMatcher()
```

#### Methods

##### match_signatures

```python
def match_signatures(self, data: str) -> List[Tuple[Signature, List[str]]]
```

Match signatures in data.

**Parameters**:
- `data` (str): Text data to analyze

**Returns**: `List[Tuple]` - (Signature, matches) tuples

##### get_risk_score

```python
def get_risk_score(self, matches: List[Tuple]) -> float
```

Calculate risk score from matches.

**Parameters**:
- `matches` (List): Matched signatures

**Returns**: `float` - Risk score (0-100)

##### generate_report

```python
def generate_report(self, matches: List[Tuple]) -> str
```

Generate signature report.

**Parameters**:
- `matches` (List): Matched signatures

**Returns**: `str` - Formatted report

---

### HexAnalyzer

Binary data analysis utilities.

#### Static Methods

##### hex_dump

```python
@staticmethod
def hex_dump(data: bytes, width: int = 16) -> str
```

Generate hex dump of binary data.

**Parameters**:
- `data` (bytes): Binary data
- `width` (int): Bytes per line

**Returns**: `str` - Formatted hex dump

##### find_pattern

```python
@staticmethod
def find_pattern(data: bytes, pattern: bytes, all_matches: bool = False) -> List[int]
```

Find pattern in data.

**Parameters**:
- `data` (bytes): Data to search
- `pattern` (bytes): Pattern to find
- `all_matches` (bool): Return all matches

**Returns**: `List[int]` - Offsets where pattern found

##### extract_strings

```python
@staticmethod
def extract_strings(data: bytes, min_length: int = 4) -> List[str]
```

Extract ASCII strings from binary.

**Parameters**:
- `data` (bytes): Binary data
- `min_length` (int): Minimum string length

**Returns**: `List[str]` - Extracted strings

---

## Enumerations

### PersistenceType

```python
class PersistenceType(Enum):
    BROADCAST_RECEIVER = "broadcast_receiver"
    SERVICE = "service"
    FOREGROUND_SERVICE = "foreground_service"
    STICKY_SERVICE = "sticky_service"
    JOB_SCHEDULER = "job_scheduler"
    WORK_MANAGER = "work_manager"
    ALARM_MANAGER = "alarm_manager"
    NATIVE_LIBRARY = "native_library"
    INTENT_FILTER = "intent_filter"
    BOOT_COMPLETION = "boot_completion"
    SYSTEM_HOOK = "system_hook"
    PROVIDER = "content_provider"
    UNKNOWN = "unknown"
```

### SeverityLevel

```python
class SeverityLevel(Enum):
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1
    NONE = 0
```

---

## Exception Handling

### Custom Exceptions

```python
try:
    detector.analyze_apk("app.apk")
except FileNotFoundError:
    print("APK file not found")
except ValueError:
    print("Invalid APK format")
except Exception as e:
    print(f"Analysis error: {e}")
```

---

## Code Examples

### Complete Workflow

```python
from src.persistence_detector import PersistenceDetector
from src.report_generator import ReportGenerator
from src.defensive_mitigations import MitigationStrategies

# Analyze
detector = PersistenceDetector()
detector.analyze_apk("myapp.apk")

# Generate report
generator = ReportGenerator("MyApp Analysis")
generator.add_findings(detector.get_findings())
generator.generate_json_report("report.json")
generator.generate_html_report("report.html")

# Get mitigations
mitigations = MitigationStrategies()
threats = [f.persistence_type.value for f in detector.get_findings()]
print(mitigations.generate_mitigation_report(threats))

# Display results
detector.print_summary()
print(f"Risk Score: {detector.get_risk_score():.1f}/100")
```

---

## Version

**Framework Version**: 1.0.0
**Last Updated**: 2024
**Python**: 3.10+
**License**: Apache-2.0
