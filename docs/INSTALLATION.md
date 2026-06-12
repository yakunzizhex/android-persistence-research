# Installation Guide

## Prerequisites

- **Python**: 3.10 or higher
- **pip**: Package manager for Python
- **Virtual Environment**: Recommended (venv or conda)
- **Git**: For cloning the repository

## System Requirements

### Minimum
- CPU: Dual-core processor
- RAM: 2GB
- Disk Space: 500MB
- OS: Linux, macOS, or Windows

### Recommended
- CPU: Quad-core processor
- RAM: 8GB+
- Disk Space: 5GB
- OS: Linux (Ubuntu 20.04 LTS or higher)

## Installation Methods

### 1. From Source (Development)

**Clone the repository**:
```bash
git clone https://github.com/yourusername/android-persistence-analysis.git
cd android-persistence-analysis
```

**Create virtual environment**:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

**Install dependencies**:
```bash
pip install -r requirements.txt
pip install -e .  # Install in editable mode
```

**Verify installation**:
```bash
python -m pytest tests/ -v
```

### 2. From PyPI (When Available)

```bash
pip install android-persistence-analysis
```

### 3. Docker Installation

**Build Docker image**:
```bash
docker build -t android-persistence-analysis .
```

**Run in container**:
```bash
docker run -it -v /path/to/apks:/data android-persistence-analysis
python -m src.persistence_detector /data/sample.apk
```

## Dependency Installation

### Core Dependencies

**androguard** (APK analysis)
```bash
pip install androguard==4.1.2
```

**capstone** (Disassembly)
```bash
pip install capstone==5.0.1
```

**pycryptodomex** (Cryptography)
```bash
pip install pycryptodomex==3.20.0
```

**requests** (HTTP client)
```bash
pip install requests==2.31.0
```

### Optional Dependencies

**reportlab** (PDF generation)
```bash
pip install reportlab==4.0.7
```

**pytest** (Testing)
```bash
pip install pytest==7.4.3 pytest-cov==4.1.0
```

## Troubleshooting

### Issue: "ModuleNotFoundError: No module named 'androguard'"

**Solution**:
```bash
pip install --upgrade androguard
# If still failing, install from source:
git clone https://github.com/androguard/androguard.git
cd androguard
pip install -e .
```

### Issue: Python version incompatibility

**Solution**: Upgrade Python
```bash
python3 --version  # Check current version
# If < 3.10, upgrade:
# Ubuntu/Debian:
sudo apt update && sudo apt install python3.11

# macOS:
brew install python@3.11
```

### Issue: Virtual environment not activating

**Solution**:
```bash
# Linux/macOS:
source venv/bin/activate

# Windows (PowerShell):
.\venv\Scripts\Activate.ps1

# Windows (CMD):
venv\Scripts\activate.bat
```

### Issue: Permission denied on Linux

**Solution**:
```bash
# Install for current user only:
pip install --user -r requirements.txt

# Or use sudo (not recommended):
sudo pip install -r requirements.txt
```

## Verification

Test the installation with the provided examples:

```bash
# Basic analysis with mock data
python examples/basic_analysis.py

# Run unit tests
pytest tests/ -v

# Check version
python -c "import src; print(src.__version__)"
```

## Next Steps

- Read [USAGE.md](USAGE.md) for usage instructions
- Review [API_REFERENCE.md](API_REFERENCE.md) for detailed API documentation
- Check [examples/](../examples/) for more usage examples
