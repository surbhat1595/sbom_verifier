# 🛡️ SBOM Verifier

> A comprehensive Software Bill of Materials (SBOM) verification toolkit that validates SBOM files for compliance, security vulnerabilities, and data quality using Snyk and industry-standard tools.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Shell Script](https://img.shields.io/badge/Shell-Bash-green.svg)](https://www.gnu.org/software/bash/)
[![Snyk](https://img.shields.io/badge/Security-Snyk-purple.svg)](https://snyk.io/)

## ✨ Features

- 🔍 **Multi-format Support**: SPDX (JSON, XML, Tag-Value), CycloneDX (JSON, XML)
- 🛡️ **Security Scanning**: Integration with Snyk for vulnerability detection
- 📄 **License Compliance**: Automated license policy checking
- ✅ **Format Validation**: Schema and structure verification
- 📊 **Content Analysis**: Component completeness and quality assessment
- 🌍 **Cross-platform**: Ubuntu, Debian, RHEL, CentOS, Fedora, Rocky Linux, AlmaLinux, Amazon Linux
- 🔧 **Flexible Authentication**: CLI args, environment variables, or interactive auth
- 🎯 **Organization Support**: Multi-tenant Snyk organization handling

## 🚀 Quick Start

### One-Line Installation

```bash
# Download and install everything automatically
curl -fsSL https://raw.githubusercontent.com/EvgeniyPatlan/sbom_verifier/main/install_sbom_verifier.sh | bash
```

### Manual Installation

<details>
<summary>📋 Click to expand manual installation instructions</summary>

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install -y curl wget jq libxml2-utils file
curl -fsSL https://deb.nodesource.com/setup_lts.x -o setup_nodejs.sh
sudo bash setup_nodejs.sh && rm setup_nodejs.sh
sudo apt install -y nodejs
sudo npm install -g snyk
```

#### RHEL/CentOS/Fedora
```bash
sudo dnf install -y curl wget jq libxml2 file  # or 'yum' for older systems
curl -fsSL https://rpm.nodesource.com/setup_lts.x -o setup_nodejs.sh
sudo bash setup_nodejs.sh && rm setup_nodejs.sh
sudo dnf install -y nodejs
sudo npm install -g snyk
```

#### Download Scripts
```bash
wget https://raw.githubusercontent.com/EvgeniyPatlan/sbom_verifier/main/sbom_verifier.sh
chmod +x sbom_verifier.sh
sudo mv sbom_verifier.sh /usr/local/bin/
```

</details>

### Authentication Setup

Choose your preferred authentication method:

#### Method 1: Environment Variables (Recommended for CI/CD)
```bash
export SNYK_TOKEN="your-api-token-here"
export SNYK_ORG="your-organization-id"
```

#### Method 2: Command Line Arguments
```bash
sbom_verifier.sh --snyk-token="your-token" --snyk-org="your-org" sbom.json
```

#### Method 3: Interactive Authentication
```bash
snyk auth
```

> 💡 **Get your token**: Visit [Snyk Account Settings](https://app.snyk.io/account) to generate an API token

## 📖 Usage

### Basic Usage

```bash
# Verify an SBOM file
sbom_verifier.sh sbom.json

# With verbose output
sbom_verifier.sh --verbose sbom.json

# Show help
sbom_verifier.sh --help
```

### Advanced Usage

```bash
# With Snyk authentication
sbom_verifier.sh --snyk-token="abc123" --snyk-org="my-org" sbom.json

# Short form flags
sbom_verifier.sh -t "abc123" -o "my-org" -v sbom.json

# Using environment variables
export SNYK_TOKEN="abc123" SNYK_ORG="my-org"
sbom_verifier.sh sbom.json
```

### Real-World Examples

<details>
<summary>🎯 Example: Successful SPDX Verification</summary>

```bash
$ sbom_verifier.sh my-app-sbom.spdx.json

SBOM Verification Script
========================

[INFO] Checking dependencies...
[SUCCESS] Snyk CLI found
[SUCCESS] jq found
[SUCCESS] xmllint found
[SUCCESS] Dependency check completed
[INFO] Checking Snyk authentication...
[SUCCESS] Snyk authentication verified via token
[INFO] Verifying file integrity...
[SUCCESS] File integrity check passed
[INFO] Detected format: spdx-json
[INFO] Verifying JSON format...
[INFO] Validating SPDX JSON format...
[INFO] Found 45 packages
[INFO] Found 12 relationships
[SUCCESS] JSON format validation passed
[INFO] Verifying SBOM with Snyk...
[INFO] Using Snyk SBOM command...
[SUCCESS] Snyk SBOM verification passed
[INFO] Found 2 vulnerabilities
[INFO] Found 1 license issues
[WARNING] Vulnerabilities found in SBOM components
[INFO] Analyzing SBOM content...
[INFO] Total components: 45
[INFO] Components with versions: 43
[INFO] Components with licenses: 38
[SUCCESS] Content analysis completed

📊 SBOM Verification Report
==========================
File: my-app-sbom.spdx.json
Format: spdx-json
Timestamp: Thu Jul 10 15:30:25 UTC 2025

Results:
  ✅ Errors: 0
  ⚠  Warnings: 2
  ℹ  Info: 12

✅ SBOM verification PASSED
```

</details>

<details>
<summary>❌ Example: Failed Verification</summary>

```bash
$ sbom_verifier.sh invalid-sbom.json

SBOM Verification Script
========================

[INFO] Checking dependencies...
[SUCCESS] Dependency check completed
[WARNING] Snyk not authenticated. Some features may be limited.
[INFO] Verifying file integrity...
[SUCCESS] File integrity check passed
[INFO] Detected format: spdx-json
[INFO] Verifying JSON format...
[INFO] Validating SPDX JSON format...
[ERROR] Missing required field: spdxVersion
[ERROR] Invalid JSON syntax

📊 SBOM Verification Report
==========================
File: invalid-sbom.json
Format: spdx-json
Timestamp: Thu Jul 10 15:35:12 UTC 2025

Results:
  ✅ Errors: 2
  ⚠  Warnings: 1
  ℹ  Info: 8

❌ SBOM verification FAILED
```

</details>

## 📋 Command Line Reference

### 🔧 Options

| Option | Short | Description | Example |
|--------|-------|-------------|---------|
| `--verbose` | `-v` | Enable detailed output | `-v` |
| `--snyk-token` | `-t` | Set Snyk API token | `-t abc123` |
| `--snyk-org` | `-o` | Set Snyk organization | `-o my-org` |
| `--help` | `-h` | Show help message | `-h` |

### 📁 Supported SBOM Formats

| Format | File Extensions | Schema Validation | Content Analysis |
|--------|----------------|-------------------|------------------|
| **SPDX JSON** | `.spdx.json`, `.json` | ✅ Full | ✅ Full |
| **SPDX XML** | `.spdx.xml`, `.xml` | ✅ Full | ⚠️ Basic |
| **SPDX Tag-Value** | `.spdx`, `.txt` | ⚠️ Basic | ⚠️ Basic |
| **CycloneDX JSON** | `.json` | ✅ Full | ✅ Full |
| **CycloneDX XML** | `.xml` | ✅ Full | ⚠️ Basic |

**Legend**: ✅ Full support, ⚠️ Basic support

## 🔍 What Gets Verified

### 🛡️ Security Analysis (via Snyk)
- ✅ Known vulnerability detection
- ✅ License policy compliance
- ✅ Dependency security scoring
- ✅ Supply chain risk assessment

### 📝 Format Compliance
- ✅ **SPDX**: Required fields (`spdxVersion`, `SPDXID`, `creationInfo`, `name`)
- ✅ **CycloneDX**: Required fields (`specVersion`, `version`)
- ✅ Schema structure verification
- ✅ Field format validation (IDs, versions, etc.)

### 📊 Content Quality
- ✅ Component version information completeness
- ✅ License data availability
- ✅ Relationship mapping accuracy
- ✅ Metadata quality assessment

### 🗂️ File Integrity
- ✅ File existence and readability
- ✅ File size validation
- ✅ UTF-8 encoding verification
- ✅ Basic syntax validation

## 🔐 Authentication Methods

### Priority Order (Highest to Lowest)

1. **🎯 Command Line Arguments**
   ```bash
   sbom_verifier.sh --snyk-token="cli-token" --snyk-org="cli-org" sbom.json
   ```

2. **🌍 Environment Variables**
   ```bash
   export SNYK_TOKEN="env-token"
   export SNYK_ORG="env-org"
   sbom_verifier.sh sbom.json
   ```

3. **🔑 Existing Snyk Authentication**
   ```bash
   snyk auth  # Interactive browser authentication
   sbom_verifier.sh sbom.json
   ```

### 🏢 Organization Support

```bash
# Specify organization via CLI
sbom_verifier.sh --snyk-org="production-team" sbom.json

# Or via environment
export SNYK_ORG="production-team"
sbom_verifier.sh sbom.json

# View available organizations
snyk organizations
```

## 🚀 CI/CD Integration

### GitHub Actions

```yaml
name: SBOM Verification
on: [push, pull_request]

jobs:
  verify-sbom:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4

    - name: Install SBOM Verifier
      run: |
        curl -fsSL https://raw.githubusercontent.com/EvgeniyPatlan/sbom_verifier/main/install_sbom_verifier.sh | bash

    - name: Verify SBOM
      env:
        SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        SNYK_ORG: ${{ vars.SNYK_ORG }}
      run: |
        sbom_verifier.sh artifacts/sbom.json
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    environment {
        SNYK_TOKEN = credentials('snyk-token')
        SNYK_ORG = 'production-team'
    }
    stages {
        stage('Install') {
            steps {
                sh 'curl -fsSL https://raw.githubusercontent.com/EvgeniyPatlan/sbom_verifier/refs/heads/main/install_sbom_verifier.sh | bash'
            }
        }
        stage('Verify SBOM') {
            steps {
                sh 'sbom_verifier.sh artifacts/sbom.json'
            }
        }
    }
}
```

### GitLab CI

```yaml
sbom-verification:
  stage: verify
  variables:
    SNYK_ORG: "production-team"
  before_script:
    - curl -fsSL https://raw.githubusercontent.com/EvgeniyPatlan/sbom_verifier/refs/heads/main/install_sbom_verifier.sh | bash
    - export SNYK_TOKEN=$SNYK_TOKEN_SECRET
  script:
    - sbom_verifier.sh sbom.json
```

### Docker Integration

```dockerfile
FROM ubuntu:22.04

# Install SBOM verifier
RUN curl -fsSL https://raw.githubusercontent.com/EvgeniyPatlan/sbom_verifier/refs/heads/main/sbom_verifier.sh | bash

# Set up environment
ENV SNYK_TOKEN=""
ENV SNYK_ORG=""

# Copy your SBOM
COPY sbom.json /app/sbom.json

# Verify on container start
ENTRYPOINT ["sbom_verifier.sh"]
CMD ["/app/sbom.json"]
```

```bash
# Run with authentication
docker run -e SNYK_TOKEN="$SNYK_TOKEN" -e SNYK_ORG="my-org" \
  -v $(pwd)/sbom.json:/app/sbom.json \
  my-sbom-verifier /app/sbom.json
```

## 🛠️ Installation Script Features

The `install_sbom_verifier.sh` script provides automated installation:

### 🎯 Options

```bash
# Basic installation
./install_sbom_verifier.sh

# Verbose installation (shows detailed progress)
./install_sbom_verifier.sh --verbose

# Debug mode (shows all commands)
./install_sbom_verifier.sh --debug

# Force reinstallation
./install_sbom_verifier.sh --force

# Show help
./install_sbom_verifier.sh --help
```

### 🖥️ Supported Operating Systems

| OS Family | Versions | Package Manager | Status |
|-----------|----------|-----------------|--------|
| **Ubuntu** | 18.04+ | apt | ✅ Fully Tested |
| **Debian** | 9+ | apt | ✅ Fully Tested |
| **RHEL** | 7+ | yum/dnf | ✅ Fully Tested |
| **CentOS** | 7+ | yum/dnf | ✅ Fully Tested |
| **Rocky Linux** | 8+ | dnf | ✅ Fully Tested |
| **AlmaLinux** | 8+ | dnf | ✅ Fully Tested |
| **Fedora** | 30+ | dnf | ✅ Fully Tested |
| **Amazon Linux** | 2 | yum | ✅ Fully Tested |

### 🔧 What Gets Installed

1. **📦 System Packages**: `curl`, `wget`, `jq`, `libxml2-utils`/`libxml2`, `file`
2. **🟢 Node.js & npm**: Latest LTS via NodeSource repository
3. **🛡️ Snyk CLI**: Via npm (with binary fallback)
4. **📝 SBOM Verifier**: Main verification script to `/usr/local/bin`
5. **✅ Verification**: Tests all installations to ensure they work

## 🔧 Advanced Usage

### 📊 Batch Processing

```bash
# Verify multiple SBOM files
for sbom in *.json; do
    echo "Verifying $sbom..."
    sbom_verifier.sh "$sbom" || echo "Failed: $sbom"
done

# Generate report for all SBOMs
find . -name "*.spdx.json" -exec sbom_verifier.sh {} \; > verification_report.txt
```

### 🐳 Container Scanning

```bash
# Extract SBOM from container and verify
docker run --rm my-app:latest cat /app/sbom.json > container-sbom.json
sbom_verifier.sh container-sbom.json

# Verify as part of container build
COPY sbom.json /tmp/sbom.json
RUN sbom_verifier.sh /tmp/sbom.json
```

### 🔄 Automated Workflows

```bash
#!/bin/bash
# automated-sbom-check.sh

set -euo pipefail

# Configuration
SBOM_DIR="./artifacts"
REPORT_DIR="./reports"
SNYK_ORG="production"

mkdir -p "$REPORT_DIR"

echo "Starting automated SBOM verification..."

for sbom in "$SBOM_DIR"/*.json; do
    filename=$(basename "$sbom")
    report_file="$REPORT_DIR/${filename%.*}-report.txt"

    echo "Verifying $filename..."

    if sbom_verifier.sh --snyk-org="$SNYK_ORG" "$sbom" > "$report_file" 2>&1; then
        echo "✅ $filename: PASSED"
    else
        echo "❌ $filename: FAILED (see $report_file)"
    fi
done

echo "Verification complete. Reports in $REPORT_DIR/"
```

## 🔧 Configuration

### 🌍 Environment Variables

```bash
# Core authentication
export SNYK_TOKEN="your-api-token"
export SNYK_ORG="your-organization-id"

# Optional configuration
export SBOM_VERBOSE=true              # Enable verbose by default
export SBOM_INSTALL_DIR="/custom/path" # Custom installation directory

# Snyk-specific configuration
export SNYK_API="https://snyk.io/api"  # Custom API endpoint
export SNYK_DISABLE_ANALYTICS=true     # Disable usage analytics
```

### ⚙️ Snyk Configuration

```bash
# View current configuration
snyk config list

# Set organization (if using Snyk Teams/Enterprise)
snyk config set org=your-org-id

# Set custom API endpoint (for on-premise Snyk)
snyk config set endpoint=https://your-snyk-instance.com

# Configure proxy settings
snyk config set proxy=http://proxy.company.com:8080
```

## 🛠️ Troubleshooting

### ❓ Common Issues

<details>
<summary>🔑 Snyk Authentication Failed</summary>

**Problem**: `Snyk not authenticated` error

**Solutions**:
```bash
# Method 1: Use token directly
sbom_verifier.sh --snyk-token="your-token" sbom.json

# Method 2: Set environment variable
export SNYK_TOKEN="your-token"
sbom_verifier.sh sbom.json

# Method 3: Interactive authentication
snyk auth

# Method 4: Verify token is valid
snyk auth --check
```

</details>

<details>
<summary>📦 jq Command Not Found</summary>

**Problem**: `jq not found` warning

**Solutions**:
```bash
# Ubuntu/Debian
sudo apt install jq

# RHEL/CentOS/Fedora
sudo dnf install jq  # or sudo yum install jq

# macOS
brew install jq

# Manual installation
curl -Lo /usr/local/bin/jq https://github.com/stedolan/jq/releases/latest/download/jq-linux64
chmod +x /usr/local/bin/jq
```

</details>

<details>
<summary>🔒 Permission Denied</summary>

**Problem**: Script cannot execute

**Solutions**:
```bash
# Make script executable
chmod +x sbom_verifier.sh

# Or run with bash
bash sbom_verifier.sh sbom.json

# Check file permissions
ls -la sbom_verifier.sh
```

</details>

<details>
<summary>🌐 Node.js Installation Failed</summary>

**Problem**: NodeSource repository issues

**Solutions**:
```bash
# Alternative: Install via package manager
# Ubuntu/Debian
sudo apt install nodejs npm

# RHEL/CentOS/Fedora
sudo dnf install nodejs npm

# Alternative: Use snap
sudo snap install node --classic

# Alternative: Direct Snyk binary installation
curl -Lo /usr/local/bin/snyk https://github.com/snyk/snyk/releases/latest/download/snyk-linux
chmod +x /usr/local/bin/snyk
```

</details>

### 🐞 Debug Mode

```bash
# Enable debug output for installation
./install_sbom_verifier.sh --debug

# Enable debug output for verification
bash -x sbom_verifier.sh sbom.json

# Check what Snyk sees
snyk --debug test --file=sbom.json
```

### 📋 Support Information

When reporting issues, please include:

```bash
# System information
uname -a
cat /etc/os-release

# Tool versions
sbom_verifier.sh --help
snyk --version
jq --version
node --version

# Error output
sbom_verifier.sh --verbose problematic-sbom.json 2>&1
```

## 📚 Examples Repository

Check out our [examples repository](https://github.com/EvgeniyPatlan/sbom-examples) for:

- 📄 Sample SBOM files in various formats
- 🔧 Configuration templates
- 🚀 CI/CD pipeline examples
- 📊 Custom validation rules
- 🐳 Docker integration examples

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### 🔄 Development Setup

```bash
# Clone the repository
git clone https://github.com/EvgeniyPatlan/sbom_verifier.git
cd sbom_verifier

# Run tests
./test/run_tests.sh

# Test installation script
./test/test_installation.sh

# Test verifier with sample files
./test/test_verification.sh
```

### 🧪 Testing

```bash
# Test on different OS (using Docker)
docker run -v $(pwd):/app ubuntu:22.04 /app/install_sbom_verifier.sh
docker run -v $(pwd):/app centos:8 /app/install_sbom_verifier.sh

# Test with sample SBOMs
./sbom_verifier.sh test/fixtures/sample.spdx.json
./sbom_verifier.sh test/fixtures/sample.cyclonedx.json
```

## 🔒 Security Considerations

- **🔑 Token Security**: Store Snyk tokens securely, never commit to version control
- **📁 SBOM Privacy**: SBOM files may contain sensitive dependency information
- **🌐 Network Access**: Required for Snyk API calls and vulnerability database updates
- **👤 Permissions**: Installation requires sudo, verification does not

## 🙏 Acknowledgments

- **🛡️ Snyk** for providing security scanning capabilities
- **📋 SPDX Community** for SBOM standards and tooling
- **🔄 CycloneDX Community** for SBOM standards and formats
- **👥 Contributors** and users of this tool

---

<div align="center">

**🛡️ Keep your software supply chain secure with SBOM Verifier!**

Made with ❤️ for the community

[⭐ Star us on GitHub](https://github.com/EvgeniyPatlan/sbom_verifier) • [🍴 Fork](https://github.com/EvgeniyPatlan/sbom_verifier/fork) • [📝 Report Issue](https://github.com/EvgeniyPatlan/sbom_verifier/issues/new)

</div>
