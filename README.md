# 🛡️ SBOM Verifier with Trivy

> A comprehensive Software Bill of Materials (SBOM) verification toolkit that validates SBOM files for compliance, security vulnerabilities, and data quality using Trivy, Snyk, and industry-standard tools.

[![Shell Script](https://img.shields.io/badge/Shell-Bash-green.svg)](https://www.gnu.org/software/bash/)
[![Trivy](https://img.shields.io/badge/Security-Trivy-blue.svg)](https://trivy.dev/)
[![Snyk](https://img.shields.io/badge/Security-Snyk-purple.svg)](https://snyk.io/)

## ✨ Features

- 🔍 **Multi-format Support**: SPDX (JSON, XML, Tag-Value), CycloneDX (JSON, XML)
- 🛡️ **Dual Security Scanning**: Integration with Trivy and Snyk for comprehensive vulnerability detection
- 🚀 **Trivy Integration**: Fast, comprehensive vulnerability scanning with extensive database coverage
- 🔐 **License Compliance**: Automated license policy checking and detection
- ✅ **Format Validation**: Schema and structure verification
- 📊 **Content Analysis**: Component completeness and quality assessment
- 🌍 **Cross-platform**: Ubuntu, Debian, RHEL, CentOS, Fedora, Rocky Linux, AlmaLinux, Amazon Linux, Oracle Linux
- 🔧 **Flexible Authentication**: CLI args, environment variables, or interactive auth
- 🎯 **Tool Selection**: Run with Trivy only, Snyk only, or both tools
- ⚡ **Performance Options**: Skip database updates for faster execution

## 🚀 Quick Start

### One-Line Installation

```bash
# Download and install everything automatically (Trivy + Snyk + dependencies)
curl -fsSL https://raw.githubusercontent.com/EvgeniyPatlan/sbom_verifier/main/install_sbom_verifier.sh | bash

# Install only Trivy and basic tools (faster, no Node.js/Snyk)
curl -fsSL https://raw.githubusercontent.com/EvgeniyPatlan/sbom_verifier/main/install_sbom_verifier.sh | bash -s -- --trivy-only
```

### Manual Installation

<details>
<summary>📋 Click to expand manual installation instructions</summary>

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install -y curl wget jq libxml2-utils file software-properties-common

# Install Trivy
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt update && sudo apt install -y trivy

# Optional: Install Snyk
curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
sudo apt install -y nodejs
sudo npm install -g snyk
```

#### RHEL/CentOS/Fedora/Oracle Linux
```bash
sudo dnf install -y curl wget jq libxml2 file  # or 'yum' for older systems

# Install Trivy
sudo tee /etc/yum.repos.d/trivy.repo << 'EOF'
[trivy]
name=Trivy repository
baseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/$releasever/$basearch/
gpgcheck=1
enabled=1
gpgkey=https://aquasecurity.github.io/trivy-repo/rpm/public.key
EOF
sudo dnf install -y trivy

# Optional: Install Snyk
curl -fsSL https://rpm.nodesource.com/setup_lts.x | sudo bash -
sudo dnf install -y nodejs
sudo npm install -g snyk
```

#### Download Scripts
```bash
wget https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/main/sbom_verifier.sh
chmod +x sbom_verifier.sh
sudo mv sbom_verifier.sh /usr/local/bin/
```

</details>

### Authentication Setup (Optional for Snyk)

Trivy requires no authentication, but Snyk needs setup if you want to use both tools:

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
# Verify an SBOM file with both Trivy and Snyk
sbom_verifier.sh sbom.json

# Use only Trivy (no authentication needed)
sbom_verifier.sh --trivy-only sbom.json

# Use only Snyk
sbom_verifier.sh --snyk-only sbom.json

# With verbose output
sbom_verifier.sh --verbose sbom.json

# Skip Trivy database update for faster execution
sbom_verifier.sh --skip-trivy-update sbom.json

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

# Trivy-only with verbose output (great for CI/CD)
sbom_verifier.sh --trivy-only --verbose sbom.json
```

### Real-World Examples

<details>
<summary>🎯 Example: Successful Trivy + Snyk Verification</summary>

```bash
$ sbom_verifier.sh --verbose my-app-sbom.spdx.json

SBOM Verification Script
========================
Running in verbose mode...

[INFO] Checking dependencies...
[SUCCESS] Snyk CLI found (1.1291.0)
[SUCCESS] Trivy found (version 0.48.3)
[SUCCESS] jq found
[SUCCESS] xmllint found
[SUCCESS] Dependency check completed
[INFO] Updating Trivy vulnerability database...
[SUCCESS] Trivy database updated successfully
[INFO] Checking Snyk authentication...
[SUCCESS] Snyk authentication verified via token
[INFO] Verifying file integrity...
[SUCCESS] File integrity check passed
[INFO] Detected format: spdx-json
[INFO] File size: 156 KB
[INFO] Verifying JSON format...
[INFO] Validating SPDX JSON format...
[INFO] Found 45 packages
[INFO] Found 12 relationships
[SUCCESS] JSON format validation passed
[INFO] Starting Trivy verification...
[INFO] Verifying SBOM with Trivy...
[SUCCESS] Trivy SBOM scan completed successfully
[INFO] Analyzing Trivy results...
[INFO] Packages scanned: 45
[INFO] Vulnerabilities found:
    Critical: 1
    High: 3
    Medium: 8
    Low: 12
    Unknown: 0
[ERROR] Found 1 CRITICAL vulnerabilities
[WARNING] Found 3 HIGH severity vulnerabilities
[INFO] Starting Snyk verification...
[INFO] Verifying SBOM with Snyk...
[SUCCESS] Snyk SBOM verification passed
[INFO] Found 4 vulnerabilities
[INFO] Found 1 license issues
[WARNING] Vulnerabilities found in SBOM components
[INFO] Analyzing SBOM content...
[INFO] Total components: 45
[INFO] Components with versions: 43
[INFO] Components with licenses: 38
[SUCCESS] Content analysis completed

SBOM Verification Report
========================
File: my-app-sbom.spdx.json
Format: spdx-json
Timestamp: Thu Jul 29 15:30:25 UTC 2025

Tools used:
  - Trivy: 0.48.3
  - Snyk: 1.1291.0
  - jq: jq-1.6
  - xmllint: available

Results:
  Errors: 1
  Warnings: 4
  Info messages: 15

❌ SBOM verification FAILED
  Please address the 1 error(s) found
```

</details>

<details>
<summary>⚡ Example: Fast Trivy-Only Verification</summary>

```bash
$ sbom_verifier.sh --trivy-only --skip-trivy-update sbom.json

SBOM Verification Script
========================

[INFO] Checking dependencies...
[SUCCESS] Trivy found (version 0.48.3)
[SUCCESS] jq found
[SUCCESS] Dependency check completed
[INFO] Skipping Trivy database update as requested
[INFO] Verifying file integrity...
[SUCCESS] File integrity check passed
[INFO] Detected format: cyclonedx-json
[INFO] Verifying JSON format...
[INFO] Validating CycloneDX JSON format...
[INFO] Found 23 components
[INFO] Found 15 dependencies
[SUCCESS] JSON format validation passed
[INFO] Verifying SBOM with Trivy...
[SUCCESS] Trivy SBOM scan completed successfully
[INFO] Packages scanned: 23
[INFO] Vulnerabilities found:
    Critical: 0
    High: 0
    Medium: 2
    Low: 5
    Unknown: 0
[INFO] Analyzing SBOM content...
[SUCCESS] Content analysis completed

SBOM Verification Report
========================
File: sbom.json
Format: cyclonedx-json
Timestamp: Thu Jul 29 15:35:12 UTC 2025

Tools used:
  - Trivy: 0.48.3
  - jq: jq-1.6

Results:
  Errors: 0
  Warnings: 0
  Info messages: 10

✅ SBOM verification PASSED
```

</details>

## 📋 Command Line Reference

### 🔧 Options

| Option | Short | Description | Example |
|--------|-------|-------------|---------|
| `--verbose` | `-v` | Enable detailed output | `-v` |
| `--trivy-only` | | Run only Trivy verification | `--trivy-only` |
| `--snyk-only` | | Run only Snyk verification | `--snyk-only` |
| `--skip-trivy-update` | | Skip Trivy database update | `--skip-trivy-update` |
| `--snyk-token` | `-t` | Set Snyk API token | `-t abc123` |
| `--snyk-org` | `-o` | Set Snyk organization | `-o my-org` |
| `--help` | `-h` | Show help message | `-h` |

### 📁 Supported SBOM Formats

| Format | File Extensions | Schema Validation | Content Analysis | Trivy Support | Snyk Support |
|--------|----------------|-------------------|------------------|---------------|--------------|
| **SPDX JSON** | `.spdx.json`, `.json` | ✅ Full | ✅ Full | ✅ Full | ✅ Full |
| **SPDX XML** | `.spdx.xml`, `.xml` | ✅ Full | ⚠️ Basic | ✅ Full | ⚠️ Limited |
| **SPDX Tag-Value** | `.spdx`, `.txt` | ⚠️ Basic | ⚠️ Basic | ✅ Full | ⚠️ Limited |
| **CycloneDX JSON** | `.json` | ✅ Full | ✅ Full | ✅ Full | ✅ Full |
| **CycloneDX XML** | `.xml` | ✅ Full | ⚠️ Basic | ✅ Full | ⚠️ Limited |

**Legend**: ✅ Full support, ⚠️ Basic support

## 🔍 What Gets Verified

### 🛡️ Security Analysis

#### **Trivy Scanner** (Primary - No Auth Required)
- ✅ Known vulnerability detection with extensive CVE database
- ✅ License detection and compliance checking
- ✅ Secret detection capabilities
- ✅ Supply chain security analysis
- ✅ Fast, offline-capable scanning
- ✅ Regular database updates
- ✅ Severity-based vulnerability categorization

#### **Snyk Scanner** (Optional - Requires Authentication)
- ✅ Commercial vulnerability database
- ✅ License policy compliance
- ✅ Dependency security scoring
- ✅ Supply chain risk assessment
- ✅ Organization-specific policies

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

### Trivy (Recommended - No Authentication Required)

Trivy works out of the box with no setup required:

```bash
# Just run it - no tokens needed!
sbom_verifier.sh --trivy-only sbom.json
```

### Snyk (Optional - Requires Setup)

#### Priority Order (Highest to Lowest)

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
name: SBOM Verification with Trivy
on: [push, pull_request]

jobs:
  verify-sbom:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4

    - name: Install SBOM Verifier
      run: |
        curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/main/install_sbom_verifier.sh | bash

    - name: Verify SBOM with Trivy (Fast)
      run: |
        sbom_verifier.sh --trivy-only artifacts/sbom.json

    - name: Verify SBOM with Both Tools (Comprehensive)
      env:
        SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        SNYK_ORG: ${{ vars.SNYK_ORG }}
      run: |
        sbom_verifier.sh --verbose artifacts/sbom.json
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
                sh 'curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/main/install_sbom_verifier.sh | bash'
            }
        }
        stage('Fast Trivy Scan') {
            steps {
                sh 'sbom_verifier.sh --trivy-only --skip-trivy-update artifacts/sbom.json'
            }
        }
        stage('Comprehensive Scan') {
            when { branch 'main' }
            steps {
                sh 'sbom_verifier.sh --verbose artifacts/sbom.json'
            }
        }
    }
}
```

### GitLab CI

```yaml
stages:
  - install
  - verify-fast
  - verify-comprehensive

install-tools:
  stage: install
  script:
    - curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/main/install_sbom_verifier.sh | bash -s -- --trivy-only
  artifacts:
    paths:
      - /usr/local/bin/sbom_verifier.sh
    expire_in: 1 hour

trivy-verification:
  stage: verify-fast
  dependencies:
    - install-tools
  script:
    - sbom_verifier.sh --trivy-only sbom.json

comprehensive-verification:
  stage: verify-comprehensive
  dependencies:
    - install-tools
  variables:
    SNYK_ORG: "production-team"
  script:
    - export SNYK_TOKEN=$SNYK_TOKEN_SECRET
    - sbom_verifier.sh --verbose sbom.json
  only:
    - main
    - develop
```

### Docker Integration

```dockerfile
FROM ubuntu:22.04

# Install SBOM verifier with Trivy
RUN curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/main/install_sbom_verifier.sh | bash

# Set up environment (optional for Snyk)
ENV SNYK_TOKEN=""
ENV SNYK_ORG=""

# Copy your SBOM
COPY sbom.json /app/sbom.json

# Verify on container start
ENTRYPOINT ["sbom_verifier.sh"]
CMD ["--trivy-only", "/app/sbom.json"]
```

```bash
# Run with Trivy only (no authentication)
docker run -v $(pwd)/sbom.json:/app/sbom.json my-sbom-verifier --trivy-only /app/sbom.json

# Run with both tools
docker run -e SNYK_TOKEN="$SNYK_TOKEN" -e SNYK_ORG="my-org" \
  -v $(pwd)/sbom.json:/app/sbom.json \
  my-sbom-verifier /app/sbom.json
```

## 🛠️ Installation Script Features

The `install_sbom_verifier.sh` script provides automated installation:

### 🎯 Options

```bash
# Install everything (Trivy + Snyk + dependencies)
./install_sbom_verifier.sh

# Install only Trivy and basic tools (faster, no Node.js)
./install_sbom_verifier.sh --trivy-only

# Install only Snyk tools
./install_sbom_verifier.sh --snyk-only

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

| OS Family | Versions | Package Manager | Trivy | Snyk | Status |
|-----------|----------|-----------------|-------|------|--------|
| **Ubuntu** | 18.04+ | apt | ✅ Repo | ✅ npm | ✅ Fully Tested |
| **Debian** | 9+ | apt | ✅ Repo | ✅ npm | ✅ Fully Tested |
| **RHEL** | 7+ | yum/dnf | ✅ Repo | ✅ npm | ✅ Fully Tested |
| **CentOS** | 7+ | yum/dnf | ✅ Repo | ✅ npm | ✅ Fully Tested |
| **Rocky Linux** | 8+ | dnf | ✅ Repo | ✅ npm | ✅ Fully Tested |
| **AlmaLinux** | 8+ | dnf | ✅ Repo | ✅ npm | ✅ Fully Tested |
| **Oracle Linux** | 8+ | dnf | ✅ Binary | ✅ npm | ✅ Fully Tested |
| **Fedora** | 30+ | dnf | ✅ Repo | ✅ npm | ✅ Fully Tested |
| **Amazon Linux** | 2 | yum | ✅ Binary | ✅ npm | ✅ Fully Tested |

### 🔧 What Gets Installed

1. **📦 System Packages**: `curl`, `wget`, `jq`, `libxml2-utils`/`libxml2`, `file`
2. **🛡️ Trivy**: Latest version via repository or binary installation
3. **🟢 Node.js & npm**: Latest LTS via NodeSource repository (if Snyk needed)
4. **🔐 Snyk CLI**: Via npm (with binary fallback, if requested)
5. **📝 SBOM Verifier**: Main verification script to `/usr/local/bin`
6. **✅ Verification**: Tests all installations to ensure they work
7. **📊 Database Update**: Initial Trivy vulnerability database setup

## 🔧 Advanced Usage

### 📊 Batch Processing

```bash
# Verify multiple SBOM files with Trivy only (fast)
for sbom in *.json; do
    echo "Verifying $sbom..."
    sbom_verifier.sh --trivy-only "$sbom" || echo "Failed: $sbom"
done

# Generate comprehensive report for all SBOMs
find . -name "*.spdx.json" -exec sbom_verifier.sh --verbose {} \; > verification_report.txt

# Fast CI verification
find . -name "*.json" -exec sbom_verifier.sh --trivy-only --skip-trivy-update {} \;
```

### 🐳 Container Scanning

```bash
# Extract SBOM from container and verify
docker run --rm my-app:latest cat /app/sbom.json > container-sbom.json
sbom_verifier.sh --trivy-only container-sbom.json

# Verify as part of container build
COPY sbom.json /tmp/sbom.json
RUN sbom_verifier.sh --trivy-only /tmp/sbom.json
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

    # Use Trivy for fast scanning, Snyk for comprehensive analysis
    if [[ "$CI" == "true" ]]; then
        # Fast CI mode
        cmd="sbom_verifier.sh --trivy-only --skip-trivy-update"
    else
        # Comprehensive mode
        cmd="sbom_verifier.sh --snyk-org=$SNYK_ORG --verbose"
    fi

    if $cmd "$sbom" > "$report_file" 2>&1; then
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
# Core authentication (for Snyk)
export SNYK_TOKEN="your-api-token"
export SNYK_ORG="your-organization-id"

# Tool selection
export TRIVY_ONLY=true                # Use only Trivy
export SNYK_ONLY=true                 # Use only Snyk
export SKIP_TRIVY_UPDATE=true         # Skip Trivy DB updates

# Optional configuration
export VERBOSE=true                   # Enable verbose by default
export SBOM_INSTALL_DIR="/custom/path" # Custom installation directory

# Snyk-specific configuration
export SNYK_API="https://snyk.io/api"  # Custom API endpoint
export SNYK_DISABLE_ANALYTICS=true     # Disable usage analytics
```

### ⚙️ Tool Configuration

#### Trivy Configuration
```bash
# View Trivy configuration
trivy --help

# Custom cache directory
export TRIVY_CACHE_DIR="/custom/cache"

# Custom database update interval
export TRIVY_OFFLINE_SCAN=true  # Disable online checks

# Skip certain vulnerability types
trivy sbom --severity HIGH,CRITICAL sbom.json
```

#### Snyk Configuration
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
<summary>🛡️ Trivy Database Update Failed</summary>

**Problem**: `Failed to update Trivy database` warning

**Solutions**:
```bash
# Manual database update
trivy image --download-db-only

# Skip updates for faster execution
sbom_verifier.sh --skip-trivy-update sbom.json

# Check network connectivity
curl -I https://github.com/aquasecurity/trivy-db/releases/latest

# Use offline mode
export TRIVY_OFFLINE_SCAN=true
sbom_verifier.sh --trivy-only sbom.json
```

</details>

<details>
<summary>🔑 Snyk Authentication Failed</summary>

**Problem**: `Snyk not authenticated` error

**Solutions**:
```bash
# Use Trivy only (no authentication needed)
sbom_verifier.sh --trivy-only sbom.json

# Use token directly
sbom_verifier.sh --snyk-token="your-token" sbom.json

# Set environment variable
export SNYK_TOKEN="your-token"
sbom_verifier.sh sbom.json

# Interactive authentication
snyk auth

# Verify token is valid
snyk auth --check
```

</details>

<details>
<summary>📦 Trivy Installation Failed</summary>

**Problem**: Trivy repository not accessible

**Solutions**:
```bash
# Manual binary installation
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Or download directly
TRIVY_VERSION=$(curl -s "https://api.github.com/repos/aquasecurity/trivy/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
curl -Lo trivy.tar.gz "https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/trivy_${TRIVY_VERSION#v}_Linux-64bit.tar.gz"
tar xzf trivy.tar.gz trivy
sudo mv trivy /usr/local/bin/

# Verify installation
trivy --version
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
<summary>🏗️ Oracle Linux EPEL Error</summary>

**Problem**: `epel-release package not available` on Oracle Linux

**Solutions**:
```bash
# Use Trivy-only installation (recommended)
./install_sbom_verifier.sh --trivy-only

# Or install manually without EPEL
sudo dnf install -y curl wget jq libxml2 file
# Then install Trivy binary manually
```

</details>

### 🐞 Debug Mode

```bash
# Enable debug output for installation
./install_sbom_verifier.sh --debug

# Enable debug output for verification
bash -x sbom_verifier.sh sbom.json

# Check what Trivy sees
trivy sbom --debug sbom.json

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
trivy --version
snyk --version
jq --version
node --version

# Error output
sbom_verifier.sh --verbose problematic-sbom.json 2>&1
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## 🔒 Security Considerations

- **🔑 Token Security**: Store Snyk tokens securely, never commit to version control
- **📁 SBOM Privacy**: SBOM files may contain sensitive dependency information
- **🌐 Network Access**: Required for Trivy DB updates and Snyk API calls
- **👤 Permissions**: Installation requires sudo, verification does not
- **🔄 Database Updates**: Trivy downloads vulnerability databases regularly

## 🙏 Acknowledgments

- **🛡️ Trivy Team** for providing excellent open-source vulnerability scanning
- **🔐 Snyk** for providing commercial security scanning capabilities
- **📋 SPDX Community** for SBOM standards and tooling
- **🔄 CycloneDX Community** for SBOM standards and formats
- **👥 Contributors** and users of this tool

---

<div align="center">

**🛡️ Keep your software supply chain secure with SBOM Verifier + Trivy!**

Made with ❤️ for the community

[⭐ Star us on GitHub](https://github.com/YOUR_USERNAME/YOUR_REPO) • [🍴 Fork](https://github.com/YOUR_USERNAME/YOUR_REPO/fork) • [📝 Report Issue](https://github.com/YOUR_USERNAME/YOUR_REPO/issues/new)

</div>