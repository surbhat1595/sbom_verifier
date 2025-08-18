#!/bin/bash

# SBOM Verifier Installation Script
# Supports Ubuntu, Debian, RHEL, CentOS, Fedora, Rocky Linux, AlmaLinux, Amazon Linux
# Installs: Trivy, Snyk CLI, jq, xmllint, and the SBOM verifier script

set -ex

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script configuration
SCRIPT_NAME="sbom_verifier.sh"
INSTALL_DIR="/usr/local/bin"
TEMP_DIR="/tmp/sbom_installer"

# Functions
log_error() {
    echo -e "${RED}❌ ERROR: $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  WARNING: $1${NC}"
}

log_info() {
    echo -e "${BLUE}ℹ️  INFO: $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

# Detect OS distribution
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
        OS_LIKE=$ID_LIKE
    else
        log_error "Cannot detect OS distribution"
        exit 1
    fi
    
    log_info "Detected OS: $OS $OS_VERSION"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_warning "Running as root. Consider running as regular user with sudo when needed."
    fi
}

# Check internet connectivity
check_internet() {
    log_info "Checking internet connectivity..."
    if ! curl -s --connect-timeout 5 https://google.com > /dev/null; then
        log_error "No internet connection. Please check your network settings."
        exit 1
    fi
    log_success "Internet connectivity verified"
}

# Install packages based on OS
install_system_packages() {
    log_info "Installing system packages..."
    
    case "$OS" in
        ubuntu|debian)
            log_info "Installing packages for Ubuntu/Debian..."
            apt update
            apt install -y curl wget jq libxml2-utils file software-properties-common apt-transport-https gnupg lsb-release
            ;;
        rhel|centos|rocky|almalinux)
            log_info "Installing packages for RHEL/CentOS/Rocky/AlmaLinux..."
            if command -v dnf &> /dev/null; then
                dnf install -y curl wget jq libxml2 file epel-release
            else
                yum install -y curl wget jq libxml2 file epel-release
            fi
            ;;
        ol)
            log_info "Installing packages for Oracle Linux..."
            if command -v dnf &> /dev/null; then
                dnf install -y curl wget jq libxml2 file
                # Enable optional repositories for Oracle Linux
                dnf config-manager --enable ol${OS_VERSION}_optional_latest >/dev/null 2>&1 || true
            else
                yum install -y curl wget jq libxml2 file
                # Enable optional repositories for Oracle Linux
                yum-config-manager --enable ol${OS_VERSION}_optional >/dev/null 2>&1 || true
            fi
            ;;
        fedora)
            log_info "Installing packages for Fedora..."
            dnf install -y curl wget jq libxml2 file
            ;;
        amzn)
            log_info "Installing packages for Amazon Linux..."
            yum update -y
            yum install -y curl wget jq libxml2 file
            ;;
        *)
            log_warning "Unknown OS: $OS. Attempting generic installation..."
            # Try to detect package manager
            if command -v apt &> /dev/null; then
                apt update
                apt install -y curl wget jq libxml2-utils file
            elif command -v dnf &> /dev/null; then
                dnf install -y curl wget jq libxml2 file
            elif command -v yum &> /dev/null; then
                yum install -y curl wget jq libxml2 file
            else
                log_error "No supported package manager found"
                exit 1
            fi
            ;;
    esac
    
    log_success "System packages installed"
}

# Install Trivy
install_trivy() {
    log_info "Installing Trivy..."
    
    # Check if Trivy is already installed
    if command -v trivy &> /dev/null; then
        local trivy_version=$(trivy --version | head -n1 | cut -d' ' -f2)
        log_info "Trivy already installed: $trivy_version"
        return 0
    fi
    
    case "$OS" in
        ubuntu|debian)
            log_info "Installing Trivy for Ubuntu/Debian..."
            # Add Trivy repository
            wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
            echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
            apt update
            apt install -y trivy
            ;;
        rhel|centos|rocky|almalinux)
            log_info "Installing Trivy for RHEL/CentOS/Rocky/AlmaLinux..."
            # Create repo file
            cat << 'EOF' > /etc/yum.repos.d/trivy.repo
[trivy]
name=Trivy repository
baseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/$releasever/$basearch/
gpgcheck=1
enabled=1
gpgkey=https://aquasecurity.github.io/trivy-repo/rpm/public.key
EOF
            if command -v dnf &> /dev/null; then
                dnf install -y trivy
            else
                yum install -y trivy
            fi
            ;;
        fedora)
            log_info "Installing Trivy for Fedora..."
            # Create repo file
            cat << 'EOF' > /etc/yum.repos.d/trivy.repo
[trivy]
name=Trivy repository
baseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/$releasever/$basearch/
gpgcheck=1
enabled=1
gpgkey=https://aquasecurity.github.io/trivy-repo/rpm/public.key
EOF
            dnf install -y trivy
            ;;
        amzn)
            log_info "Installing Trivy for Amazon Linux..."
            # Use generic binary installation for Amazon Linux
            install_trivy_binary
            ;;
        *)
            log_warning "Installing Trivy binary for unknown OS..."
            install_trivy_binary
            ;;
    esac
    
    # Verify installation
    if command -v trivy &> /dev/null; then
        local trivy_version=$(trivy --version | head -n1 | cut -d' ' -f2)
        log_success "Trivy installed: $trivy_version"
    else
        log_error "Trivy installation failed"
        exit 1
    fi
}

# Install Trivy binary directly
install_trivy_binary() {
    log_info "Installing Trivy binary..."
    
    # Detect architecture
    local arch=""
    case $(uname -m) in
        x86_64) arch="64bit" ;;
        aarch64) arch="ARM64" ;;
        arm64) arch="ARM64" ;;
        *) 
            log_error "Unsupported architecture: $(uname -m)"
            exit 1
            ;;
    esac
    
    # Get latest release version
    local latest_version=$(curl -s "https://api.github.com/repos/aquasecurity/trivy/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    if [[ -z "$latest_version" ]]; then
        log_error "Could not determine latest Trivy version"
        exit 1
    fi
    
    log_info "Installing Trivy $latest_version for $arch architecture..."
    
    # Download and install
    local trivy_url="https://github.com/aquasecurity/trivy/releases/download/${latest_version}/trivy_${latest_version#v}_Linux-${arch}.tar.gz"
    local trivy_path="$INSTALL_DIR/trivy"
    
    # Download and extract
    if curl -Lo "/tmp/trivy.tar.gz" "$trivy_url"; then
        cd /tmp
        tar xzf trivy.tar.gz trivy
        mv trivy "$trivy_path"
        chmod +x "$trivy_path"
        rm -f trivy.tar.gz
        log_success "Trivy binary installed to $trivy_path"
    else
        log_error "Failed to download Trivy binary"
        exit 1
    fi
}

# Install Node.js and npm
install_nodejs() {
    log_info "Installing Node.js and npm..."
    
    # Check if Node.js is already installed
    if command -v node &> /dev/null && command -v npm &> /dev/null; then
        local node_version=$(node --version)
        log_info "Node.js already installed: $node_version"
        return 0
    fi
    
    case "$OS" in
        ubuntu|debian)
            log_info "Installing Node.js via NodeSource repository..."
            # Download and run the setup script directly
            curl -fsSL https://deb.nodesource.com/setup_lts.x -o /tmp/nodesource_setup.sh
            bash /tmp/nodesource_setup.sh
            apt install -y nodejs
            ;;
        rhel|centos|rocky|almalinux|fedora|amzn)
            log_info "Installing Node.js via NodeSource repository..."
            # Download and run the setup script directly
            curl -fsSL https://rpm.nodesource.com/setup_lts.x -o /tmp/nodesource_setup.sh
            bash /tmp/nodesource_setup.sh
            if command -v dnf &> /dev/null; then
                dnf install -y nodejs
            else
                yum install -y nodejs
            fi
            ;;
        ol)
            log_info "Installing Node.js for Oracle Linux..."
            # For Oracle Linux, try NodeSource first, fallback to binary
            if curl -fsSL https://rpm.nodesource.com/setup_lts.x -o /tmp/nodesource_setup.sh 2>/dev/null; then
                bash /tmp/nodesource_setup.sh
                if command -v dnf &> /dev/null; then
                    dnf install -y nodejs
                else
                    yum install -y nodejs
                fi
            else
                log_warning "NodeSource repository failed, trying package manager..."
                if command -v dnf &> /dev/null; then
                    dnf install -y nodejs npm
                else
                    yum install -y nodejs npm
                fi
            fi
            ;;
        *)
            log_warning "Attempting generic Node.js installation..."
            # Try package manager approach first
            if command -v apt &> /dev/null; then
                apt install -y nodejs npm
            elif command -v dnf &> /dev/null; then
                dnf install -y nodejs npm
            elif command -v yum &> /dev/null; then
                yum install -y nodejs npm
            else
                log_error "Cannot install Node.js automatically"
                exit 1
            fi
            ;;
    esac
    
    # Clean up temp file
    rm -f /tmp/nodesource_setup.sh
    
    # Verify installation
    if command -v node &> /dev/null && command -v npm &> /dev/null; then
        local node_version=$(node --version)
        local npm_version=$(npm --version)
        log_success "Node.js installed: $node_version"
        log_success "npm installed: $npm_version"
    else
        log_error "Node.js installation failed"
        exit 1
    fi
}

# Install Snyk CLI
install_snyk() {
    log_info "Installing Snyk CLI..."
    
    # Check if Snyk is already installed
    if command -v snyk &> /dev/null; then
        local snyk_version=$(snyk --version)
        log_info "Snyk already installed: $snyk_version"
        return 0
    fi
    
    # Try npm installation first
    if command -v npm &> /dev/null; then
        log_info "Installing Snyk via npm..."
        if npm install -g snyk; then
            log_success "Snyk installed via npm"
        else
            log_warning "npm installation failed, trying binary installation..."
            install_snyk_binary
        fi
    else
        log_info "npm not available, installing Snyk binary..."
        install_snyk_binary
    fi
    
    # Verify installation
    if command -v snyk &> /dev/null; then
        local snyk_version=$(snyk --version)
        log_success "Snyk installed: $snyk_version"
    else
        log_error "Snyk installation failed"
        exit 1
    fi
}

# Install Snyk binary directly
install_snyk_binary() {
    log_info "Installing Snyk binary..."
    
    local snyk_url="https://github.com/snyk/snyk/releases/latest/download/snyk-linux"
    local snyk_path="$INSTALL_DIR/snyk"
    
    # Download Snyk binary
    if curl -Lo "$snyk_path" "$snyk_url"; then
        chmod +x "$snyk_path"
        log_success "Snyk binary installed to $snyk_path"
    else
        log_error "Failed to download Snyk binary"
        exit 1
    fi
}

# Install SBOM verifier script
install_sbom_verifier() {
    log_info "Installing SBOM verifier script..."
    
    # Create temp directory
    mkdir -p "$TEMP_DIR"
    
    # GitHub repository details
    local repo_url="https://raw.githubusercontent.com/EvgeniyPatlan/sbom_verifier/refs/heads/main"
    local script_url="$repo_url/sbom_verifier.sh"
    local script_path="$INSTALL_DIR/$SCRIPT_NAME"
    
    log_info "Downloading SBOM verifier from: $script_url"
    
    # Try to download the script using curl first, then wget as fallback
    if command -v curl >/dev/null 2>&1; then
        if curl -fsSL "$script_url" -o "$TEMP_DIR/$SCRIPT_NAME"; then
            log_success "SBOM verifier downloaded successfully with curl"
        else
            log_error "Failed to download SBOM verifier with curl"
            exit 1
        fi
    elif command -v wget >/dev/null 2>&1; then
        if wget -q -O "$TEMP_DIR/$SCRIPT_NAME" "$script_url"; then
            log_success "SBOM verifier downloaded successfully with wget"
        else
            log_error "Failed to download SBOM verifier with wget"
            exit 1
        fi
    else
        log_error "Neither curl nor wget is available for downloading the script"
        exit 1
    fi
    
    # Verify the downloaded script is not empty and contains expected content
    if [[ ! -s "$TEMP_DIR/$SCRIPT_NAME" ]]; then
        log_error "Downloaded script is empty"
        exit 1
    fi
    
    # Basic verification that it's a bash script
    if ! head -1 "$TEMP_DIR/$SCRIPT_NAME" | grep -q "#!/bin/bash"; then
        log_error "Downloaded file does not appear to be a valid bash script"
        exit 1
    fi
    
    # Install the script
    if cp "$TEMP_DIR/$SCRIPT_NAME" "$script_path"; then
        chmod +x "$script_path"
        log_success "SBOM verifier installed to $script_path"
        
        # Verify installation
        if [[ -x "$script_path" ]]; then
            log_success "SBOM verifier script is executable and ready to use"
        else
            log_warning "Script installed but may not be executable"
        fi
    else
        log_error "Failed to install SBOM verifier script"
        exit 1
    fi
}

# Create a placeholder script if download fails
create_placeholder_script() {
    local script_path="$1"
    
    log_info "Creating placeholder script..."
    
    cat << 'EOF' > "$script_path"
#!/bin/bash
echo "SBOM Verifier Script - Placeholder"
echo "Please download the actual script from your repository"
echo "and replace this file at: $0"
echo ""
echo "Expected tools are installed:"
if command -v trivy &> /dev/null; then
    echo "✅ Trivy: $(trivy --version | head -n1)"
else
    echo "❌ Trivy: not found"
fi

if command -v snyk &> /dev/null; then
    echo "✅ Snyk: $(snyk --version)"
else
    echo "❌ Snyk: not found"
fi

if command -v jq &> /dev/null; then
    echo "✅ jq: $(jq --version)"
else
    echo "❌ jq: not found"
fi

if command -v xmllint &> /dev/null; then
    echo "✅ xmllint: available"
else
    echo "❌ xmllint: not found"
fi
EOF
    
    log_warning "Placeholder script created. Please replace with actual script."
}

# Update Trivy database
update_trivy_database() {
    log_info "Updating Trivy vulnerability database..."
    
    if command -v trivy &> /dev/null; then
        if trivy image --download-db-only harbor-docker.int.percona.com/dockerhub-cache/aquasec/trivy-db:2 >/dev/null 2>&1; then
            log_success "Trivy database updated successfully"
        else
            log_warning "Failed to update Trivy database initially. This is normal for first-time installation."
            log_info "Trivy will update its database automatically on first scan"
        fi
    else
        log_warning "Trivy not found, skipping database update"
    fi
}

# Verify all installations
verify_installation() {
    log_info "Verifying installation..."
    
    local all_good=true
    
    # Check each dependency
    if command -v jq &> /dev/null; then
        log_success "jq: $(jq --version)"
    else
        log_error "jq not found"
        all_good=false
    fi
    
    if command -v xmllint &> /dev/null; then
        log_success "xmllint: $(xmllint --version 2>&1 | head -1)"
    else
        log_error "xmllint not found"
        all_good=false
    fi
    
    if command -v file &> /dev/null; then
        log_success "file: $(file --version | head -1)"
    else
        log_error "file not found"
        all_good=false
    fi
    
    if command -v curl &> /dev/null; then
        log_success "curl: $(curl --version | head -1)"
    else
        log_error "curl not found"
        all_good=false
    fi
    
    if command -v trivy &> /dev/null; then
        log_success "trivy: $(trivy --version | head -n1)"
    else
        log_error "trivy not found"
        all_good=false
    fi
    
    if command -v node &> /dev/null; then
        log_success "node: $(node --version)"
    else
        log_warning "node not found (optional for Snyk)"
    fi
    
    if command -v npm &> /dev/null; then
        log_success "npm: $(npm --version)"
    else
        log_warning "npm not found (optional for Snyk)"
    fi
    
    if command -v snyk &> /dev/null; then
        log_success "snyk: $(snyk --version)"
    else
        log_warning "snyk not found (optional)"
    fi
    
    if command -v "$SCRIPT_NAME" &> /dev/null; then
        log_success "SBOM verifier script installed"
    else
        log_error "SBOM verifier script not found"
        all_good=false
    fi
    
    if $all_good; then
        log_success "All critical dependencies installed successfully!"
        return 0
    else
        log_error "Some dependencies failed to install"
        return 1
    fi
}

# Cleanup function
cleanup() {
    log_info "Cleaning up temporary files..."
    rm -rf "$TEMP_DIR"
}

# Show post-installation instructions
show_post_install() {
    echo ""
    echo "Installation Complete!"
    echo "====================="
    echo ""
    echo "Installed tools:"
    if command -v trivy &> /dev/null; then
        echo "✅ Trivy: $(trivy --version | head -n1 | cut -d' ' -f2)"
    fi
    if command -v snyk &> /dev/null; then
        echo "✅ Snyk: $(snyk --version)"
    fi
    if command -v jq &> /dev/null; then
        echo "✅ jq: $(jq --version)"
    fi
    echo ""
    echo "Next steps:"
    echo "1. (Optional) Authenticate with Snyk:"
    echo "   snyk auth"
    echo ""
    echo "2. Test the installation:"
    echo "   $SCRIPT_NAME --help"
    echo ""
    echo "3. Verify an SBOM file:"
    echo "   $SCRIPT_NAME path/to/your/sbom.json"
    echo ""
    echo "4. Run with Trivy only (no Snyk auth needed):"
    echo "   $SCRIPT_NAME --trivy-only path/to/your/sbom.json"
    echo ""
    echo "5. Run in verbose mode:"
    echo "   $SCRIPT_NAME --verbose path/to/your/sbom.json"
    echo ""
    echo "Documentation:"
    echo "- Trivy: https://trivy.dev/"
    echo "- Snyk CLI: https://docs.snyk.io/snyk-cli"
    echo "- SBOM formats: https://spdx.dev/ and https://cyclonedx.org/"
    echo ""
}

# Handle installation failures
handle_failure() {
    log_error "Installation failed!"
    echo ""
    echo "Troubleshooting:"
    echo "1. Check your internet connection"
    echo "2. Verify you have sufficient privileges (try with sudo)"
    echo "3. Try running with --verbose for more details"
    echo "4. Check the logs above for specific error messages"
    echo ""
    echo "Manual installation alternatives:"
    echo ""
    echo "Trivy:"
    echo "  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin"
    echo ""
    echo "System packages:"
    echo "  Ubuntu/Debian: sudo apt install jq libxml2-utils file curl"
    echo "  RHEL/Fedora: sudo dnf install jq libxml2 file curl"
    echo ""
    echo "Snyk (optional):"
    echo "  npm install -g snyk"
    echo "  # or download binary from https://github.com/snyk/snyk/releases"
    echo ""
    cleanup
    exit 1
}

# Main installation function
main() {
    echo "SBOM Verifier Installation Script with Trivy"
    echo "============================================="
    echo ""
    
    # Parse command line arguments
    local verbose=false
    local debug=false
    local force=false
    local trivy_only=false
    local snyk_only=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --verbose|-v)
                verbose=true
                shift
                ;;
            --debug|-d)
                set -x
                shift
                ;;
            --force|-f)
                force=true
                shift
                ;;
            --trivy-only)
                trivy_only=true
                shift
                ;;
            --snyk-only)
                snyk_only=true
                shift
                ;;
            --help|-h)
                cat << 'EOF'
SBOM Verifier Installation Script with Trivy

Usage: $0 [options]

Options:
  --verbose, -v      Enable verbose output
  --debug, -d        Enable debug mode (shows all commands)
  --force, -f        Force reinstallation
  --trivy-only       Install only Trivy and dependencies (skip Snyk/Node.js)
  --snyk-only        Install only Snyk and dependencies (skip Trivy)
  --help, -h         Show this help message

Supported systems:
  - Ubuntu 18.04+, Debian 9+
  - RHEL/CentOS 7+, Rocky Linux, AlmaLinux
  - Oracle Linux 8+
  - Fedora 30+
  - Amazon Linux 2

What gets installed:
  - Trivy (vulnerability scanner)
  - Snyk CLI (optional, security platform)
  - jq (JSON processor)
  - xmllint (XML processor)
  - curl, wget, file (utilities)
  - Node.js/npm (for Snyk, if needed)
  - SBOM verifier script

Examples:
  $0                    # Install everything
  $0 --trivy-only       # Install only Trivy and basic tools
  $0 --verbose          # Install with detailed output
  $0 --force            # Force reinstall even if tools exist

EOF
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done
    
    # Validate conflicting options
    if [[ "$trivy_only" == "true" && "$snyk_only" == "true" ]]; then
        log_error "Cannot specify both --trivy-only and --snyk-only"
        exit 1
    fi
    
    # Set trap for cleanup on failure
    trap handle_failure ERR
    
    # Export verbose flag for use in functions
    if [[ "$verbose" == "true" ]]; then
        export VERBOSE=true
        log_info "Running in verbose mode"
    fi
    
    # Run installation steps
    detect_os
    check_root
    check_internet
    install_system_packages
    
    # Install tools based on options
    if [[ "$snyk_only" != "true" ]]; then
        install_trivy
        update_trivy_database
    fi
    
    if [[ "$trivy_only" != "true" ]]; then
        install_nodejs
        install_snyk
    fi
    
    install_sbom_verifier
    
    # Verify everything worked
    if verify_installation; then
        cleanup
        show_post_install
    else
        handle_failure
    fi
}

# Run main function with all arguments
main "$@"
