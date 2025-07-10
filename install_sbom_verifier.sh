#!/bin/bash

# SBOM Verifier Installation Script
# Supports Ubuntu, Debian, RHEL, CentOS, Fedora, Rocky Linux, AlmaLinux, Amazon Linux

set -e

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
            sudo apt update
            sudo apt install -y curl wget jq libxml2-utils file software-properties-common
            ;;
        rhel|centos|rocky|almalinux)
            log_info "Installing packages for RHEL/CentOS/Rocky/AlmaLinux..."
            if command -v dnf &> /dev/null; then
                sudo dnf install -y curl wget jq libxml2 file
            else
                sudo yum install -y curl wget jq libxml2 file
            fi
            ;;
        fedora)
            log_info "Installing packages for Fedora..."
            sudo dnf install -y curl wget jq libxml2 file
            ;;
        amzn)
            log_info "Installing packages for Amazon Linux..."
            sudo yum update -y
            sudo yum install -y curl wget jq libxml2 file
            ;;
        *)
            log_warning "Unknown OS: $OS. Attempting generic installation..."
            # Try to detect package manager
            if command -v apt &> /dev/null; then
                sudo apt update
                sudo apt install -y curl wget jq libxml2-utils file
            elif command -v dnf &> /dev/null; then
                sudo dnf install -y curl wget jq libxml2 file
            elif command -v yum &> /dev/null; then
                sudo yum install -y curl wget jq libxml2 file
            else
                log_error "No supported package manager found"
                exit 1
            fi
            ;;
    esac

    log_success "System packages installed"
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
            curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
            sudo apt install -y nodejs
            ;;
        rhel|centos|rocky|almalinux|fedora|amzn)
            log_info "Installing Node.js via NodeSource repository..."
            curl -fsSL https://rpm.nodesource.com/setup_lts.x | sudo bash -
            if command -v dnf &> /dev/null; then
                sudo dnf install -y nodejs
            else
                sudo yum install -y nodejs
            fi
            ;;
        *)
            log_warning "Attempting generic Node.js installation..."
            # Try package manager approach first
            if command -v apt &> /dev/null; then
                sudo apt install -y nodejs npm
            elif command -v dnf &> /dev/null; then
                sudo dnf install -y nodejs npm
            elif command -v yum &> /dev/null; then
                sudo yum install -y nodejs npm
            else
                log_error "Cannot install Node.js automatically"
                exit 1
            fi
            ;;
    esac

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
        if sudo npm install -g snyk; then
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
    if sudo curl -Lo "$snyk_path" "$snyk_url"; then
        sudo chmod +x "$snyk_path"
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

    # Download the verification script (you'll need to host this somewhere or embed it)
    local script_url="https://raw.githubusercontent.com/your-repo/sbom-tools/main/sbom_verifier.sh"
    local script_path="$INSTALL_DIR/$SCRIPT_NAME"

    # For now, we'll create the script inline (you can modify this to download from a URL)
    cat > "$TEMP_DIR/$SCRIPT_NAME" << 'SCRIPT_EOF'
#!/bin/bash
# This is where the SBOM verifier script content would go
# You can either embed the full script here or download it from a repository

echo "SBOM Verifier Script"
echo "This script would contain the full verification logic"
echo "Run with: $0 <sbom-file>"
SCRIPT_EOF

    # Install the script
    sudo cp "$TEMP_DIR/$SCRIPT_NAME" "$script_path"
    sudo chmod +x "$script_path"

    log_success "SBOM verifier installed to $script_path"
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

    if command -v node &> /dev/null; then
        log_success "node: $(node --version)"
    else
        log_error "node not found"
        all_good=false
    fi

    if command -v npm &> /dev/null; then
        log_success "npm: $(npm --version)"
    else
        log_error "npm not found"
        all_good=false
    fi

    if command -v snyk &> /dev/null; then
        log_success "snyk: $(snyk --version)"
    else
        log_error "snyk not found"
        all_good=false
    fi

    if command -v "$SCRIPT_NAME" &> /dev/null; then
        log_success "SBOM verifier script installed"
    else
        log_error "SBOM verifier script not found"
        all_good=false
    fi

    if $all_good; then
        log_success "All dependencies installed successfully!"
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
    echo "🎉 Installation Complete!"
    echo "======================="
    echo ""
    echo "Next steps:"
    echo "1. Authenticate with Snyk:"
    echo "   snyk auth"
    echo ""
    echo "2. Test the installation:"
    echo "   $SCRIPT_NAME --help"
    echo ""
    echo "3. Verify an SBOM file:"
    echo "   $SCRIPT_NAME path/to/your/sbom.json"
    echo ""
    echo "Documentation:"
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
    echo "2. Verify you have sudo privileges"
    echo "3. Try running with --verbose for more details"
    echo "4. Check the logs above for specific error messages"
    echo ""
    echo "Manual installation:"
    echo "1. Install system packages: jq, libxml2-utils/libxml2, file, curl"
    echo "2. Install Node.js and npm"
    echo "3. Install Snyk: npm install -g snyk"
    echo "4. Download the SBOM verifier script manually"
    cleanup
    exit 1
}

# Main installation function
main() {
    echo "🚀 SBOM Verifier Installation Script"
    echo "==================================="
    echo ""

    # Parse command line arguments
    local verbose=false
    local force=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            --verbose|-v)
                verbose=true
                set -x
                shift
                ;;
            --force|-f)
                force=true
                shift
                ;;
            --help|-h)
                echo "SBOM Verifier Installation Script"
                echo ""
                echo "Usage: $0 [options]"
                echo ""
                echo "Options:"
                echo "  --verbose, -v    Enable verbose output"
                echo "  --force, -f      Force reinstallation"
                echo "  --help, -h       Show this help message"
                echo ""
                echo "Supported systems:"
                echo "  - Ubuntu/Debian"
                echo "  - RHEL/CentOS/Rocky Linux/AlmaLinux"
                echo "  - Fedora"
                echo "  - Amazon Linux"
                echo ""
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done

    # Set trap for cleanup on failure
    trap handle_failure ERR

    # Run installation steps
    detect_os
    check_root
    check_internet
    install_system_packages
    install_nodejs
    install_snyk
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
