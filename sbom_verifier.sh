#!/bin/bash

# SBOM Verification Script
# This script verifies SBOM files using Snyk and other validation methods

# Safer script execution
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Initialize counters
ERRORS=0
WARNINGS=0
INFO=0

# Functions
log_error() {
    echo -e "${RED}[ERROR] $1${NC}"
    ERRORS=$((ERRORS + 1))
}

log_warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
    WARNINGS=$((WARNINGS + 1))
}

log_info() {
    echo -e "${BLUE}[INFO] $1${NC}"
    INFO=$((INFO + 1))
}

log_success() {
    echo -e "${GREEN}[SUCCESS] $1${NC}"
}

# Check if required tools are installed
check_dependencies() {
    log_info "Checking dependencies..."

    local all_good=true

    # Check for Snyk
    if command -v snyk >/dev/null 2>&1; then
        log_success "Snyk CLI found"
    else
        log_error "Snyk CLI not found. Please install it:"
        echo "  npm install -g snyk"
        echo "  # or"
        echo "  curl -Lo /usr/local/bin/snyk https://github.com/snyk/snyk/releases/latest/download/snyk-linux && chmod +x /usr/local/bin/snyk"
        all_good=false
    fi

    # Check for jq (for JSON processing)
    if command -v jq >/dev/null 2>&1; then
        log_success "jq found"
    else
        log_warning "jq not found. JSON validation will be limited."
        echo "  Install with: sudo apt-get install jq (Ubuntu/Debian) or sudo dnf install jq (RHEL/Fedora)"
    fi

    # Check for xmllint (for XML processing)
    if command -v xmllint >/dev/null 2>&1; then
        log_success "xmllint found"
    else
        log_warning "xmllint not found. XML validation will be limited."
        echo "  Install with: sudo apt-get install libxml2-utils (Ubuntu/Debian) or sudo dnf install libxml2 (RHEL/Fedora)"
    fi

    if ! $all_good; then
        log_error "Critical dependencies missing. Please install them first."
        exit 1
    fi

    log_success "Dependency check completed"
}

# Authenticate with Snyk
authenticate_snyk() {
    log_info "Checking Snyk authentication..."

    # Check if token is set via environment variable
    if [[ -n "$SNYK_TOKEN" ]]; then
        log_info "Using SNYK_TOKEN environment variable"
        if snyk auth --check >/dev/null 2>&1; then
            log_success "Snyk authentication verified via token"
            return 0
        else
            log_warning "SNYK_TOKEN set but authentication failed"
        fi
    fi

    # Check if already authenticated via other means
    if snyk auth --check >/dev/null 2>&1; then
        log_success "Snyk authentication verified"
        return 0
    fi

    log_warning "Snyk not authenticated. Some features may be limited."
    echo "  To authenticate, choose one of:"
    echo "  1. Run: snyk auth"
    echo "  2. Set token: export SNYK_TOKEN='your-token'"
    echo "  3. Get token from: https://app.snyk.io/account"
    return 1
}

# Detect SBOM format
detect_sbom_format() {
    local file="$1"

    if [[ ! -f "$file" ]]; then
        log_error "File not found: $file"
        return 1
    fi

    # Check file extension first
    case "${file##*.}" in
        json)
            if jq -e '.spdxVersion' "$file" &> /dev/null || jq -e '.SPDXID' "$file" &> /dev/null; then
                echo "spdx-json"
            elif jq -e '.bomFormat' "$file" &> /dev/null || jq -e '.specVersion' "$file" &> /dev/null; then
                echo "cyclonedx-json"
            else
                echo "unknown-json"
            fi
            ;;
        xml)
            if grep -q "cyclonedx" "$file" 2>/dev/null; then
                echo "cyclonedx-xml"
            elif grep -q "spdx" "$file" 2>/dev/null; then
                echo "spdx-xml"
            else
                echo "unknown-xml"
            fi
            ;;
        spdx)
            echo "spdx-tagvalue"
            ;;
        *)
            # Check content
            if grep -q "SPDXVersion:" "$file" 2>/dev/null; then
                echo "spdx-tagvalue"
            else
                echo "unknown"
            fi
            ;;
    esac
}

# Verify file integrity
verify_file_integrity() {
    local file="$1"

    log_info "Verifying file integrity..."

    # Check if file exists
    if [[ ! -f "$file" ]]; then
        log_error "File does not exist: $file"
        return 1
    fi

    # Check if file is readable
    if [[ ! -r "$file" ]]; then
        log_error "File is not readable: $file"
        return 1
    fi

    # Check file size
    local size=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null)
    if [[ $size -eq 0 ]]; then
        log_error "File is empty"
        return 1
    elif [[ $size -gt 104857600 ]]; then  # 100MB
        log_warning "File is very large ($(( size / 1024 / 1024 )) MB)"
    fi

    # Check encoding (basic UTF-8 check)
    if ! file "$file" | grep -q "UTF-8\|ASCII"; then
        log_warning "File may not be UTF-8 encoded"
    fi

    log_success "File integrity check passed"
    return 0
}

# Verify with Snyk
verify_with_snyk() {
    local file="$1"

    log_info "Verifying SBOM with Snyk..."

    # Check if Snyk supports SBOM testing
    if snyk sbom --help &> /dev/null; then
        log_info "Using Snyk SBOM command..."

        # Test the SBOM file
        if snyk sbom test --file="$file" --format=json > /tmp/snyk_sbom_result.json 2>&1; then
            log_success "Snyk SBOM verification passed"

            # Parse results if jq is available
            if command -v jq &> /dev/null; then
                local vulnerabilities=$(jq -r '.vulnerabilities | length' /tmp/snyk_sbom_result.json 2>/dev/null || echo "0")
                local licenses=$(jq -r '.licenses | length' /tmp/snyk_sbom_result.json 2>/dev/null || echo "0")

                log_info "Found $vulnerabilities vulnerabilities"
                log_info "Found $licenses license issues"

                if [[ $vulnerabilities -gt 0 ]]; then
                    log_warning "Vulnerabilities found in SBOM components"
                fi
            fi
        else
            log_warning "Snyk SBOM test failed or found issues"
            cat /tmp/snyk_sbom_result.json 2>/dev/null || true
        fi
    else
        # Fallback: try to use regular Snyk test on the project
        log_info "Snyk SBOM command not available, trying alternative verification..."

        # If the SBOM is in a project directory, we can test the project
        local project_dir=$(dirname "$file")
        if [[ -f "$project_dir/package.json" ]] || [[ -f "$project_dir/pom.xml" ]] || [[ -f "$project_dir/requirements.txt" ]]; then
            log_info "Testing project directory with Snyk..."
            if snyk test --json "$project_dir" > /tmp/snyk_project_result.json 2>&1; then
                log_success "Snyk project test passed"
            else
                log_warning "Snyk project test found issues"
            fi
        else
            log_warning "Cannot perform Snyk verification without project context"
        fi
    fi

    # Clean up temp files
    rm -f /tmp/snyk_sbom_result.json /tmp/snyk_project_result.json
}

# Verify JSON format
verify_json_format() {
    local file="$1"
    local format="$2"

    log_info "Verifying JSON format..."

    if ! command -v jq &> /dev/null; then
        log_warning "jq not available, skipping detailed JSON validation"
        return 0
    fi

    # Basic JSON syntax check
    if ! jq empty "$file" 2>/dev/null; then
        log_error "Invalid JSON syntax"
        return 1
    fi

    case "$format" in
        spdx-json)
            log_info "Validating SPDX JSON format..."

            # Check required fields
            if ! jq -e '.spdxVersion' "$file" &> /dev/null; then
                log_error "Missing required field: spdxVersion"
                return 1
            fi

            if ! jq -e '.SPDXID' "$file" &> /dev/null; then
                log_error "Missing required field: SPDXID"
                return 1
            fi

            if ! jq -e '.creationInfo' "$file" &> /dev/null; then
                log_error "Missing required field: creationInfo"
                return 1
            fi

            if ! jq -e '.name' "$file" &> /dev/null; then
                log_error "Missing required field: name"
                return 1
            fi

            # Check SPDX version format
            local spdx_version=$(jq -r '.spdxVersion' "$file")
            if [[ ! "$spdx_version" =~ ^SPDX- ]]; then
                log_error "Invalid SPDX version format: $spdx_version"
                return 1
            fi

            # Count packages
            local package_count=$(jq -r '.packages | length' "$file" 2>/dev/null || echo "0")
            log_info "Found $package_count packages"

            # Count relationships
            local relationship_count=$(jq -r '.relationships | length' "$file" 2>/dev/null || echo "0")
            log_info "Found $relationship_count relationships"

            ;;

        cyclonedx-json)
            log_info "Validating CycloneDX JSON format..."

            # Check required fields
            if ! jq -e '.specVersion' "$file" &> /dev/null; then
                log_error "Missing required field: specVersion"
                return 1
            fi

            if ! jq -e '.version' "$file" &> /dev/null; then
                log_error "Missing required field: version"
                return 1
            fi

            # Check spec version format
            local spec_version=$(jq -r '.specVersion' "$file")
            if [[ ! "$spec_version" =~ ^[0-9]+\.[0-9]+$ ]]; then
                log_error "Invalid specVersion format: $spec_version"
                return 1
            fi

            # Count components
            local component_count=$(jq -r '.components | length' "$file" 2>/dev/null || echo "0")
            log_info "Found $component_count components"

            # Count dependencies
            local dependency_count=$(jq -r '.dependencies | length' "$file" 2>/dev/null || echo "0")
            log_info "Found $dependency_count dependencies"

            ;;
    esac

    log_success "JSON format validation passed"
    return 0
}

# Verify XML format
verify_xml_format() {
    local file="$1"

    log_info "Verifying XML format..."

    if ! command -v xmllint &> /dev/null; then
        log_warning "xmllint not available, skipping XML validation"
        return 0
    fi

    # Basic XML syntax check
    if ! xmllint --noout "$file" 2>/dev/null; then
        log_error "Invalid XML syntax"
        return 1
    fi

    log_success "XML format validation passed"
    return 0
}

# Analyze SBOM content
analyze_sbom_content() {
    local file="$1"
    local format="$2"

    log_info "Analyzing SBOM content..."

    if ! command -v jq &> /dev/null; then
        log_warning "jq not available, skipping content analysis"
        return 0
    fi

    case "$format" in
        spdx-json|cyclonedx-json)
            # Count components with/without versions
            local total_components=0
            local components_with_versions=0
            local components_with_licenses=0

            if [[ "$format" == "spdx-json" ]]; then
                total_components=$(jq -r '.packages | length' "$file" 2>/dev/null || echo "0")
                components_with_versions=$(jq -r '[.packages[] | select(.versionInfo != null and .versionInfo != "")] | length' "$file" 2>/dev/null || echo "0")
                components_with_licenses=$(jq -r '[.packages[] | select(.licenseConcluded != null or .licenseDeclared != null)] | length' "$file" 2>/dev/null || echo "0")
            else
                total_components=$(jq -r '.components | length' "$file" 2>/dev/null || echo "0")
                components_with_versions=$(jq -r '[.components[] | select(.version != null and .version != "")] | length' "$file" 2>/dev/null || echo "0")
                components_with_licenses=$(jq -r '[.components[] | select(.licenses != null)] | length' "$file" 2>/dev/null || echo "0")
            fi

            log_info "Total components: $total_components"
            log_info "Components with versions: $components_with_versions"
            log_info "Components with licenses: $components_with_licenses"

            if [[ $total_components -gt 0 ]]; then
                local version_percentage=$(( components_with_versions * 100 / total_components ))
                local license_percentage=$(( components_with_licenses * 100 / total_components ))

                if [[ $version_percentage -lt 80 ]]; then
                    log_warning "Only $version_percentage% of components have version information"
                fi

                if [[ $license_percentage -lt 50 ]]; then
                    log_warning "Only $license_percentage% of components have license information"
                fi
            fi
            ;;
    esac

    log_success "Content analysis completed"
}

# Generate verification report
generate_report() {
    local file="$1"
    local format="$2"

    echo ""
    echo "SBOM Verification Report"
    echo "========================"
    echo "File: $file"
    echo "Format: $format"
    echo "Timestamp: $(date)"
    echo ""
    echo "Results:"
    echo "  [SUCCESS] Errors: $ERRORS"
    echo "  [WARNING] Warnings: $WARNINGS"
    echo "  [INFO] Info: $INFO"
    echo ""

    if [[ $ERRORS -eq 0 ]]; then
        log_success "SBOM verification PASSED"
        return 0
    else
        log_error "SBOM verification FAILED"
        return 1
    fi
}

# Main function
main() {
    local file="$1"
    local verbose="${2:-false}"

    echo "SBOM Verification Script"
    echo "========================"

    # Check if file is provided
    if [[ -z "$file" ]]; then
        echo "Usage: $0 <sbom-file> [--verbose]"
        echo ""
        echo "Examples:"
        echo "  $0 sbom.json"
        echo "  $0 sbom.spdx.json --verbose"
        echo "  $0 sbom.xml"
        exit 1
    fi

    # Check dependencies
    check_dependencies

    # Authenticate with Snyk (optional)
    authenticate_snyk || true

    # Verify file integrity
    if ! verify_file_integrity "$file"; then
        exit 1
    fi

    # Detect SBOM format
    local format=$(detect_sbom_format "$file")
    log_info "Detected format: $format"

    # Format-specific verification
    case "$format" in
        spdx-json|cyclonedx-json)
            verify_json_format "$file" "$format"
            ;;
        *-xml)
            verify_xml_format "$file"
            ;;
        spdx-tagvalue)
            log_info "Tag-value format detected (basic validation only)"
            ;;
        unknown*)
            log_warning "Unknown format, performing basic checks only"
            ;;
    esac

    # Verify with Snyk
    verify_with_snyk "$file"

    # Analyze content
    analyze_sbom_content "$file" "$format"

    # Generate report
    if generate_report "$file" "$format"; then
        exit 0
    else
        exit 1
    fi
}

# Parse command line arguments
VERBOSE=false
SNYK_TOKEN=""
SNYK_ORG=""
SBOM_FILE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --snyk-token|-t)
            if [[ -n "${2:-}" ]]; then
                SNYK_TOKEN="$2"
                export SNYK_TOKEN="$SNYK_TOKEN"
                shift 2
            else
                log_error "Option --snyk-token requires a value"
                exit 1
            fi
            ;;
        --snyk-org|-o)
            if [[ -n "${2:-}" ]]; then
                SNYK_ORG="$2"
                export SNYK_ORG="$SNYK_ORG"
                shift 2
            else
                log_error "Option --snyk-org requires a value"
                exit 1
            fi
            ;;
        --help|-h)
            echo "SBOM Verification Script"
            echo ""
            echo "Usage: $0 [options] <sbom-file>"
            echo ""
            echo "Options:"
            echo "  --verbose, -v                Enable verbose output"
            echo "  --snyk-token, -t TOKEN       Set Snyk API token"
            echo "  --snyk-org, -o ORG_ID        Set Snyk organization ID"
            echo "  --help, -h                   Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 sbom.json"
            echo "  $0 --verbose sbom.spdx.json"
            echo "  $0 --snyk-token=abc123 --snyk-org=my-org sbom.json"
            echo "  $0 -t abc123 -o my-org -v sbom.json"
            echo ""
            echo "Supported formats:"
            echo "  - SPDX JSON"
            echo "  - SPDX XML"
            echo "  - SPDX Tag-Value"
            echo "  - CycloneDX JSON"
            echo "  - CycloneDX XML"
            echo ""
            echo "Requirements:"
            echo "  - Snyk CLI (recommended)"
            echo "  - jq (for JSON processing)"
            echo "  - xmllint (for XML processing)"
            echo ""
            echo "Authentication:"
            echo "  You can authenticate with Snyk in several ways:"
            echo "  1. Command line: --snyk-token=your-token"
            echo "  2. Environment: export SNYK_TOKEN=your-token"
            echo "  3. Interactive: snyk auth"
            echo "  4. Get token from: https://app.snyk.io/account"
            exit 0
            ;;
        --*)
            log_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
        *)
            if [[ -z "$SBOM_FILE" ]]; then
                SBOM_FILE="$1"
            else
                log_error "Multiple SBOM files specified. Only one file is allowed."
                exit 1
            fi
            shift
            ;;
    esac
done

# Run main function
main "$SBOM_FILE" "$VERBOSE"
