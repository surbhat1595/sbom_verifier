#!/bin/bash

# SBOM Verification Script
# This script verifies SBOM files using Snyk, Trivy, and other validation methods

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
        log_success "Snyk CLI found ($(snyk version))"
    else
        log_warning "Snyk CLI not found. Install with:"
        echo "  npm install -g snyk"
        echo "  # or"
        echo "  curl -Lo /usr/local/bin/snyk https://github.com/snyk/snyk/releases/latest/download/snyk-linux && chmod +x /usr/local/bin/snyk"
    fi

    # Check for Trivy
    if command -v trivy >/dev/null 2>&1; then
        local trivy_version=$(trivy --version | head -n1 | cut -d' ' -f2)
        log_success "Trivy found (version $trivy_version)"
    else
        log_error "Trivy not found. Please install it:"
        echo "  # Install via package manager:"
        echo "  sudo apt-get update && sudo apt-get install trivy  # Ubuntu/Debian"
        echo "  sudo dnf install trivy  # RHEL/Fedora"
        echo "  brew install trivy  # macOS"
        echo ""
        echo "  # Or install manually:"
        echo "  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin"
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

    # Skip if Snyk is not available
    if ! command -v snyk >/dev/null 2>&1; then
        log_info "Snyk not available, skipping authentication"
        return 1
    fi

    # Check if token is set via environment variable
    if [[ -n "${SNYK_TOKEN:-}" ]]; then
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
        # Try to determine auth method
        if snyk whoami >/dev/null 2>&1; then
            local snyk_user=$(snyk whoami 2>/dev/null | grep -E "username|email" || echo "authenticated user")
            log_info "Authenticated as: $snyk_user"
        fi
        return 0
    fi

    # Check if there's a stored auth config
    local snyk_config_dir="$HOME/.config/configstore"
    local snyk_config_file="$snyk_config_dir/snyk.json"
    
    if [[ -f "$snyk_config_file" ]]; then
        log_info "Found Snyk configuration file, checking validity..."
        if snyk auth --check >/dev/null 2>&1; then
            log_success "Snyk authentication verified via stored config"
            return 0
        else
            log_warning "Snyk config exists but authentication failed"
        fi
    fi

    # Check for legacy auth methods or if Snyk is in free mode
    log_warning "Snyk authentication status unclear"
    
    # Test if Snyk commands work without explicit auth (some features work in limited mode)
    if snyk test --help >/dev/null 2>&1; then
        log_info "Snyk CLI responds to commands (may be in limited/free mode)"
        log_warning "For full features, authenticate with: snyk auth"
        return 2  # Special return code for "working but not authenticated"
    fi

    log_warning "Snyk not authenticated. Some features may be limited."
    echo "  To authenticate, choose one of:"
    echo "  1. Run: snyk auth"
    echo "  2. Set token: export SNYK_TOKEN='your-token'"
    echo "  3. Get token from: https://app.snyk.io/account"
    return 1
}

# Update Trivy database
update_trivy_db() {
    log_info "Updating Trivy vulnerability database..."

    # Update Trivy DB (this is important for accurate results)
    if trivy image --download-db-only >/dev/null 2>&1; then
        log_success "Trivy database updated successfully"
    else
        log_warning "Failed to update Trivy database. Results may be outdated."
        log_info "You can manually update with: trivy image --download-db-only"
    fi
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

# Verify with Trivy
verify_with_trivy() {
    local file="$1"
    local temp_dir="/tmp/sbom_verification_$"
    
    log_info "Verifying SBOM with Trivy..."

    # Create temporary directory for results
    mkdir -p "$temp_dir"

    # Test SBOM with Trivy
    local trivy_result="$temp_dir/trivy_sbom_result.json"
    local trivy_stderr="$temp_dir/trivy_stderr.log"
    local trivy_exit_code=0

    # Run Trivy SBOM scan with better error handling
    if trivy sbom --format json --output "$trivy_result" "$file" 2>"$trivy_stderr"; then
        log_success "Trivy SBOM scan completed successfully"
    else
        trivy_exit_code=$?
        log_warning "Trivy SBOM scan completed with warnings/errors (exit code: $trivy_exit_code)"
        
        # Show detailed error information
        if [[ -s "$trivy_stderr" ]]; then
            log_info "Trivy error details:"
            if [[ "${VERBOSE:-false}" == "true" ]]; then
                cat "$trivy_stderr" | while IFS= read -r line; do
                    echo "    $line"
                done
            else
                head -3 "$trivy_stderr" | while IFS= read -r line; do
                    echo "    $line"
                done
                if [[ $(wc -l < "$trivy_stderr") -gt 3 ]]; then
                    echo "    ... (use --verbose for full error details)"
                fi
            fi
        fi
        
        # Try alternative scanning methods
        log_info "Attempting alternative Trivy scan methods..."
        
        # Try filesystem scan if SBOM scan failed
        local fs_result="$temp_dir/trivy_fs_fallback.json"
        local project_dir=$(dirname "$file")
        
        if trivy fs --format json --output "$fs_result" "$project_dir" 2>/dev/null; then
            log_info "Trivy filesystem scan succeeded as fallback"
            trivy_result="$fs_result"
        else
            # Try scanning the SBOM as a generic file
            if trivy fs --format json --output "$trivy_result" "$file" 2>/dev/null; then
                log_info "Trivy file scan succeeded as fallback"
            else
                log_warning "All Trivy scan methods failed"
                # Clean up and return
                if [[ "${VERBOSE:-false}" != "true" ]]; then
                    rm -rf "$temp_dir"
                fi
                return 1
            fi
        fi
    fi

# Create Trivy-compatible SBOM by filtering unsupported components
create_trivy_compatible_sbom() {
    local input_file="$1"
    local output_dir="$2"
    local filtered_file="$output_dir/filtered_sbom.json"
    
    # Check if jq is available for filtering
    if ! command -v jq &> /dev/null; then
        log_warning "jq not available for SBOM filtering"
        return 1
    fi
    
    # Check if input is valid JSON
    if ! jq empty "$input_file" 2>/dev/null; then
        log_warning "Input file is not valid JSON, cannot filter"
        return 1
    fi
    
    # Detect SBOM format to apply appropriate filtering
    if jq -e '.specVersion' "$input_file" &> /dev/null; then
        # CycloneDX format - filter out file components and other unsupported types
        log_info "Filtering CycloneDX SBOM for Trivy compatibility..."
        
        # Supported component types for Trivy: library, application, framework, container, operating-system
        jq '
        if .components then
            .components = [.components[] | select(.type and (.type == "library" or .type == "application" or .type == "framework" or .type == "container" or .type == "operating-system"))]
        else . end |
        if .dependencies then
            # Filter dependencies to only include those referencing remaining components
            .dependencies = [.dependencies[] | select(.ref as $ref | any(.components[]?; .["bom-ref"] == $ref))]
        else . end
        ' "$input_file" > "$filtered_file" 2>/dev/null
        
        if [[ $? -eq 0 ]] && [[ -s "$filtered_file" ]]; then
            local original_count=$(jq -r '.components | length' "$input_file" 2>/dev/null || echo "0")
            local filtered_count=$(jq -r '.components | length' "$filtered_file" 2>/dev/null || echo "0")
            log_info "Filtered SBOM: $original_count -> $filtered_count components (removed $((original_count - filtered_count)) unsupported components)"
            return 0
        else
            log_warning "Failed to create filtered CycloneDX SBOM"
            return 1
        fi
        
    elif jq -e '.spdxVersion' "$input_file" &> /dev/null; then
        # SPDX format - less filtering needed, but remove file packages if they cause issues
        log_info "Filtering SPDX SBOM for Trivy compatibility..."
        
        jq '
        if .packages then
            .packages = [.packages[] | select(.name and .name != "" and (.downloadLocation // "NOASSERTION") != "")]
        else . end
        ' "$input_file" > "$filtered_file" 2>/dev/null
        
        if [[ $? -eq 0 ]] && [[ -s "$filtered_file" ]]; then
            local original_count=$(jq -r '.packages | length' "$input_file" 2>/dev/null || echo "0")
            local filtered_count=$(jq -r '.packages | length' "$filtered_file" 2>/dev/null || echo "0")
            log_info "Filtered SBOM: $original_count -> $filtered_count packages"
            return 0
        else
            log_warning "Failed to create filtered SPDX SBOM"
            return 1
        fi
    else
        log_warning "Unknown SBOM format, cannot filter"
        return 1
    fi
}
    if [[ -f "$trivy_result" ]] && [[ -s "$trivy_result" ]] && command -v jq &> /dev/null; then
        log_info "Analyzing Trivy results..."

        # Validate JSON format first
        if ! jq empty "$trivy_result" 2>/dev/null; then
            log_warning "Trivy output is not valid JSON, attempting text analysis..."
            if [[ "${VERBOSE:-false}" == "true" ]]; then
                log_info "Raw Trivy output (first 10 lines):"
                head -10 "$trivy_result" | while IFS= read -r line; do
                    echo "    $line"
                done
            fi
        else
            # Count vulnerabilities by severity
            local critical_vulns=$(jq -r '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' "$trivy_result" 2>/dev/null || echo "0")
            local high_vulns=$(jq -r '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH")] | length' "$trivy_result" 2>/dev/null || echo "0")
            local medium_vulns=$(jq -r '[.Results[]?.Vulnerabilities[]? | select(.Severity == "MEDIUM")] | length' "$trivy_result" 2>/dev/null || echo "0")
            local low_vulns=$(jq -r '[.Results[]?.Vulnerabilities[]? | select(.Severity == "LOW")] | length' "$trivy_result" 2>/dev/null || echo "0")
            local unknown_vulns=$(jq -r '[.Results[]?.Vulnerabilities[]? | select(.Severity == "UNKNOWN")] | length' "$trivy_result" 2>/dev/null || echo "0")

            # Count total packages scanned
            local total_packages=$(jq -r '[.Results[]?.Packages[]?] | length' "$trivy_result" 2>/dev/null || echo "0")
            
            # Alternative counting if packages field is different
            if [[ "$total_packages" == "0" ]]; then
                total_packages=$(jq -r '[.Results[]?.Target] | length' "$trivy_result" 2>/dev/null || echo "0")
            fi

            log_info "Packages scanned: $total_packages"
            log_info "Vulnerabilities found:"
            echo "    Critical: $critical_vulns"
            echo "    High: $high_vulns"
            echo "    Medium: $medium_vulns"
            echo "    Low: $low_vulns"
            echo "    Unknown: $unknown_vulns"

            # Warn about critical/high vulnerabilities
            if [[ $critical_vulns -gt 0 ]]; then
                log_error "Found $critical_vulns CRITICAL vulnerabilities"
            fi

            if [[ $high_vulns -gt 0 ]]; then
                log_warning "Found $high_vulns HIGH severity vulnerabilities"
            fi

            # Generate detailed vulnerability report if verbose mode
            if [[ "${VERBOSE:-false}" == "true" ]] && [[ $(( critical_vulns + high_vulns )) -gt 0 ]]; then
                log_info "Top critical/high vulnerabilities:"
                jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL" or .Severity == "HIGH") | "  - \(.VulnerabilityID): \(.Title // .Description // "No description") (Severity: \(.Severity))"' "$trivy_result" 2>/dev/null | head -10 || true
            fi

            # Check for license issues
            local license_count=$(jq -r '[.Results[]?.Licenses[]?] | length' "$trivy_result" 2>/dev/null || echo "0")
            if [[ $license_count -gt 0 ]]; then
                log_info "Found $license_count license entries"
            fi

            # Check for secrets (if Trivy supports it in SBOM mode)
            local secrets_count=$(jq -r '[.Results[]?.Secrets[]?] | length' "$trivy_result" 2>/dev/null || echo "0")
            if [[ $secrets_count -gt 0 ]]; then
                log_warning "Found $secrets_count potential secrets"
            fi
        fi

    elif [[ -f "$trivy_result" ]]; then
        log_info "Trivy results saved to: $trivy_result"
        log_warning "jq not available for detailed result analysis"
        
        # Basic text analysis if jq is not available
        if grep -q "CRITICAL\|HIGH" "$trivy_result" 2>/dev/null; then
            log_warning "High severity vulnerabilities detected (install jq for detailed analysis)"
        fi
        
    else
        log_warning "Trivy results not available for analysis"
        
        # Provide troubleshooting hints
        if [[ "${VERBOSE:-false}" == "true" ]]; then
            log_info "Troubleshooting suggestions:"
            echo "  1. Check if the SBOM file format is supported by Trivy"
            echo "  2. Verify the SBOM file is valid JSON/XML"
            echo "  3. Try running: trivy sbom --debug $file"
            echo "  4. Update Trivy database: trivy image --download-db-only"
            echo "  5. Consider using --snyk-only if Trivy continues to fail"
            echo "  6. For CycloneDX SBOMs with file components, this is a known Trivy limitation"
        fi
    fi

    # Also try scanning for vulnerabilities in the project directory if it exists
    local project_dir=$(dirname "$file")
    if [[ -f "$project_dir/package.json" ]] || [[ -f "$project_dir/pom.xml" ]] || [[ -f "$project_dir/requirements.txt" ]] || [[ -f "$project_dir/go.mod" ]] || [[ -f "$project_dir/Cargo.toml" ]]; then
        log_info "Detected project files, running Trivy filesystem scan..."
        
        local fs_result="$temp_dir/trivy_fs_result.json"
        if trivy fs --format json --output "$fs_result" "$project_dir" 2>/dev/null; then
            log_success "Trivy filesystem scan completed"
            
            if command -v jq &> /dev/null; then
                local fs_vulns=$(jq -r '[.Results[]?.Vulnerabilities[]?] | length' "$fs_result" 2>/dev/null || echo "0")
                log_info "Filesystem scan found $fs_vulns vulnerabilities"
            fi
        else
            log_info "Trivy filesystem scan completed with warnings"
        fi
    fi

    # Clean up temp files (keep them if verbose for debugging)
    if [[ "${VERBOSE:-false}" != "true" ]]; then
        rm -rf "$temp_dir"
    else
        log_info "Trivy results saved in: $temp_dir"
    fi

    return 0
}

# Verify with Snyk
verify_with_snyk() {
    local file="$1"

    log_info "Verifying SBOM with Snyk..."

    # Skip if Snyk is not available
    if ! command -v snyk >/dev/null 2>&1; then
        log_info "Snyk not available, skipping Snyk verification"
        return 0
    fi

    # Check authentication status
    local auth_status=0
    if ! snyk auth --check >/dev/null 2>&1; then
        auth_status=1
        log_warning "Snyk not authenticated - attempting limited functionality"
    fi

    # Check if Snyk supports SBOM testing
    if snyk sbom --help &> /dev/null; then
        log_info "Using Snyk SBOM command..."

        # Test the SBOM file
        local snyk_result="/tmp/snyk_sbom_result_$.json"
        local snyk_stderr="/tmp/snyk_sbom_stderr_$.log"
        
        if snyk sbom test --file="$file" --format=json > "$snyk_result" 2>"$snyk_stderr"; then
            log_success "Snyk SBOM verification passed"

            # Parse results if jq is available
            if command -v jq &> /dev/null && [[ -s "$snyk_result" ]]; then
                # Check if result is valid JSON
                if jq empty "$snyk_result" 2>/dev/null; then
                    local vulnerabilities=$(jq -r '.vulnerabilities | length' "$snyk_result" 2>/dev/null || echo "0")
                    local licenses=$(jq -r '.licenses | length' "$snyk_result" 2>/dev/null || echo "0")

                    log_info "Found $vulnerabilities vulnerabilities"
                    log_info "Found $licenses license issues"

                    if [[ $vulnerabilities -gt 0 ]]; then
                        log_warning "Vulnerabilities found in SBOM components"
                        
                        if [[ "${VERBOSE:-false}" == "true" ]]; then
                            log_info "Vulnerability details (top 5):"
                            jq -r '.vulnerabilities[0:5][] | "  - \(.id): \(.title) (Severity: \(.severity))"' "$snyk_result" 2>/dev/null || true
                        fi
                    fi
                    
                    if [[ $licenses -gt 0 ]]; then
                        log_warning "License issues found in SBOM components"
                        
                        if [[ "${VERBOSE:-false}" == "true" ]]; then
                            log_info "License details (top 3):"
                            jq -r '.licenses[0:3][] | "  - \(.id): \(.title)"' "$snyk_result" 2>/dev/null || true
                        fi
                    fi
                else
                    log_warning "Snyk returned invalid JSON response"
                    
                    # Try to parse as text output (common when not fully authenticated)
                    if [[ -s "$snyk_result" ]]; then
                        local first_line=$(head -1 "$snyk_result")
                        
                        if echo "$first_line" | grep -q -i "no.*vulnerabilities\|no.*issues"; then
                            log_info "Snyk found no vulnerabilities (text response)"
                            log_info "Note: JSON output may require authentication"
                        elif echo "$first_line" | grep -q -i "vulnerabilities\|issues.*found"; then
                            log_warning "Snyk found vulnerabilities (text response)"
                            if [[ "${VERBOSE:-false}" == "true" ]]; then
                                log_info "Snyk text output (first 10 lines):"
                                head -10 "$snyk_result" | while IFS= read -r line; do
                                    echo "    $line"
                                done
                            fi
                        elif echo "$first_line" | grep -q -i "authentication\|login\|unauthorized"; then
                            log_warning "Snyk authentication required for JSON output"
                            log_info "Text parsing: checking for vulnerability indicators..."
                            if grep -q -i "high\|critical\|medium" "$snyk_result" 2>/dev/null; then
                                log_warning "Potential vulnerabilities detected in text output"
                            fi
                        else
                            if [[ "${VERBOSE:-false}" == "true" ]]; then
                                log_info "Raw Snyk output (first 5 lines):"
                                head -5 "$snyk_result" | while IFS= read -r line; do
                                    echo "    $line"
                                done
                            fi
                            
                            # Try to extract useful information from text
                            local vuln_count=$(grep -c -i "vulnerability\|CVE-" "$snyk_result" 2>/dev/null || echo "0")
                            if [[ $vuln_count -gt 0 ]]; then
                                log_info "Text analysis found $vuln_count potential vulnerability references"
                            fi
                        fi
                    fi
                fi
            fi
        else
            local exit_code=$?
            log_warning "Snyk SBOM test failed or found issues (exit code: $exit_code)"
            
            # Analyze stderr for specific error messages
            if [[ -s "$snyk_stderr" ]]; then
                local stderr_content=$(cat "$snyk_stderr")
                
                if echo "$stderr_content" | grep -q -i "unauthorized\|authentication\|api.*key\|token"; then
                    log_warning "Snyk authentication issue detected"
                    log_info "This may explain why Snyk appeared to work but is now failing"
                    echo "  Possible reasons:"
                    echo "  1. Previous authentication session expired"
                    echo "  2. SBOM testing requires different permissions"
                    echo "  3. Rate limiting without authentication"
                    echo "  4. Organization-specific SBOM features require auth"
                    
                elif echo "$stderr_content" | grep -q -i "rate.limit\|quota\|usage"; then
                    log_warning "Snyk rate limiting detected (authentication may help)"
                    
                elif echo "$stderr_content" | grep -q -i "unsupported\|format\|parse"; then
                    log_warning "Snyk doesn't support this SBOM format or structure"
                    
                else
                    log_info "Snyk error details:"
                    if [[ "${VERBOSE:-false}" == "true" ]]; then
                        echo "$stderr_content" | while IFS= read -r line; do
                            echo "    $line"
                        done
                    else
                        echo "$stderr_content" | head -3 | while IFS= read -r line; do
                            echo "    $line"
                        done
                        echo "    ... (use --verbose for full details)"
                    fi
                fi
            fi
        fi
        
        # Clean up temp files
        rm -f "$snyk_result" "$snyk_stderr"
        
    else
        # Fallback: try to use regular Snyk test on the project
        log_info "Snyk SBOM command not available, trying alternative verification..."

        # If the SBOM is in a project directory, we can test the project
        local project_dir=$(dirname "$file")
        if [[ -f "$project_dir/package.json" ]] || [[ -f "$project_dir/pom.xml" ]] || [[ -f "$project_dir/requirements.txt" ]]; then
            log_info "Testing project directory with Snyk..."
            local project_result="/tmp/snyk_project_result_$.json"
            
            if snyk test --json "$project_dir" > "$project_result" 2>&1; then
                log_success "Snyk project test passed"
            else
                log_warning "Snyk project test found issues"
                if [[ "${VERBOSE:-false}" == "true" ]]; then
                    head -10 "$project_result" 2>/dev/null || true
                fi
            fi
            
            rm -f "$project_result"
        else
            log_warning "Cannot perform Snyk verification without project context"
            if [[ $auth_status -eq 1 ]]; then
                log_info "Note: Authentication might enable additional Snyk SBOM features"
            fi
        fi
    fi
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

            # Add component type breakdown analysis
            log_info "Component type breakdown:"
            if [[ "$format" == "spdx-json" ]]; then
                # SPDX doesn't have explicit component types, analyze by other means
                local packages_with_purl=$(jq -r '[.packages[] | select(.externalRefs[]?.referenceType == "purl")] | length' "$file" 2>/dev/null || echo "0")
                local packages_with_files=$(jq -r '[.packages[] | select(.hasFiles == true)] | length' "$file" 2>/dev/null || echo "0")
                echo "    Packages with PURL: $packages_with_purl"
                echo "    Packages with files: $packages_with_files"
                echo "    Other packages: $((total_components - packages_with_purl - packages_with_files))"
            else
                # CycloneDX has explicit component types
                jq -r '.components | group_by(.type) | map("    \(length) \(.[0].type // "unknown") components") | .[]' "$file" 2>/dev/null || echo "    Could not analyze component types"
            fi

            # Analyze components missing critical information
            if [[ $total_components -gt 10 ]]; then
                log_info "Data quality analysis:"
                
                if [[ "$format" == "cyclonedx-json" ]]; then
                    # Check for components without versions
                    local no_version_sample=$(jq -r '[.components[] | select(.version == null or .version == "") | .name] | .[0:3] | .[]' "$file" 2>/dev/null)
                    if [[ -n "$no_version_sample" ]]; then
                        echo "    Components without versions (sample):"
                        echo "$no_version_sample" | while IFS= read -r comp; do
                            echo "      - $comp"
                        done
                    fi

                    # Check for components without licenses
                    local no_license_sample=$(jq -r '[.components[] | select(.licenses == null) | .name] | .[0:3] | .[]' "$file" 2>/dev/null)
                    if [[ -n "$no_license_sample" ]]; then
                        echo "    Components without licenses (sample):"
                        echo "$no_license_sample" | while IFS= read -r comp; do
                            echo "      - $comp"
                        done
                    fi

                    # Check for file components (often cause issues)
                    local file_components=$(jq -r '[.components[] | select(.type == "file")] | length' "$file" 2>/dev/null || echo "0")
                    if [[ $file_components -gt 0 ]]; then
                        log_warning "Found $file_components file components (may cause Trivy compatibility issues)"
                        if [[ "${VERBOSE:-false}" == "true" ]]; then
                            echo "    File components (sample):"
                            jq -r '[.components[] | select(.type == "file") | .name] | .[0:5] | .[]' "$file" 2>/dev/null | while IFS= read -r comp; do
                                echo "      - $comp"
                            done
                        fi
                    fi

                    # Check for library components with good metadata
                    local library_components=$(jq -r '[.components[] | select(.type == "library")] | length' "$file" 2>/dev/null || echo "0")
                    local library_with_versions=$(jq -r '[.components[] | select(.type == "library" and .version != null and .version != "")] | length' "$file" 2>/dev/null || echo "0")
                    if [[ $library_components -gt 0 ]]; then
                        local lib_version_percentage=$(( library_with_versions * 100 / library_components ))
                        echo "    Library components: $library_components (${lib_version_percentage}% with versions)"
                        if [[ $lib_version_percentage -lt 90 ]]; then
                            log_warning "Library components missing version information may indicate SBOM generation issues"
                        fi
                    fi
                fi
            fi

            # Security-relevant analysis
            if [[ "$format" == "cyclonedx-json" ]]; then
                # Check for components with known security-relevant indicators
                local components_with_cpe=$(jq -r '[.components[] | select(.cpe != null)] | length' "$file" 2>/dev/null || echo "0")
                local components_with_purl=$(jq -r '[.components[] | select(.purl != null)] | length' "$file" 2>/dev/null || echo "0")
                local components_with_hashes=$(jq -r '[.components[] | select(.hashes != null and (.hashes | length) > 0)] | length' "$file" 2>/dev/null || echo "0")

                if [[ $components_with_cpe -gt 0 ]] || [[ $components_with_purl -gt 0 ]] || [[ $components_with_hashes -gt 0 ]]; then
                    log_info "Security identifiers:"
                    echo "    Components with CPE: $components_with_cpe"
                    echo "    Components with PURL: $components_with_purl"
                    echo "    Components with hashes: $components_with_hashes"
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
    echo "Tools used:"
    if command -v trivy >/dev/null 2>&1; then
        echo "  - Trivy: $(trivy --version | head -n1 | cut -d' ' -f2)"
    fi
    if command -v snyk >/dev/null 2>&1; then
        echo "  - Snyk: $(snyk version)"
    fi
    if command -v jq >/dev/null 2>&1; then
        echo "  - jq: $(jq --version)"
    fi
    if command -v xmllint >/dev/null 2>&1; then
        echo "  - xmllint: available"
    fi
    echo ""
    echo "Results:"
    echo "  Errors: $ERRORS"
    echo "  Warnings: $WARNINGS"
    echo "  Info messages: $INFO"
    echo ""

    if [[ $ERRORS -eq 0 ]]; then
        log_success "SBOM verification PASSED"
        if [[ $WARNINGS -gt 0 ]]; then
            echo "  Note: $WARNINGS warnings found - review recommended"
        fi
        return 0
    else
        log_error "SBOM verification FAILED"
        echo "  Please address the $ERRORS error(s) found"
        return 1
    fi
}

# Main function
main() {
    local file="$1"

    echo "SBOM Verification Script"
    echo "========================"
    
    if [[ "${VERBOSE:-false}" == "true" ]]; then
        echo "Running in verbose mode..."
        echo "File: $file"
        echo "Options: TRIVY_ONLY=${TRIVY_ONLY:-false}, SNYK_ONLY=${SNYK_ONLY:-false}"
        echo ""
    fi

    # Check if file is provided
    if [[ -z "$file" ]]; then
        echo "Usage: $0 <sbom-file> [options]"
        echo ""
        echo "Examples:"
        echo "  $0 sbom.json"
        echo "  $0 sbom.spdx.json --verbose"
        echo "  $0 sbom.xml --trivy-only"
        echo ""
        echo "Use --help for more options"
        exit 1
    fi

    # Check dependencies
    check_dependencies
    
    if [[ "${VERBOSE:-false}" == "true" ]]; then
        echo "Verbose mode: Dependency check completed"
        echo ""
    fi

    # Update Trivy database if not skipped
    if [[ "${SKIP_TRIVY_UPDATE:-false}" != "true" ]]; then
        update_trivy_db
    elif [[ "${VERBOSE:-false}" == "true" ]]; then
        log_info "Skipping Trivy database update as requested"
    fi

    # Authenticate with Snyk (optional)
    if [[ "${SNYK_ONLY:-false}" != "true" ]] && [[ "${TRIVY_ONLY:-false}" != "true" ]]; then
        authenticate_snyk || true
    fi

    # Verify file integrity
    if ! verify_file_integrity "$file"; then
        exit 1
    fi

    # Detect SBOM format
    local format=$(detect_sbom_format "$file")
    log_info "Detected format: $format"
    
    if [[ "${VERBOSE:-false}" == "true" ]]; then
        local file_size=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null)
        log_info "File size: $(( file_size / 1024 )) KB"
    fi

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

    # Run security scans
    if [[ "${SNYK_ONLY:-false}" != "true" ]]; then
        if [[ "${VERBOSE:-false}" == "true" ]]; then
            log_info "Starting Trivy verification..."
        fi
        verify_with_trivy "$file"
    fi

    if [[ "${TRIVY_ONLY:-false}" != "true" ]]; then
        if [[ "${VERBOSE:-false}" == "true" ]]; then
            log_info "Starting Snyk verification..."
        fi
        verify_with_snyk "$file"
    fi

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
TRIVY_ONLY=false
SNYK_ONLY=false
SKIP_TRIVY_UPDATE=false

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
        --trivy-only)
            TRIVY_ONLY=true
            shift
            ;;
        --snyk-only)
            SNYK_ONLY=true
            shift
            ;;
        --skip-trivy-update)
            SKIP_TRIVY_UPDATE=true
            shift
            ;;
        --help|-h)
            cat << 'EOF'
SBOM Verification Script with Trivy and Snyk

Usage: $0 [options] <sbom-file>

Options:
  --verbose, -v                Enable verbose output
  --snyk-token, -t TOKEN       Set Snyk API token
  --snyk-org, -o ORG_ID        Set Snyk organization ID
  --trivy-only                 Run only Trivy verification
  --snyk-only                  Run only Snyk verification
  --skip-trivy-update          Skip Trivy database update
  --help, -h                   Show this help message

Examples:
  $0 sbom.json
  $0 --verbose sbom.spdx.json
  $0 --trivy-only sbom.json
  $0 --snyk-token=abc123 --snyk-org=my-org sbom.json
  $0 -t abc123 -o my-org -v sbom.json

Supported formats:
  - SPDX JSON
  - SPDX XML
  - SPDX Tag-Value
  - CycloneDX JSON
  - CycloneDX XML

Requirements:
  - Trivy (recommended for vulnerability scanning)
  - Snyk CLI (optional, for additional vulnerability checks)
  - jq (for JSON processing)
  - xmllint (for XML processing)

Tool Installation:
  Trivy:
    - Package manager: sudo apt-get install trivy
    - Manual: curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

  Snyk:
    - npm install -g snyk
    - curl -Lo /usr/local/bin/snyk https://github.com/snyk/snyk/releases/latest/download/snyk-linux && chmod +x /usr/local/bin/snyk

Authentication:
  Snyk (optional):
    1. Command line: --snyk-token=your-token
    2. Environment: export SNYK_TOKEN=your-token
    3. Interactive: snyk auth
    4. Get token from: https://app.snyk.io/account

  Trivy:
    - No authentication required for basic usage
    - Database updates automatically

Environment Variables:
  SNYK_TOKEN                   Snyk API token
  SNYK_ORG                     Snyk organization ID
  SKIP_TRIVY_UPDATE           Set to 'true' to skip DB update
  VERBOSE                     Set to 'true' for verbose output
EOF
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

# Validate conflicting options
if [[ "$TRIVY_ONLY" == "true" && "$SNYK_ONLY" == "true" ]]; then
    log_error "Cannot specify both --trivy-only and --snyk-only"
    exit 1
fi

# Check if SBOM file was provided
if [[ -z "$SBOM_FILE" ]]; then
    log_error "No SBOM file specified"
    echo "Use --help for usage information"
    exit 1
fi

# Export variables for use in functions
export VERBOSE
export TRIVY_ONLY
export SNYK_ONLY
export SKIP_TRIVY_UPDATE

# Run main function
main "$SBOM_FILE"