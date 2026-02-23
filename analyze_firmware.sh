#!/bin/bash
#
# Huawei Firmware Analysis Script
# This script helps analyze Huawei firmware files using various tools
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

show_usage() {
    cat << EOF
Usage: $0 [OPTIONS] <firmware.bin>

Analyze Huawei firmware files using multiple tools.

OPTIONS:
    -h, --help          Show this help message
    -o, --output DIR    Output directory for unpacked files (default: ./unpacked)
    -d, --deep          Perform deep analysis with binwalk and radare2
    -s, --sign KEY      Generate signature with private key
    -v, --verify KEY    Verify signature with public key

EXAMPLES:
    # Basic analysis and unpacking
    $0 firmware.bin

    # Deep analysis with output directory
    $0 -d -o /tmp/fw_analysis firmware.bin

    # Unpack and generate signature
    $0 -s private.pem -o ./unpacked firmware.bin

    # Verify existing signature
    $0 -v public.pem -o ./unpacked firmware.bin

EOF
}

log_info() {
    echo -e "${GREEN}[+]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[*]${NC} $1"
}

log_error() {
    echo -e "${RED}[-]${NC} $1"
}

# Default values
OUTPUT_DIR="./unpacked"
DEEP_ANALYSIS=0
SIGN_KEY=""
VERIFY_KEY=""
FIRMWARE=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_usage
            exit 0
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -d|--deep)
            DEEP_ANALYSIS=1
            shift
            ;;
        -s|--sign)
            SIGN_KEY="$2"
            shift 2
            ;;
        -v|--verify)
            VERIFY_KEY="$2"
            shift 2
            ;;
        *)
            if [ -z "$FIRMWARE" ]; then
                FIRMWARE="$1"
            else
                log_error "Unknown option: $1"
                show_usage
                exit 1
            fi
            shift
            ;;
    esac
done

# Check if firmware file is provided
if [ -z "$FIRMWARE" ]; then
    log_error "No firmware file specified"
    show_usage
    exit 1
fi

# Check if firmware file exists
if [ ! -f "$FIRMWARE" ]; then
    log_error "Firmware file not found: $FIRMWARE"
    exit 1
fi

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"

# Check if tools are built
if [ ! -f "$BUILD_DIR/hw_fmw" ]; then
    log_warn "Tools not built. Building now..."
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    cmake .. && make
    cd - > /dev/null
fi

log_info "=== Huawei Firmware Analysis ==="
log_info "Firmware: $FIRMWARE"
log_info "Output: $OUTPUT_DIR"
echo ""

# Basic file info
log_info "File Information:"
file "$FIRMWARE"
ls -lh "$FIRMWARE"
echo ""

# Show hex header
log_info "Firmware Header (first 64 bytes):"
hexdump -C "$FIRMWARE" | head -4
echo ""

# Unpack firmware
log_info "Unpacking firmware..."
mkdir -p "$OUTPUT_DIR"
"$BUILD_DIR/hw_fmw" -d "$OUTPUT_DIR" -u -f "$FIRMWARE" -v
echo ""

# Show unpacked contents
log_info "Unpacked contents:"
ls -lh "$OUTPUT_DIR"
echo ""

log_info "Item list:"
cat "$OUTPUT_DIR/item_list.txt"
echo ""

# Deep analysis with binwalk
if [ "$DEEP_ANALYSIS" -eq 1 ]; then
    log_info "=== Deep Analysis ==="

    if command -v binwalk &> /dev/null; then
        log_info "Running binwalk analysis..."
        binwalk "$FIRMWARE" | head -20
        echo ""
    else
        log_warn "binwalk not installed, skipping"
    fi

    # Analyze individual components
    for item in "$OUTPUT_DIR"/*; do
        if [ -f "$item" ] && [ ! "$item" = "$OUTPUT_DIR/item_list.txt" ] && [ ! "$item" = "$OUTPUT_DIR/sig_item_list.txt" ]; then
            filename=$(basename "$item")
            log_info "Analyzing: $filename"
            file "$item"

            # Check if it's a filesystem image
            if file "$item" | grep -q "filesystem"; then
                log_info "  -> Detected filesystem image"
            fi

            # Check if it's compressed
            if file "$item" | grep -q "gzip\|bzip2\|xz\|lzma"; then
                log_info "  -> Detected compressed data"
            fi
        fi
    done
    echo ""
fi

# Generate signature if requested
if [ -n "$SIGN_KEY" ]; then
    if [ ! -f "$SIGN_KEY" ]; then
        log_error "Private key not found: $SIGN_KEY"
        exit 1
    fi

    log_info "Generating signature..."

    # Mark items to sign
    sed 's/^- /+ /' "$OUTPUT_DIR/sig_item_list.txt" > "$OUTPUT_DIR/sig_item_list.txt.tmp"
    mv "$OUTPUT_DIR/sig_item_list.txt.tmp" "$OUTPUT_DIR/sig_item_list.txt"

    "$BUILD_DIR/hw_sign" -d "$OUTPUT_DIR" -k "$SIGN_KEY" -o "$OUTPUT_DIR/signature"
    log_info "Signature saved to: $OUTPUT_DIR/signature"
    echo ""
fi

# Verify signature if requested
if [ -n "$VERIFY_KEY" ]; then
    if [ ! -f "$VERIFY_KEY" ]; then
        log_error "Public key not found: $VERIFY_KEY"
        exit 1
    fi

    if [ ! -f "$OUTPUT_DIR/signature" ]; then
        log_error "Signature file not found: $OUTPUT_DIR/signature"
        exit 1
    fi

    log_info "Verifying signature..."
    "$BUILD_DIR/hw_verify" -d "$OUTPUT_DIR" -k "$VERIFY_KEY" -i "$OUTPUT_DIR/signature"
    echo ""
fi

log_info "=== Analysis Complete ==="
log_info "To repack the firmware:"
log_info "  1. Edit $OUTPUT_DIR/item_list.txt (mark items with '+' to include)"
log_info "  2. Run: $BUILD_DIR/hw_fmw -d $OUTPUT_DIR -p -o new_firmware.bin -v"
