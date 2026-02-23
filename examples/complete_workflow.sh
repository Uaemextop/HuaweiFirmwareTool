#!/bin/bash
#
# Example: Complete Workflow for Firmware Modification with Signatures
#
# This script demonstrates a complete workflow:
# 1. Unpack firmware
# 2. Generate RSA keys (for testing)
# 3. Sign the firmware components
# 4. Verify the signature
# 5. Repack the firmware
#

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== Huawei Firmware Complete Workflow Example ===${NC}"
echo ""

# Check arguments
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <firmware.bin>"
    echo ""
    echo "This example will:"
    echo "  - Unpack the firmware"
    echo "  - Generate test RSA keys"
    echo "  - Sign firmware components"
    echo "  - Verify signatures"
    echo "  - Repack with all components"
    exit 1
fi

FIRMWARE="$1"
WORK_DIR="./example_workflow"
BUILD_DIR="./build"

if [ ! -f "$FIRMWARE" ]; then
    echo "Error: Firmware file not found: $FIRMWARE"
    exit 1
fi

if [ ! -f "$BUILD_DIR/hw_fmw" ]; then
    echo "Error: Tools not built. Please run 'make' first."
    exit 1
fi

# Clean up previous run
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"

echo -e "${YELLOW}[1/6] Unpacking firmware...${NC}"
"$BUILD_DIR/hw_fmw" -d "$WORK_DIR/unpacked" -u -f "$FIRMWARE" -v
echo ""

echo -e "${YELLOW}[2/6] Generating test RSA keys...${NC}"
echo "  Note: These are for testing only. Use secure keys for production!"
openssl genrsa -out "$WORK_DIR/private.pem" 2048 > /dev/null 2>&1
openssl rsa -in "$WORK_DIR/private.pem" -pubout -out "$WORK_DIR/public.pem" > /dev/null 2>&1
echo "  Private key: $WORK_DIR/private.pem"
echo "  Public key:  $WORK_DIR/public.pem"
echo ""

echo -e "${YELLOW}[3/6] Marking components for signing...${NC}"
# Copy the sig_item_list.txt and mark critical components for signing
# We'll mark components that exist with '+'
cp "$WORK_DIR/unpacked/sig_item_list.txt" "$WORK_DIR/unpacked/sig_item_list.txt.bak"

# Mark rootfs for signing (most critical component)
sed -i 's/^- \(.*rootfs.*\)$/+ \1/' "$WORK_DIR/unpacked/sig_item_list.txt"
# Also mark kernel and uboot if they exist
sed -i 's/^- \(.*kernel.*\)$/+ \1/' "$WORK_DIR/unpacked/sig_item_list.txt"
sed -i 's/^- \(.*uboot.*\)$/+ \1/' "$WORK_DIR/unpacked/sig_item_list.txt"

echo "  Marked critical components for signing"
grep "^+ " "$WORK_DIR/unpacked/sig_item_list.txt" || echo "  (Components marked: rootfs and any kernel/uboot if present)"
echo ""

echo -e "${YELLOW}[4/6] Generating signature...${NC}"
"$BUILD_DIR/hw_sign" -d "$WORK_DIR/unpacked" -k "$WORK_DIR/private.pem" -o "$WORK_DIR/unpacked/signature"
echo ""

echo -e "${YELLOW}[5/6] Verifying signature...${NC}"
"$BUILD_DIR/hw_verify" -d "$WORK_DIR/unpacked" -k "$WORK_DIR/public.pem" -i "$WORK_DIR/unpacked/signature"
echo ""

echo -e "${YELLOW}[6/6] Repacking firmware...${NC}"
# Mark all items for inclusion
sed -i 's/^- /+ /' "$WORK_DIR/unpacked/item_list.txt"
"$BUILD_DIR/hw_fmw" -d "$WORK_DIR/unpacked" -p -o "$WORK_DIR/modified_firmware.bin" -v
echo ""

echo -e "${GREEN}=== Workflow Complete ===${NC}"
echo ""
echo "Results:"
echo "  Working directory:  $WORK_DIR/"
echo "  Unpacked files:     $WORK_DIR/unpacked/"
echo "  Test keys:          $WORK_DIR/private.pem & public.pem"
echo "  Signature:          $WORK_DIR/unpacked/signature"
echo "  Modified firmware:  $WORK_DIR/modified_firmware.bin"
echo ""
echo "File comparison:"
ls -lh "$FIRMWARE" "$WORK_DIR/modified_firmware.bin"
echo ""
echo "MD5 checksums:"
md5sum "$FIRMWARE" "$WORK_DIR/modified_firmware.bin"
echo ""
echo -e "${YELLOW}Note: In this example, no modifications were made, so the checksums match.${NC}"
echo -e "${YELLOW}To actually modify the firmware, edit files in $WORK_DIR/unpacked/ before step 6.${NC}"
