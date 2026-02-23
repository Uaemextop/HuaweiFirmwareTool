#!/bin/bash
#
# Quick Repack Script
# Automatically marks all items for inclusion and repacks firmware
#

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <unpacked_dir> <output_firmware.bin>"
    echo ""
    echo "Example:"
    echo "  $0 unpacked repacked_firmware.bin"
    exit 1
fi

UNPACKED_DIR="$1"
OUTPUT_BIN="$2"

if [ ! -d "$UNPACKED_DIR" ]; then
    echo "Error: Directory not found: $UNPACKED_DIR"
    exit 1
fi

if [ ! -f "$UNPACKED_DIR/item_list.txt" ]; then
    echo "Error: item_list.txt not found in $UNPACKED_DIR"
    exit 1
fi

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"

if [ ! -f "$BUILD_DIR/hw_fmw" ]; then
    echo "Error: hw_fmw not built. Please run 'make' first."
    exit 1
fi

echo "[+] Marking all items for inclusion..."
sed 's/^- /+ /' "$UNPACKED_DIR/item_list.txt" > "$UNPACKED_DIR/item_list.txt.tmp"
mv "$UNPACKED_DIR/item_list.txt.tmp" "$UNPACKED_DIR/item_list.txt"

echo "[+] Repacking firmware..."
"$BUILD_DIR/hw_fmw" -d "$UNPACKED_DIR" -p -o "$OUTPUT_BIN" -v

if [ $? -eq 0 ]; then
    echo ""
    echo "[+] Successfully repacked firmware to: $OUTPUT_BIN"
    ls -lh "$OUTPUT_BIN"
else
    echo ""
    echo "[-] Failed to repack firmware"
    exit 1
fi
