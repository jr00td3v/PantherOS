#!/bin/bash
# PantherOS QEMU Run Script
# 
# Usage: ./run.sh [debug|release]

set -e

MODE="${1:-release}"
KERNEL="target/aarch64-unknown-none/${MODE}/pantheros"

# Build if needed
if [ ! -f "$KERNEL" ] || [ "$(find src -newer "$KERNEL" 2>/dev/null)" ]; then
    echo "Building kernel (${MODE})..."
    if [ "$MODE" = "debug" ]; then
        cargo build
    else
        cargo build --release
    fi
fi

echo "Starting QEMU..."
echo "Press Ctrl+A then X to exit"
echo ""

qemu-system-aarch64 \
    -machine virt \
    -cpu cortex-a72 \
    -m 128M \
    -nographic \
    -kernel "$KERNEL"
