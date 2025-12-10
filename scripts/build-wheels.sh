#!/bin/bash
# Build wheels for the current platform

set -e

echo "Building Cedar-py wheels..."

# Check if maturin is installed
if ! command -v maturin &> /dev/null; then
    echo "Installing maturin..."
    pip install maturin
fi

# Build release wheel
echo "Building release wheel for current platform..."
maturin build --release

echo ""
echo "✓ Wheels built successfully!"
echo "Location: target/wheels/"
echo ""
echo "To install: pip install target/wheels/cedar_py-*.whl"
