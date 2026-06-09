#!/usr/bin/env bash
set -euo pipefail

BUILD_DIR="${1:-build}"

cmake -S . -B "$BUILD_DIR"
cmake --build "$BUILD_DIR"

echo ""
echo "Build complete. Run tests with: ./$BUILD_DIR/test_cauth"
echo "Run cauth with:        ./$BUILD_DIR/cauth --help"
