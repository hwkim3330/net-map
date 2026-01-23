#!/bin/bash
# Net-Map Build Script for Linux
# Requires: cmake, ninja-build, libpcap-dev

set -e

# Kill running instance if exists
pkill -f net-map 2>/dev/null || true

# Create build directory
mkdir -p build

# Configure if needed
if [ ! -f build/build.ninja ]; then
    echo "Configuring with CMake..."
    cmake -B build -G Ninja
fi

# Build
echo "Building..."
cmake --build build

echo ""
echo "Build successful!"
echo "Output: build/bin/net-map"
echo ""
echo "Run with: sudo ./build/bin/net-map -l"
