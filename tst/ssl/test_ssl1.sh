#!/bin/bash

# Test SSL handshake with DH/DHE
CLIENT="main_client1"
SERVER="main_server"

# Cleanup function
cleanup() {
    echo "Cleaning up processes..."
    pkill -f $SERVER 2>/dev/null || true
    pkill -f $CLIENT 2>/dev/null || true
    rm -f *.log
}

# Set up error handling
set -e
trap cleanup EXIT

# Build everything
echo "Building SSL library..."
(cd ../../src/ssl && make clean && make) || exit 1

echo "Building test executables..."
make clean
make $SERVER || exit 1
make $CLIENT || exit 1

# Run tests
echo "Starting server..."
./$SERVER &
SERVER_PID=$!

echo "Waiting for server to initialize..."
sleep 2

echo "Starting client 1..."
./$CLIENT 1 &
CLIENT1_PID=$!

echo "Starting client 2..."
sleep 1
./$CLIENT 2 &
CLIENT2_PID=$!

# Wait for tests to complete
sleep 8

# Exit cleanly
exit 0

