#!/bin/bash
set -euo pipefail

BITCOIN_DIR="/Users/tzinas/Library/Application Support/Bitcoin/regtest"

echo "Stopping any existing bitcoind..."
bitcoin-cli -regtest stop || true
sleep 1

echo "Cleaning regtest directory..."
rm -rf "$BITCOIN_DIR"

echo "Starting bitcoind..."
bitcoind -daemon -chain=regtest
sleep 1