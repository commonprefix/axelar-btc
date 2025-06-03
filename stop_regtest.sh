#!/bin/bash
set -euo pipefail
echo "Stopping any existing bitcoind..."
bitcoin-cli -regtest stop || true