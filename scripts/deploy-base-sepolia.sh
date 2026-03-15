#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
#  SIGIL PROTOCOL — Base Sepolia Deployment Guide
# ═══════════════════════════════════════════════════════════════════
#
#  Prerequisites:
#  1. Node.js installed
#  2. A wallet with Base Sepolia ETH (see step 1 below)
#  3. Export your private key from MetaMask
#
# ═══════════════════════════════════════════════════════════════════

echo "═══════════════════════════════════════════════════"
echo "  SIGIL-RD: Base Sepolia Deployment"
echo "═══════════════════════════════════════════════════"

# ── STEP 1: Get Base Sepolia ETH ──────────────────────────────────
# Option A: Coinbase faucet (recommended)
#   https://www.coinbase.com/faucets/base-ethereum-goerli-faucet
#
# Option B: Alchemy faucet
#   https://www.alchemy.com/faucets/base-sepolia
#
# Option C: Bridge from Sepolia ETH
#   https://bridge.base.org/deposit (switch to Sepolia testnet)

# ── STEP 2: Set environment variables ─────────────────────────────
# Create .env file:
#
#   PRIVATE_KEY=your_private_key_here_without_0x_prefix
#   BASE_SEPOLIA_RPC_URL=https://sepolia.base.org
#   BASESCAN_API_KEY=your_basescan_api_key (optional, for verification)
#
# Or export them directly:

if [ -z "$PRIVATE_KEY" ]; then
    echo ""
    echo "ERROR: PRIVATE_KEY not set."
    echo ""
    echo "Usage:"
    echo "  export PRIVATE_KEY=your_private_key"
    echo "  export BASE_SEPOLIA_RPC_URL=https://sepolia.base.org"
    echo "  bash scripts/deploy-base-sepolia.sh"
    echo ""
    echo "Or with .env:"
    echo "  cp .env.example .env"
    echo "  # Edit .env with your values"
    echo "  npx hardhat run scripts/deploy.js --network baseSepolia"
    exit 1
fi

export BASE_SEPOLIA_RPC_URL=${BASE_SEPOLIA_RPC_URL:-"https://sepolia.base.org"}

echo ""
echo "Network: Base Sepolia (Chain ID 84532)"
echo "RPC: $BASE_SEPOLIA_RPC_URL"
echo ""

# ── STEP 3: Deploy ────────────────────────────────────────────────
npx hardhat run scripts/deploy.js --network baseSepolia

# ── STEP 4: Verify on BaseScan (optional) ─────────────────────────
# After deployment, note the contract address and run:
#
# npx hardhat verify --network baseSepolia <CONTRACT_ADDRESS>
#
# This requires BASESCAN_API_KEY in your environment.
# Get one at: https://basescan.org/myapikey

echo ""
echo "═══════════════════════════════════════════════════"
echo "  Next steps:"
echo "  1. Copy the contract address above"
echo "  2. Verify: npx hardhat verify --network baseSepolia <ADDRESS>"
echo "  3. View on: https://sepolia.basescan.org/address/<ADDRESS>"
echo "  4. Update README.md with the contract address"
echo "  5. Update Zenodo DOI in README.md"
echo "═══════════════════════════════════════════════════"
