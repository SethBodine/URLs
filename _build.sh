#!/bin/bash
set -e

# ─────────────────────────────────────────────────────────────────────────────
# Cloudflare Pages Build Script
# ─────────────────────────────────────────────────────────────────────────────
# This script runs during the Cloudflare Pages build process.
# It substitutes placeholder tokens in wrangler.toml with real values from
# Cloudflare environment variables.
#
# The substituted wrangler.toml exists only during this build — it is never
# committed back to the repository.
# ─────────────────────────────────────────────────────────────────────────────

echo "→ Injecting KV namespace IDs into wrangler.toml from CF environment variables..."

# Check that required environment variables are set
if [ -z "$KV_NAMESPACE_ID" ]; then
  echo "ERROR: KV_NAMESPACE_ID environment variable is not set."
  echo "Set it in: Pages → Settings → Environment variables"
  exit 1
fi

if [ -z "$KV_PREVIEW_NAMESPACE_ID" ]; then
  echo "ERROR: KV_PREVIEW_NAMESPACE_ID environment variable is not set."
  echo "Set it in: Pages → Settings → Environment variables"
  exit 1
fi

# Perform the substitution
sed -i \
  -e "s|__KV_NAMESPACE_ID__|$KV_NAMESPACE_ID|g" \
  -e "s|__KV_PREVIEW_NAMESPACE_ID__|$KV_PREVIEW_NAMESPACE_ID|g" \
  wrangler.toml

# Verify substitution succeeded (fail loudly if tokens remain)
if grep -q "__KV_" wrangler.toml; then
  echo "ERROR: wrangler.toml still contains unsubstituted tokens after build script."
  echo "Check that KV_NAMESPACE_ID and KV_PREVIEW_NAMESPACE_ID are set correctly."
  exit 1
fi

echo "✓ KV namespace IDs injected successfully."
echo "✓ Build ready."
