#!/bin/bash
set -e

# ─────────────────────────────────────────────────────────────────────────────
# Cloudflare Pages Build Script
# ─────────────────────────────────────────────────────────────────────────────
# Substitutes KV namespace IDs from Cloudflare build environment variables.
# These must be set in: Settings → Environment variables → Production/Preview
# WITHOUT the "Encrypt" toggle (build vars can't be encrypted).
# ─────────────────────────────────────────────────────────────────────────────

echo "→ Injecting KV namespace IDs..."

if [ -z "$CF_PAGES" ]; then
  echo "ERROR: Not running in Cloudflare Pages build environment."
  echo "For local dev, copy wrangler.local.toml.example to wrangler.local.toml"
  exit 1
fi

if [ -z "$KV_NAMESPACE_ID" ] || [ -z "$KV_PREVIEW_NAMESPACE_ID" ]; then
  echo "ERROR: KV namespace ID environment variables not set."
  echo "Set these in Cloudflare Pages dashboard:"
  echo "  Settings → Environment variables → Production"
  echo "  KV_NAMESPACE_ID = your production namespace ID"
  echo "  KV_PREVIEW_NAMESPACE_ID = your preview namespace ID"
  echo "  (do NOT enable 'Encrypt' - build vars must be plaintext)"
  exit 1
fi

# Substitute tokens in wrangler.toml
sed -i \
  -e "s|__KV_NAMESPACE_ID__|$KV_NAMESPACE_ID|g" \
  -e "s|__KV_PREVIEW_NAMESPACE_ID__|$KV_PREVIEW_NAMESPACE_ID|g" \
  wrangler.toml

# Verify
if grep -q "__KV_" wrangler.toml; then
  echo "ERROR: Substitution failed - tokens remain in wrangler.toml"
  exit 1
fi

echo "✓ KV namespace IDs injected"
