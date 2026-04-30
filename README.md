# b0x.nz — Self-Hosted URL Shortener on Cloudflare Pages

Minimal, secure, zero-cost URL shortener running entirely on Cloudflare Pages + Workers + KV.

**Cost:** $0 (Cloudflare free tier)  
**Licence:** MIT  
**Dependencies:** Zero npm packages — native Workers runtime only  

---

## Features

- 4-character auto-generated slugs + optional custom slugs
- **Preview interstitial** — optional 5-second countdown before redirect, with cancel button
- **URL preview lookup** — reveal a link's destination without visiting it
- **My Links** — browser-fingerprint-based self-service: view, edit, and delete your own links
- **Link expiry** — 30 / 60 / 90 / 180 / 365 days, enforced at KV level (auto-deleted)
- **Access logging** — IP, user agent, country, city, and timestamp per visit (rolling 50-entry window)
- **Google Safe Browsing** check at creation time (optional, free)
- QR codes with custom logo (client-side, no third-party)
- Admin panel (`/admin.html`) with full stats and search
- JSON API with single and batch slug lookup
- OWASP Top 10 mitigations (see Security section)
- Conspiracy Easter eggs in `X-Truth` response header

---

## Architecture

```
Cloudflare Pages (static)
  public/
    index.html       ← main UI (shorten / preview / my links)
    admin.html       ← admin panel
    _headers         ← CSP + security headers for static files

Cloudflare Pages Functions (Workers)
  functions/
    [slug].js        ← redirect handler + access logging + preview interstitial
    _security.js     ← shared validation, auth, owner-hash, access-log helpers
    _safebrowsing.js ← Google Safe Browsing API integration
    _conspiracies.js ← X-Truth header content
    api/
      shorten.js     ← POST /api/shorten
      lookup.js      ← POST /api/lookup
      admin.js       ← GET|DELETE /api/admin
      mylinks.js     ← GET|DELETE|PATCH /api/mylinks

Cloudflare KV
  LINKS              ← one key per slug, JSON record (see schema below)
```

---

## KV Record Schema

```json
{
  "slug":            "ab3x",
  "url":             "https://example.com/destination",
  "createdAt":       "2026-04-29T10:00:00.000Z",
  "creatorIp":       "1.2.3.4",
  "creatorUa":       "Mozilla/5.0 ...",
  "creatorCountry":  "NZ",
  "creatorCity":     "Auckland",
  "ownerHash":       "a1b2c3d4e5f6...",
  "previewMode":     false,
  "expiryDays":      30,
  "expiresAt":       "2026-05-29T10:00:00.000Z",
  "accessCount":     12,
  "lastAccessed":    "2026-04-30T08:15:00.000Z",
  "accessLog": [
    { "ip": "5.6.7.8", "ua": "...", "country": "AU", "city": "Sydney", "ts": "2026-04-30T08:15:00.000Z" }
  ],
  "safeBrowsing": {
    "checked":   true,
    "checkedAt": "2026-04-29T10:00:00.000Z"
  }
}
```

`accessLog` is a rolling window capped at 50 entries. `accessCount` is the lifetime total (not capped).

---

## Environment Variables

All secrets are set in Cloudflare — **never in source code**.

| Variable | Required | Description |
|---|---|---|
| `ADMIN_KEY` | **Yes** | Bearer token for `/api/admin` — minimum 16 characters |
| `OWNER_HASH_SECRET` | **Yes** | HMAC-SHA256 secret for browser fingerprint verification — minimum 32 characters |
| `SAFE_BROWSING_API_KEY` | Optional | Google Safe Browsing API key — link creation skips check if absent |
| `KV_NAMESPACE_ID` | Option B only | Production KV namespace ID (build-time injection) |
| `KV_PREVIEW_NAMESPACE_ID` | Option B only | Preview KV namespace ID (build-time injection) |

`ADMIN_KEY` and `OWNER_HASH_SECRET` must be set as **Encrypted** variables in Cloudflare Pages.  
`SAFE_BROWSING_API_KEY` can be encrypted or plain — it's a Google API key, not a user secret.

### Generating secrets

```bash
# ADMIN_KEY (32-byte hex = 64 chars)
openssl rand -hex 32

# OWNER_HASH_SECRET (32-byte hex = 64 chars)
openssl rand -hex 32
```

---

## Deployment

Two options — choose based on whether you want any infrastructure identifiers visible in the repo.

### Option A — Hardcode KV IDs (Recommended for most users)

KV namespace IDs are infrastructure identifiers, not credentials. An attacker with only the namespace ID cannot read or write your data.

#### 1. Create KV Namespaces

1. [dash.cloudflare.com](https://dash.cloudflare.com) → **Workers & Pages → KV**
2. Create `shortener-links` → copy the **Namespace ID**
3. Create `shortener-links-preview` → copy that **Namespace ID**

#### 2. Edit wrangler.toml

```toml
[[kv_namespaces]]
binding    = "LINKS"
id         = "YOUR_PRODUCTION_NAMESPACE_ID"
preview_id = "YOUR_PREVIEW_NAMESPACE_ID"
```

Commit and push.

#### 3. Create Pages Project

1. **Workers & Pages → Create → Pages → Connect to Git**
2. Select your repository
3. Build settings:
   - Build command: *(leave blank)*
   - Build output directory: `public`
4. **Save and Deploy**

#### 4. Set Secrets

**Settings → Environment variables** — add for both Production and Preview:

| Variable | Value | Encrypt |
|---|---|---|
| `ADMIN_KEY` | `openssl rand -hex 32` | ✅ Yes |
| `OWNER_HASH_SECRET` | `openssl rand -hex 32` | ✅ Yes |
| `SAFE_BROWSING_API_KEY` | *(your Google API key)* | ✅ Yes |

#### 5. Redeploy and Add Domain

1. **Deployments → Retry deployment** (so the new env vars are picked up)
2. **Custom domains → Set up domain** → follow DNS instructions

---

### Option B — Build-Time ID Injection (Zero IDs in Repo)

Use this if you want the repo to contain no infrastructure identifiers at all.

#### 1. Create KV Namespaces

Same as Option A — create two namespaces, copy both IDs.

#### 2. Leave wrangler.toml as-is

The `_build.sh` script substitutes `__KV_NAMESPACE_ID__` and `__KV_PREVIEW_NAMESPACE_ID__` tokens at build time.

#### 3. Create Pages Project

1. **Workers & Pages → Create → Pages → Connect to Git**
2. Build settings:
   - **Build command:** `bash _build.sh`
   - Build output directory: `public`

#### 4. Set All Variables

Add for both Production and Preview:

| Variable | Value | Encrypt |
|---|---|---|
| `KV_NAMESPACE_ID` | Your production namespace ID | ❌ No* |
| `KV_PREVIEW_NAMESPACE_ID` | Your preview namespace ID | ❌ No* |
| `ADMIN_KEY` | `openssl rand -hex 32` | ✅ Yes |
| `OWNER_HASH_SECRET` | `openssl rand -hex 32` | ✅ Yes |
| `SAFE_BROWSING_API_KEY` | Your Google API key | ✅ Yes |

*Build scripts cannot read encrypted variables, so namespace IDs must remain unencrypted.

#### 5. Deploy and Add Domain

Same as Option A steps 4–5.

---

## Google Safe Browsing Setup (Optional)

Checks every submitted URL against Google's threat lists (malware, phishing, unwanted software) at creation time. Free for up to 10,000 lookups/day.

1. Go to [console.cloud.google.com](https://console.cloud.google.com)
2. Create a project (or use an existing one)
3. **APIs & Services → Enable APIs** → search **Safe Browsing API** → Enable
4. **APIs & Services → Credentials → Create Credentials → API Key**
5. Copy the key → paste as `SAFE_BROWSING_API_KEY` in Cloudflare Pages secrets

If the key is absent or the API is unreachable, link creation proceeds normally (fail-open). Flagged URLs return a `422` error with the threat types.

---

## Local Development

```bash
# Install Wrangler
npm install -g wrangler
wrangler login

# Create local KV namespaces
wrangler kv:namespace create "local-links"
wrangler kv:namespace create "local-links" --preview

# Create wrangler.local.toml (gitignored)
cp wrangler.local.toml.example wrangler.local.toml
# Edit: paste your local namespace IDs

# Create .dev.vars (gitignored) — local equivalents of CF secrets
cat > .dev.vars << EOF
ADMIN_KEY=local-test-admin-key-change-me
OWNER_HASH_SECRET=local-test-owner-secret-minimum-32-chars-x
SAFE_BROWSING_API_KEY=
EOF

# Run dev server
wrangler pages dev public
# → http://localhost:8788
```

Safe Browsing is skipped locally if `SAFE_BROWSING_API_KEY` is empty — that's fine for development.

---

## API Reference

All endpoints return `Content-Type: application/json` with security headers on every response.

---

### `POST /api/shorten`

Create a shortened URL.

**Request:**
```json
{
  "url":        "https://example.com/long/path",
  "customSlug": "my-link",
  "preview":    false,
  "expiryDays": 30
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `url` | string | Yes | Destination URL (http/https only, 2048 char max) |
| `customSlug` | string | No | 2–32 chars, a-z 0-9 hyphens underscores |
| `preview` | boolean | No | Show 5-second interstitial before redirect |
| `expiryDays` | number | No | One of: 30, 60, 90, 180, 365. Omit for no expiry |

**Headers (optional — for My Links ownership):**
```
X-Fingerprint: <raw browser fingerprint string>
X-Owner-Hash:  <HMAC hash returned or cached from previous request>
```

**Response `200`:**
```json
{
  "shortUrl":    "https://b0x.nz/ab3x",
  "slug":        "ab3x",
  "url":         "https://example.com/long/path",
  "previewMode": false,
  "expiresAt":   "2026-05-29T10:00:00.000Z",
  "ownerLinked": true,
  "truth":       "..."
}
```

**Errors:** `400` bad JSON · `409` slug taken · `422` validation or Safe Browsing block

---

### `POST /api/lookup`

Reveal the destination of a short URL without visiting it. Public fields are returned to everyone; private fields (`creatorIp`, `creatorUa`, `ownerHash`, `accessLog`) require either admin auth or verified owner headers.

**Single lookup:**
```json
{ "slug": "ab3x" }
```

**Batch lookup (max 50):**
```json
{ "slugs": ["ab3x", "yz9q"] }
```

**Response (public):**
```json
{
  "slug":           "ab3x",
  "shortUrl":       "https://b0x.nz/ab3x",
  "url":            "https://example.com",
  "createdAt":      "2026-04-29T10:00:00.000Z",
  "previewMode":    false,
  "expiresAt":      null,
  "accessCount":    7,
  "lastAccessed":   "2026-04-30T08:00:00.000Z",
  "creatorCountry": "NZ"
}
```

Add `Authorization: Bearer ADMIN_KEY` or owner headers to also receive `creatorIp`, `creatorUa`, `creatorCity`, `ownerHash`, `accessLog`.

---

### `GET /api/mylinks`

List all URLs linked to the current browser fingerprint. Requires owner headers.

**Headers:**
```
X-Fingerprint: <raw fingerprint>
X-Owner-Hash:  <cached hash>
```

**Response:**
```json
{
  "links": [
    {
      "slug":        "ab3x",
      "shortUrl":    "https://b0x.nz/ab3x",
      "url":         "https://example.com",
      "createdAt":   "2026-04-29T10:00:00.000Z",
      "previewMode": false,
      "expiresAt":   null,
      "expiryDays":  null,
      "accessCount": 7,
      "lastAccessed":"2026-04-30T08:00:00.000Z",
      "accessLog":   [...]
    }
  ],
  "count": 1
}
```

---

### `DELETE /api/mylinks`

Delete one of your own links. Ownership is verified server-side.

```json
{ "slug": "ab3x" }
```

Requires owner headers. Returns `403` if you don't own the slug.

---

### `PATCH /api/mylinks`

Toggle preview mode on one of your own links.

```json
{ "slug": "ab3x", "previewMode": true }
```

Requires owner headers.

---

### `GET /api/admin`

List all links. Requires `Authorization: Bearer ADMIN_KEY`.

**Response:** `{ "links": [...], "count": 42 }`

---

### `DELETE /api/admin`

Delete one link or purge all. Requires `Authorization: Bearer ADMIN_KEY`.

```json
{ "slug": "ab3x" }
{ "purgeAll": true }
```

---

## curl Examples

```bash
# Shorten a URL
curl -X POST https://b0x.nz/api/shorten \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'

# Shorten with custom slug, expiry, and preview interstitial
curl -X POST https://b0x.nz/api/shorten \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com","customSlug":"demo","expiryDays":30,"preview":true}'

# Preview a slug without visiting it
curl -X POST https://b0x.nz/api/lookup \
  -H "Content-Type: application/json" \
  -d '{"slug":"ab3x"}'

# List all links (admin)
curl https://b0x.nz/api/admin \
  -H "Authorization: Bearer YOUR_ADMIN_KEY"

# Delete a link (admin)
curl -X DELETE https://b0x.nz/api/admin \
  -H "Authorization: Bearer YOUR_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"slug":"ab3x"}'

# Check conspiracy header
curl -sI https://b0x.nz/ab3x | grep x-truth
```

---

## Security

### OWASP Top 10 Mitigations

| Risk | Mitigation |
|---|---|
| A01 Broken Access Control | Timing-safe admin key comparison; HMAC-verified owner hash; reserved slug blocklist |
| A02 Cryptographic Failures | All secrets in Cloudflare encrypted env vars; HMAC-SHA256 for fingerprint; no secrets in source |
| A03 Injection | Allowlist regex on all slugs; native `URL` API for parsing; `escapeHtml()` on all rendered content; KV keys only from validated slugs |
| A04 Insecure Design | http/https only; no embedded credentials in URLs; preview interstitial blocks direct redirect |
| A05 Misconfiguration | Security headers on all responses; CSP via `_headers`; no verbose server errors; admin CORS locked to same-origin |
| A06 Vulnerable Components | Zero npm dependencies — native Workers runtime only |
| A07 Auth Failures | `timingSafeEqual()` for admin key; owner ops require verified HMAC header |
| A08 Data Integrity | NFKC normalisation; control chars stripped; 8KB body cap; KV TTL for expiry |
| A09 Logging | Creator IP/UA/country/city at creation; rolling 50-entry access log per slug with IP/UA/country/city/timestamp |
| A10 SSRF | Private IPv4/IPv6 ranges, loopback, cloud metadata endpoints all blocked before KV write |

### Additional Protections

- **Google Safe Browsing** — checks every URL against malware, phishing, and unwanted software lists at creation time
- **XSS prevention** — `escapeHtml()` applied to all user-supplied strings before any HTML rendering (fixes original vulnerability in admin panel)
- **Owner hash isolation** — browser fingerprint is HMAC-hashed server-side; raw fingerprint never stored; owners can only see/edit/delete their own links
- **Access log capped** — rolling window of 50 entries prevents unbounded KV growth on high-traffic links; lifetime `accessCount` is always accurate
- **KV expiry** — `expirationTtl` set directly on KV entries so Cloudflare auto-purges them; no cron job required

---

## Costs

| Service | Free Tier | Notes |
|---|---|---|
| Cloudflare Pages | ∞ requests, 500 builds/month | Static hosting |
| Cloudflare Workers | 100k requests/day | Functions |
| Cloudflare KV | 100k reads, 1k writes, 1GB/day | Link storage |
| Google Safe Browsing | 10,000 lookups/day | Optional |

**Total: $0** for personal or low-traffic use.

---

## Licence

MIT — see [LICENSE](./LICENSE).
