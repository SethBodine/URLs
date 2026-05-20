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
- **Google Safe Browsing** — URL canonicalization and threat check at creation time (optional, free)
- **Scheduled Safe Browsing rescan** — daily cron re-checks all stored links; deactivates flagged ones without deleting them
- **IP blocklist** — auto-blocks submitter IPs on threat detection (creation or rescan); silent blank response; admin-managed
- QR codes with custom logo (client-side, no third-party)
- Admin panel with stats, search, select mode, batch delete, rescan trigger, and IP blocklist management
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
    _safebrowsing.js ← Google Safe Browsing API v4 integration + URL canonicalization
    _blocklist.js    ← IP blocklist helpers (check, add, remove, list)
    _rescan.js       ← Safe Browsing rescan logic (shared by cron + HTTP trigger)
    _ratelimit.js    ← IP-based rate limiting (hourly + daily KV counters)
    _conspiracies.js ← X-Truth header content
    api/
      shorten.js     ← POST /api/shorten
      lookup.js      ← POST /api/lookup
      admin.js       ← GET|DELETE /api/admin
      mylinks.js     ← GET|DELETE|PATCH /api/mylinks
      scan.js        ← POST /api/scan + scheduled cron handler
      blocklist.js   ← GET|POST|DELETE /api/blocklist

Cloudflare KV (LINKS namespace)
  {slug}             ← link record (JSON)
  rl:{endpoint}:{ip}:{window}  ← rate-limit counters (auto-expire)
  bl:ip:{ip}         ← blocklist entries (permanent until removed)
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
    "checked":          true,
    "checkedAt":        "2026-04-29T10:00:00.000Z",
    "checkedUrl":       "https://example.com/destination",
    "lastRescannedAt":  "2026-05-20T03:00:00.000Z",
    "rescannedClean":   true
  },

  "_deactivated_fields_present_only_when_flagged": null,
  "deactivated":        true,
  "deactivatedAt":      "2026-05-20T03:00:00.000Z",
  "deactivatedReason":  "safe_browsing_rescan",
  "deactivatedThreats": ["MALWARE"]
}
```

`accessLog` is a rolling window capped at 50 entries. `accessCount` is the lifetime total (not capped).  
`deactivated` and related fields are only present if the link was flagged post-creation.  
`checkedUrl` is the canonicalized URL that was actually submitted to the Safe Browsing API.

### Blocklist Entry Schema

Stored under `bl:ip:{normalized-ip}`:

```json
{
  "ip":          "1.2.3.4",
  "addedAt":     "2026-05-20T03:00:00.000Z",
  "reason":      "threat_at_rescan",
  "triggerSlug": "ab3x",
  "threats":     ["MALWARE"],
  "addedBy":     "system"
}
```

`reason` is one of: `threat_at_creation`, `threat_at_rescan`, `manual`.  
`addedBy` is one of: `system` (auto-blocked), `admin` (manually blocked).

---

## Environment Variables

All secrets are set in Cloudflare — **never in source code**.

| Variable | Required | Description |
|---|---|---|
| `ADMIN_KEY` | **Yes** | Bearer token for `/api/admin`, `/api/scan`, `/api/blocklist` — minimum 16 characters |
| `OWNER_HASH_SECRET` | **Yes** | HMAC-SHA256 secret for browser fingerprint verification — minimum 32 characters |
| `SAFE_BROWSING_API_KEY` | Recommended | Google Safe Browsing API key — creation check and rescan both skip if absent |

`ADMIN_KEY` and `OWNER_HASH_SECRET` must be set as **Encrypted** variables in Cloudflare Pages.  
`SAFE_BROWSING_API_KEY` can be encrypted or plain — it's a Google API key, not a user secret.

Without `SAFE_BROWSING_API_KEY` the blocklist still works for manually-blocked IPs, but no
automatic threat detection or auto-blocking will occur.

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

#### 5. Redeploy and Set Up the Cron Trigger

1. **Deployments → Retry deployment** (picks up new env vars)
2. **Custom domains → Set up domain** → follow DNS instructions
3. Set up the scheduled rescan cron trigger:
   - **Workers & Pages → your project → Settings → Functions → Cron Triggers**
   - Click **Add Cron Trigger** and enter: `0 3 * * *` (daily at 03:00 UTC)
   - Save

> **Why not wrangler.toml?** The `[triggers]` key is Cloudflare Workers-only and causes a build failure in Pages projects. The cron must be configured through the dashboard instead. The `onScheduled` handler in `functions/api/scan.js` is called automatically once the dashboard trigger is set up.

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

Same as Option A steps 5.

---

## Google Safe Browsing Setup (Optional but Recommended)

Checks every submitted URL against Google's threat lists (malware, phishing, unwanted software)
at creation time and during scheduled rescans. Free for up to 10,000 lookups/day.

1. Go to [console.cloud.google.com](https://console.cloud.google.com)
2. Create a project (or use an existing one)
3. **APIs & Services → Enable APIs** → search **Safe Browsing API** → Enable
4. **APIs & Services → Credentials → Create Credentials → API Key**
5. Copy the key → paste as `SAFE_BROWSING_API_KEY` in Cloudflare Pages secrets

If the key is absent or the API is unreachable, link creation and rescans proceed without Safe
Browsing checks (fail-open). The IP blocklist continues to work independently.

### Cron Schedule

The rescan runs daily at `03:00 UTC` by default. To change it:

1. Go to **Workers & Pages → your project → Settings → Functions → Cron Triggers**
2. Delete the existing trigger and add a new one with your preferred expression

Common expressions:

```
0 3 * * *      daily at 03:00 UTC (default)
0 */6 * * *    every 6 hours
0 3 * * 0      weekly on Sunday at 03:00 UTC
```

> `[triggers] crons = [...]` in `wrangler.toml` is a **Workers-only** configuration key. Using it in a Pages project causes a build failure. Always configure Pages cron triggers through the dashboard.

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

Safe Browsing and the rescan are skipped locally if `SAFE_BROWSING_API_KEY` is empty — that's fine for development. The IP blocklist still works locally via KV.

The cron trigger (`POST /api/scan`) can be called manually during development:

```bash
curl -X POST http://localhost:8788/api/scan \
  -H "Authorization: Bearer local-test-admin-key-change-me" \
  -H "Content-Type: application/json" \
  -d '{}'
```

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
X-Fingerprint: "<raw browser fingerprint string>"
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

**Notes:**
- If the URL is flagged by Safe Browsing, the response is an **empty `200`** with no body — no error is returned (the submitting IP is silently blocked)
- If the submitting IP is already on the blocklist, the response is also an empty `200`
- **Errors:** `400` bad JSON · `409` slug taken · `422` validation failure · `429` rate limited

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

---

### `DELETE /api/mylinks`

Delete one of your own links. Returns `403` if you don't own the slug.

```json
{ "slug": "ab3x" }
```

---

### `PATCH /api/mylinks`

Toggle preview mode on one of your own links.

```json
{ "slug": "ab3x", "previewMode": true }
```

---

### `GET /api/admin`

List all links. Requires `Authorization: Bearer ADMIN_KEY`.

**Response:** `{ "links": [...], "count": 42 }`

---

### `DELETE /api/admin`

Delete one link, a batch, or purge everything. Requires `Authorization: Bearer ADMIN_KEY`.

```json
{ "slug": "ab3x" }
{ "slugs": ["ab3x", "yz9q", "my-link"] }
{ "purgeAll": true }
```

---

### `POST /api/scan`

Trigger a Safe Browsing rescan of all stored links. Requires `Authorization: Bearer ADMIN_KEY`.

**Request (optional):**
```json
{ "forceAll": true }
```

`forceAll: true` re-checks links that are already deactivated (default: skipped).

**Response:**
```json
{
  "success": true,
  "stats": {
    "startedAt":    "2026-05-20T03:00:00.000Z",
    "completedAt":  "2026-05-20T03:00:04.231Z",
    "scanned":      142,
    "clean":        139,
    "newlyFlagged": 3,
    "ipsBlocked":   2,
    "skipped":      0,
    "errors":       0,
    "flaggedSlugs": ["ab3x", "yz9q", "bad1"],
    "errorSlugs":   []
  }
}
```

---

### `GET /api/blocklist`

List all blocked IPs. Requires `Authorization: Bearer ADMIN_KEY`.

**Response:**
```json
{
  "entries": [
    {
      "ip":          "1.2.3.4",
      "addedAt":     "2026-05-20T03:00:00.000Z",
      "reason":      "threat_at_rescan",
      "triggerSlug": "ab3x",
      "threats":     ["MALWARE"],
      "addedBy":     "system"
    }
  ],
  "count": 1
}
```

---

### `POST /api/blocklist`

Manually block an IP. Requires `Authorization: Bearer ADMIN_KEY`.

```json
{ "ip": "1.2.3.4" }
```

Accepts both IPv4 and IPv6. Returns `422` if the string is not a valid IP address.

---

### `DELETE /api/blocklist`

Unblock an IP. Requires `Authorization: Bearer ADMIN_KEY`.

```json
{ "ip": "1.2.3.4" }
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

# List all links (admin)
curl https://b0x.nz/api/admin \
  -H "Authorization: Bearer YOUR_ADMIN_KEY"

# Delete a link (admin)
curl -X DELETE https://b0x.nz/api/admin \
  -H "Authorization: Bearer YOUR_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"slug":"ab3x"}'

# Trigger a manual rescan (admin)
curl -X POST https://b0x.nz/api/scan \
  -H "Authorization: Bearer YOUR_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{}'

# Rescan including already-deactivated links
curl -X POST https://b0x.nz/api/scan \
  -H "Authorization: Bearer YOUR_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"forceAll":true}'

# List blocked IPs (admin)
curl https://b0x.nz/api/blocklist \
  -H "Authorization: Bearer YOUR_ADMIN_KEY"

# Manually block an IP (admin)
curl -X POST https://b0x.nz/api/blocklist \
  -H "Authorization: Bearer YOUR_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"ip":"1.2.3.4"}'

# Unblock an IP (admin)
curl -X DELETE https://b0x.nz/api/blocklist \
  -H "Authorization: Bearer YOUR_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"ip":"1.2.3.4"}'

# Preview a slug without visiting it
curl -X POST https://b0x.nz/api/lookup \
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

- **Google Safe Browsing** — URL canonicalization before submission; checks every URL against malware, phishing, and unwanted software lists at creation time and on scheduled rescans
- **Silent threat blocking** — flagged URLs return an empty `200`, not a descriptive error; the submitting IP is immediately blocked; prevents probing and information leakage
- **IP blocklist** — permanent KV-backed blocklist; IPv6 normalization closes compressed-notation bypass; blocked IPs get silent `200` responses with no content
- **Retroactive deactivation** — daily rescan catches URLs added before a threat was listed; deactivated slugs serve `410 Gone` without exposing the destination
- **XSS prevention** — `escapeHtml()` applied to all user-supplied strings before HTML rendering
- **Owner hash isolation** — browser fingerprint is HMAC-hashed server-side; raw fingerprint never stored; owners can only see/edit/delete their own links
- **Access log capped** — rolling window of 50 entries prevents unbounded KV growth on high-traffic links; lifetime `accessCount` is always accurate
- **KV expiry** — `expirationTtl` set directly on KV entries so Cloudflare auto-purges them; no cron job required for expiry

---

## Costs

| Service | Free Tier | Notes |
|---|---|---|
| Cloudflare Pages | ∞ requests, 500 builds/month | Static hosting |
| Cloudflare Workers | 100k requests/day | Functions |
| Cloudflare KV | 100k reads, 1k writes, 1GB/day | Link storage + blocklist |
| Google Safe Browsing | 10,000 lookups/day | Optional — creation + rescan |

**Total: $0** for personal or low-traffic use.

---

## Licence

MIT — see [LICENSE](./LICENSE).
