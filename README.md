# Link Shortener — Self-Hosted on Cloudflare Pages

Minimal, secure, free link shortener on Cloudflare Pages + Workers + KV.

**Cost:** $0 (Cloudflare free tier)  
**Licence:** MIT  
**Security:** All secrets in Cloudflare only

---

## Two Deployment Options

You can deploy this in two ways, depending on your security preferences:

### Option A: Hardcode KV Namespace IDs (Simpler, Recommended)

**Repo stays public.** KV namespace IDs are infrastructure identifiers, not credentials. An attacker can't read/write your data with just the namespace ID - they'd need your Cloudflare account credentials.

**Pros:** Simple, no build script, easier to debug  
**Cons:** Your infrastructure topology is visible (but harmless)

### Option B: Inject IDs at Build Time (Zero IDs in Repo)

**Repo can be public or private.** Use a build script that reads namespace IDs from Cloudflare environment variables at build time.

**Pros:** Zero infrastructure identifiers in repo  
**Cons:** More complex, requires build script, harder to debug

Choose based on your threat model. **Most users should use Option A.**

---

## Features

- 4-character short codes + optional custom slugs
- QR codes with custom logo (client-side)
- Browser localStorage for history
- Metadata: IP, country, user agent, timestamp
- Admin panel (`/admin.html`)
- JSON API (single/batch lookup)
- Conspiracy Easter eggs
- OWASP Top 10 mitigations
- Zero npm dependencies
- Domain-agnostic (all branding from `window.location`)

---

## Deployment — Option A (Recommended)

### Step 1 — Create KV Namespaces

1. [dash.cloudflare.com](https://dash.cloudflare.com) → **Workers & Pages → KV**
2. Create namespace (e.g. `shortener-links`) → **copy the namespace ID**
3. Create preview namespace (e.g. `shortener-links-preview`) → **copy that ID**

### Step 2 — Add IDs to wrangler.toml

Edit `wrangler.toml` in your local repo:

```toml
[[kv_namespaces]]
binding = "LINKS"
id = "abc123..."           # paste your production namespace ID here
preview_id = "def456..."   # paste your preview namespace ID here
```

Commit and push:

```bash
git add wrangler.toml
git commit -m "add KV namespace IDs"
git push
```

### Step 3 — Create Pages Project

1. **Workers & Pages → Create → Pages → Connect to Git**
2. Select your repository
3. Build settings:
   - Production branch: `main`
   - Build command: *(blank)*
   - Build output directory: `public`
4. Click **Save and Deploy**

### Step 4 — Set ADMIN_KEY

1. **Settings → Environment variables → Add variable**
2. For **Production** and **Preview**:
   - Variable name: `ADMIN_KEY`
   - Value: `openssl rand -hex 32`
   - **Encrypt: ON**

### Step 5 — Redeploy & Add Domain

1. **Deployments → Retry deployment**
2. **Custom domains → Set up domain**
3. Test with the curl commands below

---

## Deployment — Option B (Zero IDs in Repo)

### Step 1 — Create KV Namespaces

Same as Option A - create two namespaces, **copy both IDs**.

### Step 2 — Keep wrangler.toml as Placeholders

**Do NOT edit wrangler.toml.** Leave it with the `__KV_NAMESPACE_ID__` tokens.

### Step 3 — Create Pages Project

1. **Workers & Pages → Create → Pages → Connect to Git**
2. Select your repository  
3. Build settings:
   - Production branch: `main`
   - **Build command:** `bash _build.sh`
   - Build output directory: `public`
4. **Don't click Save yet** — continue to Step 4

### Step 4 — Set Build Environment Variables

Still on the project creation screen, scroll to **Environment variables**.

Add these **three** for **Production**:

| Variable | Value | Encrypt? |
|---|---|---|
| `KV_NAMESPACE_ID` | Your production namespace ID | **No** |
| `KV_PREVIEW_NAMESPACE_ID` | Your preview namespace ID | **No** |
| `ADMIN_KEY` | `openssl rand -hex 32` | **Yes** |

Repeat for **Preview** (same values or different).

**Why aren't the namespace IDs encrypted?** Build scripts can't read encrypted variables. Only `ADMIN_KEY` should be encrypted (it's a runtime variable).

Now click **Save and Deploy**.

### Step 5 — Add Domain

Same as Option A.

---

## Verify Deployment

```bash
# Shorten URL
curl -X POST https://YOUR_DOMAIN/api/shorten \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'

# Follow redirect
curl https://YOUR_DOMAIN/xxxx

# Check conspiracy header
curl -sI https://YOUR_DOMAIN/xxxx | grep x-truth

# Test admin (should fail)
curl https://YOUR_DOMAIN/api/admin

# Test admin with key
curl https://YOUR_DOMAIN/api/admin \
  -H "Authorization: Bearer YOUR_ADMIN_KEY"

# Open browser
https://YOUR_DOMAIN/admin.html
```

---

## Local Development

```bash
# Install Wrangler
npm install -g wrangler
wrangler login

# Create local namespaces
wrangler kv:namespace create "local-links"
wrangler kv:namespace create "local-links" --preview

# Create wrangler.local.toml (gitignored)
cp wrangler.local.toml.example wrangler.local.toml
# Edit: add your local namespace IDs

# Create .dev.vars (gitignored)
echo "ADMIN_KEY=test-key" > .dev.vars

# Run dev server
wrangler pages dev public
# → http://localhost:8788
```

---

## Admin Panel

`https://YOUR_DOMAIN/admin.html` → enter `ADMIN_KEY`

Session in `sessionStorage` (clears on tab close).

---

## API Reference

### `POST /api/shorten`
```json
{ "url": "https://example.com", "customSlug": "my-link" }
```
Response: `{ "shortUrl": "...", "slug": "...", "url": "..." }`

Errors: `400` (bad JSON), `409` (slug taken), `422` (validation failed)

### `POST /api/lookup`
```json
{ "slug": "xk2a" }
{ "slugs": ["xk2a", "yz9q"] }
```
Add `Authorization: Bearer ADMIN_KEY` for `ip`/`userAgent`.

### `GET /api/admin`
List all. Requires `Authorization: Bearer ADMIN_KEY`.

### `DELETE /api/admin`
```json
{ "slug": "xk2a" }
{ "purgeAll": true }
```
Requires auth.

---

## Security (OWASP Top 10)

| Risk | Mitigation |
|---|---|
| A01 Access Control | Timing-safe comparison; reserved slugs |
| A02 Crypto Failures | Secrets in CF encrypted env vars |
| A03 Injection | Allowlist regex; native URL API |
| A04 Insecure Design | http/https only; no embedded creds |
| A05 Misconfiguration | Security headers; no verbose errors |
| A06 Components | Zero npm dependencies |
| A07 Auth Failures | `timingSafeEqual()` |
| A08 Data Integrity | NFKC normalization; control chars stripped |
| A09 Logging | IP, country, UA, timestamp |
| A10 SSRF | Private IPs, metadata endpoints blocked |

Plus: 8KB body limit, Content-Type enforcement, client validation.

---

## Hidden Layer

Conspiracy theories in `X-Truth` header and redirect bodies:

```bash
curl https://YOUR_DOMAIN/xxxx
curl -sI https://YOUR_DOMAIN/xxxx | grep x-truth
```

55 statements: grassy knoll, Building 7, Tiananmen, Elvis, MKUltra, Epstein, hollow moon, more.

---

## Costs

| Service | Free Tier |
|---|---|
| Pages | ∞ requests, 500 builds/month |
| Workers | 100k req/day |
| KV | 100k reads, 1k writes, 1GB/day |

**$0 total** for personal use.

---

## Licence

MIT — see [LICENSE](./LICENSE).
