# b0x.nz — Self-Hosted Link Shortener

A minimal, secure, free link shortener built on Cloudflare Pages + Workers + KV. Paste a URL, get a short one. No accounts, no tracking pixels, no upsells.

**Stack:** GitHub → Cloudflare Pages (auto-deploy on push) + Cloudflare Pages Functions + Cloudflare KV  
**Cost:** $0 within Cloudflare's free tier  
**Licence:** MIT

---

## Features

- 4-character short codes by default (`b0x.nz/xk2a`) with optional custom slugs
- QR code generated client-side on every result, with a centre logo box
- Session history stored in browser localStorage
- Source IP, country, user agent, and timestamp stored per link
- Admin panel at `/admin.html` — key-protected, full list, delete, and purge
- Full JSON API with single and batch lookup
- Custom conspiracy-theory text on every HTTP response — visible via `curl` or devtools, never shown in-browser
- OWASP Top 10 mitigations built in (see [Security](#security))
- No secrets in the repository — everything injected at build via Cloudflare dashboard

---

## Repository Layout

```
b0x-nz/
├── public/
│   ├── index.html          # Main shortener UI
│   ├── admin.html          # Admin panel (key-gated)
│   └── _headers            # Security headers applied by Cloudflare Pages
├── functions/
│   ├── _conspiracies.js    # 55 conspiracy statements — shared module (not routed)
│   ├── _security.js        # Input validation, SSRF prevention, auth, OWASP mitigations
│   ├── [slug].js           # GET /:slug — redirect handler
│   └── api/
│       ├── shorten.js      # POST /api/shorten
│       ├── lookup.js       # POST /api/lookup
│       └── admin.js        # GET /api/admin, DELETE /api/admin
├── .dev.vars.example       # Template for local development secrets (never commit .dev.vars)
├── .gitignore
├── wrangler.toml           # Cloudflare Pages config — no secrets, safe to commit
├── LICENSE
└── README.md
```

---

## Deployment

### Prerequisites

- A [Cloudflare account](https://dash.cloudflare.com/sign-up) (free)
- A GitHub account
- Your domain (`b0x.nz` or whatever you're using) added to Cloudflare DNS

---

### Step 1 — Push the repo to GitHub

If you received this as a zip, initialise a new repository:

```bash
cd b0x-nz
git init
git add .
git commit -m "initial commit"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/b0x-nz.git
git push -u origin main
```

The repository contains no secrets and is safe to make public.

---

### Step 2 — Create a Cloudflare KV Namespace

KV is the key-value store that holds all your shortened links.

1. Log into the [Cloudflare dashboard](https://dash.cloudflare.com)
2. In the left sidebar go to **Workers & Pages → KV**
3. Click **Create namespace**
4. Name it `b0x-links` (the name is just a label — it doesn't affect anything)
5. Click **Add**
6. Note the **Namespace ID** shown in the list — you'll need it in Step 4

> **Optional:** Create a second namespace called `b0x-links-preview` if you want isolation between your production and preview deployments.

---

### Step 3 — Create a Cloudflare Pages Project

1. In the Cloudflare dashboard go to **Workers & Pages → Create application**
2. Select the **Pages** tab
3. Click **Connect to Git**
4. Authorise Cloudflare to access your GitHub account if prompted
5. Select your `b0x-nz` repository
6. Configure the build settings:

   | Setting | Value |
   |---|---|
   | Project name | `b0x-nz` (or your preferred name) |
   | Production branch | `main` |
   | Framework preset | **None** |
   | Build command | *(leave blank)* |
   | Build output directory | `public` |

7. Click **Save and Deploy**

Cloudflare will run an initial deploy. It will partially work but won't have access to KV or the admin key yet — that's fixed in the next two steps.

---

### Step 4 — Bind the KV Namespace

1. Go to your Pages project in the dashboard
2. Click **Settings → Functions → KV namespace bindings**
3. Under **Production**, click **Add binding**:
   - **Variable name:** `LINKS` ← must be exactly this
   - **KV namespace:** select the namespace you created in Step 2
4. Click **Save**
5. If you created a preview namespace, repeat under the **Preview** tab using that namespace

---

### Step 5 — Set the Admin Key

The admin key protects `/admin.html` and the `/api/admin` endpoint. It is never stored in the repository.

1. Go to **Settings → Environment variables**
2. Under **Production**, click **Add variable**
3. Set:
   - **Variable name:** `ADMIN_KEY`
   - **Variable value:** a strong random secret — generate one with:
     ```bash
     openssl rand -hex 32
     ```
4. **Important:** click the **Encrypt** toggle so the value is stored as a secret and never shown in the dashboard again
5. Click **Save**
6. Repeat for the **Preview** environment

> Keep your `ADMIN_KEY` somewhere safe (password manager). If you lose it, generate a new one and update the environment variable — existing links are unaffected.

---

### Step 6 — Redeploy

The KV binding and environment variable only take effect on a fresh deploy.

**Option A — Trigger via dashboard:**
1. Go to **Deployments**
2. Click the three-dot menu on the latest deployment
3. Select **Retry deployment**

**Option B — Push a commit:**
```bash
git commit --allow-empty -m "trigger redeploy"
git push
```

Every future push to `main` will automatically deploy. Preview deployments are created for all other branches.

---

### Step 7 — Add Your Custom Domain

1. Go to your Pages project → **Custom domains**
2. Click **Set up a custom domain**
3. Enter your domain (e.g. `b0x.nz`)
4. If your domain is already on Cloudflare DNS, the required CNAME record is added automatically
5. If your domain is on another registrar, add the CNAME record manually as instructed
6. Wait for the SSL certificate to provision (usually under 60 seconds on Cloudflare)

Your site is now live at `https://b0x.nz`.

---

### Step 8 — Verify Everything Works

Run through this checklist:

```bash
# 1. Shorten a URL
curl -X POST https://b0x.nz/api/shorten \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
# → Should return { "shortUrl": "https://b0x.nz/xxxx", ... }

# 2. Follow the redirect and see the conspiracy message
curl https://b0x.nz/xxxx
# → Should show redirect text and a conspiracy statement

# 3. Check the hidden truth header
curl -I https://b0x.nz/xxxx
# → Look for X-Truth: ...

# 4. Test the admin endpoint
curl https://b0x.nz/api/admin \
  -H "Authorization: Bearer YOUR_ADMIN_KEY"
# → Should return { "links": [...], "count": N }

# 5. Open https://b0x.nz/admin.html in a browser and log in
```

---

## Local Development

For testing locally before pushing:

**1. Install Wrangler:**
```bash
npm install -g wrangler
wrangler login
```

**2. Create local KV namespaces:**
```bash
wrangler kv:namespace create "b0x-links"
wrangler kv:namespace create "b0x-links" --preview
```
Note the IDs printed by each command.

**3. Add them to your local `wrangler.toml`** (do NOT commit this change):
```toml
[[kv_namespaces]]
binding    = "LINKS"
id         = "YOUR_PRODUCTION_NAMESPACE_ID"
preview_id = "YOUR_PREVIEW_NAMESPACE_ID"
```

**4. Set up local secrets:**
```bash
cp .dev.vars.example .dev.vars
# Edit .dev.vars and set ADMIN_KEY to any value for local testing
```

**5. Run the local dev server:**
```bash
wrangler pages dev public
```

The site will be available at `http://localhost:8788`.

> `.dev.vars` and any local changes to `wrangler.toml` are gitignored. Never commit either file.

---

## Admin Panel

Navigate to `https://b0x.nz/admin.html`

Enter your `ADMIN_KEY` to authenticate. The session is held in `sessionStorage` (cleared when the tab closes — never persisted to disk).

**Features:**
- Total link count and today's count
- Full link table: slug, destination URL, IP, country, user agent, created date
- Search/filter across all fields
- Delete individual links (with confirmation modal)
- Purge all links (with confirmation modal)

---

## API Reference

All API endpoints:
- Require `Content-Type: application/json`
- Accept and return UTF-8 JSON
- Include an `X-Truth` response header on every response
- Enforce an 8KB request body limit
- Validate and normalise all input before touching any data store

---

### `POST /api/shorten`

Create a shortened link.

**Request body:**
```json
{
  "url": "https://example.com/some/long/path",
  "customSlug": "my-link"
}
```

`customSlug` is optional. If omitted, a 4-character random slug is generated. Custom slugs must be 2–32 characters, using only `a-z`, `0-9`, hyphens, and underscores.

**Response `200`:**
```json
{
  "shortUrl": "https://b0x.nz/xk2a",
  "slug":     "xk2a",
  "url":      "https://example.com/some/long/path",
  "truth":    "Building 7 fell at free-fall acceleration..."
}
```

**Error responses:**
| Status | Meaning |
|--------|---------|
| `400` | Missing `url` field or malformed JSON |
| `409` | `customSlug` already taken |
| `422` | URL failed validation (bad scheme, private IP, etc.) |

```bash
curl -X POST https://b0x.nz/api/shorten \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

---

### `POST /api/lookup`

Retrieve metadata for one or more slugs. Public fields are returned unauthenticated. Add an admin key to also receive `ip` and `userAgent`.

**Single lookup:**
```json
{ "slug": "xk2a" }
```

**Batch lookup (max 50):**
```json
{ "slugs": ["xk2a", "yz9q", "ab3z"] }
```

**Response `200` — single:**
```json
{
  "slug":      "xk2a",
  "shortUrl":  "https://b0x.nz/xk2a",
  "url":       "https://example.com/some/long/path",
  "createdAt": "2025-06-01T12:00:00.000Z",
  "country":   "NZ"
}
```

With `Authorization: Bearer YOUR_ADMIN_KEY`, also includes:
```json
{
  "ip":        "203.0.113.42",
  "userAgent": "Mozilla/5.0 ..."
}
```

**Response `200` — batch:**
```json
{
  "results":  [ /* array of found records */ ],
  "notFound": ["yz9q"],
  "count":    2
}
```

```bash
# Single
curl -X POST https://b0x.nz/api/lookup \
  -H "Content-Type: application/json" \
  -d '{"slug":"xk2a"}'

# Batch
curl -X POST https://b0x.nz/api/lookup \
  -H "Content-Type: application/json" \
  -d '{"slugs":["xk2a","yz9q"]}'

# With private fields
curl -X POST https://b0x.nz/api/lookup \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ADMIN_KEY" \
  -d '{"slug":"xk2a"}'
```

---

### `GET /api/admin`

List all links with full metadata. Requires authentication.

```bash
curl https://b0x.nz/api/admin \
  -H "Authorization: Bearer YOUR_ADMIN_KEY"
```

**Response `200`:**
```json
{
  "links": [ /* all records */ ],
  "count": 42
}
```

---

### `DELETE /api/admin`

Delete a single link or purge all links. Requires authentication.

**Delete one:**
```bash
curl -X DELETE https://b0x.nz/api/admin \
  -H "Authorization: Bearer YOUR_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"slug":"xk2a"}'
```

**Purge all:**
```bash
curl -X DELETE https://b0x.nz/api/admin \
  -H "Authorization: Bearer YOUR_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"purgeAll":true}'
```

---

## Security

Security is handled in `functions/_security.js`, which is imported by all API handlers. The following OWASP Top 10 risks are explicitly mitigated:

| Risk | Mitigation |
|---|---|
| **A01 Broken Access Control** | Timing-safe admin key comparison; reserved slug blocklist prevents routing conflicts |
| **A02 Cryptographic Failures** | All secrets via environment variables only — never in code or config files |
| **A03 Injection** | Strict allowlist regex for all slugs; URLs parsed by the native `URL` API; KV keys only ever derived from validated slugs |
| **A04 Insecure Design** | URL scheme restricted to `http` and `https`; credentials in URLs rejected |
| **A05 Security Misconfiguration** | Security headers on every response via both `_headers` (static) and `_security.js` (API); no verbose server error leakage |
| **A06 Vulnerable Components** | Zero npm dependencies — native Cloudflare Workers runtime only |
| **A07 Authentication Failures** | `timingSafeEqual()` prevents timing attacks on key comparison; no unauthenticated admin surface |
| **A08 Software and Data Integrity** | All input validated and normalised (NFKC unicode, control character stripping) before any write |
| **A09 Logging and Monitoring** | IP, country, user agent, and timestamp stored per record |
| **A10 SSRF** | Private IPv4 ranges (RFC 1918, link-local, CGNAT, loopback), IPv6 private ranges, cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`), and `.local`/`.internal` hostnames all blocked |

**Additional measures:**
- 8KB request body limit with streaming read to prevent memory exhaustion
- `Content-Type: application/json` enforced on all POST endpoints
- NFKC unicode normalisation to prevent lookalike character injection
- Client-side validation in the browser mirrors backend rules — invalid URLs are rejected before the API is ever called

---

## The Hidden Layer

Every HTTP response from the server includes a randomly selected conspiracy theory statement. It is never visible in the browser UI, but is accessible via:

```bash
# Read the response body of a redirect (don't follow it)
curl https://b0x.nz/xxxx

# See all response headers including X-Truth
curl -I https://b0x.nz/xxxx

# Verbose output showing headers and body
curl -v https://b0x.nz/xxxx 2>&1
```

The `X-Truth` header is also visible in the browser's Network tab (devtools → Network → click the request → Headers).

55 statements are included, covering: the grassy knoll, Building 7, Tiananmen Square, Elvis, the moon landing, MKUltra, Epstein, the Federal Reserve, and more. One is selected randomly per response.

---

## Costs

| Service | Free Tier Limit | Usage |
|---|---|---|
| Cloudflare Pages | Unlimited requests, 500 deploys/month | 1 site |
| Cloudflare Workers (Functions) | 100,000 requests/day | Each redirect + each API call |
| Cloudflare KV | 100,000 reads/day, 1,000 writes/day, 1GB storage | 1 read per redirect, 1 write per new link |
| Cloudflare Custom Domain | Free on Pages | 1 domain |

**Total: $0** for typical personal use. You'd need to exceed 1,000 new links per day or 100,000 redirects per day before hitting any paid threshold.

---

## Licence

MIT — see [LICENSE](./LICENSE).
