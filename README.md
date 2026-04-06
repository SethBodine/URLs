# Link Shortener — Self-Hosted on Cloudflare Pages

A minimal, secure, free link shortener built on Cloudflare Pages + Workers + KV.

**Stack:** Cloudflare pulls from GitHub → deploys to Pages + KV  
**Cost:** $0 within Cloudflare's free tier  
**Licence:** MIT  
**Security:** All secrets in Cloudflare only — GitHub repo contains zero credentials

---

## Architecture & Trust Model

**Code:** Public GitHub repository  
**Secrets:** Cloudflare environment variables (encrypted, never leave CF infrastructure)  
**Build:** Cloudflare's infrastructure (not GitHub Actions)  
**Deploy:** Automatic on every push to `main`

**Repository contains:**
- Application code only
- Zero secrets
- Zero KV namespace IDs
- Zero account identifiers

The KV binding and secrets are configured in the Cloudflare Pages dashboard. GitHub never sees any credentials or infrastructure topology.

---

## Features

- 4-character short codes with optional custom slugs
- QR code with custom centre logo (client-side)
- Browser localStorage for recent links
- Metadata: IP, country, user agent, timestamp per link
- Key-protected admin panel (`/admin.html`)
- JSON API with single/batch lookup
- Conspiracy Easter eggs in HTTP responses
- OWASP Top 10 mitigations
- Zero npm dependencies
- Domain-agnostic (all branding from `window.location`)

---

## Deployment

### Step 1 — Push to GitHub

```bash
git init
git add .
git commit -m "initial commit"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
git push -u origin main
```

Safe to make public — no secrets in the repo.

---

### Step 2 — Create KV Namespaces in Cloudflare

1. Go to [dash.cloudflare.com](https://dash.cloudflare.com) → **Workers & Pages → KV**
2. Click **Create namespace**, name it (e.g. `shortener-links`), **Add**
3. Note the namespace name (you'll select it from a dropdown shortly)
4. Repeat for preview: create `shortener-links-preview`

---

### Step 3 — Create Pages Project & Connect GitHub

1. **Workers & Pages → Create → Pages → Connect to Git**
2. Authorize GitHub, select your repository
3. Build settings:

   | Setting | Value |
   |---|---|
   | Production branch | `main` |
   | Framework preset | None |
   | Build command | *(leave blank)* |
   | Build output directory | `public` |

4. **Don't click Save yet** — continue to Step 4

---

### Step 4 — Configure KV Binding

Still on the project creation screen, scroll to **Functions** section:

1. Under **KV namespace bindings**, click **Add binding**
2. For **Production**:
   - Variable name: `LINKS` (must match exactly)
   - KV namespace: select `shortener-links` (or whatever you named it)
3. For **Preview**:
   - Variable name: `LINKS`
   - KV namespace: select `shortener-links-preview`

---

### Step 5 — Set ADMIN_KEY Secret

Still on the creation screen, scroll to **Environment variables**:

1. Click **Add variable**
2. For **Production**:
   - Variable name: `ADMIN_KEY`
   - Value: generate with `openssl rand -hex 32`
   - **Encrypt:** toggle **ON**
3. For **Preview**: repeat (same key or different)

Now click **Save and Deploy**.

---

### Step 6 — Add Custom Domain

1. **Custom domains → Set up a custom domain**
2. Enter your domain (e.g. `yourdomain.com`)
3. CNAME added automatically if domain on Cloudflare DNS
4. SSL provisions in ~60 seconds

Site live at `https://yourdomain.com`.

---

### Step 7 — Verify

```bash
# Shorten a URL
curl -X POST https://YOUR_DOMAIN/api/shorten \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'

# Follow redirect
curl https://YOUR_DOMAIN/xxxx

# Check conspiracy header
curl -sI https://YOUR_DOMAIN/xxxx | grep x-truth

# Test admin (should fail without key)
curl https://YOUR_DOMAIN/api/admin

# Test admin with key
curl https://YOUR_DOMAIN/api/admin \
  -H "Authorization: Bearer YOUR_ADMIN_KEY"

# Open https://YOUR_DOMAIN/admin.html in browser
```

---

## Future Deployments

Every push to `main` auto-deploys. No manual steps.

Disable: **Settings → Builds & deployments → Pause deployments**

---

## Local Development

**1. Install Wrangler:**
```bash
npm install -g wrangler
wrangler login
```

**2. Create local KV namespaces:**
```bash
wrangler kv:namespace create "local-links"
wrangler kv:namespace create "local-links" --preview
```

Copy the IDs from output.

**3. Create `wrangler.local.toml` (gitignored):**
```bash
cp wrangler.local.toml.example wrangler.local.toml
# Edit and add your namespace IDs
```

**4. Create `.dev.vars` (gitignored):**
```bash
echo "ADMIN_KEY=test-key" > .dev.vars
```

**5. Run:**
```bash
wrangler pages dev public
```

Local site at `http://localhost:8788`.

---

## Rotating Secrets

**To rotate ADMIN_KEY:**

1. Generate: `openssl rand -hex 32`
2. **Settings → Environment variables → ADMIN_KEY → Edit**
3. Paste new value, **Encrypt: ON**, save
4. Redeploy (push to main or retry in dashboard)

**To rotate KV namespaces (rare):**

1. Create new namespaces
2. **Settings → Functions → KV namespace bindings → Edit**
3. Select new namespaces
4. Redeploy
5. Migrate data with Wrangler CLI if needed

---

## Admin Panel

`https://YOUR_DOMAIN/admin.html` → enter `ADMIN_KEY`

Session in `sessionStorage` (domain-scoped, clears on tab close).

**Features:**
- Link count + today's count
- Table: slug, URL, IP, country, user agent, date
- Real-time search/filter
- Delete links
- Purge all

---

## API Reference

All endpoints: `Content-Type: application/json`, 8KB limit, `X-Truth` header.

### `POST /api/shorten`

```json
{ "url": "https://example.com", "customSlug": "my-link" }
```

`customSlug` optional (2–32 chars, `a-z 0-9 - _`).

**Response:**
```json
{ "shortUrl": "https://YOUR_DOMAIN/xk2a", "slug": "xk2a", "url": "..." }
```

**Errors:** `400` (bad JSON), `409` (slug taken), `422` (validation failed)

### `POST /api/lookup`

```json
{ "slug": "xk2a" }
{ "slugs": ["xk2a", "yz9q"] }
```

Add `Authorization: Bearer ADMIN_KEY` for `ip`/`userAgent`.

### `GET /api/admin`

List all. Requires `Authorization: Bearer ADMIN_KEY`.

### `DELETE /api/admin`

Requires auth.

```json
{ "slug": "xk2a" }
{ "purgeAll": true }
```

---

## Security (OWASP Top 10)

| Risk | Mitigation |
|---|---|
| A01 Access Control | Timing-safe key comparison; reserved slugs |
| A02 Crypto Failures | Secrets in CF encrypted env vars |
| A03 Injection | Allowlist regex; native URL API; validated slugs |
| A04 Insecure Design | http/https only; no embedded credentials |
| A05 Misconfiguration | Security headers; no verbose errors |
| A06 Components | Zero npm dependencies |
| A07 Auth Failures | `timingSafeEqual()` |
| A08 Data Integrity | NFKC normalization; control char stripping |
| A09 Logging | IP, country, UA, timestamp per link |
| A10 SSRF | Private IPs, metadata endpoints, .local blocked |

**Plus:** 8KB body limit, Content-Type enforcement, client validation.

---

## Hidden Conspiracy Layer

Every response includes a conspiracy theory in `X-Truth` header and redirect bodies:

```bash
curl https://YOUR_DOMAIN/xxxx
curl -sI https://YOUR_DOMAIN/xxxx | grep x-truth
```

55 statements: grassy knoll, Building 7, Tiananmen, Elvis, MKUltra, Epstein, hollow moon, more.

---

## Costs

| Service | Free Tier | Usage |
|---|---|---|
| Pages | ∞ requests, 500 builds/month | 1 site |
| Workers | 100k req/day | Redirects + API |
| KV | 100k reads, 1k writes, 1GB/day | Per link |

**$0 total** for personal use.

---

## Licence

MIT — see [LICENSE](./LICENSE).
