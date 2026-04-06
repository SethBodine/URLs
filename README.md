# Link Shortener — Self-Hosted on Cloudflare Pages

A minimal, secure, free link shortener built on Cloudflare Pages + Workers + KV.

**Stack:** Cloudflare pulls from GitHub → builds in CF infrastructure → deploys to Pages + KV  
**Cost:** $0 within Cloudflare's free tier  
**Licence:** MIT  
**Security:** All secrets stored in Cloudflare only — GitHub repo contains zero credentials

---

## Architecture & Trust Model

**Code:** Public GitHub repository (this repo)  
**Secrets:** Cloudflare environment variables (encrypted at rest, never leave CF infrastructure)  
**Build:** Cloudflare's build environment (not GitHub Actions runners — avoids third-party trust boundary)  
**Deploy:** Automatic on every push to `main` — Cloudflare pulls code, builds, deploys

**The repository contains:**
- Application code
- Zero secrets
- Zero API tokens
- Zero KV namespace IDs
- Zero account identifiers

Cloudflare pulls the code and injects all secrets at build time from environment variables you configure in the dashboard. GitHub never sees any credentials.

---

## Features

- 4-character short codes with optional custom slugs
- QR code with custom centre logo generated client-side
- Browser localStorage for recent links
- Metadata per link: IP, country, user agent, timestamp
- Key-protected admin panel at `/admin.html`
- JSON API with single and batch lookup
- Conspiracy-theory Easter eggs in every HTTP response
- OWASP Top 10 mitigations throughout
- Zero npm dependencies
- Works on any domain — all branding derived from `window.location` at runtime

---

## Deployment

### Prerequisites

- A [Cloudflare account](https://dash.cloudflare.com/sign-up) (free tier)
- A GitHub account
- Your domain already added to Cloudflare DNS (for custom domain step)

---

### Step 1 — Push to GitHub

If you received this as a zip:

```bash
cd link-shortener
git init
git add .
git commit -m "initial commit"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
git push -u origin main
```

The repository is safe to make public — it contains no secrets.

---

### Step 2 — Create Cloudflare KV Namespaces

KV is the datastore for all shortened links.

1. Log into [dash.cloudflare.com](https://dash.cloudflare.com)
2. Go to **Workers & Pages → KV**
3. Click **Create namespace**, name it (e.g. `shortener-links`), click **Add**
4. Note the **Namespace ID** (you'll select it from a dropdown in Step 4 — no need to copy it)
5. Repeat: create a second namespace for preview deployments (e.g. `shortener-links-preview`)

---

### Step 3 — Create a Cloudflare Pages Project

1. Go to **Workers & Pages → Create application → Pages**
2. Click **Connect to Git**
3. Authorize Cloudflare to access GitHub if prompted
4. Select your repository
5. Configure build settings:

   | Setting | Value |
   |---|---|
   | Production branch | `main` |
   | Framework preset | **None** |
   | Build command | *(leave blank)* |
   | Build output directory | `public` |

6. Click **Save and Deploy**

The first deploy will fail with a KV binding error — this is expected. The binding is configured in the next step.

---

### Step 4 — Configure the KV Namespace Binding

This tells Cloudflare which KV namespace to use for the `LINKS` binding referenced in `wrangler.toml`.

1. Go to your Pages project → **Settings → Functions**
2. Scroll to **KV namespace bindings**
3. Under **Production**, click **Add binding**:
   - **Variable name:** `LINKS` (must match exactly — the code expects this)
   - **KV namespace:** select your production namespace (e.g. `shortener-links`)
4. Under **Preview**, click **Add binding**:
   - **Variable name:** `LINKS`
   - **KV namespace:** select your preview namespace (e.g. `shortener-links-preview`)
5. Click **Save**

---

### Step 5 — Set the ADMIN_KEY Secret

This protects the admin panel and `/api/admin` endpoint.

1. Go to **Settings → Environment variables**
2. Click **Add variable** for **Production**:
   - **Variable name:** `ADMIN_KEY`
   - **Value:** a strong random secret — generate one:
     ```bash
     openssl rand -hex 32
     ```
   - **Encrypt toggle:** **ON** (so it's stored as an encrypted secret, never shown in dashboard again)
3. Repeat for **Preview** (use the same key or a different one)
4. Click **Save**

> Store your `ADMIN_KEY` in a password manager. If lost, generate a new one and update the environment variable.

---

### Step 6 — Redeploy

The KV binding and environment variable only take effect on a fresh deployment.

**Option A — Trigger via dashboard:**
1. Go to **Deployments**
2. Click the latest deployment
3. Click **Retry deployment**

**Option B — Push a commit:**
```bash
git commit --allow-empty -m "trigger redeploy"
git push
```

This time the deploy should succeed. Cloudflare builds the site in its own infrastructure, injects the `LINKS` binding and `ADMIN_KEY` from the dashboard config (never from GitHub), and deploys.

---

### Step 7 — Add Your Custom Domain

1. Go to **Custom domains → Set up a custom domain**
2. Enter your domain (e.g. `yourdomain.com`)
3. If the domain is on Cloudflare DNS, the CNAME is added automatically
4. If on an external registrar, add the CNAME as instructed
5. SSL provisions automatically (usually under 60 seconds)

The site is now live at `https://yourdomain.com`. All UI text (title, footer, API docs) automatically adapts to your domain.

---

### Step 8 — Verify It Works

```bash
# Replace YOUR_DOMAIN with your actual domain

# 1. Shorten a URL
curl -X POST https://YOUR_DOMAIN/api/shorten \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
# → {"shortUrl":"https://YOUR_DOMAIN/xxxx", ...}

# 2. Follow the short link
curl https://YOUR_DOMAIN/xxxx
# → Redirect + conspiracy message

# 3. Check the hidden header
curl -sI https://YOUR_DOMAIN/xxxx | grep -i x-truth
# → X-Truth: <statement>

# 4. Confirm admin requires auth
curl https://YOUR_DOMAIN/api/admin
# → 401 Unauthorized

# 5. Confirm admin works with your key
curl https://YOUR_DOMAIN/api/admin \
  -H "Authorization: Bearer YOUR_ADMIN_KEY"
# → {"links":[...], "count":N}

# 6. Open https://YOUR_DOMAIN/admin.html in a browser and log in
```

---

## Future Deployments

Every push to `main` triggers an automatic deployment — Cloudflare pulls the new code and redeploys within ~30 seconds. No manual steps, no secrets to rotate unless you want to change `ADMIN_KEY`.

To disable auto-deploy: Pages → Settings → Builds & deployments → Pause deployments

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
Copy the IDs from the output.

**3. Create a local-only `wrangler.toml` override:**

Create `wrangler.local.toml` (gitignored):
```toml
[[kv_namespaces]]
binding = "LINKS"
id = "YOUR_LOCAL_NAMESPACE_ID"
preview_id = "YOUR_PREVIEW_NAMESPACE_ID"
```

**4. Create `.dev.vars` (gitignored):**
```bash
echo "ADMIN_KEY=test-key-for-local-dev" > .dev.vars
```

**5. Run the dev server:**
```bash
wrangler pages dev public
```

Site runs at `http://localhost:8788`. Never commit `wrangler.local.toml` or `.dev.vars` — both are gitignored.

---

## Rotating Secrets

To rotate `ADMIN_KEY`:

1. Generate a new key: `openssl rand -hex 32`
2. Pages → Settings → Environment variables → `ADMIN_KEY` → Edit
3. Paste the new value, ensure **Encrypt** is ON, save
4. Redeploy (any push to `main`, or retry deployment in dashboard)

No changes to the code or repository needed.

---

## Admin Panel

Navigate to `https://YOUR_DOMAIN/admin.html` and enter your `ADMIN_KEY`.

Session held in `sessionStorage` (scoped to your domain, clears when tab closes).

**Features:**
- Total link count + today's count
- Full table: slug, destination, IP, country, user agent, created date
- Real-time search/filter
- Delete individual links
- Purge all links

---

## API Reference

All endpoints require `Content-Type: application/json`, enforce an 8KB body limit, and include an `X-Truth` header in every response.

---

### `POST /api/shorten`

**Request:**
```json
{ "url": "https://example.com/path", "customSlug": "my-link" }
```

`customSlug` optional (2–32 chars, `a-z 0-9 - _`). Omit for a random 4-char slug.

**Response `200`:**
```json
{ "shortUrl": "https://YOUR_DOMAIN/xk2a", "slug": "xk2a", "url": "..." }
```

**Errors:**  
`400` — missing `url` or malformed JSON  
`409` — `customSlug` already taken  
`422` — URL validation failed (bad scheme, private IP, etc.)

---

### `POST /api/lookup`

**Single:**
```json
{ "slug": "xk2a" }
```

**Batch (max 50):**
```json
{ "slugs": ["xk2a", "yz9q"] }
```

Returns public fields. Add `Authorization: Bearer ADMIN_KEY` to also receive `ip` and `userAgent`.

**Response `200`:**
```json
{ "slug": "xk2a", "shortUrl": "...", "url": "...", "createdAt": "...", "country": "NZ" }
```

---

### `GET /api/admin`

Returns all links. Requires `Authorization: Bearer ADMIN_KEY`.

---

### `DELETE /api/admin`

Requires `Authorization: Bearer ADMIN_KEY`.

**Delete one:**
```json
{ "slug": "xk2a" }
```

**Purge all:**
```json
{ "purgeAll": true }
```

---

## Security

All security logic lives in `functions/_security.js`.

| OWASP Risk | Mitigation |
|---|---|
| **A01 Broken Access Control** | Timing-safe key comparison; reserved slug blocklist |
| **A02 Cryptographic Failures** | All secrets in CF environment variables (encrypted at rest, injected at build) |
| **A03 Injection** | Strict allowlist regex; native `URL` API parsing; KV keys only from validated slugs |
| **A04 Insecure Design** | URL scheme restricted to `http`/`https`; embedded credentials rejected |
| **A05 Security Misconfiguration** | Security headers on all responses; no verbose errors |
| **A06 Vulnerable Components** | Zero npm dependencies |
| **A07 Authentication Failures** | `timingSafeEqual()` prevents timing attacks |
| **A08 Data Integrity** | NFKC unicode normalisation + control char stripping before every write |
| **A09 Logging** | IP, country, user agent, timestamp captured per link |
| **A10 SSRF** | RFC 1918 private IPs, link-local, CGNAT, loopback, cloud metadata endpoints, `.local`/`.internal` all blocked |

**Additional:**  
8KB request body limit, `Content-Type` enforcement, client-side validation mirrors backend rules.

---

## The Hidden Layer

Every HTTP response includes a randomly selected conspiracy theory in the `X-Truth` header and in redirect bodies. Browsers discard both — `curl` doesn't:

```bash
curl https://YOUR_DOMAIN/xxxx
curl -sI https://YOUR_DOMAIN/xxxx | grep -i x-truth
```

55 statements covering: the grassy knoll, Building 7, Tiananmen Square, Elvis, MKUltra, Epstein, hollow moon, and more.

---

## Costs

| Service | Free Tier | Usage |
|---|---|---|
| Cloudflare Pages | Unlimited requests, 500 builds/month | 1 site |
| Cloudflare Workers | 100,000 req/day | Each redirect + API call |
| Cloudflare KV | 100,000 reads/day, 1,000 writes/day, 1GB | 1 read per redirect; 1 write per link |

**Total: $0** for typical personal use.

---

## Licence

MIT — see [LICENSE](./LICENSE).
