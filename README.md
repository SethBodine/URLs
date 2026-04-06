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
**Build:** Cloudflare's build environment (not GitHub Actions — avoids third-party trust boundary)  
**Deploy:** Automatic on every push to `main`

**The repository contains:**
- Application code
- Zero secrets
- Zero KV namespace IDs (stored as `__PLACEHOLDER__` tokens, substituted at build time)
- Zero account identifiers

Cloudflare pulls the code and runs `_build.sh`, which injects KV namespace IDs from environment variables. GitHub never sees any credentials or infrastructure IDs.

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

```bash
cd link-shortener
git init
git add .
git commit -m "initial commit"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
git push -u origin main
```

The repository is safe to make public — it contains no secrets or infrastructure IDs.

---

### Step 2 — Create Cloudflare KV Namespaces

1. Log into [dash.cloudflare.com](https://dash.cloudflare.com)
2. Go to **Workers & Pages → KV**
3. Click **Create namespace**, name it (e.g. `shortener-links`), click **Add**
4. **Copy the Namespace ID** (you'll need it in Step 4)
5. Repeat: create a second namespace for preview (e.g. `shortener-links-preview`)
6. **Copy that Namespace ID** too

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
   | **Build command** | `bash _build.sh` |
   | Build output directory | `public` |

6. **Do not click "Save and Deploy" yet** — environment variables must be set first

---

### Step 4 — Set Environment Variables

Still on the "Create Pages Project" screen, scroll down to **Environment variables (advanced)**.

Add the following **three** variables for **Production**:

| Variable name | Value | Encrypt? |
|---|---|---|
| `KV_NAMESPACE_ID` | Your production namespace ID from Step 2 | No |
| `KV_PREVIEW_NAMESPACE_ID` | Your preview namespace ID from Step 2 | No |
| `ADMIN_KEY` | A strong secret: `openssl rand -hex 32` | **Yes** |

Then add the same three for **Preview** (you can use the same values or different ones).

> **Why aren't the namespace IDs encrypted?** They're infrastructure identifiers, not credentials. Encrypting them would prevent the build script from reading them. Only `ADMIN_KEY` should be encrypted.

Now click **Save and Deploy**.

---

### Step 5 — Verify the Build Succeeded

1. Go to **Deployments** and watch the build log
2. You should see:
   ```
   → Injecting KV namespace IDs into wrangler.toml from CF environment variables...
   ✓ KV namespace IDs injected successfully.
   ✓ Build ready.
   ```
3. If the build fails with "KV_NAMESPACE_ID environment variable is not set", go back to Step 4 and ensure you added the variables to the **Production** environment (not just Preview)

---

### Step 6 — Add Your Custom Domain

1. Go to **Custom domains → Set up a custom domain**
2. Enter your domain (e.g. `yourdomain.com`)
3. If on Cloudflare DNS, the CNAME is added automatically
4. If on an external registrar, add the CNAME as instructed
5. SSL provisions automatically

The site is now live at `https://yourdomain.com`.

---

### Step 7 — Verify It Works

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

# 6. Open https://YOUR_DOMAIN/admin.html and log in
```

---

## Future Deployments

Every push to `main` triggers automatic deployment. Cloudflare pulls the code, runs `_build.sh` to inject namespace IDs, builds, and deploys. No manual steps required.

To disable auto-deploy: **Settings → Builds & deployments → Pause deployments**

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

**3. Create `wrangler.local.toml` (gitignored):**
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

**5. Run:**
```bash
wrangler pages dev public
```

Never commit `wrangler.local.toml` or `.dev.vars` — both are gitignored.

---

## Rotating Secrets

To rotate `ADMIN_KEY`:

1. Generate a new key: `openssl rand -hex 32`
2. **Settings → Environment variables → ADMIN_KEY → Edit**
3. Paste new value, ensure **Encrypt** is ON, save
4. Redeploy (push to `main` or retry deployment in dashboard)

To rotate KV namespace IDs (rare — only if migrating datastores):

1. Create new namespaces
2. **Settings → Environment variables → Edit `KV_NAMESPACE_ID` and `KV_PREVIEW_NAMESPACE_ID`**
3. Redeploy

---

## Admin Panel

Navigate to `https://YOUR_DOMAIN/admin.html` and enter your `ADMIN_KEY`.

Session held in `sessionStorage` (scoped to your domain, clears on tab close).

**Features:**
- Total link count + today's count
- Full table: slug, destination, IP, country, user agent, created date
- Real-time search/filter
- Delete individual links
- Purge all links

---

## API Reference

All endpoints require `Content-Type: application/json`, enforce 8KB body limit, include `X-Truth` header.

### `POST /api/shorten`

```json
{ "url": "https://example.com/path", "customSlug": "my-link" }
```

`customSlug` optional (2–32 chars, `a-z 0-9 - _`). Omit for random 4-char slug.

**Response `200`:**
```json
{ "shortUrl": "https://YOUR_DOMAIN/xk2a", "slug": "xk2a", "url": "..." }
```

**Errors:** `400` (missing url/malformed JSON), `409` (slug taken), `422` (validation failed)

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

Add `Authorization: Bearer ADMIN_KEY` to also receive `ip` and `userAgent`.

---

### `GET /api/admin`

Returns all links. Requires `Authorization: Bearer ADMIN_KEY`.

---

### `DELETE /api/admin`

Requires `Authorization: Bearer ADMIN_KEY`.

**Delete one:** `{ "slug": "xk2a" }`  
**Purge all:** `{ "purgeAll": true }`

---

## Security

| OWASP Risk | Mitigation |
|---|---|
| **A01 Broken Access Control** | Timing-safe key comparison; reserved slug blocklist |
| **A02 Cryptographic Failures** | Secrets in CF encrypted env vars (injected at build, never in repo) |
| **A03 Injection** | Strict allowlist regex; native `URL` API; validated slugs only |
| **A04 Insecure Design** | URL scheme `http`/`https` only; embedded credentials rejected |
| **A05 Security Misconfiguration** | Security headers; no verbose errors |
| **A06 Vulnerable Components** | Zero npm dependencies |
| **A07 Authentication Failures** | `timingSafeEqual()` prevents timing attacks |
| **A08 Data Integrity** | NFKC unicode normalisation + control char stripping |
| **A09 Logging** | IP, country, user agent, timestamp per link |
| **A10 SSRF** | Private IPs, cloud metadata, `.local`/`.internal` all blocked |

**Additional:** 8KB body limit, `Content-Type` enforcement, client-side validation mirrors backend.

---

## The Hidden Layer

Every HTTP response includes a conspiracy theory in `X-Truth` header and redirect bodies:

```bash
curl https://YOUR_DOMAIN/xxxx
curl -sI https://YOUR_DOMAIN/xxxx | grep -i x-truth
```

55 statements covering: grassy knoll, Building 7, Tiananmen, Elvis, MKUltra, Epstein, hollow moon, more.

---

## Costs

| Service | Free Tier | Usage |
|---|---|---|
| Cloudflare Pages | Unlimited requests, 500 builds/month | 1 site |
| Cloudflare Workers | 100,000 req/day | Redirects + API |
| Cloudflare KV | 100,000 reads/day, 1,000 writes/day, 1GB | Per link |

**$0 total** for typical use.

---

## Licence

MIT — see [LICENSE](./LICENSE).
