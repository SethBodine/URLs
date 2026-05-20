# Changelog

All notable changes to this project are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [2.1.0] — 2026-05-20

### Added

#### IP Blocklist (`functions/_blocklist.js`, `functions/api/blocklist.js`)
- New IP blocklist stored in the existing LINKS KV namespace under `bl:ip:` prefixed keys
- Supports both IPv4 and IPv6 — IPv6 is expanded to full 8-group notation for consistent lookup regardless of compressed (`::`) representation; IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is unwrapped to its IPv4 form
- **Silent blocking** — blocked IPs receive an empty `200 OK` with no body, no error message, and no hint they are blocked; prevents blocklist probing
- Blocklist check runs before rate limiting so blocked IPs do not consume quota counters
- **Auto-blocking at creation** — if Safe Browsing flags a URL during shortening, the submitting IP is silently blocked and no link is created (replaces the previous `422` error response for threat detections)
- **Auto-blocking on rescan** — when a previously-stored link is retroactively flagged during a scheduled or manual rescan, the original creator IP is automatically added to the blocklist
- Admin API at `GET|POST|DELETE /api/blocklist` for listing, manually adding, and removing blocked IPs

#### Scheduled Safe Browsing Rescan (`functions/_rescan.js`, `functions/api/scan.js`)
- Daily cron trigger at `03:00 UTC` configurable via the Cloudflare dashboard: **Workers & Pages → project → Settings → Functions → Cron Triggers** — enter `0 3 * * *`. Note: `[triggers]` in `wrangler.toml` is a Workers-only key and causes a build failure in Pages projects; cron must be configured through the dashboard
- Re-checks every active link against Google Safe Browsing; deactivates flagged links and blocks their creator IPs without deleting any records
- `POST /api/scan` HTTP endpoint for admin-triggered manual rescans (body `{ "forceAll": true }` to also re-check already-deactivated links)
- Rescan results returned as a stats object: `scanned`, `clean`, `newlyFlagged`, `ipsBlocked`, `skipped`, `errors`, `flaggedSlugs`
- Fan-out concurrency capped at 10 parallel Safe Browsing requests to stay comfortably within the free 10,000 lookup/day quota
- Deactivated links are marked with `deactivated: true`, `deactivatedAt`, `deactivatedReason`, and `deactivatedThreats` — record is preserved for audit; the slug serves a `410 Gone` warning page instead of redirecting

#### Admin Panel — Rescan Button
- **⟳ Rescan** button in the toolbar triggers `POST /api/scan` directly from the UI
- Inline status badge shows live progress and result (e.g. `✓ All clean — 42 checked` or `⚠ 3 flagged, 2 IP(s) blocked`); auto-hides after 12 seconds
- Table and blocklist panel both reload automatically after a rescan completes

#### Admin Panel — IP Blocklist Panel
- Full blocklist table below the links table: IP address, reason, threat types, trigger slug, timestamp, added-by
- Per-row **Unblock** button
- Manual block input field — enter any IPv4 or IPv6 address and block it immediately
- **🚫 quick-block** icon button on every creator IP chip in the links table — block an IP in one click without leaving the links view
- Blocked IP count stat card (orange) updates live

#### Admin Panel — Deactivated Link Display
- New **Deactivated** stat card (red) in the stats strip
- Deactivated rows styled with a red left border, reduced opacity, and a `⛔ deactivated` pill badge in the Flags column
- Expanded meta row for deactivated links shows flagged timestamp and threat types
- Last rescan timestamp shown in the Safe Browsing meta section for all links

### Changed

#### Safe Browsing URL Canonicalization (`functions/_safebrowsing.js`)
- Added `canonicalizeForSafeBrowsing()` — URLs are normalized before submission per Google's canonicalization spec:
  - **Fragments stripped** (`#section`) — Google's threat database never indexes fragments; omitting them previously caused misses on flagged URLs
  - **Default ports removed** — `https://example.com:443/` and `https://example.com/` are treated identically
  - **Hostname lowercased** — consistent with the Safe Browsing hash algorithm; IDN/punycode handled by the native `URL` parser
  - **Embedded credentials stripped** — belt-and-suspenders on top of `validateUrl()`
  - **Control characters removed** — matches Google's own pre-processing step
- `checkSafeBrowsing()` now returns `checkedUrl` — the exact canonicalized URL submitted to the API — stored in the KV record's `safeBrowsing` block for audit
- API errors (quota exceeded, bad key, network failure) still fail open so legitimate users are not blocked by infrastructure problems

#### `shorten.js` — Threat Handling
- Safe Browsing flags now trigger **silent blocking** (blank `200`, IP added to blocklist) instead of a `422` error response — prevents attackers from probing which URLs are known threats
- Blocklist check added at the top of the handler, before rate limiting

#### `admin.js` — Key Filtering
- `isLinkKey()` updated to exclude both `rl:` (rate-limit) and `bl:ip:` (blocklist) KV keys from the links listing; previously only rate-limit keys were filtered

#### `_rescan.js` — Key Filtering
- `isLinkKey()` uses the shared `isBlocklistKey()` helper from `_blocklist.js` to exclude blocklist entries during rescan iteration; previously only rate-limit keys were excluded

### Security

- Threat-detected submissions now silently block the submitting IP rather than returning a descriptive error, reducing information leakage to malicious actors
- IPv6 address normalization ensures that compressed notations (`::1`, `2001:db8::1`) and full notations resolve to the same blocklist key — prevents trivial blocklist bypass via address reformatting
- Deactivated links serve `410 Gone` (not `404`) — signals permanent removal without leaking redirect destination

### API Changes

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/api/scan` | `POST` | Admin | Trigger a manual Safe Browsing rescan of all stored links |
| `/api/blocklist` | `GET` | Admin | List all blocked IPs with metadata |
| `/api/blocklist` | `POST` | Admin | Manually block an IP `{ "ip": "1.2.3.4" }` |
| `/api/blocklist` | `DELETE` | Admin | Unblock an IP `{ "ip": "1.2.3.4" }` |

### KV Schema Changes

Link records gain optional fields when deactivated:

```json
{
  "deactivated":        true,
  "deactivatedAt":      "2026-05-20T03:00:00.000Z",
  "deactivatedReason":  "safe_browsing_rescan",
  "deactivatedThreats": ["MALWARE"],
  "safeBrowsing": {
    "checked":          true,
    "checkedAt":        "2026-04-29T10:00:00.000Z",
    "checkedUrl":       "https://example.com/path",
    "lastRescannedAt":  "2026-05-20T03:00:00.000Z",
    "lastCheckedUrl":   "https://example.com/path",
    "rescannedClean":   false,
    "threats":          ["MALWARE"]
  }
}
```

Blocklist entries are stored under `bl:ip:{normalized-ip}`:

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

### Files Added / Changed

| File | Status | Summary |
|---|---|---|
| `functions/_blocklist.js` | **New** | IP normalization, KV helpers, `blankResponse()` |
| `functions/_safebrowsing.js` | **Updated** | URL canonicalization, `checkedUrl` in result |
| `functions/_rescan.js` | **Updated** | Blocks creator IPs, uses `isBlocklistKey()` filter |
| `functions/api/shorten.js` | **Updated** | Blocklist pre-check, silent blocking on threat |
| `functions/api/scan.js` | **New** | `POST /api/scan` + `onScheduled` cron handler |
| `functions/api/blocklist.js` | **New** | `GET|POST|DELETE /api/blocklist` admin API |
| `functions/api/admin.js` | **Updated** | `isLinkKey()` filters `bl:ip:` keys |
| `public/admin.html` | **Updated** | Rescan button, blocklist panel, deactivated styling |
| `wrangler.toml` | **Updated** | Removed `[triggers]` (Pages build failure) — cron configured via dashboard |

---

## [2.0.0] — 2026-05-04

Initial public release.

- 4-character auto-generated slugs + custom slugs
- Preview interstitial with 5-second countdown
- URL preview lookup (public + authenticated)
- My Links — owner-hash-based self-service management
- Link expiry (30/60/90/180/365 days) enforced at KV level
- Per-slug access logging (IP, UA, country, city, timestamp) — rolling 50-entry window
- Google Safe Browsing check at creation time
- QR codes with custom logo (client-side)
- Admin panel with stats, search, select mode, batch delete
- JSON API — single and batch slug lookup
- IP-based rate limiting (hourly + daily sliding windows)
- OWASP Top 10 mitigations throughout
- Zero npm dependencies — native Workers runtime only
