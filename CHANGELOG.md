# Changelog

All notable changes to this project are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [2.4.0] — 2026-08-16

### Fixed

#### Select-bar and relink buttons stretching full-width, one per row (`public/admin.html`)
- A global `button { width: 100%; }` rule (meant for the login form's submit button) applied to every button on the page unless overridden per-button. The older select-bar buttons (`Rescan`, `Delete`) got away with it because `.select-bar` had no `flex-wrap`, so the row's `nowrap` forced same-line shrinking despite each button's 100%-wide flex-basis. Adding `flex-wrap: wrap` in the previous fix (to stop the summary text fracturing mid-word) removed that forced compression — so every select-bar button, plus the newer bulk-action and relink/unlink buttons which never had a `width: auto` override to begin with, started stacking full-width, one per line. Added `width: auto` to `.select-bar button` and `.relink-btn`, so all of them size to their content again and wrap as a compact group instead.

#### First link created on a brand-new browser never linked to "My Links" (`functions/_security.js`, `functions/api/shorten.js`)
- `getVerifiedOwnerHash` required **both** `X-Owner-Hash` and `X-Fingerprint` to be present, returning `null` otherwise. On a brand-new browser there's no cached hash yet, so the very first "link to my browser" request only carries `X-Fingerprint` — the server rejected it outright and created that link with `ownerHash: null`, i.e. genuinely never linked, not just temporarily hidden. Whatever the user did next (e.g. opening the My Links tab, which derives and caches a hash via the existing recovery flow) is why the *second* link would then work.
- Added `resolveOwnerHash()`: behaves exactly like `getVerifiedOwnerHash` when both headers are sent, but if only `X-Fingerprint` is present it derives and self-issues a fresh hash instead of rejecting — the same trust model `POST /api/mylinks` already uses for recovery (deriving a hash from a fingerprint is a pure function of the fingerprint and the server secret, so it discloses nothing an already-authenticated client couldn't compute itself). `shorten.js` now uses this for the one endpoint that originates new ownership links; every read/mutate endpoint (`mylinks.js`, `lookup.js`, `debug-auth.js`) keeps using the strict `getVerifiedOwnerHash`.

#### Admin panel — three UI bugs in select mode (`public/admin.html`)
- **Select-bar text wrapping character-by-character** ("Check / rows / to / select" stacking vertically) — `#select-summary` now has `white-space: nowrap`, and `.select-bar` wraps as a whole (`flex-wrap: wrap`) so the summary text stays intact on one line and the controls flow below it as a group on narrow viewports, instead of the label itself fracturing mid-word.
- **Table content squeezed inward when entering select mode** — the expandable meta-row (Safe Browsing status / access log / etc.) was hardcoded to `colspan="8"`, but the table actually has 9 columns; the leading checkbox column exists in the DOM at all times and is only toggled via CSS (`display:none` outside select mode), and a hidden column still counts toward `colspan`. Once select mode was entered, the checkbox column became visible and the meta-row's `colspan="8"` fell one column short of the table's actual width, squeezing its content. Corrected to `colspan="9"` (also fixed on the "Loading…" and "No links found" placeholder rows, which had the same bug).
- **Stacked flag pills touching** — `.pill` had `margin-right` but no vertical margin, so pills that wrapped onto a second line (e.g. `preview` + `exp 15/09/2026`) sat flush against each other. Added `margin-bottom` alongside the existing `margin-right`.

### Added

#### Admin panel — relink a link's owner on a user's behalf (`public/admin.html`, `functions/api/admin.js`, `README.md`)
- Each link's expandable row now has an "Ownership" section: paste the value from the affected user's `X-Fingerprint` (their device key) *or* their `X-Owner-Hash` directly — both are things they can copy from their own "view API credentials" panel and hand you — and click Relink. An "Unlink" button (shown once a link has an owner) clears ownership entirely, behind the existing confirm-modal pattern.
- `PATCH /api/admin` gained `ownerFingerprint` (derives the hash server-side from a raw device key, same as normal linking) and `ownerHash` (sets a known hash directly, or `null` to unlink) — usable per-slug or across a batch via `slugs`, alongside the existing `deactivated`/`expiryDays`/`previewMode` fields. Documented in `README.md`.

### Files Changed

| File | Summary |
|---|---|
| `functions/_security.js` | Add `resolveOwnerHash()` — self-issues a hash from a fingerprint-only request instead of rejecting it |
| `functions/api/shorten.js` | Use `resolveOwnerHash()` so a browser's first-ever link actually gets linked |
| `functions/api/admin.js` | `PATCH /api/admin` gains `ownerFingerprint`/`ownerHash` for admin-driven relinking |
| `public/admin.html` | Fix select-bar text wrap, meta-row `colspan`, stacked-pill spacing; add per-slug relink/unlink UI |
| `README.md` | Document the new `ownerFingerprint`/`ownerHash` PATCH fields |
| `CHANGELOG.md` | This entry |

---

## [2.3.0] — 2026-08-16

### Fixed

#### Admin panel — invalid key briefly rendered the full dashboard (`public/admin.html`)
- `showPanel()` was called immediately on login submit (and on page load whenever a cached session key existed), before the key had been checked against the server. `loadLinks()` then ran afterward and only *then* discovered the key was invalid, alerting and reloading — but by that point the stats, table headers, and IP blocklist section had already rendered behind the alert.
- Replaced with `attemptLogin(key, fromSession)`, which calls `GET /api/admin` to verify the key **before** anything is shown. A bad key from the login form now shows an inline error on the login card instead of an `alert()`; a stale cached session key is cleared silently and the user stays on the login screen. `showPanel()` is only ever called after a `200` from the server, and now accepts the already-fetched link list so login doesn't trigger a redundant second request.

#### `GET /api/mylinks` — intermittent `401 Owner verification failed` (`public/index.html`)
- Root cause: the client fingerprint sent as `X-Fingerprint` was built from `navigator.userAgent`, which includes the browser's exact version string. Routine browser auto-updates (roughly every 2–4 weeks) change that string, which silently changed the derived owner hash and orphaned every link the browser had previously linked. Screen-resolution changes (docking a laptop) and timezone changes (travel) could do the same to the other signals in the mix.
- Replaced the multi-signal environment fingerprint (UA, language, `hardwareConcurrency`, `deviceMemory`, screen dimensions, color depth, timezone, platform, `cookieEnabled`, canvas rendering) with a single random ID generated once via `crypto.randomUUID()` and stored in `localStorage`. Nothing about a browser update, OS update, or reboot touches `localStorage`, so the key no longer drifts on its own. This also stops relying on canvas fingerprinting, which several privacy-hardened browsers (Firefox, Brave) intentionally randomize per session, and which was very likely a second, independent source of the same symptom.
- Added a one-time self-healing retry: if a cached `X-Owner-Hash` is rejected with `401`, the client now clears it, re-derives from the current device key via `POST /api/mylinks`, and retries once before surfacing an error — covers residual edge cases (e.g. `OWNER_HASH_SECRET` rotation) without a full page reload.
- **One-time side effect:** because the raw value being hashed changed shape entirely (a bare UUID vs. the old joined-signal string), every existing owner hash stops matching on deploy — this is expected and is a single occurrence, not a recurrence of the bug being fixed.

### Added

#### Admin panel — bulk expiry and preview toggle for selected links (`public/admin.html`, `functions/api/admin.js`)
- Select mode's action bar now includes a "Set expiry…" dropdown (same 30/60/90/180/365-day options as link creation, plus "Clear expiry") and `+ Preview` / `− Preview` buttons, applying to every checked row in one request.
- `PATCH /api/admin` now accepts `{ "slugs": [...] }` (max 500) alongside the existing single-slug `{ "slug": "..." }`, and any combination of `deactivated`, `expiryDays` (`30|60|90|180|365|null`), and `previewMode` in one call — only fields present in the body are touched. The response includes a per-slug `results` array so partial failures in a batch (e.g. a slug deleted mid-flight) are distinguishable from a full failure; the admin UI now surfaces those partial failures in an alert instead of treating any `200` as fully successful.
- `PATCH /api/admin` was previously undocumented in `README.md` entirely — added full documentation with request/response shapes and curl examples.

#### My Links — manual device key backup/restore (`public/index.html`)
- The existing "view API credentials" panel gained a "Restore a device key" field: paste a previously copied `X-Fingerprint` value (saved from this or another browser) to reassociate this browser with an existing set of links. Covers cases the stored key alone can't survive — a cleared site data, a browser reinstall, a new profile, or a new machine.
- Added a hover tooltip on the fingerprint badge (main view) and a persistent notice above the list (My Links view) explaining the device-key change in plain terms, with a link that jumps straight to and focuses the restore field.

### Files Changed

| File | Summary |
|---|---|
| `public/admin.html` | Fix login flow to verify key before rendering panel; add bulk expiry/preview UI and handlers; surface partial batch failures |
| `functions/api/admin.js` | `PATCH /api/admin` now supports `slugs` batch + `expiryDays`/`previewMode` alongside `deactivated`, with per-slug results |
| `public/index.html` | Replace environment-derived fingerprint with a stored random device key; add 401 self-healing retry on `/api/mylinks`; add device-key restore field, tooltip, and My Links notice |
| `README.md` | Rename "browser fingerprint" → "device key" throughout; document `PATCH /api/admin` (previously undocumented); add curl examples |
| `CHANGELOG.md` | This entry |

---

## [2.2.0] — 2026-05-23

### Fixed

#### Safe Browsing — Protobuf response decoding (`functions/_safebrowsing.js`, `functions/_rescan.js`)
- **Root cause of all missed threat detections:** `$alt=json` was being appended to every Safe Browsing v5 API request. The v5 endpoint does not support this parameter and returns HTTP 400 for any request that includes it. All three call sites (`checkSafeBrowsing`, `probeApi`, `batchCheck`) were silently failing open — treating every URL as clean — because the 400 response triggered the fail-open error path.
- The v5 API always returns binary protobuf regardless of query parameters. Removed `$alt=json` from all call sites and replaced `res.json()` / `res.text()` with `res.arrayBuffer()` + a new `parseSafeBrowsingProto()` decoder.
- `parseSafeBrowsingProto()` is an explicit schema-aware protobuf decoder ported from the reference Python implementation in the API quick-reference doc. It decodes the `SearchResponse` wire format directly against the known field layout — field 1 (repeated `Threat`), field 2 (`Duration`) — without relying on generic recursive heuristics that could misinterpret URL strings as nested messages.
- The initial generic recursive decoder was replaced because URL strings (e.g. `https://malware.example.com`) start with bytes that look like valid protobuf varint tags. The generic approach would decode the URL field as a nested message, discard it as having no URL, and silently report the threat as clean. The schema-aware decoder treats field 1 of every `Threat` message as a UTF-8 string unconditionally.
- `parseSafeBrowsingProto` is exported from `_safebrowsing.js` and shared by both `_rescan.js` call sites (`probeApi` and `batchCheck`).
- Removed the `protobuf_response` detection branch from `probeApi` — this dead-end guard existed solely because `$alt=json` was causing binary responses on what should have been error paths; it is no longer reachable.
- Removed `Accept: application/json` header from all Safe Browsing fetch calls — meaningless for this API.

#### `admin.js` — `purgeAll` deleted count inflated (`functions/api/admin.js`)
- `deleted` counter was incremented by the total number of KV keys listed (including `rl:` rate-limit and `bl:ip:` blocklist entries) before the `isLinkKey()` filter was applied. The reported deleted count could be significantly higher than the number of links actually removed. Fixed to count only after filtering.

#### `mylinks.js` — unnecessary KV reads on non-link keys (`functions/api/mylinks.js`)
- The owner links scan was reading every key in the KV namespace — including `rl:` and `bl:ip:` entries — before filtering by `ownerHash`. These keys can never match and the reads were wasted. Added `isLinkKey`-equivalent prefix filter before the `LINKS.get` calls, consistent with the pattern already used in `_rescan.js`.

#### `_rescan.js` — flagged stats incremented before KV write confirmed (`functions/_rescan.js`)
- `stats.newlyFlagged` and `stats.flaggedSlugs` were incremented before the `env.LINKS.put()` deactivation write. If the KV write failed, the slug would appear in both `flaggedSlugs` (falsely implying deactivation succeeded) and `errorSlugs`. Moved both increments to inside the `try` block after the `put()` resolves successfully.

#### `_rescan.js` — dead import and stale comments
- Removed unused `checkSafeBrowsing` import — `_rescan.js` performs its own batched fetch and never called this function.
- Updated `probeApi` JSDoc and file-level header comments that incorrectly described the batch size as 50 (the v5 API maximum) when the actual `BATCH_SIZE` constant is 10 (chosen to respect Cloudflare's ~8KB URL length limit).
- Updated `probeApi` JSDoc return description from "returning JSON" to "protobuf response is decodable".

#### `_rescan.js` — `skippedNoKey` stat not initialised (`functions/_rescan.js`)
- `skippedNoKey` was written dynamically with `(stats.skippedNoKey || 0) + 1` but never declared in the `stats` object initialisation, causing the field to be absent from scan responses unless that path was hit. Initialised to `0` alongside all other stat fields.

#### `lookup.js` — unused import (`functions/api/lookup.js`)
- Removed `CORS_ADMIN` from the `_security.js` import — it was imported but every response in the file uses `CORS_PUBLIC`.

#### `debug-auth.js` — missing security headers on preflight response (`functions/api/debug-auth.js`)
- `onRequestOptions` was returning `{ ...CORS_PUBLIC }` directly, bypassing `secureHeaders()`. This meant the 204 preflight response was missing all `SECURITY_HEADERS` (CSP, X-Frame-Options, Cache-Control, etc.). Fixed to use `secureHeaders(CORS_PUBLIC)` consistently with every other `onRequestOptions` in the codebase.

### Files Changed

| File | Summary |
|---|---|
| `functions/_safebrowsing.js` | Removed `$alt=json`; replaced `res.json()` with `arrayBuffer()` + schema-aware protobuf decoder; export `parseSafeBrowsingProto` |
| `functions/_rescan.js` | Removed `$alt=json` from `probeApi` and `batchCheck`; use `parseSafeBrowsingProto`; fix stat ordering; fix `skippedNoKey` init; remove dead import; fix comments |
| `functions/api/admin.js` | Fix `purgeAll` deleted count |
| `functions/api/mylinks.js` | Filter non-link keys before KV reads in owner scan |
| `functions/api/lookup.js` | Remove unused `CORS_ADMIN` import |
| `functions/api/debug-auth.js` | Fix `onRequestOptions` to use `secureHeaders()` |
| `README.md` | Fix stale v4 reference in architecture diagram; add `skippedNoKey` to scan response example |
| `CHANGELOG.md` | This entry |

---



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
