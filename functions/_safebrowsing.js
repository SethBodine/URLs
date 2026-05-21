/**
 * _safebrowsing.js — Google Safe Browsing API v5 integration
 *
 * WHY v5, NOT v4
 * ──────────────
 * The v4 API is deprecated. More importantly, v4 uses locally-cached threat
 * lists that can be 20–50 minutes stale. v5 performs real-time checks against
 * Google's live database — the same data used by the Transparency Report and
 * Chrome. This is why URLs that show as flagged on the Transparency Report
 * were passing our v4 checks.
 *
 * The v5 `urls:search` endpoint is simpler than v4:
 *   - Plain GET request with urls[] query params — no POST body, no threat type
 *     matrix to configure
 *   - Google classifies threats on their end — no platformTypes or
 *     threatEntryTypes to specify
 *   - Same API key as v4 — no changes needed in Cloudflare env vars
 *   - Up to 50 URLs per request (we call one at a time for the lookup path;
 *     the rescan path fans out with concurrency capping)
 *
 * ENDPOINT
 * ────────
 * GET https://safebrowsing.googleapis.com/v5alpha1/urls:search
 *   ?key=API_KEY
 *   &urls[]=https://example.com
 *
 * RESPONSE (threat found)
 * ───────────────────────
 * {
 *   "threats": [
 *     { "url": "https://example.com", "threatTypes": ["MALWARE"] }
 *   ],
 *   "cacheDuration": "300s"
 * }
 *
 * RESPONSE (clean)
 * ────────────────
 * { "cacheDuration": "300s" }   ← threats field absent or empty array
 *
 * QUOTA
 * ─────
 * Free tier: 10,000 lookups/day. Each call to checkSafeBrowsing() = 1 lookup.
 * Get/manage key: console.cloud.google.com → Safe Browsing API → Credentials
 */

const V5_ENDPOINT = 'https://safebrowsing.googleapis.com/v5alpha1/urls:search';

/**
 * Canonicalize a URL before submission.
 *
 * v5 performs its own canonicalization server-side, but we still normalize
 * on our end to ensure consistent KV audit records and to strip fragments
 * (which are never part of any threat list entry).
 *
 * Returns the canonical URL string, or null if unparseable.
 */
function canonicalize(rawUrl) {
  // eslint-disable-next-line no-control-regex
  const cleaned = String(rawUrl).replace(/[\u0000-\u001F\u007F\u200B-\u200D\uFEFF\u202A-\u202E]/g, '').trim();
  let parsed;
  try { parsed = new URL(cleaned); } catch { return null; }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
  parsed.hash = '';      // fragments never appear in threat lists
  parsed.username = '';  // strip credentials
  parsed.password = '';
  if ((parsed.protocol === 'http:'  && parsed.port === '80') ||
      (parsed.protocol === 'https:' && parsed.port === '443')) {
    parsed.port = '';
  }
  parsed.hostname = parsed.hostname.toLowerCase();
  return parsed.toString();
}

/**
 * checkSafeBrowsing(url, env)
 *
 * Checks a URL against Google Safe Browsing v5.
 *
 * @param {string} url  — The URL to check (will be canonicalized internally)
 * @param {object} env  — Cloudflare env (needs SAFE_BROWSING_API_KEY)
 * @returns {Promise<{
 *   safe:       boolean,   — true if no threats found (or check skipped)
 *   threats:    string[],  — threat type strings if flagged, e.g. ['MALWARE']
 *   skipped:    boolean,   — true if API key absent (fail-open degradation)
 *   checkedUrl: string|null — canonicalized URL actually submitted
 * }>}
 */
export async function checkSafeBrowsing(url, env) {
  const apiKey = env.SAFE_BROWSING_API_KEY;

  if (!apiKey || apiKey.length < 10) {
    // No key — skip silently (don't block link creation)
    return { safe: true, threats: [], skipped: true, checkedUrl: null };
  }

  const checkedUrl = canonicalize(url);
  if (!checkedUrl) {
    console.warn('[safebrowsing] Could not canonicalize URL:', url);
    return { safe: false, threats: ['UNPARSEABLE_URL'], skipped: false, checkedUrl: null };
  }

  const requestUrl = `${V5_ENDPOINT}?key=${apiKey}&urls[]=${encodeURIComponent(checkedUrl)}`;

  try {
    const res = await fetch(requestUrl, {
      method: 'GET',
      headers: {
        'User-Agent': 'b0x-url-shortener/2.1 (Safe Browsing v5)',
      },
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => '(unreadable)');
      console.error(`[safebrowsing] API error ${res.status}:`, errText);
      // Fail open on API errors — don't block legitimate users due to
      // infrastructure problems (quota, bad key, rate limit, etc.)
      return { safe: true, threats: [], skipped: true, checkedUrl };
    }

    const data = await res.json();

    // v5: threats field is absent or empty when clean
    if (!data.threats || data.threats.length === 0) {
      return { safe: true, threats: [], skipped: false, checkedUrl };
    }

    // Collect all threat types across all matched URLs
    const threatTypes = [
      ...new Set(data.threats.flatMap(t => t.threatTypes || [])),
    ];

    console.warn(`[safebrowsing] THREAT detected for ${checkedUrl}:`, threatTypes.join(', '));
    return { safe: false, threats: threatTypes, skipped: false, checkedUrl };

  } catch (err) {
    // Network error — fail open
    console.error('[safebrowsing] Fetch failed:', err);
    return { safe: true, threats: [], skipped: true, checkedUrl };
  }
}
