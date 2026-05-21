/**
 * _safebrowsing.js — Google Safe Browsing API v5 urls:search
 *
 * Uses the stable v5 urls:search endpoint — NOT v5alpha1.
 * Both have identical request/response format; v5 is the production version.
 *
 *   GET https://safebrowsing.googleapis.com/v5/urls:search
 *     ?key=API_KEY
 *     &urls[]=https://example.com/path
 *
 * Google handles all URL expression generation and hashing server-side —
 * no local SHA256 computation or suffix/prefix expansion needed.
 * The server checks the URL plus its host-suffix/path-prefix expressions
 * automatically, so coverage is equivalent to hashes:search.
 *
 * Response (threat found):
 *   { "threats": [{ "url": "...", "threatTypes": ["MALWARE"] }], "cacheDuration": "300s" }
 *
 * Response (clean):
 *   { "cacheDuration": "300s" }   ← threats field absent or empty
 *
 * Same API key as v4 — no changes to Cloudflare env vars required.
 * Free quota: 10,000 lookups/day.
 */

const V5_ENDPOINT = 'https://safebrowsing.googleapis.com/v5/urls:search';

/**
 * Canonicalize a URL before submission.
 * Strips fragment, default ports, credentials, control chars, lowercases host.
 * Returns canonical URL string, or null if unparseable / non-http(s).
 */
function canonicalize(rawUrl) {
  // eslint-disable-next-line no-control-regex
  const cleaned = String(rawUrl).replace(/[\u0000-\u001F\u007F\u200B-\u200D\uFEFF\u202A-\u202E]/g, '').trim();
  let parsed;
  try { parsed = new URL(cleaned); } catch { return null; }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
  parsed.hash     = '';
  parsed.username = '';
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
 * @param {string} url  — URL to check (canonicalized internally)
 * @param {object} env  — Cloudflare env (needs SAFE_BROWSING_API_KEY)
 * @returns {Promise<{
 *   safe:       boolean,    true if no threats found (or check skipped/errored)
 *   threats:    string[],   threat type strings if flagged, e.g. ['MALWARE']
 *   skipped:    boolean,    true ONLY if API key is absent
 *   apiError:   boolean,    true if key present but API call failed
 *   apiStatus:  number|null HTTP status from a failed API call
 *   checkedUrl: string|null canonicalized URL actually submitted
 * }>}
 */
export async function checkSafeBrowsing(url, env) {
  const apiKey = env.SAFE_BROWSING_API_KEY;

  if (!apiKey || apiKey.length < 10) {
    return { safe: true, threats: [], skipped: true, apiError: false, apiStatus: null, checkedUrl: null };
  }

  const checkedUrl = canonicalize(url);
  if (!checkedUrl) {
    console.warn('[safebrowsing] Could not canonicalize URL:', url);
    return { safe: false, threats: ['UNPARSEABLE_URL'], skipped: false, apiError: false, apiStatus: null, checkedUrl: null };
  }

  const requestUrl = `${V5_ENDPOINT}?key=${apiKey}&urls[]=${encodeURIComponent(checkedUrl)}`;

  try {
    const res = await fetch(requestUrl, {
      method: 'GET',
      headers: { 'User-Agent': 'b0x-url-shortener/2.2 (Safe Browsing v5)' },
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => '(unreadable)');
      console.error(`[safebrowsing] API error ${res.status}:`, errText);
      return { safe: true, threats: [], skipped: false, apiError: true, apiStatus: res.status, checkedUrl };
    }

    const data = await res.json();

    // v5: threats field absent or empty = clean
    if (!data.threats || data.threats.length === 0) {
      return { safe: true, threats: [], skipped: false, apiError: false, apiStatus: null, checkedUrl };
    }

    const threatTypes = [...new Set(data.threats.flatMap(t => t.threatTypes || []))];
    console.warn(`[safebrowsing] THREAT detected for ${checkedUrl}:`, threatTypes.join(', '));
    return { safe: false, threats: threatTypes, skipped: false, apiError: false, apiStatus: null, checkedUrl };

  } catch (err) {
    console.error('[safebrowsing] Fetch failed:', err);
    return { safe: true, threats: [], skipped: false, apiError: true, apiStatus: null, checkedUrl };
  }
}
