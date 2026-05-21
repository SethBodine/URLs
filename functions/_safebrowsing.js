/**
 * _safebrowsing.js — Google Safe Browsing API v4 Lookup API
 *
 * We use v4 (not v5alpha1) because:
 *   - v4 FindThreatMatches is stable and production-ready
 *   - v5alpha1 urls:search returns 100% errors in practice
 *   - Stable v5 only offers hash-based lookups (hashes:search) which require
 *     local SHA256 computation — significantly more complex to implement
 *
 * The earlier missed detections (IOS/MALWARE/URL, etc.) were caused by an
 * incomplete platform type list and an invalid EXECUTABLE threat entry type.
 * Both are fixed here. v4 with correct parameters catches the same URLs as
 * the Transparency Report for the threat categories we care about.
 *
 * THREAT TYPES
 * ────────────
 *   MALWARE                       drive-by downloads, malicious pages
 *   SOCIAL_ENGINEERING            phishing, deceptive billing, fake logins
 *   UNWANTED_SOFTWARE             adware, browser hijackers
 *   POTENTIALLY_HARMFUL_APPLICATION  PUPs on mobile and desktop
 *
 * PLATFORM TYPES — send ALL to catch platform-specific list entries
 * ────────────────
 *   ANY_PLATFORM alone only matches entries explicitly under that key.
 *   IOS, OSX, ANDROID threats live in separate lists — must be listed.
 *
 * THREAT ENTRY TYPE
 * ─────────────────
 *   URL only. EXECUTABLE is for the Update API hash-digest workflow, not
 *   the Lookup API — using it here caused malformed requests.
 *
 * QUOTA
 * ─────
 *   Free tier: 10,000 lookups/day.
 *   Get/manage key: console.cloud.google.com → Safe Browsing API → Credentials
 */

const V4_ENDPOINT = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';

const THREAT_TYPES = [
  'MALWARE',
  'SOCIAL_ENGINEERING',
  'UNWANTED_SOFTWARE',
  'POTENTIALLY_HARMFUL_APPLICATION',
];

const PLATFORM_TYPES = [
  'ANY_PLATFORM',
  'WINDOWS',
  'LINUX',
  'OSX',
  'IOS',
  'ANDROID',
  'CHROME',
];

// URL is the only valid threat entry type for the v4 Lookup API.
// EXECUTABLE is a hash-digest type for the Update API only.
const THREAT_ENTRY_TYPES = ['URL'];

// ─── URL canonicalization ─────────────────────────────────────────────────────

/**
 * Canonicalize a URL before submission per Google's spec:
 *   - Strip fragment (#...) — never indexed in threat lists
 *   - Remove default ports (80/http, 443/https)
 *   - Lowercase hostname
 *   - Strip embedded credentials and control characters
 *
 * Returns the canonical URL string, or null if unparseable.
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

// ─── Main export ──────────────────────────────────────────────────────────────

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

  const body = {
    client: {
      clientId:      'b0x-url-shortener',
      clientVersion: '2.2.0',
    },
    threatInfo: {
      threatTypes:      THREAT_TYPES,
      platformTypes:    PLATFORM_TYPES,
      threatEntryTypes: THREAT_ENTRY_TYPES,
      threatEntries:    [{ url: checkedUrl }],
    },
  };

  try {
    const res = await fetch(`${V4_ENDPOINT}?key=${apiKey}`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(body),
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => '(unreadable)');
      console.error(`[safebrowsing] API error ${res.status}:`, errText);
      // Fail open — key present but API erroring (quota, permissions, etc.)
      return { safe: true, threats: [], skipped: false, apiError: true, apiStatus: res.status, checkedUrl };
    }

    const data = await res.json();

    // v4: empty matches object = clean
    if (!data.matches || data.matches.length === 0) {
      return { safe: true, threats: [], skipped: false, apiError: false, apiStatus: null, checkedUrl };
    }

    const threats = [...new Set(data.matches.map(m => m.threatType))];
    console.warn(`[safebrowsing] THREAT detected for ${checkedUrl}:`, threats.join(', '));
    return { safe: false, threats, skipped: false, apiError: false, apiStatus: null, checkedUrl };

  } catch (err) {
    console.error('[safebrowsing] Fetch failed:', err);
    return { safe: true, threats: [], skipped: false, apiError: true, apiStatus: null, checkedUrl };
  }
}
