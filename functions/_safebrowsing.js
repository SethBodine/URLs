/**
 * _safebrowsing.js — Google Safe Browsing API v4 integration
 *
 * Checks a URL against Google's threat lists:
 *   - MALWARE
 *   - SOCIAL_ENGINEERING (phishing)
 *   - UNWANTED_SOFTWARE
 *   - POTENTIALLY_HARMFUL_APPLICATION
 *
 * Requires SAFE_BROWSING_API_KEY environment variable.
 * If the key is absent the check is skipped (non-blocking degradation).
 *
 * Free quota: 10,000 lookups/day — more than enough for a personal shortener.
 * Get a key: https://console.developers.google.com → Enable "Safe Browsing API"
 *
 * URL canonicalization applied before sending:
 *   - Fragments (#...) stripped — not part of Google's threat database
 *   - Default ports removed (80/http, 443/https)
 *   - Hostname lowercased; IDN/punycode handled by URL parser
 *   - Control characters and whitespace stripped
 *   - Credentials (user:pass@) stripped (already blocked by validateUrl but
 *     safe to double-strip here in case called outside that path)
 */

/**
 * Threat types to check against.
 *
 * MALWARE                      — drive-by downloads, malicious executables
 * SOCIAL_ENGINEERING           — phishing, deceptive billing ("trick_to_bill"),
 *                                credential harvesting, fake login pages
 * UNWANTED_SOFTWARE            — adware, browser hijackers, PUPs
 * POTENTIALLY_HARMFUL_APPLICATION — PUA/PUP on mobile and desktop
 */
const THREAT_TYPES = [
  'MALWARE',
  'SOCIAL_ENGINEERING',
  'UNWANTED_SOFTWARE',
  'POTENTIALLY_HARMFUL_APPLICATION',
];

/**
 * Platform types — send ALL of them so we catch platform-specific threat list
 * entries (IOS, OSX, ANDROID, etc.).
 *
 * ANY_PLATFORM alone only matches entries explicitly listed under ANY_PLATFORM;
 * it does NOT automatically include entries that are only listed under a
 * specific platform (e.g. IOS/MALWARE/URL). Sending all platforms ensures full
 * coverage. The API deduplicates matches server-side.
 */
const PLATFORM_TYPES = [
  'ANY_PLATFORM',
  'WINDOWS',
  'LINUX',
  'OSX',
  'IOS',
  'ANDROID',
  'CHROME',
];

/**
 * Threat entry types.
 *
 * URL        — web page threats (phishing, malware landing pages, etc.)
 * EXECUTABLE — binary/download threats (malicious .exe, .apk, .zip, etc.)
 *              Covers the "Desktop Download Warnings" and "cookie theft"
 *              categories from Google's test suite.
 */
const THREAT_ENTRY_TYPES = ['URL', 'EXECUTABLE'];

const API_ENDPOINT = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';

/**
 * Canonicalize a URL for Safe Browsing submission.
 *
 * Google's lookup API checks permutations of the URL server-side, but the
 * URL we submit must itself be a valid, normalised form.  Key rules from
 * https://developers.google.com/safe-browsing/v4/urls-hashing#canonicalization
 *
 *   1. Strip fragment identifier (never stored in threat lists)
 *   2. Lowercase the scheme and host
 *   3. Remove default ports
 *   4. Resolve percent-encoding for non-reserved characters
 *   5. Strip embedded credentials
 *   6. Remove control / whitespace chars
 *
 * Returns the canonical URL string, or null if the input cannot be parsed.
 */
function canonicalizeForSafeBrowsing(rawUrl) {
  // Strip control characters and surrounding whitespace
  // eslint-disable-next-line no-control-regex
  const cleaned = String(rawUrl).replace(/[\u0000-\u001F\u007F\u200B-\u200D\uFEFF\u202A-\u202E]/g, '').trim();

  let parsed;
  try {
    parsed = new URL(cleaned);
  } catch {
    return null;
  }

  // Only http/https — other schemes should have been rejected upstream
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;

  // Strip fragment — Safe Browsing does not index fragments
  parsed.hash = '';

  // Strip embedded credentials (extra safety)
  parsed.username = '';
  parsed.password = '';

  // Remove default ports
  if (
    (parsed.protocol === 'http:'  && parsed.port === '80') ||
    (parsed.protocol === 'https:' && parsed.port === '443')
  ) {
    parsed.port = '';
  }

  // Lowercase hostname (URL parser already does this, but be explicit)
  parsed.hostname = parsed.hostname.toLowerCase();

  return parsed.toString();
}

/**
 * Checks a URL against Google Safe Browsing.
 *
 * @param {string} url   - The URL to check (will be canonicalized internally)
 * @param {object} env   - Cloudflare env (needs SAFE_BROWSING_API_KEY)
 * @returns {Promise<{ safe: boolean, threats: string[], skipped: boolean, checkedUrl: string|null }>}
 *   safe:       true if no threats found (or check skipped)
 *   threats:    array of threat type strings if flagged
 *   skipped:    true if the API key is absent (graceful degradation)
 *   checkedUrl: the canonicalized URL that was actually sent to the API
 */
export async function checkSafeBrowsing(url, env) {
  const apiKey = env.SAFE_BROWSING_API_KEY;

  // No key configured — skip silently (don't block link creation)
  if (!apiKey || apiKey.length < 10) {
    return { safe: true, threats: [], skipped: true, checkedUrl: null };
  }

  // Canonicalize before submitting
  const checkedUrl = canonicalizeForSafeBrowsing(url);
  if (!checkedUrl) {
    // Unparseable URL — treat as unsafe to be conservative
    console.warn('Safe Browsing: could not canonicalize URL:', url);
    return { safe: false, threats: ['UNPARSEABLE_URL'], skipped: false, checkedUrl: null };
  }

  const body = {
    client: {
      clientId:      'b0x-url-shortener',
      clientVersion: '2.0.0',
    },
    threatInfo: {
      threatTypes:      THREAT_TYPES,
      platformTypes:    PLATFORM_TYPES,
      threatEntryTypes: THREAT_ENTRY_TYPES,
      threatEntries:    [{ url: checkedUrl }],
    },
  };

  try {
    const res = await fetch(`${API_ENDPOINT}?key=${apiKey}`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(body),
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => '(unreadable)');
      console.error(`Safe Browsing API error ${res.status}:`, errText);
      // Fail open on API errors (quota exceeded, bad key, etc.) so legitimate
      // users aren't blocked by infrastructure problems.
      return { safe: true, threats: [], skipped: true, checkedUrl };
    }

    const data = await res.json();

    // Empty matches object = clean
    if (!data.matches || data.matches.length === 0) {
      return { safe: true, threats: [], skipped: false, checkedUrl };
    }

    const threats = [...new Set(data.matches.map(m => m.threatType))];
    return { safe: false, threats, skipped: false, checkedUrl };

  } catch (err) {
    // Network error — fail open
    console.error('Safe Browsing fetch failed:', err);
    return { safe: true, threats: [], skipped: true, checkedUrl };
  }
}
