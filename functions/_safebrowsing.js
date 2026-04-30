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
 */

const THREAT_TYPES = [
  'MALWARE',
  'SOCIAL_ENGINEERING',
  'UNWANTED_SOFTWARE',
  'POTENTIALLY_HARMFUL_APPLICATION',
];

const PLATFORM_TYPES    = ['ANY_PLATFORM'];
const THREAT_ENTRY_TYPES = ['URL'];

const API_ENDPOINT = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';

/**
 * Checks a URL against Google Safe Browsing.
 *
 * @param {string} url   - The normalised URL to check
 * @param {object} env   - Cloudflare env (needs SAFE_BROWSING_API_KEY)
 * @returns {Promise<{ safe: boolean, threats: string[], skipped: boolean }>}
 *   safe:    true if no threats found (or check skipped)
 *   threats: array of threat type strings if flagged
 *   skipped: true if the API key is absent (graceful degradation)
 */
export async function checkSafeBrowsing(url, env) {
  const apiKey = env.SAFE_BROWSING_API_KEY;

  // No key configured — skip silently (don't block link creation)
  if (!apiKey || apiKey.length < 10) {
    return { safe: true, threats: [], skipped: true };
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
      threatEntries:    [{ url }],
    },
  };

  try {
    const res = await fetch(`${API_ENDPOINT}?key=${apiKey}`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(body),
    });

    if (!res.ok) {
      // API error (quota exceeded, bad key, etc.) — fail open (don't block users)
      console.error('Safe Browsing API error:', res.status, await res.text());
      return { safe: true, threats: [], skipped: true };
    }

    const data = await res.json();

    // Empty matches object = clean
    if (!data.matches || data.matches.length === 0) {
      return { safe: true, threats: [], skipped: false };
    }

    const threats = [...new Set(data.matches.map(m => m.threatType))];
    return { safe: false, threats, skipped: false };

  } catch (err) {
    // Network error — fail open
    console.error('Safe Browsing fetch failed:', err);
    return { safe: true, threats: [], skipped: true };
  }
}
