/**
 * _safebrowsing.js — Google Safe Browsing API v5 urls:search
 *
 * Uses the stable v5 urls:search endpoint — NOT v5alpha1.
 * Both have identical request/response format; v5 is the production version.
 *
 *   GET https://safebrowsing.googleapis.com/v5/urls:search
 *     ?key=API_KEY
 *     &urls=https://example.com/path
 *
 * Google handles all URL expression generation and hashing server-side —
 * no local SHA256 computation or suffix/prefix expansion needed.
 * The server checks the URL plus its host-suffix/path-prefix expressions
 * automatically, so coverage is equivalent to hashes:search.
 *
 * Response format: binary protobuf always — alt=json returns 400.
 * parseSafeBrowsingProto() decodes the binary response into the shape:
 *   { threats: [{ url, threatTypes: ['MALWARE', ...] }], cacheDuration: '300s', safe: bool }
 *
 * Same API key as v4 — no changes to Cloudflare env vars required.
 * Free quota: 10,000 lookups/day.
 */

const V5_ENDPOINT = 'https://safebrowsing.googleapis.com/v5/urls:search';

const THREAT_TYPES = {
  1: 'MALWARE',
  2: 'SOCIAL_ENGINEERING',
  3: 'UNWANTED_SOFTWARE',
  4: 'POTENTIALLY_HARMFUL_APPLICATION',
};

/**
 * Parse a protobuf varint starting at pos in a Uint8Array.
 * Returns [value, nextPos].
 */
function parseVarint(data, pos) {
  let result = 0, shift = 0;
  while (true) {
    const b = data[pos++];
    result |= (b & 0x7F) << shift;
    if (!(b & 0x80)) return [result, pos];
    shift += 7;
  }
}

/**
 * Decode a raw Safe Browsing v5 protobuf response (ArrayBuffer) into a
 * normalised plain object matching the shape the rest of the codebase expects:
 *
 *   {
 *     threats:       [{ url: string, threatTypes: string[] }],
 *     cacheDuration: '300s',
 *     safe:          boolean,
 *   }
 *
 * Schema decoded explicitly against the known wire layout — no generic
 * recursive heuristic. This avoids the class of bug where a URL string
 * (e.g. "https://...") is misread as a nested message because its leading
 * bytes happen to look like valid varint tags.
 *
 * Proto schema:
 *   message SearchResponse {
 *     repeated Threat threat        = 1;   // wire 2 (length-delimited)
 *     Duration        cacheDuration = 2;   // wire 2 (length-delimited)
 *   }
 *   message Threat {
 *     string          url           = 1;   // wire 2 — always decoded as UTF-8 string
 *     repeated ThreatType threatType = 2;  // wire 0 — varint enum
 *   }
 *   message Duration {
 *     int64 seconds = 1;                   // wire 0 — varint
 *     int32 nanos   = 2;                   // wire 0 — varint
 *   }
 */
export function parseSafeBrowsingProto(arrayBuffer) {
  const utf8 = new TextDecoder();
  const data  = new Uint8Array(arrayBuffer);

  // ── Parse a Threat message bytes into { url, threatTypes } ───────────────
  function parseThreat(bytes) {
    let pos = 0;
    let url = '';
    const threatTypeInts = [];
    while (pos < bytes.length) {
      let tag;
      [tag, pos] = parseVarint(bytes, pos);
      const field = tag >> 3;
      const wire  = tag & 7;
      if (wire === 2) {
        // Length-delimited
        let length;
        [length, pos] = parseVarint(bytes, pos);
        const value = bytes.slice(pos, pos + length);
        pos += length;
        if (field === 1) {
          // url — always a UTF-8 string, never a nested message
          url = utf8.decode(value);
        }
        // Any other wire-2 fields in Threat are unknown — skip them
      } else if (wire === 0) {
        let value;
        [value, pos] = parseVarint(bytes, pos);
        if (field === 2) {
          // threatType — varint enum
          threatTypeInts.push(value);
        }
        // Any other wire-0 fields in Threat are unknown — skip them
      } else {
        break; // unknown wire type — stop parsing this message
      }
    }
    return { url, threatTypes: threatTypeInts.map(v => THREAT_TYPES[v] || `UNKNOWN(${v})`) };
  }

  // ── Parse a Duration message bytes into seconds ───────────────────────────
  function parseDuration(bytes) {
    let pos = 0;
    let seconds = 0;
    while (pos < bytes.length) {
      let tag;
      [tag, pos] = parseVarint(bytes, pos);
      const field = tag >> 3;
      const wire  = tag & 7;
      if (wire === 0) {
        let value;
        [value, pos] = parseVarint(bytes, pos);
        if (field === 1) seconds = value; // seconds field
        // field 2 = nanos — not needed for display; skip
      } else if (wire === 2) {
        let length;
        [length, pos] = parseVarint(bytes, pos);
        pos += length; // skip unknown length-delimited fields
      } else {
        break;
      }
    }
    return seconds;
  }

  // ── Parse the top-level SearchResponse ───────────────────────────────────
  const threats     = [];
  let cacheSeconds  = 0;
  let pos           = 0;

  while (pos < data.length) {
    let tag;
    [tag, pos] = parseVarint(data, pos);
    const field = tag >> 3;
    const wire  = tag & 7;

    if (wire === 2) {
      let length;
      [length, pos] = parseVarint(data, pos);
      const value = data.slice(pos, pos + length);
      pos += length;
      if (field === 1) {
        // repeated Threat
        const t = parseThreat(value);
        if (t.url) threats.push(t);
      } else if (field === 2) {
        // cacheDuration
        cacheSeconds = parseDuration(value);
      }
      // unknown fields — already advanced pos, so just continue
    } else if (wire === 0) {
      // Unexpected varint at top level — skip it
      [, pos] = parseVarint(data, pos);
    } else {
      break; // unknown wire type — stop
    }
  }

  return {
    threats,
    cacheDuration: `${cacheSeconds}s`,
    safe: threats.length === 0,
  };
}

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

  const params = new URLSearchParams({ key: apiKey });
  params.append('urls', checkedUrl);
  const requestUrl = `${V5_ENDPOINT}?${params.toString()}`;

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

    // Response is always binary protobuf — decode it
    const buffer = await res.arrayBuffer();
    const data   = parseSafeBrowsingProto(buffer);

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
