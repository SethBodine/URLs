/**
 * /api/mylinks — self-service endpoint for URL owners
 *
 * Allows a browser with a verified owner fingerprint to:
 *   GET  /api/mylinks  — list their own shortened URLs
 *   DELETE /api/mylinks — delete one of their own slugs
 *
 * Authentication: X-Owner-Hash + X-Fingerprint headers (HMAC-verified server-side)
 * No admin key required — owners can only see and manage their own URLs.
 */

import { getRandomConspiracy } from '../_conspiracies.js';
import {
  jsonResponse,
  secureHeaders,
  CORS_PUBLIC,
  getVerifiedOwnerHash,
  deriveOwnerHash,
  validateLookupSlug,
  readJsonBody,
} from '../_security.js';

const OWNER_CORS = {
  ...CORS_PUBLIC,
  'Access-Control-Allow-Methods': 'GET, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Owner-Hash, X-Fingerprint',
};

/**
 * Parses a User-Agent string and returns only the browser name and OS name.
 * Never returns the full UA string — prevents fingerprinting/tracking abuse.
 * Examples:
 *   "Chrome 124 / Windows"
 *   "Safari / macOS"
 *   "Firefox / Android"
 */
function parseUaSummary(ua) {
  if (!ua || ua === 'unknown') return 'Unknown';

  // OS detection (order matters — check mobile before desktop)
  let os = 'Unknown OS';
  if (/android/i.test(ua))                         os = 'Android';
  else if (/iphone|ipad|ipod/i.test(ua))           os = 'iOS';
  else if (/windows nt/i.test(ua))                 os = 'Windows';
  else if (/macintosh|mac os x/i.test(ua))         os = 'macOS';
  else if (/linux/i.test(ua))                      os = 'Linux';
  else if (/cros/i.test(ua))                       os = 'ChromeOS';

  // Browser detection (order matters — Edge/OPR before Chrome, Chrome before Safari)
  let browser = 'Unknown Browser';
  if (/edg\//i.test(ua))                           browser = 'Edge';
  else if (/opr\/|opera/i.test(ua))                browser = 'Opera';
  else if (/firefox\/\d/i.test(ua))                browser = 'Firefox';
  else if (/chrome\/\d/i.test(ua))                 browser = 'Chrome';
  else if (/safari\/\d/i.test(ua) && /version\//i.test(ua)) browser = 'Safari';
  else if (/curl\//i.test(ua))                     browser = 'curl';
  else if (/bot|crawler|spider/i.test(ua))         browser = 'Bot';

  return `${browser} / ${os}`;
}

/**
 * Returns a redacted access log entry safe for owner consumption.
 * IP address and full User-Agent are never exposed — only datetime,
 * country, and a parsed browser/OS summary.
 */
function redactLogEntry(entry) {
  return {
    ts:      entry.ts,
    country: entry.country || 'unknown',
    city:    entry.city    || undefined,
    ua:      parseUaSummary(entry.ua),
    // ip and full ua intentionally omitted
  };
}

function ownerView(record, baseUrl) {
  return {
    slug:        record.slug,
    shortUrl:    `${baseUrl}/${record.slug}`,
    url:         record.url,
    createdAt:   record.createdAt,
    previewMode: record.previewMode || false,
    expiresAt:   record.expiresAt || null,
    expiryDays:  record.expiryDays || null,
    accessCount: record.accessCount || 0,
    lastAccessed:record.lastAccessed || null,
    accessLog:   (record.accessLog || []).map(redactLogEntry),
  };
}

// ─── GET /api/mylinks — list the caller's own links ──────────────────────────
export async function onRequestGet(context) {
  const { request, env } = context;

  const ownerHash = await getVerifiedOwnerHash(request, env);
  if (!ownerHash) {
    return jsonResponse({ error: 'Owner verification failed. Provide valid X-Owner-Hash and X-Fingerprint headers.', truth: getRandomConspiracy() }, 401, OWNER_CORS);
  }

  const baseUrl = new URL(request.url).origin;

  try {
    // Scan all keys to find those belonging to this owner.
    // For large deployments a secondary index (ownerHash → [slugs]) would be
    // more efficient, but at this scale a full scan is fine.
    const myLinks = [];
    let cursor;
    do {
      const result = await env.LINKS.list({ cursor, limit: 1000 });
      await Promise.all(result.keys.map(async (key) => {
        const data = await env.LINKS.get(key.name, { type: 'json' });
        if (data && data.ownerHash === ownerHash) {
          myLinks.push(ownerView(data, baseUrl));
        }
      }));
      cursor = result.cursor;
      if (result.list_complete) break;
    } while (cursor);

    // Sort newest first
    myLinks.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    return jsonResponse({ links: myLinks, count: myLinks.length, truth: getRandomConspiracy() }, 200, OWNER_CORS);
  } catch {
    return jsonResponse({ error: 'Failed to retrieve your links.' }, 500, OWNER_CORS);
  }
}

// ─── DELETE /api/mylinks — delete one of the caller's own slugs ──────────────
export async function onRequestDelete(context) {
  const { request, env } = context;

  const ownerHash = await getVerifiedOwnerHash(request, env);
  if (!ownerHash) {
    return jsonResponse({ error: 'Owner verification failed.', truth: getRandomConspiracy() }, 401, OWNER_CORS);
  }

  const bodyResult = await readJsonBody(request);
  if (!bodyResult.ok) {
    return jsonResponse({ error: bodyResult.error, truth: getRandomConspiracy() }, 400, OWNER_CORS);
  }

  const { slug } = bodyResult.body;
  if (!slug) {
    return jsonResponse({ error: 'Provide { "slug": "..." } to delete a link.' }, 400, OWNER_CORS);
  }

  const sv = validateLookupSlug(slug);
  if (!sv.ok) {
    return jsonResponse({ error: sv.error, truth: getRandomConspiracy() }, 422, OWNER_CORS);
  }

  const record = await env.LINKS.get(sv.slug, { type: 'json' });
  if (!record) {
    return jsonResponse({ error: 'Slug not found.', truth: getRandomConspiracy() }, 404, OWNER_CORS);
  }

  // Ownership check — must match
  if (!record.ownerHash || record.ownerHash !== ownerHash) {
    return jsonResponse({ error: 'You do not own this link.', truth: getRandomConspiracy() }, 403, OWNER_CORS);
  }

  await env.LINKS.delete(sv.slug);
  return jsonResponse({ success: true, slug: sv.slug, truth: getRandomConspiracy() }, 200, OWNER_CORS);
}

// ─── PATCH /api/mylinks — update preview mode or expiry on own link ───────────
export async function onRequestPatch(context) {
  const { request, env } = context;

  const ownerHash = await getVerifiedOwnerHash(request, env);
  if (!ownerHash) {
    return jsonResponse({ error: 'Owner verification failed.', truth: getRandomConspiracy() }, 401, OWNER_CORS);
  }

  const bodyResult = await readJsonBody(request);
  if (!bodyResult.ok) {
    return jsonResponse({ error: bodyResult.error, truth: getRandomConspiracy() }, 400, OWNER_CORS);
  }

  const { slug, previewMode } = bodyResult.body;
  if (!slug) {
    return jsonResponse({ error: 'Provide { "slug": "...", "previewMode": true|false }.' }, 400, OWNER_CORS);
  }

  const sv = validateLookupSlug(slug);
  if (!sv.ok) {
    return jsonResponse({ error: sv.error, truth: getRandomConspiracy() }, 422, OWNER_CORS);
  }

  const record = await env.LINKS.get(sv.slug, { type: 'json' });
  if (!record) {
    return jsonResponse({ error: 'Slug not found.', truth: getRandomConspiracy() }, 404, OWNER_CORS);
  }

  if (!record.ownerHash || record.ownerHash !== ownerHash) {
    return jsonResponse({ error: 'You do not own this link.', truth: getRandomConspiracy() }, 403, OWNER_CORS);
  }

  if (previewMode !== undefined) {
    record.previewMode = previewMode === true;
  }

  const kvOptions = record.expiresAt
    ? { expirationTtl: Math.max(1, Math.floor((new Date(record.expiresAt) - Date.now()) / 1000)) }
    : {};

  await env.LINKS.put(sv.slug, JSON.stringify(record), kvOptions);
  return jsonResponse({ success: true, slug: sv.slug, previewMode: record.previewMode, truth: getRandomConspiracy() }, 200, OWNER_CORS);
}

// ─── POST /api/mylinks — derive owner hash from fingerprint (hash recovery) ───
// Allows a browser that has lost its cached hash (e.g. localStorage cleared,
// or OWNER_HASH_SECRET rotated) to re-derive it from its raw fingerprint.
// Only the fingerprint is sent; the server derives and returns the hash.
// This is safe because the secret stays server-side — the fingerprint alone
// cannot be used to forge requests (the server still HMAC-verifies on all
// mutating operations).
export async function onRequestPost(context) {
  const { request, env } = context;

  const rawFp = (request.headers.get('X-Fingerprint') || '').trim();
  if (!rawFp) {
    return jsonResponse({ error: 'X-Fingerprint header is required.' }, 400, OWNER_CORS);
  }

  const hash = await deriveOwnerHash(rawFp, env);
  if (!hash) {
    return jsonResponse({ error: 'Owner hash derivation failed. OWNER_HASH_SECRET may not be configured.' }, 500, OWNER_CORS);
  }

  return jsonResponse({ ownerHash: hash }, 200, OWNER_CORS);
}

export async function onRequestOptions() {
  return new Response(null, { status: 204, headers: secureHeaders(OWNER_CORS) });
}
