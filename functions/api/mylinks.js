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
  validateLookupSlug,
  readJsonBody,
} from '../_security.js';

const OWNER_CORS = {
  ...CORS_PUBLIC,
  'Access-Control-Allow-Methods': 'GET, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Owner-Hash, X-Fingerprint',
};

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
    accessLog:   record.accessLog   || [],
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

export async function onRequestOptions() {
  return new Response(null, { status: 204, headers: secureHeaders(OWNER_CORS) });
}
