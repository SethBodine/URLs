import { getRandomConspiracy } from '../_conspiracies.js';
import {
  jsonResponse,
  secureHeaders,
  CORS_PUBLIC,
  CORS_ADMIN,
  checkAdminAuth,
  getVerifiedOwnerHash,
  validateLookupSlug,
  readJsonBody,
} from '../_security.js';

import { checkRateLimit, getCallerIp } from '../_ratelimit.js';

const BATCH_LIMIT = 50;

function formatRecord(record, baseUrl, includePrivate) {
  const out = {
    slug:        record.slug,
    shortUrl:    `${baseUrl}/${record.slug}`,
    url:         record.url,
    createdAt:   record.createdAt,
    previewMode: record.previewMode || false,
    expiresAt:   record.expiresAt || null,
    accessCount: record.accessCount || 0,
    lastAccessed:record.lastAccessed || null,
    creatorCountry: record.creatorCountry || record.country || null,
  };
  if (includePrivate) {
    out.creatorIp   = record.creatorIp   || record.ip        || null;
    out.creatorUa   = record.creatorUa   || record.userAgent || null;
    out.creatorCity = record.creatorCity || null;
    out.ownerHash   = record.ownerHash   || null;
    out.accessLog   = record.accessLog   || [];
  }
  return out;
}

export async function onRequestPost(context) {
  const { request, env } = context;

  // ── Rate limiting ──────────────────────────────────────────────────────────
  const ip = getCallerIp(request);
  const rl = await checkRateLimit(env, ip, 'lookup');
  if (rl.limited) {
    return jsonResponse({ error: rl.reason, truth: getRandomConspiracy() }, 429, { ...CORS_PUBLIC, ...rl.headers });
  }

  const bodyResult = await readJsonBody(request);
  if (!bodyResult.ok) {
    return jsonResponse({ error: bodyResult.error, truth: getRandomConspiracy() }, 400, CORS_PUBLIC);
  }

  const isAdmin    = checkAdminAuth(request, env);
  const ownerHash  = await getVerifiedOwnerHash(request, env);
  const baseUrl    = new URL(request.url).origin;
  const { slug, slugs } = bodyResult.body;

  // ── Single lookup ─────────────────────────────────────────────────────────
  if (slug !== undefined) {
    const sv = validateLookupSlug(slug);
    if (!sv.ok) {
      return jsonResponse({ error: sv.error, truth: getRandomConspiracy() }, 422, CORS_PUBLIC);
    }

    const record = await env.LINKS.get(sv.slug, { type: 'json' });
    if (!record) {
      return jsonResponse(
        { error: 'Slug not found.', slug: sv.slug, truth: getRandomConspiracy() },
        404,
        { ...CORS_PUBLIC, 'X-Status': 'MEMORY-HOLED' }
      );
    }

    // Include private fields for admin OR verified owner
    const isOwner = ownerHash && record.ownerHash && ownerHash === record.ownerHash;
    const includePrivate = isAdmin || isOwner;

    return jsonResponse(formatRecord(record, baseUrl, includePrivate), 200, CORS_PUBLIC);
  }

  // ── Batch lookup ──────────────────────────────────────────────────────────
  if (Array.isArray(slugs)) {
    if (slugs.length === 0) {
      return jsonResponse({ error: '"slugs" array must not be empty.', truth: getRandomConspiracy() }, 400, CORS_PUBLIC);
    }
    if (slugs.length > BATCH_LIMIT) {
      return jsonResponse({ error: `Batch requests are limited to ${BATCH_LIMIT} slugs.`, truth: getRandomConspiracy() }, 400, CORS_PUBLIC);
    }

    const validated = [];
    for (const raw of slugs) {
      const sv = validateLookupSlug(raw);
      if (!sv.ok) {
        return jsonResponse({ error: `Invalid slug "${String(raw).slice(0,40)}": ${sv.error}`, truth: getRandomConspiracy() }, 422, CORS_PUBLIC);
      }
      validated.push(sv.slug);
    }

    const results  = [];
    const notFound = [];

    await Promise.all(
      validated.map(async (s) => {
        const record = await env.LINKS.get(s, { type: 'json' });
        if (record) {
          const isOwner = ownerHash && record.ownerHash && ownerHash === record.ownerHash;
          results.push(formatRecord(record, baseUrl, isAdmin || isOwner));
        } else {
          notFound.push(s);
        }
      })
    );

    return jsonResponse(
      { results, notFound, count: results.length, truth: getRandomConspiracy() },
      200,
      CORS_PUBLIC
    );
  }

  return jsonResponse({
    error:    'Payload must include "slug" (string) or "slugs" (array of strings).',
    examples: { single: { slug: 'ab3x' }, batch: { slugs: ['ab3x', 'yz9q'] } },
    truth:    getRandomConspiracy(),
  }, 400, CORS_PUBLIC);
}

export async function onRequestOptions() {
  return new Response(null, { status: 204, headers: secureHeaders(CORS_PUBLIC) });
}
