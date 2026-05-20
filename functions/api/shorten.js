import { getRandomConspiracy } from '../_conspiracies.js';
import {
  jsonResponse,
  secureHeaders,
  CORS_PUBLIC,
  validateUrl,
  validateCustomSlug,
  validateExpiry,
  getVerifiedOwnerHash,
  readJsonBody,
} from '../_security.js';
import { checkSafeBrowsing } from '../_safebrowsing.js';
import { checkRateLimit, getCallerIp } from '../_ratelimit.js';
import { isIpBlocked, blockIp, blankResponse } from '../_blocklist.js';

const CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789';
const SHORT_LENGTH = 4;
const MAX_RETRIES  = 8;

function generateCode(length = SHORT_LENGTH) {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return Array.from(array, b => CHARS[b % CHARS.length]).join('');
}

async function generateUniqueSlug(kv) {
  for (let i = 0; i < MAX_RETRIES; i++) {
    const len  = i < 5 ? SHORT_LENGTH : SHORT_LENGTH + 1;
    const slug = generateCode(len);
    if (!(await kv.get(slug))) return slug;
  }
  return generateCode(SHORT_LENGTH + 2);
}

export async function onRequestPost(context) {
  const { request, env } = context;

  const ip = getCallerIp(request);

  // ── IP blocklist check (silent — blank 200, no hints) ─────────────────────
  // Check BEFORE rate limiting so blocked IPs don't consume quota counters.
  if (await isIpBlocked(env, ip)) {
    return blankResponse();
  }

  // ── Rate limiting ──────────────────────────────────────────────────────────
  const rl = await checkRateLimit(env, ip, 'shorten');
  if (rl.limited) {
    return jsonResponse({ error: rl.reason, truth: getRandomConspiracy() }, 429, { ...CORS_PUBLIC, ...rl.headers });
  }

  const bodyResult = await readJsonBody(request);
  if (!bodyResult.ok) {
    return jsonResponse({ error: bodyResult.error, truth: getRandomConspiracy() }, 400, CORS_PUBLIC);
  }

  const { url, customSlug, expiryDays, preview } = bodyResult.body;

  if (url === undefined || url === null) {
    return jsonResponse({ error: 'A "url" field is required.', truth: getRandomConspiracy() }, 400, CORS_PUBLIC);
  }

  // ── URL validation ─────────────────────────────────────────────────────────
  const urlResult = validateUrl(url);
  if (!urlResult.ok) {
    return jsonResponse({ error: urlResult.error, truth: getRandomConspiracy() }, 422, CORS_PUBLIC);
  }

  const normalisedUrl = urlResult.url;

  // ── Safe Browsing check ────────────────────────────────────────────────────
  const sbResult = await checkSafeBrowsing(normalisedUrl, env);
  if (!sbResult.safe) {
    // Silently block — add the IP to the blocklist and return a blank page.
    // Do NOT reveal that the URL was flagged or that the IP is now blocked.
    await blockIp(env, ip, {
      reason:      'threat_at_creation',
      triggerSlug: null, // slug not yet created
      threats:     sbResult.threats,
      addedBy:     'system',
    });
    return blankResponse();
  }

  // ── Expiry validation ──────────────────────────────────────────────────────
  const expiryResult = validateExpiry(expiryDays);
  if (!expiryResult.ok) {
    return jsonResponse({ error: expiryResult.error, truth: getRandomConspiracy() }, 422, CORS_PUBLIC);
  }

  // Preview mode
  const previewMode = preview === true;

  // ── Slug handling ──────────────────────────────────────────────────────────
  let slug;
  if (customSlug !== undefined) {
    const slugResult = validateCustomSlug(customSlug);
    if (!slugResult.ok) {
      return jsonResponse({ error: slugResult.error, truth: getRandomConspiracy() }, 422, CORS_PUBLIC);
    }
    const existing = await env.LINKS.get(slugResult.slug);
    if (existing) {
      return jsonResponse(
        { error: `The slug "${slugResult.slug}" is already taken.`, slug: slugResult.slug, truth: getRandomConspiracy() },
        409, CORS_PUBLIC
      );
    }
    slug = slugResult.slug;
  } else {
    slug = await generateUniqueSlug(env.LINKS);
  }

  // ── Creator metadata ───────────────────────────────────────────────────────
  const ua      = (request.headers.get('User-Agent') || 'unknown').slice(0, 512);
  const country = request.cf?.country || 'unknown';
  const city    = request.cf?.city    || undefined;

  // ── Owner hash ─────────────────────────────────────────────────────────────
  const ownerHash = await getVerifiedOwnerHash(request, env);

  // ── KV expiry ──────────────────────────────────────────────────────────────
  let expiresAt  = null;
  let kvOptions  = {};
  if (expiryResult.days !== null) {
    expiresAt  = new Date(Date.now() + expiryResult.days * 86_400_000).toISOString();
    kvOptions  = { expirationTtl: expiryResult.days * 86_400 };
  }

  const record = {
    url:            normalisedUrl,
    slug,
    createdAt:      new Date().toISOString(),
    creatorIp:      ip,
    creatorUa:      ua,
    creatorCountry: country,
    creatorCity:    city,
    ownerHash:      ownerHash || null,
    previewMode,
    expiryDays:     expiryResult.days,
    expiresAt,
    accessCount:    0,
    lastAccessed:   null,
    accessLog:      [],
    safeBrowsing: {
      checked:    !sbResult.skipped,
      checkedAt:  new Date().toISOString(),
      checkedUrl: sbResult.checkedUrl || null,
    },
  };

  await env.LINKS.put(slug, JSON.stringify(record), kvOptions);

  const baseUrl  = new URL(request.url).origin;
  const shortUrl = `${baseUrl}/${slug}`;

  return jsonResponse(
    {
      shortUrl,
      slug,
      url:        normalisedUrl,
      previewMode,
      expiresAt,
      ownerLinked: !!ownerHash,
      ownerHash:   ownerHash || null,
      truth:       getRandomConspiracy(),
    },
    200,
    { ...CORS_PUBLIC, ...rl.headers, 'X-Status': 'RECORD CREATED — IT KNOWS WHERE YOU GO' }
  );
}

export async function onRequestOptions() {
  return new Response(null, { status: 204, headers: secureHeaders(CORS_PUBLIC) });
}
