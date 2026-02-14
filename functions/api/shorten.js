import { getRandomConspiracy } from '../_conspiracies.js';
import {
  jsonResponse,
  secureHeaders,
  CORS_PUBLIC,
  validateUrl,
  validateCustomSlug,
  readJsonBody,
} from '../_security.js';

const CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789';
const SHORT_LENGTH = 4;
const MAX_RETRIES = 8;

function generateCode(length = SHORT_LENGTH) {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return Array.from(array, b => CHARS[b % CHARS.length]).join('');
}

async function generateUniqueSlug(kv) {
  for (let i = 0; i < MAX_RETRIES; i++) {
    const len = i < 5 ? SHORT_LENGTH : SHORT_LENGTH + 1;
    const slug = generateCode(len);
    const existing = await kv.get(slug);
    if (!existing) return slug;
  }
  return generateCode(SHORT_LENGTH + 2);
}

export async function onRequestPost(context) {
  const { request, env } = context;

  const bodyResult = await readJsonBody(request);
  if (!bodyResult.ok) {
    return jsonResponse({ error: bodyResult.error, truth: getRandomConspiracy() }, 400, CORS_PUBLIC);
  }

  const { url, customSlug } = bodyResult.body;

  if (url === undefined || url === null) {
    return jsonResponse({ error: 'A "url" field is required.', truth: getRandomConspiracy() }, 400, CORS_PUBLIC);
  }

  const urlResult = validateUrl(url);
  if (!urlResult.ok) {
    return jsonResponse({ error: urlResult.error, truth: getRandomConspiracy() }, 422, CORS_PUBLIC);
  }

  const normalisedUrl = urlResult.url;

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

  const ip        = (request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() || 'unknown');
  const userAgent = (request.headers.get('User-Agent') || 'unknown').slice(0, 512);
  const country   = request.cf?.country || 'unknown';

  const record = { url: normalisedUrl, slug, ip, userAgent, country, createdAt: new Date().toISOString() };
  await env.LINKS.put(slug, JSON.stringify(record));

  const baseUrl  = new URL(request.url).origin;
  const shortUrl = `${baseUrl}/${slug}`;

  return jsonResponse(
    { shortUrl, slug, url: normalisedUrl, truth: getRandomConspiracy() },
    200,
    { ...CORS_PUBLIC, 'X-Status': 'RECORD CREATED — IT KNOWS WHERE YOU GO' }
  );
}

export async function onRequestOptions() {
  return new Response(null, { status: 204, headers: secureHeaders(CORS_PUBLIC) });
}
