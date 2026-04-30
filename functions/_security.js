/**
 * _security.js — shared security primitives (v2)
 *
 * OWASP Top 10 mitigations addressed here:
 *
 * A01 Broken Access Control    → timing-safe admin key comparison; reserved slug blocklist;
 *                                owner-hash verification for self-serve operations
 * A02 Cryptographic Failures   → secrets only via env vars; browser fingerprint hashed via HMAC-SHA256
 * A03 Injection                → strict slug allowlist regex; URL parsed via native URL API;
 *                                all KV keys from validated slugs only; escapeHtml for any output
 * A04 Insecure Design          → URL scheme allowlist; SSRF prevention; preview interstitial
 * A05 Security Misconfiguration→ security headers on every response; CORS locked on admin endpoints
 * A06 Vulnerable Components    → zero npm dependencies; native Workers runtime only
 * A07 Auth Failures            → timing-safe key comparison; owner hash prevents cross-user ops
 * A08 Data Integrity           → input validated before any KV write; expiry enforced
 * A09 Logging & Monitoring     → rich metadata per record; rolling access log MAX_ACCESS_LOG entries
 * A10 SSRF                     → private IP ranges, loopback, cloud metadata endpoints blocked
 */

// ─── Security Headers ────────────────────────────────────────────────────────

export const SECURITY_HEADERS = {
  'X-Content-Type-Options':    'nosniff',
  'X-Frame-Options':           'DENY',
  'Referrer-Policy':           'strict-origin-when-cross-origin',
  'Permissions-Policy':        'geolocation=(), microphone=(), camera=(), payment=()',
  'Cache-Control':             'no-store, no-cache',
  'Content-Security-Policy':   "default-src 'none'; frame-ancestors 'none'",
};

export const CORS_PUBLIC = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Owner-Hash, X-Fingerprint',
};

// Admin CORS is NOT wildcard — same-origin only
export const CORS_ADMIN = {
  'Access-Control-Allow-Origin':  'same-origin',
  'Access-Control-Allow-Methods': 'GET, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Vary':                         'Origin',
};

export function secureHeaders(...sets) {
  return Object.assign({}, SECURITY_HEADERS, ...sets);
}

// ─── JSON response helper ─────────────────────────────────────────────────────

export function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...secureHeaders(extraHeaders),
    },
  });
}

// ─── Admin Key Auth (timing-safe) ────────────────────────────────────────────

function timingSafeEqual(a, b) {
  const enc = new TextEncoder();
  const ab = enc.encode(a);
  const bb = enc.encode(b);
  if (ab.length !== bb.length) {
    let diff = 0;
    for (let i = 0; i < ab.length; i++) diff |= ab[i] ^ (bb[i % bb.length] ?? 0);
    return false;
  }
  let diff = 0;
  for (let i = 0; i < ab.length; i++) diff |= ab[i] ^ bb[i];
  return diff === 0;
}

export function checkAdminAuth(request, env) {
  const adminKey = env.ADMIN_KEY;
  if (!adminKey || adminKey.length < 16) return false;
  const auth = (request.headers.get('Authorization') || '').trim();
  if (!auth.startsWith('Bearer ')) return false;
  return timingSafeEqual(auth.slice(7), adminKey);
}

// ─── Owner Hash (browser fingerprint HMAC) ───────────────────────────────────

/**
 * Derives an HMAC-SHA256 of the raw fingerprint using OWNER_HASH_SECRET.
 * Returns a 32-char lowercase hex string (128-bit).
 */
export async function deriveOwnerHash(rawFingerprint, env) {
  const secret = env.OWNER_HASH_SECRET;
  if (!secret || secret.length < 16) return null;
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(rawFingerprint));
  return Array.from(new Uint8Array(sig))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
    .slice(0, 32);
}

/**
 * Verifies X-Owner-Hash + X-Fingerprint headers.
 * Returns the verified hash or null.
 */
export async function getVerifiedOwnerHash(request, env) {
  const sentHash = (request.headers.get('X-Owner-Hash') || '').trim().toLowerCase();
  const rawFp    = (request.headers.get('X-Fingerprint') || '').trim();
  if (!sentHash || !rawFp) return null;
  if (!/^[a-f0-9]{32}$/.test(sentHash)) return null;

  const expected = await deriveOwnerHash(rawFp, env);
  if (!expected) return null;

  const enc = new TextEncoder();
  const a = enc.encode(sentHash);
  const b = enc.encode(expected);
  if (a.length !== b.length) return null;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0 ? sentHash : null;
}

// ─── URL Validation & Normalisation ──────────────────────────────────────────

const BLOCKED_HOSTNAMES = new Set([
  'localhost', 'metadata.google.internal', 'metadata.goog', 'instance-data', 'computemetadata',
]);

const BLOCKED_IPV4 = [
  /^0\./, /^127\./, /^10\./, /^172\.(1[6-9]|2\d|3[01])\./, /^192\.168\./,
  /^169\.254\./, /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./, /^198\.51\.100\./,
  /^203\.0\.113\./, /^240\./, /^255\.255\.255\.255$/,
];

const BLOCKED_IPV6 = [/^::1$/i, /^::/, /^fc/i, /^fd/i, /^fe80/i, /^ff/i];

function isBlockedHostname(hostname) {
  const h = hostname.toLowerCase();
  if (BLOCKED_HOSTNAMES.has(h)) return true;
  if (/\.(local|internal|localhost|lan|corp|intranet)$/i.test(h)) return true;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return BLOCKED_IPV4.some(re => re.test(h));
  if (h.includes(':')) return BLOCKED_IPV6.some(re => re.test(h));
  return false;
}

function stripControlChars(str) {
  // eslint-disable-next-line no-control-regex
  return str.replace(/[\u0000-\u001F\u007F\u200B-\u200D\uFEFF\u202A-\u202E]/g, '');
}

export function validateUrl(raw) {
  if (typeof raw !== 'string') return { ok: false, error: 'URL must be a string.' };
  let str = stripControlChars(raw).trim().normalize('NFKC');
  if (!str.length) return { ok: false, error: 'URL must not be empty.' };
  if (str.length > 2048) return { ok: false, error: 'URL must be 2048 characters or fewer.' };

  const schemeMatch = str.match(/^([a-zA-Z][a-zA-Z0-9+\-.]*):\/\//i);
  if (!schemeMatch) return { ok: false, error: 'URL must include a scheme (https:// or http://).' };

  const scheme = schemeMatch[1].toLowerCase();
  if (scheme !== 'http' && scheme !== 'https') {
    return { ok: false, error: `URL scheme "${scheme}" is not allowed. Only http and https are accepted.` };
  }

  let parsed;
  try { parsed = new URL(str); } catch { return { ok: false, error: 'URL is not valid and could not be parsed.' }; }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return { ok: false, error: 'Only http and https URLs are accepted.' };
  if (parsed.username || parsed.password) return { ok: false, error: 'URLs with embedded credentials are not accepted.' };

  const hostname = parsed.hostname;
  if (!hostname) return { ok: false, error: 'URL must contain a valid hostname.' };

  const isRawIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.includes(':');
  if (!isRawIp && !hostname.includes('.')) return { ok: false, error: 'URL hostname does not appear to be a valid domain.' };
  if (isBlockedHostname(hostname)) return { ok: false, error: 'URL resolves to a reserved or private address.' };

  parsed.protocol = parsed.protocol.toLowerCase();
  parsed.hostname  = parsed.hostname.toLowerCase();
  if ((parsed.protocol === 'http:' && parsed.port === '80') || (parsed.protocol === 'https:' && parsed.port === '443')) {
    parsed.port = '';
  }
  return { ok: true, url: parsed.toString() };
}

// ─── Slug Validation ──────────────────────────────────────────────────────────

const RESERVED_SLUGS = new Set([
  'api', 'admin', 'assets', 'static', 'public', 'cdn',
  '_headers', '_redirects', '_routes', 'favicon', 'robots',
  'sitemap', 'index', 'health', 'ping', 'status',
  'login', 'logout', 'signup', 'register', 'dashboard',
  'wp-admin', 'wp-login', '.env', '.git',
  'preview', 'p', // reserved for preview interstitial
]);

const SLUG_RE = /^[a-z0-9][a-z0-9\-_]{1,31}$/;

export function validateCustomSlug(raw) {
  if (typeof raw !== 'string') return { ok: false, error: 'customSlug must be a string.' };
  const slug = stripControlChars(raw).trim().toLowerCase().normalize('NFKC');
  if (slug.length < 2) return { ok: false, error: 'customSlug must be at least 2 characters.' };
  if (slug.length > 32) return { ok: false, error: 'customSlug must be 32 characters or fewer.' };
  if (!SLUG_RE.test(slug)) return { ok: false, error: 'customSlug may only contain a-z, 0-9, hyphens, and underscores, and must start with a letter or number.' };
  if (RESERVED_SLUGS.has(slug)) return { ok: false, error: `The slug "${slug}" is reserved and cannot be used.` };
  if (slug.includes('..') || slug.includes('/') || slug.includes('\\')) return { ok: false, error: 'customSlug must not contain path separators.' };
  return { ok: true, slug };
}

export function validateLookupSlug(raw) {
  if (typeof raw !== 'string') return { ok: false, error: 'slug must be a string.' };
  const slug = stripControlChars(raw).trim().toLowerCase();
  if (slug.length < 1 || slug.length > 64) return { ok: false, error: 'slug must be between 1 and 64 characters.' };
  if (!/^[a-z0-9\-_]+$/.test(slug)) return { ok: false, error: 'slug contains invalid characters.' };
  if (slug.includes('..')) return { ok: false, error: 'slug must not contain path traversal sequences.' };
  return { ok: true, slug };
}

// ─── Expiry Helpers ───────────────────────────────────────────────────────────

export const ALLOWED_EXPIRY_DAYS = [30, 60, 90, 180, 365];

export function validateExpiry(raw) {
  if (raw === undefined || raw === null) return { ok: true, days: null };
  const n = Number(raw);
  if (!Number.isInteger(n) || !ALLOWED_EXPIRY_DAYS.includes(n)) {
    return { ok: false, error: `expiryDays must be one of: ${ALLOWED_EXPIRY_DAYS.join(', ')}, or omitted for no expiry.` };
  }
  return { ok: true, days: n };
}

// ─── Access Log Helpers ───────────────────────────────────────────────────────

export const MAX_ACCESS_LOG = 50; // rolling window per slug

export function appendAccessLog(record, request) {
  if (!Array.isArray(record.accessLog)) record.accessLog = [];
  const entry = {
    ip:      (request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() || 'unknown'),
    ua:      (request.headers.get('User-Agent') || 'unknown').slice(0, 300),
    country: request.cf?.country || 'unknown',
    city:    request.cf?.city    || undefined,
    ts:      new Date().toISOString(),
  };
  record.accessLog.push(entry);
  if (record.accessLog.length > MAX_ACCESS_LOG) record.accessLog = record.accessLog.slice(-MAX_ACCESS_LOG);
  record.accessCount = (record.accessCount || 0) + 1;
  record.lastAccessed = entry.ts;
  return record;
}

// ─── Request Body Reader ──────────────────────────────────────────────────────

const MAX_BODY_BYTES = 8192;

export async function readJsonBody(request) {
  const ct = (request.headers.get('Content-Type') || '').split(';')[0].trim().toLowerCase();
  if (ct !== 'application/json') return { ok: false, error: 'Content-Type must be application/json.' };

  const contentLength = parseInt(request.headers.get('Content-Length') || '0', 10);
  if (contentLength > MAX_BODY_BYTES) return { ok: false, error: 'Request body too large.' };

  let text;
  try {
    const reader = request.body.getReader();
    const chunks = [];
    let total = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_BODY_BYTES) { reader.cancel(); return { ok: false, error: 'Request body too large.' }; }
      chunks.push(value);
    }
    const merged = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) { merged.set(chunk, offset); offset += chunk.byteLength; }
    text = new TextDecoder('utf-8', { fatal: true }).decode(merged);
  } catch { return { ok: false, error: 'Could not read request body.' }; }

  let parsed;
  try { parsed = JSON.parse(text); } catch { return { ok: false, error: 'Invalid JSON payload.' }; }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return { ok: false, error: 'JSON payload must be an object.' };
  return { ok: true, body: parsed };
}

// ─── HTML Escaping (XSS prevention) ──────────────────────────────────────────

export function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
