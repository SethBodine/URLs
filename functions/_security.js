/**
 * _security.js — shared security primitives for b0x.nz
 *
 * OWASP Top 10 mitigations addressed here:
 *
 * A01 Broken Access Control    → timing-safe admin key comparison; reserved slug blocklist
 * A02 Cryptographic Failures   → secrets only via env vars; no sensitive data in error bodies
 * A03 Injection                → strict slug allowlist regex; URL parsed via native URL API;
 *                                all KV keys come from validated slugs only
 * A04 Insecure Design          → URL scheme allowlist; SSRF prevention via IP/hostname blocklist
 * A05 Security Misconfiguration→ security headers on every response; no verbose server errors
 * A06 Vulnerable Components    → zero npm dependencies; native Workers runtime only
 * A07 Auth Failures            → timing-safe key comparison; no unauthenticated admin surface
 * A08 Data Integrity           → input validated and normalised before any KV write
 * A09 Logging & Monitoring     → structured metadata captured per record
 * A10 SSRF                     → private IP ranges, loopback, cloud metadata endpoints blocked
 */

// ─── Security Headers ────────────────────────────────────────────────────────

export const SECURITY_HEADERS = {
  'X-Content-Type-Options':    'nosniff',
  'X-Frame-Options':           'DENY',
  'Referrer-Policy':           'strict-origin-when-cross-origin',
  'Permissions-Policy':        'geolocation=(), microphone=(), camera=(), payment=()',
  'Cache-Control':             'no-store, no-cache',
  // CSP for API responses — documents served from public/ have their own via _headers
  'Content-Security-Policy':   "default-src 'none'; frame-ancestors 'none'",
};

export const CORS_PUBLIC = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

export const CORS_ADMIN = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
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

/**
 * Timing-safe string comparison to prevent timing attacks on the admin key.
 * Uses TextEncoder to get byte arrays and XORs them — always compares
 * the full length regardless of where a mismatch occurs.
 */
function timingSafeEqual(a, b) {
  const enc = new TextEncoder();
  const ab = enc.encode(a);
  const bb = enc.encode(b);
  if (ab.length !== bb.length) {
    // Still do a comparison to avoid leaking length via timing
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
  // If ADMIN_KEY is not configured, reject all admin requests
  if (!adminKey || adminKey.length < 16) return false;

  const auth = (request.headers.get('Authorization') || '').trim();
  if (!auth.startsWith('Bearer ')) return false;

  const token = auth.slice(7);
  return timingSafeEqual(token, adminKey);
}

// ─── URL Validation & Normalisation ──────────────────────────────────────────

// A10 SSRF — blocked hostnames and IP patterns
const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'metadata.google.internal',
  'metadata.goog',
  'instance-data',
  'computemetadata',
]);

// Matches private/loopback/link-local/CGNAT IPv4 ranges
const BLOCKED_IPV4 = [
  /^0\./,                                    // 0.0.0.0/8
  /^127\./,                                  // 127.0.0.0/8 loopback
  /^10\./,                                   // 10.0.0.0/8 private
  /^172\.(1[6-9]|2\d|3[01])\./,             // 172.16.0.0/12 private
  /^192\.168\./,                             // 192.168.0.0/16 private
  /^169\.254\./,                             // 169.254.0.0/16 link-local / AWS metadata
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./, // 100.64.0.0/10 CGNAT
  /^198\.51\.100\./,                         // TEST-NET-2
  /^203\.0\.113\./,                          // TEST-NET-3
  /^240\./,                                  // Reserved
  /^255\.255\.255\.255$/,                    // Broadcast
];

// Matches private/loopback IPv6
const BLOCKED_IPV6 = [
  /^::1$/i,                  // loopback
  /^::/,                     // unspecified
  /^fc/i,                    // ULA fc00::/7
  /^fd/i,                    // ULA fd00::/8
  /^fe80/i,                  // link-local fe80::/10
  /^ff/i,                    // multicast
];

function isBlockedHostname(hostname) {
  const h = hostname.toLowerCase();

  // Exact hostname match
  if (BLOCKED_HOSTNAMES.has(h)) return true;

  // .local, .internal, .localhost, .lan, .corp
  if (/\.(local|internal|localhost|lan|corp|intranet)$/i.test(h)) return true;

  // Raw IPv4
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) {
    return BLOCKED_IPV4.some(re => re.test(h));
  }

  // IPv6 (bracketed form stripped by URL parser)
  if (h.includes(':')) {
    return BLOCKED_IPV6.some(re => re.test(h));
  }

  return false;
}

function stripControlChars(str) {
  // Remove null bytes, control characters, and unicode direction overrides
  // eslint-disable-next-line no-control-regex
  return str.replace(/[\u0000-\u001F\u007F\u200B-\u200D\uFEFF\u202A-\u202E]/g, '');
}

/**
 * Validates and normalises a URL string.
 * Returns { ok: true, url: normalised } or { ok: false, error: string }
 *
 * Mitigates: A03 Injection, A04 Insecure Design, A10 SSRF
 */
export function validateUrl(raw) {
  if (typeof raw !== 'string') {
    return { ok: false, error: 'URL must be a string.' };
  }

  // Strip control/zero-width characters
  let str = stripControlChars(raw).trim();

  // Normalise unicode (NFKC collapses lookalike chars)
  str = str.normalize('NFKC');

  if (str.length === 0) {
    return { ok: false, error: 'URL must not be empty.' };
  }

  if (str.length > 2048) {
    return { ok: false, error: 'URL must be 2048 characters or fewer.' };
  }

  // Reject clearly dangerous schemes before URL parsing
  const schemeMatch = str.match(/^([a-zA-Z][a-zA-Z0-9+\-.]*):\/\//i);
  if (!schemeMatch) {
    // Try adding https:// if it looks like a bare domain (convenience)
    return { ok: false, error: 'URL must include a scheme (https:// or http://).' };
  }

  const scheme = schemeMatch[1].toLowerCase();
  if (scheme !== 'http' && scheme !== 'https') {
    return { ok: false, error: `URL scheme "${scheme}" is not allowed. Only http and https are accepted.` };
  }

  let parsed;
  try {
    parsed = new URL(str);
  } catch {
    return { ok: false, error: 'URL is not valid and could not be parsed.' };
  }

  // Re-check scheme after parsing (URL constructor may normalise it)
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { ok: false, error: 'Only http and https URLs are accepted.' };
  }

  // No credentials embedded in URL (A07)
  if (parsed.username || parsed.password) {
    return { ok: false, error: 'URLs with embedded credentials are not accepted.' };
  }

  const hostname = parsed.hostname;

  // Must have a hostname
  if (!hostname) {
    return { ok: false, error: 'URL must contain a valid hostname.' };
  }

  // Must have a TLD or at least look like a real host (not bare word)
  // Allows: example.com, sub.example.co.nz, 93.184.216.34
  // Blocks: http://admin, http://internal
  const isRawIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.includes(':');
  if (!isRawIp && !hostname.includes('.')) {
    return { ok: false, error: 'URL hostname does not appear to be a valid domain.' };
  }

  // SSRF: block private/reserved addresses (A10)
  if (isBlockedHostname(hostname)) {
    return { ok: false, error: 'URL resolves to a reserved or private address.' };
  }

  // Normalise: lowercase scheme + host, strip default ports
  parsed.protocol = parsed.protocol.toLowerCase();
  parsed.hostname  = parsed.hostname.toLowerCase();
  if (
    (parsed.protocol === 'http:'  && parsed.port === '80')  ||
    (parsed.protocol === 'https:' && parsed.port === '443')
  ) {
    parsed.port = '';
  }

  return { ok: true, url: parsed.toString() };
}

// ─── Slug Validation ──────────────────────────────────────────────────────────

// Slugs that must never be used — they conflict with routes or reserved paths
const RESERVED_SLUGS = new Set([
  'api', 'admin', 'assets', 'static', 'public', 'cdn',
  '_headers', '_redirects', '_routes', 'favicon', 'robots',
  'sitemap', 'index', 'health', 'ping', 'status',
  'login', 'logout', 'signup', 'register', 'dashboard',
  'wp-admin', 'wp-login', '.env', '.git',
]);

const SLUG_RE = /^[a-z0-9][a-z0-9\-_]{1,31}$/;

/**
 * Validates a user-supplied custom slug.
 * Returns { ok: true, slug: normalised } or { ok: false, error: string }
 */
export function validateCustomSlug(raw) {
  if (typeof raw !== 'string') {
    return { ok: false, error: 'customSlug must be a string.' };
  }

  const slug = stripControlChars(raw).trim().toLowerCase().normalize('NFKC');

  if (slug.length < 2) {
    return { ok: false, error: 'customSlug must be at least 2 characters.' };
  }

  if (slug.length > 32) {
    return { ok: false, error: 'customSlug must be 32 characters or fewer.' };
  }

  if (!SLUG_RE.test(slug)) {
    return { ok: false, error: 'customSlug may only contain a-z, 0-9, hyphens, and underscores, and must start with a letter or number.' };
  }

  if (RESERVED_SLUGS.has(slug)) {
    return { ok: false, error: `The slug "${slug}" is reserved and cannot be used.` };
  }

  // No path traversal
  if (slug.includes('..') || slug.includes('/') || slug.includes('\\')) {
    return { ok: false, error: 'customSlug must not contain path separators.' };
  }

  return { ok: true, slug };
}

/**
 * Validates a slug being used for lookup (looser — allows any stored slug format).
 */
export function validateLookupSlug(raw) {
  if (typeof raw !== 'string') {
    return { ok: false, error: 'slug must be a string.' };
  }

  const slug = stripControlChars(raw).trim().toLowerCase();

  if (slug.length < 1 || slug.length > 64) {
    return { ok: false, error: 'slug must be between 1 and 64 characters.' };
  }

  if (!/^[a-z0-9\-_]+$/.test(slug)) {
    return { ok: false, error: 'slug contains invalid characters.' };
  }

  if (slug.includes('..')) {
    return { ok: false, error: 'slug must not contain path traversal sequences.' };
  }

  return { ok: true, slug };
}

// ─── Request Guards ───────────────────────────────────────────────────────────

const MAX_BODY_BYTES = 8192; // 8 KB — more than enough for any valid payload

/**
 * Reads and validates a JSON request body.
 * Enforces Content-Type and body size limit.
 */
export async function readJsonBody(request) {
  const ct = (request.headers.get('Content-Type') || '').split(';')[0].trim().toLowerCase();
  if (ct !== 'application/json') {
    return { ok: false, error: 'Content-Type must be application/json.' };
  }

  const contentLength = parseInt(request.headers.get('Content-Length') || '0', 10);
  if (contentLength > MAX_BODY_BYTES) {
    return { ok: false, error: 'Request body too large.' };
  }

  let text;
  try {
    // Consume with a size cap
    const reader = request.body.getReader();
    const chunks = [];
    let total = 0;

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_BODY_BYTES) {
        reader.cancel();
        return { ok: false, error: 'Request body too large.' };
      }
      chunks.push(value);
    }

    const merged = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) { merged.set(chunk, offset); offset += chunk.byteLength; }
    text = new TextDecoder('utf-8', { fatal: true }).decode(merged);
  } catch {
    return { ok: false, error: 'Could not read request body.' };
  }

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { ok: false, error: 'Invalid JSON payload.' };
  }

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return { ok: false, error: 'JSON payload must be an object.' };
  }

  return { ok: true, body: parsed };
}
