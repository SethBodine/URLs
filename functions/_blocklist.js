/**
 * _blocklist.js — IP address blocklist
 *
 * Blocks both IPv4 and IPv6 addresses that have been associated with
 * malicious content, either caught at submission time or retroactively
 * flagged during a Safe Browsing rescan.
 *
 * Storage
 * ───────
 * Uses the existing LINKS KV namespace with keys prefixed `bl:ip:`.
 * Example key:  bl:ip:1.2.3.4
 *               bl:ip:2001:db8:0000:0000:0000:0000:0000:0001
 *
 * IPv6 addresses are expanded to full 8-group form for consistent lookup,
 * regardless of how the address was originally represented (compressed ::
 * notation, mixed IPv4-in-IPv6, etc.).
 *
 * Blocked IP response
 * ───────────────────
 * Any request from a blocked IP receives an empty 200 response — no error
 * message, no body, no hint that they are blocked.  This prevents blocklist
 * probing.
 *
 * Record schema
 * ─────────────
 * {
 *   ip:          string   — normalized IP address (key without prefix)
 *   addedAt:     string   — ISO timestamp
 *   reason:      string   — 'threat_at_creation' | 'threat_at_rescan' | 'manual'
 *   triggerSlug: string?  — slug that triggered the block (if applicable)
 *   threats:     string[] — threat types reported by Safe Browsing
 *   addedBy:     string   — 'system' | 'admin'
 * }
 */

const PREFIX = 'bl:ip:';

// ─── IP Normalization ─────────────────────────────────────────────────────────

/**
 * Expand a compressed IPv6 address to full 8-group notation.
 * E.g. "::1" → "0000:0000:0000:0000:0000:0000:0000:0001"
 *      "2001:db8::1" → "2001:0db8:0000:0000:0000:0000:0000:0001"
 *
 * Also handles IPv4-mapped IPv6 (::ffff:192.0.2.1).
 */
function expandIPv6(addr) {
  // Strip brackets (e.g. [::1] in URLs)
  addr = addr.replace(/^\[|\]$/g, '').toLowerCase();

  // Handle IPv4-mapped IPv6: ::ffff:a.b.c.d
  const ipv4Mapped = addr.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (ipv4Mapped) {
    // Store as the IPv4 address directly — it's the same client
    return normalizeIPv4(ipv4Mapped[1]);
  }

  const sides = addr.split('::');
  if (sides.length > 2) return null; // invalid

  const left  = sides[0] ? sides[0].split(':') : [];
  const right = sides.length === 2 && sides[1] ? sides[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  if (missing < 0) return null;

  const groups = [
    ...left,
    ...Array(missing).fill('0'),
    ...right,
  ];
  if (groups.length !== 8) return null;

  return groups.map(g => g.padStart(4, '0')).join(':');
}

/**
 * Normalize an IPv4 address — lowercase (no-op for digits), strip leading zeros.
 * E.g. "001.002.003.004" → "1.2.3.4"
 */
function normalizeIPv4(addr) {
  const parts = addr.split('.');
  if (parts.length !== 4) return null;
  const nums = parts.map(p => parseInt(p, 10));
  if (nums.some(n => isNaN(n) || n < 0 || n > 255)) return null;
  return nums.join('.');
}

/**
 * Normalizes an IP address string for use as a consistent KV key component.
 * Returns null if the input is not a recognizable IPv4 or IPv6 address.
 */
export function normalizeIp(raw) {
  if (!raw || typeof raw !== 'string') return null;
  const addr = raw.trim().replace(/^\[|\]$/g, ''); // strip brackets

  // IPv4
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(addr)) {
    return normalizeIPv4(addr);
  }

  // IPv6 (contains at least one colon)
  if (addr.includes(':')) {
    return expandIPv6(addr);
  }

  return null; // unrecognized
}

// ─── KV helpers ───────────────────────────────────────────────────────────────

function blKey(normalizedIp) {
  return `${PREFIX}${normalizedIp}`;
}

/**
 * Returns true if `ip` is on the blocklist.
 * Returns false for 'unknown' or unparseable IPs (fail open — don't block
 * requests where we genuinely cannot determine the IP).
 */
export async function isIpBlocked(env, ip) {
  if (!ip || ip === 'unknown') return false;
  const normalized = normalizeIp(ip);
  if (!normalized) return false;
  try {
    const val = await env.LINKS.get(blKey(normalized));
    return val !== null;
  } catch {
    return false; // KV error — fail open
  }
}

/**
 * Adds an IP to the blocklist.  If the IP is already blocked, the existing
 * record is updated with the latest reason and timestamp.
 *
 * @param {object} env
 * @param {string} ip            — raw IP string (will be normalized)
 * @param {object} details
 * @param {string} details.reason       — 'threat_at_creation' | 'threat_at_rescan' | 'manual'
 * @param {string} [details.triggerSlug]
 * @param {string[]} [details.threats]
 * @param {string} [details.addedBy]    — 'system' (default) | 'admin'
 * @returns {Promise<string|null>} — the normalized IP that was stored, or null on failure
 */
export async function blockIp(env, ip, { reason = 'manual', triggerSlug, threats = [], addedBy = 'system' } = {}) {
  if (!ip || ip === 'unknown') return null;
  const normalized = normalizeIp(ip);
  if (!normalized) return null;

  const record = {
    ip:          normalized,
    addedAt:     new Date().toISOString(),
    reason,
    triggerSlug: triggerSlug || null,
    threats:     threats.length ? threats : [],
    addedBy,
  };

  try {
    await env.LINKS.put(blKey(normalized), JSON.stringify(record));
    console.warn(`[blocklist] BLOCKED IP ${normalized} — reason: ${reason}, threats: ${threats.join(', ')}`);
    return normalized;
  } catch (err) {
    console.error(`[blocklist] Failed to block IP ${normalized}:`, err);
    return null;
  }
}

/**
 * Removes an IP from the blocklist.
 * @returns {Promise<boolean>} — true if removed, false on error
 */
export async function unblockIp(env, ip) {
  const normalized = normalizeIp(ip);
  if (!normalized) return false;
  try {
    await env.LINKS.delete(blKey(normalized));
    console.log(`[blocklist] UNBLOCKED IP ${normalized}`);
    return true;
  } catch {
    return false;
  }
}

/**
 * Returns all blocked IP records.
 */
export async function getBlocklist(env) {
  const entries = [];
  let cursor;
  do {
    const result = await env.LINKS.list({ prefix: PREFIX, cursor, limit: 1000 });
    await Promise.all(result.keys.map(async (key) => {
      try {
        const data = await env.LINKS.get(key.name, { type: 'json' });
        if (data) entries.push(data);
      } catch { /* skip corrupt entries */ }
    }));
    cursor = result.cursor;
    if (result.list_complete) break;
  } while (cursor);

  return entries.sort((a, b) => new Date(b.addedAt) - new Date(a.addedAt));
}

/**
 * A blank 200 response — returned to blocked IPs.
 * No body, no content-type, no error hint.
 */
export function blankResponse() {
  return new Response('', {
    status: 200,
    headers: {
      'Cache-Control':          'no-store',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

/**
 * isBlocklistKey — used by admin.js getAllLinks to exclude blocklist entries
 * from the link listing.
 */
export function isBlocklistKey(name) {
  return name.startsWith(PREFIX);
}
