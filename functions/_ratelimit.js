/**
 * _ratelimit.js — IP-based rate limiting using KV counters
 *
 * Two sliding windows per IP per endpoint:
 *   - Hourly  (default: 25 requests)
 *   - Daily   (default: 100 requests)
 *
 * Limits are read from env vars:
 *   RATE_LIMIT_HOURLY  (default: 25)
 *   RATE_LIMIT_DAILY   (default: 100)
 *
 * KV keys:
 *   rl:{endpoint}:{ip}:h:{YYYY-MM-DDTHH}   — hourly bucket, TTL 2h
 *   rl:{endpoint}:{ip}:d:{YYYY-MM-DD}       — daily bucket,  TTL 48h
 *
 * Admin-authenticated requests are never rate-limited.
 * Owner-authenticated requests share the same IP bucket as public requests
 * (ownership doesn't grant extra quota — the IP is the identity for limiting).
 */

/**
 * Check and increment rate limit counters for a given IP + endpoint.
 *
 * @param {object} env        — Cloudflare env (needs LINKS KV, RATE_LIMIT_HOURLY, RATE_LIMIT_DAILY)
 * @param {string} ip         — Caller IP address
 * @param {string} endpoint   — Short label, e.g. 'shorten', 'lookup', 'mylinks'
 * @returns {Promise<{ limited: boolean, reason: string|null, headers: object }>}
 */
export async function checkRateLimit(env, ip, endpoint) {
  const maxHourly = parseInt(env.RATE_LIMIT_HOURLY  || '25',  10);
  const maxDaily  = parseInt(env.RATE_LIMIT_DAILY   || '100', 10);

  const now     = new Date();
  const hourKey = `rl:${endpoint}:${ip}:h:` + now.toISOString().slice(0, 13); // YYYY-MM-DDTHH
  const dayKey  = `rl:${endpoint}:${ip}:d:` + now.toISOString().slice(0, 10); // YYYY-MM-DD

  // Read both counters in parallel
  const [hourRaw, dayRaw] = await Promise.all([
    env.LINKS.get(hourKey),
    env.LINKS.get(dayKey),
  ]);

  const hourCount = parseInt(hourRaw || '0', 10);
  const dayCount  = parseInt(dayRaw  || '0', 10);

  // Build rate-limit info headers (always returned so clients can inspect quota)
  const headers = {
    'X-RateLimit-Limit-Hour':      String(maxHourly),
    'X-RateLimit-Limit-Day':       String(maxDaily),
    'X-RateLimit-Remaining-Hour':  String(Math.max(0, maxHourly - hourCount - 1)),
    'X-RateLimit-Remaining-Day':   String(Math.max(0, maxDaily  - dayCount  - 1)),
  };

  if (hourCount >= maxHourly) {
    return {
      limited: true,
      reason:  `Hourly limit of ${maxHourly} requests reached. Try again next hour.`,
      headers: { ...headers, 'Retry-After': '3600' },
    };
  }

  if (dayCount >= maxDaily) {
    return {
      limited: true,
      reason:  `Daily limit of ${maxDaily} requests reached. Try again tomorrow.`,
      headers: { ...headers, 'Retry-After': '86400' },
    };
  }

  // Increment both counters — fire and forget (don't block the response)
  // TTLs are generous to handle clock skew: 2h for hourly, 48h for daily
  Promise.all([
    env.LINKS.put(hourKey, String(hourCount + 1), { expirationTtl: 7200  }),
    env.LINKS.put(dayKey,  String(dayCount  + 1), { expirationTtl: 172800 }),
  ]).catch(() => { /* non-fatal — if KV write fails, we don't block the request */ });

  return { limited: false, reason: null, headers };
}

/**
 * Extract the caller's IP from the request.
 * Prefers CF-Connecting-IP (set by Cloudflare), falls back to X-Forwarded-For.
 */
export function getCallerIp(request) {
  return (
    request.headers.get('CF-Connecting-IP') ||
    request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ||
    'unknown'
  );
}
