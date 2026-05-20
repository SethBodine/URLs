/**
 * functions/api/blocklist.js — Admin API for the IP blocklist
 *
 * All endpoints require admin auth (Authorization: Bearer ADMIN_KEY).
 *
 *   GET    /api/blocklist            — list all blocked IPs
 *   POST   /api/blocklist            — manually block an IP   { ip, reason? }
 *   DELETE /api/blocklist            — unblock an IP          { ip }
 */

import { getRandomConspiracy } from '../_conspiracies.js';
import {
  jsonResponse,
  secureHeaders,
  CORS_ADMIN,
  checkAdminAuth,
  readJsonBody,
} from '../_security.js';
import {
  getBlocklist,
  blockIp,
  unblockIp,
  normalizeIp,
} from '../_blocklist.js';

function unauthorized(request) {
  return jsonResponse(
    { error: 'Unauthorized.', truth: getRandomConspiracy() },
    401,
    { ...CORS_ADMIN, 'WWW-Authenticate': `Bearer realm="${new URL(request.url).hostname}"` }
  );
}

// ─── GET /api/blocklist ───────────────────────────────────────────────────────
export async function onRequestGet(context) {
  const { request, env } = context;
  if (!checkAdminAuth(request, env)) return unauthorized(request);

  try {
    const entries = await getBlocklist(env);
    return jsonResponse(
      { entries, count: entries.length, truth: getRandomConspiracy() },
      200,
      CORS_ADMIN
    );
  } catch (err) {
    console.error('blocklist GET failed:', err);
    return jsonResponse({ error: 'Failed to retrieve blocklist.' }, 500, CORS_ADMIN);
  }
}

// ─── POST /api/blocklist — manual block ───────────────────────────────────────
export async function onRequestPost(context) {
  const { request, env } = context;
  if (!checkAdminAuth(request, env)) return unauthorized(request);

  const bodyResult = await readJsonBody(request);
  if (!bodyResult.ok) {
    return jsonResponse({ error: bodyResult.error }, 400, CORS_ADMIN);
  }

  const { ip, reason } = bodyResult.body;
  if (!ip || typeof ip !== 'string') {
    return jsonResponse({ error: 'Provide { "ip": "..." }.' }, 400, CORS_ADMIN);
  }

  const normalized = normalizeIp(ip.trim());
  if (!normalized) {
    return jsonResponse({ error: `"${ip}" is not a valid IPv4 or IPv6 address.` }, 422, CORS_ADMIN);
  }

  try {
    await blockIp(env, normalized, {
      reason:  reason || 'manual',
      addedBy: 'admin',
    });
    return jsonResponse(
      { success: true, ip: normalized, truth: getRandomConspiracy() },
      200,
      CORS_ADMIN
    );
  } catch (err) {
    console.error('blocklist POST failed:', err);
    return jsonResponse({ error: 'Failed to block IP.' }, 500, CORS_ADMIN);
  }
}

// ─── DELETE /api/blocklist — unblock ──────────────────────────────────────────
export async function onRequestDelete(context) {
  const { request, env } = context;
  if (!checkAdminAuth(request, env)) return unauthorized(request);

  const bodyResult = await readJsonBody(request);
  if (!bodyResult.ok) {
    return jsonResponse({ error: bodyResult.error }, 400, CORS_ADMIN);
  }

  const { ip } = bodyResult.body;
  if (!ip || typeof ip !== 'string') {
    return jsonResponse({ error: 'Provide { "ip": "..." }.' }, 400, CORS_ADMIN);
  }

  const normalized = normalizeIp(ip.trim());
  if (!normalized) {
    return jsonResponse({ error: `"${ip}" is not a valid IPv4 or IPv6 address.` }, 422, CORS_ADMIN);
  }

  try {
    const ok = await unblockIp(env, normalized);
    return jsonResponse(
      { success: ok, ip: normalized, truth: getRandomConspiracy() },
      200,
      CORS_ADMIN
    );
  } catch (err) {
    console.error('blocklist DELETE failed:', err);
    return jsonResponse({ error: 'Failed to unblock IP.' }, 500, CORS_ADMIN);
  }
}

export async function onRequestOptions() {
  return new Response(null, { status: 204, headers: secureHeaders(CORS_ADMIN) });
}
