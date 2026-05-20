/**
 * functions/api/scan.js
 *
 * Two entry points:
 *
 *   1. POST /api/scan  (admin-only HTTP trigger)
 *      Manually kick off a rescan from the admin panel or curl.
 *      Body (optional JSON): { "forceAll": true }   — re-check even deactivated links
 *
 *   2. export const onScheduled (Cloudflare cron trigger)
 *      Cloudflare calls this on the schedule defined in wrangler.toml [triggers].
 *      See: https://developers.cloudflare.com/pages/functions/scheduling/
 *
 * Setup
 * ─────
 * Add to wrangler.toml:
 *
 *   [triggers]
 *   crons = ["0 3 * * *"]   # daily at 03:00 UTC — adjust to taste
 *
 * Then deploy:  npx wrangler pages deploy public --project-name=link-shortener
 *
 * The cron only fires in the deployed (production/preview) environment —
 * it does NOT run during `wrangler pages dev`.
 */

import { getRandomConspiracy } from '../_conspiracies.js';
import {
  jsonResponse,
  secureHeaders,
  CORS_ADMIN,
  checkAdminAuth,
  readJsonBody,
} from '../_security.js';
import { runRescan } from '../_rescan.js';

// ─── POST /api/scan — manual admin trigger ────────────────────────────────────
export async function onRequestPost(context) {
  const { request, env } = context;

  if (!checkAdminAuth(request, env)) {
    return jsonResponse(
      { error: 'Unauthorized. Your clearance level is insufficient.', truth: getRandomConspiracy() },
      401,
      { ...CORS_ADMIN, 'WWW-Authenticate': `Bearer realm="${new URL(request.url).hostname}"` }
    );
  }

  // Optional body: { forceAll: true }
  let forceAll = false;
  const bodyResult = await readJsonBody(request).catch(() => ({ ok: false }));
  if (bodyResult.ok && bodyResult.body?.forceAll === true) {
    forceAll = true;
  }

  try {
    const stats = await runRescan(env, { forceAll });
    return jsonResponse(
      {
        success: true,
        stats,
        truth: getRandomConspiracy(),
      },
      200,
      CORS_ADMIN
    );
  } catch (err) {
    console.error('Rescan failed:', err);
    return jsonResponse(
      { error: 'Rescan failed. Check worker logs.', truth: getRandomConspiracy() },
      500,
      CORS_ADMIN
    );
  }
}

// ─── Scheduled cron handler ───────────────────────────────────────────────────
// Cloudflare Pages calls this when a cron trigger fires.
// Reference: https://developers.cloudflare.com/pages/functions/scheduling/
export async function onScheduled(event, env) {
  console.log(`[rescan] Cron triggered at ${new Date().toISOString()} (cron: ${event.cron})`);
  try {
    const stats = await runRescan(env);
    console.log('[rescan] Completed:', JSON.stringify(stats));
  } catch (err) {
    console.error('[rescan] Fatal error during scheduled rescan:', err);
  }
}

export async function onRequestOptions() {
  return new Response(null, { status: 204, headers: secureHeaders(CORS_ADMIN) });
}
