/**
 * functions/api/scan.js
 *
 * Two entry points:
 *
 *   1. POST /api/scan  (admin-only HTTP trigger)
 *      Manually kick off a rescan from the admin panel or curl.
 *      Body (optional JSON): { "forceAll": true }   — re-check even deactivated links
 *
 *   2. onScheduled export (Cloudflare Pages cron trigger)
 *      Cloudflare calls this automatically on the schedule you configure.
 *
 * ── Cron Setup (Pages projects) ──────────────────────────────────────────────
 * [triggers] in wrangler.toml is a Workers-only key — it causes a build failure
 * in Pages projects. Configure the cron through the Cloudflare dashboard instead:
 *
 *   Workers & Pages → your project → Settings → Functions → Cron Triggers
 *   → Add trigger:  0 3 * * *   (daily 03:00 UTC — adjust to taste)
 *
 * The onScheduled handler below will be called automatically once configured.
 * The cron only fires in deployed environments — not during `wrangler pages dev`.
 *
 * ── Manual trigger (no cron needed) ──────────────────────────────────────────
 * Use the ⟳ Rescan button in the admin panel, or:
 *   curl -X POST https://your-domain/api/scan \
 *        -H "Authorization: Bearer YOUR_ADMIN_KEY" \
 *        -H "Content-Type: application/json" -d '{}'
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
