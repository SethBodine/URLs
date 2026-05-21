import { getRandomConspiracy } from '../_conspiracies.js';
import {
  jsonResponse,
  secureHeaders,
  CORS_ADMIN,
  CORS_PUBLIC,
  checkAdminAuth,
  getVerifiedOwnerHash,
  validateLookupSlug,
  readJsonBody,
} from '../_security.js';

function unauthorized(request) {
  return jsonResponse(
    { error: 'Unauthorized. Your clearance level is insufficient.', truth: getRandomConspiracy() },
    401,
    { ...CORS_ADMIN, 'WWW-Authenticate': `Bearer realm="${new URL(request.url).hostname}"` }
  );
}

// Exclude rate-limit keys (rl:) and blocklist keys (bl:ip:) from link operations
function isLinkKey(name) {
  return !name.startsWith('rl:') && !name.startsWith('bl:ip:');
}

async function getAllLinks(kv) {
  const links = [];
  let cursor;
  do {
    const result = await kv.list({ cursor, limit: 1000 });
    await Promise.all(result.keys.filter(k => isLinkKey(k.name)).map(async (key) => {
      const data = await kv.get(key.name, { type: 'json' });
      if (data) links.push(data);
    }));
    cursor = result.cursor;
    if (result.list_complete) break;
  } while (cursor);
  return links;
}

// ─── GET /api/admin — list all links (admin only) ─────────────────────────────
export async function onRequestGet(context) {
  const { request, env } = context;
  if (!checkAdminAuth(request, env)) return unauthorized(request);

  try {
    const links = await getAllLinks(env.LINKS);
    return jsonResponse(
      { links, count: links.length, truth: getRandomConspiracy() },
      200,
      CORS_ADMIN
    );
  } catch {
    return jsonResponse({ error: 'Failed to retrieve records.' }, 500, CORS_ADMIN);
  }
}

// ─── POST /api/admin/mylinks — list the caller's own links (owner-hash auth) ──
// This is handled in a separate file: /api/mylinks.js

// ─── PATCH /api/admin — deactivate or reactivate a link (admin) ──────────────
export async function onRequestPatch(context) {
  const { request, env } = context;
  if (!checkAdminAuth(request, env)) return unauthorized(request);

  const bodyResult = await readJsonBody(request);
  if (!bodyResult.ok) {
    return jsonResponse({ error: bodyResult.error, truth: getRandomConspiracy() }, 400, CORS_ADMIN);
  }

  const { slug, deactivated } = bodyResult.body;

  if (!slug || typeof deactivated !== 'boolean') {
    return jsonResponse(
      { error: 'Provide { "slug": "...", "deactivated": true|false }.', truth: getRandomConspiracy() },
      400, CORS_ADMIN
    );
  }

  const sv = validateLookupSlug(slug);
  if (!sv.ok) {
    return jsonResponse({ error: sv.error, truth: getRandomConspiracy() }, 422, CORS_ADMIN);
  }

  try {
    const record = await env.LINKS.get(sv.slug, { type: 'json' });
    if (!record) {
      return jsonResponse({ error: `Slug "${sv.slug}" not found.`, truth: getRandomConspiracy() }, 404, CORS_ADMIN);
    }

    const now = new Date().toISOString();
    let updated;

    if (deactivated) {
      updated = {
        ...record,
        deactivated:       true,
        deactivatedAt:     record.deactivatedAt || now, // preserve original timestamp if already deactivated
        deactivatedReason: 'manual_admin',
        deactivatedThreats: record.deactivatedThreats || [],
      };
    } else {
      // Reactivate — remove all deactivation fields
      const { deactivated: _d, deactivatedAt: _da, deactivatedReason: _dr, deactivatedThreats: _dt, ...rest } = record;
      updated = {
        ...rest,
        reactivatedAt: now,
      };
    }

    const kvOptions = record.expiresAt
      ? { expirationTtl: Math.max(1, Math.floor((new Date(record.expiresAt) - Date.now()) / 1000)) }
      : {};

    await env.LINKS.put(sv.slug, JSON.stringify(updated), kvOptions);

    return jsonResponse(
      { success: true, slug: sv.slug, deactivated, truth: getRandomConspiracy() },
      200, CORS_ADMIN
    );
  } catch (err) {
    console.error('Admin PATCH failed:', err);
    return jsonResponse({ error: 'Update failed.' }, 500, CORS_ADMIN);
  }
}

// ─── DELETE /api/admin — delete one slug or purge all (admin) ────────────────
export async function onRequestDelete(context) {
  const { request, env } = context;
  if (!checkAdminAuth(request, env)) return unauthorized(request);

  const bodyResult = await readJsonBody(request);
  if (!bodyResult.ok) {
    return jsonResponse({ error: bodyResult.error, truth: getRandomConspiracy() }, 400, CORS_ADMIN);
  }

  const { slug, purgeAll } = bodyResult.body;

  if (purgeAll === true) {
    try {
      let cursor, deleted = 0;
      do {
        const result = await env.LINKS.list({ cursor, limit: 1000 });
        await Promise.all(result.keys.filter(k => isLinkKey(k.name)).map(k => env.LINKS.delete(k.name)));
        deleted += result.keys.length;
        cursor = result.cursor;
        if (result.list_complete) break;
      } while (cursor);
      return jsonResponse({ success: true, deleted, truth: getRandomConspiracy() }, 200, CORS_ADMIN);
    } catch {
      return jsonResponse({ error: 'Purge failed.' }, 500, CORS_ADMIN);
    }
  }

  // Batch delete: { slugs: ["a", "b", ...] }
  if (Array.isArray(bodyResult.body.slugs)) {
    const { slugs } = bodyResult.body;
    if (slugs.length === 0) return jsonResponse({ error: 'slugs array must not be empty.' }, 400, CORS_ADMIN);
    if (slugs.length > 500) return jsonResponse({ error: 'Maximum 500 slugs per batch.' }, 400, CORS_ADMIN);
    const validated = slugs.map(s => validateLookupSlug(s));
    const invalid = validated.filter(v => !v.ok);
    if (invalid.length) return jsonResponse({ error: `Invalid slug(s): ${invalid.map(v => v.error).join('; ')}` }, 422, CORS_ADMIN);
    try {
      await Promise.all(validated.map(v => env.LINKS.delete(v.slug)));
      return jsonResponse({ success: true, deleted: validated.length, slugs: validated.map(v => v.slug), truth: getRandomConspiracy() }, 200, CORS_ADMIN);
    } catch {
      return jsonResponse({ error: 'Batch delete failed.' }, 500, CORS_ADMIN);
    }
  }

  if (slug !== undefined) {
    const sv = validateLookupSlug(slug);
    if (!sv.ok) {
      return jsonResponse({ error: sv.error, truth: getRandomConspiracy() }, 422, CORS_ADMIN);
    }
    try {
      await env.LINKS.delete(sv.slug);
      return jsonResponse({ success: true, slug: sv.slug, truth: getRandomConspiracy() }, 200, CORS_ADMIN);
    } catch {
      return jsonResponse({ error: 'Delete failed.' }, 500, CORS_ADMIN);
    }
  }

  return jsonResponse(
    { error: 'Provide { "slug": "..." }, { "slugs": [...] }, or { "purgeAll": true }.', truth: getRandomConspiracy() },
    400,
    CORS_ADMIN
  );
}

export async function onRequestOptions() {
  return new Response(null, { status: 204, headers: secureHeaders(CORS_ADMIN) });
}
