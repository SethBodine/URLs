import { getRandomConspiracy } from '../_conspiracies.js';
import {
  jsonResponse,
  secureHeaders,
  CORS_ADMIN,
  checkAdminAuth,
  validateLookupSlug,
  readJsonBody,
} from '../_security.js';

function unauthorized() {
  return jsonResponse(
    { error: 'Unauthorized. Your clearance level is insufficient.', truth: getRandomConspiracy() },
    401,
    { ...CORS_ADMIN, 'WWW-Authenticate': 'Bearer realm="b0x.nz"' }
  );
}

async function getAllLinks(kv) {
  const links = [];
  let cursor;
  do {
    const result = await kv.list({ cursor, limit: 1000 });
    await Promise.all(result.keys.map(async (key) => {
      const data = await kv.get(key.name, { type: 'json' });
      if (data) links.push(data);
    }));
    cursor = result.cursor;
    if (result.list_complete) break;
  } while (cursor);
  return links;
}

// GET /api/admin — list all links
export async function onRequestGet(context) {
  const { request, env } = context;
  if (!checkAdminAuth(request, env)) return unauthorized();

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

// DELETE /api/admin — delete one slug or purge all
export async function onRequestDelete(context) {
  const { request, env } = context;
  if (!checkAdminAuth(request, env)) return unauthorized();

  const bodyResult = await readJsonBody(request);
  if (!bodyResult.ok) {
    return jsonResponse({ error: bodyResult.error, truth: getRandomConspiracy() }, 400, CORS_ADMIN);
  }

  const { slug, purgeAll } = bodyResult.body;

  // ── Purge all ─────────────────────────────────────────────────────────────
  if (purgeAll === true) {
    try {
      let cursor, deleted = 0;
      do {
        const result = await env.LINKS.list({ cursor, limit: 1000 });
        await Promise.all(result.keys.map(k => env.LINKS.delete(k.name)));
        deleted += result.keys.length;
        cursor = result.cursor;
        if (result.list_complete) break;
      } while (cursor);

      return jsonResponse({ success: true, deleted, truth: getRandomConspiracy() }, 200, CORS_ADMIN);
    } catch {
      return jsonResponse({ error: 'Purge failed.' }, 500, CORS_ADMIN);
    }
  }

  // ── Delete one ────────────────────────────────────────────────────────────
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
    { error: 'Provide either { "slug": "..." } to delete one, or { "purgeAll": true } to wipe all.', truth: getRandomConspiracy() },
    400,
    CORS_ADMIN
  );
}

export async function onRequestOptions() {
  return new Response(null, { status: 204, headers: secureHeaders(CORS_ADMIN) });
}
