import { getRandomConspiracy } from '../_conspiracies.js';
import {
  jsonResponse,
  secureHeaders,
  CORS_ADMIN,
  CORS_PUBLIC,
  checkAdminAuth,
  getVerifiedOwnerHash,
  deriveOwnerHash,
  validateLookupSlug,
  validateExpiry,
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

// ─── PATCH /api/admin — deactivate/reactivate, set expiry, or toggle preview ──
// Supports a single slug ({ slug }) or many ({ slugs: [...] }), for one or more of:
//   deactivated: true|false
//   expiryDays:  30|60|90|180|365|null   (null clears expiry)
//   previewMode: true|false
// Only fields present in the body are touched — omit a field to leave it unchanged.
async function applyPatchToRecord(kv, slug, { deactivated, hasExpiry, expiryDays, hasPreview, previewMode, hasOwner, ownerHash }) {
  const record = await kv.get(slug, { type: 'json' });
  if (!record) return { slug, ok: false, error: 'not found', status: 404 };

  const now = new Date().toISOString();
  let updated = record;

  if (typeof deactivated === 'boolean') {
    if (deactivated) {
      updated = {
        ...updated,
        deactivated:        true,
        deactivatedAt:      updated.deactivatedAt || now, // preserve original timestamp if already deactivated
        deactivatedReason:  'manual_admin',
        deactivatedThreats: updated.deactivatedThreats || [],
      };
    } else {
      // Reactivate — remove all deactivation fields
      const { deactivated: _d, deactivatedAt: _da, deactivatedReason: _dr, deactivatedThreats: _dt, ...rest } = updated;
      updated = { ...rest, reactivatedAt: now };
    }
  }

  if (hasExpiry) {
    if (expiryDays === null) {
      updated = { ...updated, expiryDays: null, expiresAt: null };
    } else {
      updated = {
        ...updated,
        expiryDays,
        expiresAt: new Date(Date.now() + expiryDays * 86_400_000).toISOString(),
      };
    }
  }

  if (hasPreview) {
    updated = { ...updated, previewMode };
  }

  if (hasOwner) {
    updated = { ...updated, ownerHash };
  }

  const kvOptions = updated.expiresAt
    ? { expirationTtl: Math.max(1, Math.floor((new Date(updated.expiresAt) - Date.now()) / 1000)) }
    : {};

  await kv.put(slug, JSON.stringify(updated), kvOptions);
  return { slug, ok: true };
}

export async function onRequestPatch(context) {
  const { request, env } = context;
  if (!checkAdminAuth(request, env)) return unauthorized(request);

  const bodyResult = await readJsonBody(request);
  if (!bodyResult.ok) {
    return jsonResponse({ error: bodyResult.error, truth: getRandomConspiracy() }, 400, CORS_ADMIN);
  }

  const { slug, slugs, deactivated, previewMode } = bodyResult.body;
  const hasExpiry  = Object.prototype.hasOwnProperty.call(bodyResult.body, 'expiryDays');
  const hasPreview = typeof previewMode === 'boolean';
  const hasDeactivated = typeof deactivated === 'boolean';

  // Resolve + validate expiry (null is allowed here to mean "clear expiry")
  let expiryDays = null;
  if (hasExpiry) {
    const raw = bodyResult.body.expiryDays;
    if (raw !== null) {
      const ev = validateExpiry(raw);
      if (!ev.ok || ev.days === null) {
        return jsonResponse({ error: ev.error || 'expiryDays must be one of 30, 60, 90, 180, 365, or null to clear.', truth: getRandomConspiracy() }, 422, CORS_ADMIN);
      }
      expiryDays = ev.days;
    }
  }

  // Relink ownership — either from a raw device key (X-Fingerprint value the
  // user handed you), or directly from a known owner hash. Set to null to
  // unlink entirely. `ownerFingerprint` takes priority if both are sent.
  const hasOwnerFingerprint = typeof bodyResult.body.ownerFingerprint === 'string' && bodyResult.body.ownerFingerprint.trim() !== '';
  const hasOwnerHashField   = Object.prototype.hasOwnProperty.call(bodyResult.body, 'ownerHash');
  const hasOwner = hasOwnerFingerprint || hasOwnerHashField;
  let ownerHash = null;
  if (hasOwnerFingerprint) {
    ownerHash = await deriveOwnerHash(bodyResult.body.ownerFingerprint.trim(), env);
    if (!ownerHash) {
      return jsonResponse({ error: 'Could not derive an owner hash — OWNER_HASH_SECRET may not be configured.', truth: getRandomConspiracy() }, 500, CORS_ADMIN);
    }
  } else if (hasOwnerHashField) {
    const raw = bodyResult.body.ownerHash;
    if (raw === null) {
      ownerHash = null; // explicit unlink
    } else if (typeof raw === 'string' && /^[a-f0-9]{32}$/i.test(raw.trim())) {
      ownerHash = raw.trim().toLowerCase();
    } else {
      return jsonResponse({ error: 'ownerHash must be a 32-character hex hash, or null to unlink.', truth: getRandomConspiracy() }, 422, CORS_ADMIN);
    }
  }

  if (!hasDeactivated && !hasExpiry && !hasPreview && !hasOwner) {
    return jsonResponse(
      { error: 'Provide at least one of "deactivated", "expiryDays", "previewMode", "ownerFingerprint", or "ownerHash" to update.', truth: getRandomConspiracy() },
      400, CORS_ADMIN
    );
  }

  // Resolve target slug list
  let targets;
  if (Array.isArray(slugs)) {
    if (slugs.length === 0) return jsonResponse({ error: 'slugs array must not be empty.' }, 400, CORS_ADMIN);
    if (slugs.length > 500) return jsonResponse({ error: 'Maximum 500 slugs per batch.' }, 400, CORS_ADMIN);
    const validated = slugs.map(s => validateLookupSlug(s));
    const invalid = validated.filter(v => !v.ok);
    if (invalid.length) return jsonResponse({ error: `Invalid slug(s): ${invalid.map(v => v.error).join('; ')}` }, 422, CORS_ADMIN);
    targets = validated.map(v => v.slug);
  } else if (slug !== undefined) {
    const sv = validateLookupSlug(slug);
    if (!sv.ok) return jsonResponse({ error: sv.error, truth: getRandomConspiracy() }, 422, CORS_ADMIN);
    targets = [sv.slug];
  } else {
    return jsonResponse(
      { error: 'Provide { "slug": "..." } or { "slugs": [...] }.', truth: getRandomConspiracy() },
      400, CORS_ADMIN
    );
  }

  try {
    const results = await Promise.all(targets.map(s => applyPatchToRecord(env.LINKS, s, {
      deactivated: hasDeactivated ? deactivated : undefined,
      hasExpiry, expiryDays,
      hasPreview, previewMode,
      hasOwner, ownerHash,
    })));

    const failed = results.filter(r => !r.ok);
    const status = failed.length === results.length ? (failed[0]?.status || 500) : 200;

    return jsonResponse(
      {
        success: failed.length === 0,
        updated: results.filter(r => r.ok).length,
        results,
        // Back-compat single-slug fields
        slug: targets.length === 1 ? targets[0] : undefined,
        deactivated: hasDeactivated ? deactivated : undefined,
        truth: getRandomConspiracy(),
      },
      status, CORS_ADMIN
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
        const linkKeys = result.keys.filter(k => isLinkKey(k.name));
        await Promise.all(linkKeys.map(k => env.LINKS.delete(k.name)));
        deleted += linkKeys.length;
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
