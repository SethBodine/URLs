/**
 * _rescan.js — Safe Browsing rescan logic
 *
 * Supports full rescan (all links) or targeted rescan (specific slugs only).
 * URLs are batched in groups of 50 — the v5 urls:search limit per request —
 * rather than the old fan-out of one request per URL. This dramatically
 * reduces API quota consumption when rescanning large link sets.
 *
 * Batch math:
 *   - v5 allows up to 50 URLs per GET request
 *   - 1,000 links = 20 API calls (vs 1,000 calls with the old approach)
 *   - Free quota: 10,000 lookups/day → supports up to 500,000 links/day
 */

import { checkSafeBrowsing } from './_safebrowsing.js';
import { blockIp, isBlocklistKey } from './_blocklist.js';

const BATCH_SIZE = 10; // Keep GET URL length well within Cloudflare's ~8KB limit.
                       // At ~200 chars/URL encoded, 10 URLs ≈ 2KB — safe headroom.
                       // v5 allows up to 50 but that risks exceeding URL limits in practice.

// ─── Key filter ───────────────────────────────────────────────────────────────

function isLinkKey(name) {
  return !name.startsWith('rl:') && !isBlocklistKey(name);
}

// ─── API diagnostic probe ─────────────────────────────────────────────────────

/**
 * Fire a minimal single-URL probe to the Safe Browsing API and return
 * a plain-English diagnosis. Called once before the main rescan loop so
 * any configuration problem is surfaced in the scan response immediately,
 * without having to dig through raw worker logs.
 *
 * Uses example.com — guaranteed clean, never flagged — so the probe
 * itself has no side-effects on stats.
 *
 * Returns:
 *   { ok: true }                              — API is reachable and returning JSON
 *   { ok: false, reason: string, detail: string }  — specific failure description
 */
async function probeApi(apiKey) {
  const params = new URLSearchParams({ key: apiKey });
  params.append('urls', 'https://example.com/');
  params.append('$alt', 'json');
  const probeUrl = `https://safebrowsing.googleapis.com/v5/urls:search?${params.toString()}`;

  let res;
  try {
    res = await fetch(probeUrl, {
      method: 'GET',
      headers: { 'User-Agent': 'b0x-url-shortener/2.2 (Safe Browsing v5)', 'Accept': 'application/json' },
    });
  } catch (err) {
    return { ok: false, reason: 'network_error', detail: `Fetch threw: ${err.message}` };
  }

  const rawText = await res.text().catch(() => '(unreadable)');

  if (!res.ok) {
    // Try to extract a human-readable message from the error body
    let apiMessage = rawText;
    try {
      const parsed = JSON.parse(rawText);
      apiMessage = parsed?.error?.message || rawText;
    } catch { /* leave as raw text */ }
    return {
      ok: false,
      reason: `http_${res.status}`,
      detail: `API returned HTTP ${res.status}: ${apiMessage.slice(0, 300)}`,
    };
  }

  // Check we got JSON, not protobuf (protobuf starts with non-printable bytes)
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u0008\u000E-\u001F]/.test(rawText.slice(0, 4))) {
    return {
      ok: false,
      reason: 'protobuf_response',
      detail: 'API returned binary protobuf instead of JSON despite $alt=json query param. The Safe Browsing v5 endpoint may not support this parameter — check API key restrictions or try the v5alpha1 endpoint.',
    };
  }

  try {
    JSON.parse(rawText);
  } catch {
    return {
      ok: false,
      reason: 'invalid_json',
      detail: `API returned non-JSON body (first 100 chars): ${rawText.slice(0, 100)}`,
    };
  }

  return { ok: true };
}

// ─── True batch check using v5 multi-URL support ─────────────────────────────

/**
 * Check a batch of up to BATCH_SIZE records in a single v5 API call.
 * Returns a Map<url, sbResult>.
 */
async function batchCheck(records, env) {
  const results = new Map();
  if (records.length === 0) return results;

  // Deduplicate URLs within the batch (multiple slugs may share a destination)
  const uniqueUrls = [...new Set(records.map(r => r.record.url))];

  // Build a single fetch with all URLs as query params
  const apiKey = env.SAFE_BROWSING_API_KEY;
  if (!apiKey || apiKey.length < 10) {
    // No key — return skipped for all
    uniqueUrls.forEach(url => results.set(url, { safe: true, threats: [], skipped: true, apiError: false, apiStatus: null, checkedUrl: url }));
    return results;
  }

  const params = new URLSearchParams();
  params.append('key', apiKey);
  uniqueUrls.forEach(u => params.append('urls', u));
  params.append('$alt', 'json');
  const requestUrl = `https://safebrowsing.googleapis.com/v5/urls:search?${params.toString()}`;

  let res;
  try {
    res = await fetch(requestUrl, {
      method: 'GET',
      headers: { 'User-Agent': 'b0x-url-shortener/2.2 (Safe Browsing v5)', 'Accept': 'application/json' },
    });
  } catch (err) {
    console.error('[rescan] Batch fetch network error:', err.message);
    uniqueUrls.forEach(url => results.set(url, { safe: true, threats: [], skipped: false, apiError: true, apiStatus: null, apiErrorDetail: `network_error: ${err.message}`, checkedUrl: url }));
    return results;
  }

  if (!res.ok) {
    const errText = await res.text().catch(() => '(unreadable)');
    console.error(`[rescan] Safe Browsing batch error ${res.status}:`, errText);
    uniqueUrls.forEach(url => results.set(url, { safe: true, threats: [], skipped: false, apiError: true, apiStatus: res.status, apiErrorDetail: errText.slice(0, 200), checkedUrl: url }));
    return results;
  }

  // Read raw text first so we can detect protobuf before attempting JSON.parse
  const rawText = await res.text().catch(() => '');

  let data;
  try {
    data = JSON.parse(rawText);
  } catch (err) {
    // eslint-disable-next-line no-control-regex
    const isProtobuf = /[\u0000-\u0008\u000E-\u001F]/.test(rawText.slice(0, 4));
    const detail = isProtobuf
      ? 'protobuf_response — API returned binary protobuf despite $alt=json param'
      : `json_parse_error: ${err.message} (first 100 chars: ${rawText.slice(0, 100)})`;
    console.error('[rescan] Batch response parse failed:', detail);
    uniqueUrls.forEach(url => results.set(url, { safe: true, threats: [], skipped: false, apiError: true, apiStatus: res.status, apiErrorDetail: detail, checkedUrl: url }));
    return results;
  }

  // Build a map of url → threat types from the response
  const threatMap = new Map();
  for (const threat of (data.threats || [])) {
    const existing = threatMap.get(threat.url) || [];
    threatMap.set(threat.url, [...existing, ...(threat.threatTypes || [])]);
  }

  // Map each input URL to its result
  uniqueUrls.forEach(url => {
    const threats = threatMap.get(url);
    if (threats && threats.length > 0) {
      results.set(url, { safe: false, threats: [...new Set(threats)], skipped: false, apiError: false, apiStatus: null, checkedUrl: url });
    } else {
      results.set(url, { safe: true, threats: [], skipped: false, apiError: false, apiStatus: null, checkedUrl: url });
    }
  });

  return results;
}

// ─── Main export ──────────────────────────────────────────────────────────────

/**
 * runRescan(env, options?)
 *
 * @param {object} env
 * @param {object} [options]
 * @param {boolean} [options.forceAll=false]  Re-check already-deactivated links
 * @param {string[]} [options.slugs]          Only rescan these specific slugs
 *                                            (undefined = rescan everything)
 * @returns {Promise<RescanStats>}
 */
export async function runRescan(env, { forceAll = false, slugs } = {}) {
  const startedAt = new Date().toISOString();
  const targetSlugs = slugs && slugs.length > 0 ? new Set(slugs) : null;

  const stats = {
    startedAt,
    scanned:            0,
    skipped:            0,
    clean:              0,
    newlyFlagged:       0,
    ipsBlocked:         0,
    errors:             0,
    apiKeyMissing:      false,
    apiErrors:          0,
    lastApiStatus:      null,
    lastApiErrorDetail: null,  // human-readable diagnosis from probe or first batch error
    apiProbe:           null,  // pre-flight probe result: { ok, reason?, detail? }
    flaggedSlugs:       [],
    errorSlugs:         [],
    completedAt:        null,
  };

  // ── 0. Pre-flight API probe (only if key is present) ─────────────────────
  const apiKey = env.SAFE_BROWSING_API_KEY;
  if (apiKey && apiKey.length >= 10) {
    const probe = await probeApi(apiKey);
    stats.apiProbe = probe;
    if (!probe.ok) {
      console.error('[rescan] Pre-flight probe failed:', probe.reason, probe.detail);
      stats.lastApiErrorDetail = probe.detail;
      // Don't abort — continue so stats.scanned/skipped are still accurate,
      // but every URL will come back as apiError from batchCheck.
    }
  } else {
    stats.apiKeyMissing = true;
    stats.apiProbe = { ok: false, reason: 'no_key', detail: 'SAFE_BROWSING_API_KEY is not set or too short.' };
  }

  // ── 1. Collect records ────────────────────────────────────────────────────
  const allRecords = [];
  let cursor;
  do {
    const result = await env.LINKS.list({ cursor, limit: 1000 });
    const linkKeys = result.keys.filter(k => isLinkKey(k.name));

    const fetched = await Promise.all(
      linkKeys.map(async (key) => {
        try {
          const data = await env.LINKS.get(key.name, { type: 'json' });
          return data ? { key: key.name, record: data } : null;
        } catch { return null; }
      })
    );
    allRecords.push(...fetched.filter(Boolean));
    cursor = result.cursor;
    if (result.list_complete) break;
  } while (cursor);

  // ── 2. Filter ─────────────────────────────────────────────────────────────
  const toScan = allRecords.filter(({ record }) => {
    // Targeted rescan — only the requested slugs
    if (targetSlugs && !targetSlugs.has(record.slug)) return false;
    // Skip already-deactivated unless forceAll
    if (record.deactivated && !forceAll) { stats.skipped++; return false; }
    return true;
  });

  if (toScan.length === 0) {
    stats.completedAt = new Date().toISOString();
    return stats;
  }

  // ── 3. Batch check in groups of 50 (v5 API limit) ────────────────────────
  const checkedAt = new Date().toISOString();

  for (let i = 0; i < toScan.length; i += BATCH_SIZE) {
    const batch = toScan.slice(i, i + BATCH_SIZE);
    const sbResults = await batchCheck(batch, env);

    // ── 4. Process each result ─────────────────────────────────────────────
    await Promise.all(batch.map(async ({ key, record }) => {
      const sbResult = sbResults.get(record.url);
      if (!sbResult) {
        stats.errors++;
        stats.errorSlugs.push(record.slug);
        return;
      }

      stats.scanned++;

      const kvOptions = record.expiresAt
        ? { expirationTtl: Math.max(1, Math.floor((new Date(record.expiresAt) - Date.now()) / 1000)) }
        : {};

      if (sbResult.safe) {
        if (sbResult.skipped) {
          stats.apiKeyMissing = true;
          stats.skippedNoKey = (stats.skippedNoKey || 0) + 1;
          return;
        }
        if (sbResult.apiError) {
          stats.apiErrors++;
          stats.lastApiStatus = sbResult.apiStatus;
          if (sbResult.apiErrorDetail && !stats.lastApiErrorDetail) {
            stats.lastApiErrorDetail = sbResult.apiErrorDetail;
          }
          return;
        }

        stats.clean++;
        const updated = {
          ...record,
          safeBrowsing: {
            ...record.safeBrowsing,
            lastRescannedAt:  checkedAt,
            lastCheckedUrl:   sbResult.checkedUrl || record.safeBrowsing?.checkedUrl || null,
            rescannedClean:   true,
            rescannedSkipped: false,
          },
        };
        try {
          await env.LINKS.put(key, JSON.stringify(updated), kvOptions);
        } catch (err) {
          console.error(`[rescan] KV update failed for ${key}:`, err);
          stats.errors++;
          stats.errorSlugs.push(record.slug);
        }
        return;
      }

      // ── Flagged — deactivate and block creator IP ──────────────────────
      stats.newlyFlagged++;
      stats.flaggedSlugs.push(record.slug);

      const deactivatedRecord = {
        ...record,
        deactivated:        true,
        deactivatedAt:      checkedAt,
        deactivatedReason:  'safe_browsing_rescan',
        deactivatedThreats: sbResult.threats,
        safeBrowsing: {
          ...record.safeBrowsing,
          lastRescannedAt:  checkedAt,
          lastCheckedUrl:   sbResult.checkedUrl || null,
          rescannedClean:   false,
          rescannedSkipped: false,
          threats:          sbResult.threats,
        },
      };

      try {
        await env.LINKS.put(key, JSON.stringify(deactivatedRecord), kvOptions);
        console.warn(`[rescan] DEACTIVATED /${record.slug} — threats: ${sbResult.threats.join(', ')}`);
      } catch (err) {
        console.error(`[rescan] KV deactivation failed for ${key}:`, err);
        stats.errors++;
        stats.errorSlugs.push(record.slug);
        return;
      }

      const creatorIp = record.creatorIp;
      if (creatorIp && creatorIp !== 'unknown') {
        const blocked = await blockIp(env, creatorIp, {
          reason:      'threat_at_rescan',
          triggerSlug: record.slug,
          threats:     sbResult.threats,
          addedBy:     'system',
        });
        if (blocked) stats.ipsBlocked++;
      }
    }));
  }

  stats.completedAt = new Date().toISOString();
  return stats;
}
