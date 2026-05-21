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

const BATCH_SIZE = 50; // v5 urls:search limit per request

// ─── Key filter ───────────────────────────────────────────────────────────────

function isLinkKey(name) {
  return !name.startsWith('rl:') && !isBlocklistKey(name);
}

// ─── True batch check using v5 multi-URL support ─────────────────────────────

/**
 * Check a batch of up to 50 records in a single v5 API call.
 * Returns a Map<url, sbResult>.
 *
 * We call checkSafeBrowsing once per unique URL in the batch.
 * The v5 endpoint handles all expression generation server-side,
 * so there's nothing more to do on our end.
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

  const params = uniqueUrls.map(u => `urls=${encodeURIComponent(u)}`).join('&');
  const requestUrl = `https://safebrowsing.googleapis.com/v5/urls:search?key=${apiKey}&${params}`;

  try {
    const res = await fetch(requestUrl, {
      method: 'GET',
      headers: { 'User-Agent': 'b0x-url-shortener/2.2 (Safe Browsing v5)' },
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => '(unreadable)');
      console.error(`[rescan] Safe Browsing batch error ${res.status}:`, errText);
      // Fail open — mark all as apiError (not skipped)
      uniqueUrls.forEach(url => results.set(url, { safe: true, threats: [], skipped: false, apiError: true, apiStatus: res.status, checkedUrl: url }));
      return results;
    }

    const data = await res.json();

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

  } catch (err) {
    console.error('[rescan] Batch fetch failed:', err);
    uniqueUrls.forEach(url => results.set(url, { safe: true, threats: [], skipped: false, apiError: true, apiStatus: null, checkedUrl: url }));
  }

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
    scanned:      0,
    skipped:      0,
    clean:        0,
    newlyFlagged: 0,
    ipsBlocked:   0,
    errors:       0,
    apiKeyMissing: false,
    apiErrors:    0,
    lastApiStatus: null,
    flaggedSlugs: [],
    errorSlugs:   [],
    completedAt:  null,
  };

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
