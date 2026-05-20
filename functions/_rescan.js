/**
 * _rescan.js — Periodic re-validation of stored links against Google Safe Browsing
 *
 * Strategy:
 *   - Iterates all KV link records (skips rate-limit keys, blocklist keys,
 *     and already-deactivated links unless forceAll is set)
 *   - Fan-outs Safe Browsing checks with concurrency cap (stays within free quota)
 *   - Any link newly flagged is DEACTIVATED (not deleted) — all metadata preserved
 *   - The creator IP is automatically added to the blocklist
 *   - Deactivated links serve a warning page via [slug].js
 */

import { checkSafeBrowsing } from './_safebrowsing.js';
import { blockIp, isBlocklistKey } from './_blocklist.js';

const CONCURRENCY = 10; // parallel Safe Browsing requests per batch

/**
 * isLinkKey — excludes rate-limit and blocklist keys from scanning.
 */
function isLinkKey(name) {
  return !name.startsWith('rl:') && !isBlocklistKey(name);
}

/**
 * Fan-out Safe Browsing checks with a concurrency cap.
 * Returns a Map<url, sbResult>.
 */
async function batchCheckSafeBrowsing(records, env) {
  const results = new Map();
  for (let i = 0; i < records.length; i += CONCURRENCY) {
    const chunk = records.slice(i, i + CONCURRENCY);
    const checks = await Promise.all(chunk.map(({ record }) => checkSafeBrowsing(record.url, env)));
    chunk.forEach(({ record }, idx) => results.set(record.url, checks[idx]));
  }
  return results;
}

/**
 * runRescan(env, options?)
 *
 * @param {object} env
 * @param {object} [options]
 * @param {boolean} [options.forceAll=false]  Re-check already-deactivated links too
 * @returns {Promise<RescanStats>}
 */
export async function runRescan(env, { forceAll = false } = {}) {
  const startedAt = new Date().toISOString();
  const stats = {
    startedAt,
    scanned:      0,
    skipped:      0,
    clean:        0,
    newlyFlagged: 0,
    ipsBlocked:   0,
    errors:       0,
    flaggedSlugs: [],
    errorSlugs:   [],
    completedAt:  null,
  };

  // ── 1. Collect all link records ───────────────────────────────────────────
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

  // ── 2. Filter records that need scanning ──────────────────────────────────
  const toScan = allRecords.filter(({ record }) => {
    if (record.deactivated && !forceAll) {
      stats.skipped++;
      return false;
    }
    return true;
  });

  if (toScan.length === 0) {
    stats.completedAt = new Date().toISOString();
    return stats;
  }

  // ── 3. Batch check all URLs ───────────────────────────────────────────────
  let sbResults;
  try {
    sbResults = await batchCheckSafeBrowsing(toScan, env);
  } catch (err) {
    console.error('[rescan] Safe Browsing batch failed:', err);
    stats.errors += toScan.length;
    stats.errorSlugs.push(...toScan.map(({ record }) => record.slug));
    stats.completedAt = new Date().toISOString();
    return stats;
  }

  // ── 4. Process results ────────────────────────────────────────────────────
  const checkedAt = new Date().toISOString();

  await Promise.all(
    toScan.map(async ({ key, record }) => {
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
        // Distinguish a genuine clean result from a skipped check (no API key)
        if (sbResult.skipped) {
          stats.apiKeyMissing = true;
          stats.skippedNoKey = (stats.skippedNoKey || 0) + 1;
          // Don't overwrite audit stamps — record is unchanged
          return;
        }

        stats.clean++;
        // Update the audit stamp only — no structural change
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

      // ── Newly flagged — deactivate link + block creator IP ───────────────
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
        return; // don't block IP if we couldn't deactivate
      }

      // Block the original creator IP
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
    })
  );

  stats.completedAt = new Date().toISOString();
  return stats;
}
