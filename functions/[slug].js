import { getRandomConspiracy, getStatusMessage } from './_conspiracies.js';
import { secureHeaders, appendAccessLog, escapeHtml } from './_security.js';

const BASE_HEADERS = secureHeaders();

export async function onRequest(context) {
  const { request, env, params } = context;
  const slug = params.slug;

  // Pass through — no slug, static asset, API route, or admin page
  if (!slug || slug.startsWith('api') || slug.includes('.') || slug === 'admin') {
    return context.next();
  }

  // Basic slug sanity before touching KV
  if (!/^[a-z0-9][a-z0-9\-_]{0,63}$/i.test(slug) || slug.length > 64) {
    return new Response(getStatusMessage(400), {
      status: 400,
      headers: { 'Content-Type': 'text/plain; charset=utf-8', ...BASE_HEADERS, 'X-Truth': getRandomConspiracy() },
    });
  }

  try {
    const record = await env.LINKS.get(slug.toLowerCase(), { type: 'json' });

    if (!record) {
      return new Response(getStatusMessage(404), {
        status: 404,
        headers: {
          'Content-Type': 'text/plain; charset=utf-8',
          ...BASE_HEADERS,
          'X-Truth':  getRandomConspiracy(),
          'X-Status': 'MEMORY-HOLED',
        },
      });
    }

    // ── Record the access asynchronously (non-blocking) ───────────────────
    // We update the KV record with access metadata without blocking the redirect.
    const updatedRecord = appendAccessLog({ ...record }, request);
    // Use waitUntil if available so we don't block the response
    const kvPutOptions = record.expiresAt
      ? { expirationTtl: Math.max(1, Math.floor((new Date(record.expiresAt) - Date.now()) / 1000)) }
      : {};
    context.waitUntil(
      env.LINKS.put(slug.toLowerCase(), JSON.stringify(updatedRecord), kvPutOptions)
    );

    const conspiracy = getRandomConspiracy();

    // ── Preview / Interstitial mode ───────────────────────────────────────
    if (record.previewMode) {
      return previewInterstitial(record, conspiracy, request);
    }

    return new Response(
      `${getStatusMessage(302)}\n\nDESTINATION: ${record.url}\n\nIf you are reading this in a terminal, you know too much.`,
      {
        status: 302,
        headers: {
          'Location':        record.url,
          'Content-Type':    'text/plain; charset=utf-8',
          'X-Truth':         conspiracy,
          'X-Redirect-To':   record.url,
          'Cache-Control':   'no-store, no-cache',
          'X-Frame-Options': 'DENY',
          'X-Content-Type-Options': 'nosniff',
        },
      }
    );
  } catch {
    return new Response(getStatusMessage(500), {
      status: 500,
      headers: { 'Content-Type': 'text/plain; charset=utf-8', ...BASE_HEADERS, 'X-Truth': getRandomConspiracy() },
    });
  }
}

function previewInterstitial(record, conspiracy, request) {
  const origin  = new URL(request.url).origin;
  const safeUrl = escapeHtml(record.url);
  const safeSlug = escapeHtml(record.slug);
  const DELAY   = 5; // seconds

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <meta name="robots" content="noindex, nofollow"/>
  <title>Redirecting… — ${escapeHtml(new URL(origin).hostname)}</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --bg: #0d0d0d; --surface: #1a1a1a; --border: #2a2a2a;
      --text: #f0f0f0; --muted: #888; --accent: #f59e0b;
      --danger: #ef4444; --success: #10b981;
      --radius: 8px;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: var(--bg); color: var(--text);
      min-height: 100vh; display: flex; align-items: center; justify-content: center;
      padding: 1rem;
    }
    .card {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 12px; padding: 2.5rem; max-width: 520px; width: 100%;
      box-shadow: 0 20px 60px rgba(0,0,0,0.5);
    }
    .badge {
      display: inline-flex; align-items: center; gap: 0.4rem;
      background: rgba(245,158,11,0.15); color: var(--accent);
      border: 1px solid rgba(245,158,11,0.3); border-radius: 999px;
      padding: 0.3rem 0.85rem; font-size: 0.75rem; font-weight: 600;
      letter-spacing: 0.05em; text-transform: uppercase; margin-bottom: 1.5rem;
    }
    h1 { font-size: 1.375rem; font-weight: 600; margin-bottom: 0.5rem; }
    .subtitle { color: var(--muted); font-size: 0.875rem; margin-bottom: 1.75rem; }
    .dest-box {
      background: #111; border: 1px solid var(--border); border-radius: var(--radius);
      padding: 1rem 1.25rem; margin-bottom: 1.75rem;
      word-break: break-all; font-size: 0.875rem;
    }
    .dest-label { font-size: 0.75rem; color: var(--muted); margin-bottom: 0.35rem; text-transform: uppercase; letter-spacing: 0.05em; }
    .dest-url { color: var(--accent); font-family: monospace; }
    .countdown-ring {
      display: flex; align-items: center; justify-content: center; margin-bottom: 1.75rem;
    }
    svg.ring { width: 80px; height: 80px; transform: rotate(-90deg); }
    .ring-bg { fill: none; stroke: var(--border); stroke-width: 6; }
    .ring-fill { fill: none; stroke: var(--accent); stroke-width: 6; stroke-linecap: round;
      stroke-dasharray: 220; stroke-dashoffset: 0;
      transition: stroke-dashoffset 1s linear;
    }
    .ring-text { font-size: 1.5rem; font-weight: 700; fill: var(--text); text-anchor: middle; dominant-baseline: central; }
    .actions { display: flex; gap: 0.75rem; }
    .btn {
      flex: 1; padding: 0.75rem; font-size: 0.875rem; font-weight: 500;
      border-radius: var(--radius); cursor: pointer; border: none;
      font-family: inherit; transition: opacity 0.15s, transform 0.1s;
    }
    .btn:active { transform: scale(0.97); }
    .btn-proceed { background: var(--success); color: #fff; }
    .btn-cancel  { background: var(--border); color: var(--text); }
    .btn:hover { opacity: 0.85; }
    .slug-ref { text-align: center; margin-top: 1.25rem; color: var(--muted); font-size: 0.8rem; }
    .slug-ref code { background: #111; padding: 0.15rem 0.4rem; border-radius: 4px; color: var(--accent); }
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">⚠ Preview Mode</div>
    <h1>You're being redirected</h1>
    <p class="subtitle">This shortened link has a preview interstitial enabled. You will be sent to the destination in <strong id="sec">${DELAY}</strong> seconds.</p>

    <div class="dest-box">
      <div class="dest-label">Destination URL</div>
      <div class="dest-url">${safeUrl}</div>
    </div>

    <div class="countdown-ring">
      <svg class="ring" viewBox="0 0 80 80" xmlns="http://www.w3.org/2000/svg">
        <circle class="ring-bg" cx="40" cy="40" r="35"/>
        <circle class="ring-fill" id="ring" cx="40" cy="40" r="35"/>
        <text class="ring-text" x="40" y="40" transform="rotate(90 40 40)" id="ring-num">${DELAY}</text>
      </svg>
    </div>

    <div class="actions">
      <button class="btn btn-cancel" onclick="cancelRedirect()">Cancel</button>
      <button class="btn btn-proceed" onclick="proceedNow()">Go Now</button>
    </div>
    <div class="slug-ref">Short link: <code>${safeSlug}</code></div>
  </div>

  <script>
    const DELAY = ${DELAY};
    const CIRCUMFERENCE = 2 * Math.PI * 35; // ~219.9
    const dest = ${JSON.stringify(record.url)};
    let timer, remaining = DELAY, cancelled = false;

    const ring    = document.getElementById('ring');
    const ringNum = document.getElementById('ring-num');
    const secEl   = document.getElementById('sec');

    ring.style.strokeDasharray  = CIRCUMFERENCE;
    ring.style.strokeDashoffset = 0;

    function tick() {
      remaining--;
      ringNum.textContent = remaining;
      secEl.textContent   = remaining;
      ring.style.strokeDashoffset = CIRCUMFERENCE * (1 - remaining / DELAY);
      if (remaining <= 0) {
        clearInterval(timer);
        if (!cancelled) window.location.href = dest;
      }
    }

    timer = setInterval(tick, 1000);

    function cancelRedirect() {
      cancelled = true;
      clearInterval(timer);
      ring.style.stroke = '#ef4444';
      ringNum.textContent = '✕';
      secEl.textContent = '—';
      document.querySelector('.subtitle').textContent = 'Redirect cancelled. You can close this tab.';
    }

    function proceedNow() {
      cancelled = true;
      clearInterval(timer);
      window.location.href = dest;
    }
  </script>
</body>
</html>`;

  return new Response(html, {
    status: 200,
    headers: {
      'Content-Type':          'text/html; charset=utf-8',
      'X-Truth':               conspiracy,
      'Cache-Control':         'no-store, no-cache',
      'X-Frame-Options':       'DENY',
      'X-Content-Type-Options':'nosniff',
      'Referrer-Policy':       'no-referrer',
      'Content-Security-Policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'",
    },
  });
}
