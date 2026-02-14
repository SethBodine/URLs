import { getRandomConspiracy, getStatusMessage } from './_conspiracies.js';
import { secureHeaders } from './_security.js';

const BASE_HEADERS = secureHeaders();

export async function onRequest(context) {
  const { request, env, params } = context;
  const slug = params.slug;

  // Pass through — no slug or looks like a static asset/API route
  if (!slug || slug.startsWith('api') || slug.includes('.')) {
    return context.next();
  }

  // Basic slug sanity before touching KV — prevents KV abuse with junk keys
  if (!/^[a-z0-9][a-z0-9\-_]{0,63}$/i.test(slug) || slug.length > 64) {
    return new Response(getStatusMessage(400), {
      status: 400,
      headers: { 'Content-Type': 'text/plain; charset=utf-8', ...BASE_HEADERS, 'X-Truth': getRandomConspiracy() },
    });
  }

  try {
    const data = await env.LINKS.get(slug.toLowerCase(), { type: 'json' });

    if (!data) {
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

    const conspiracy = getRandomConspiracy();

    return new Response(
      `${getStatusMessage(302)}\n\nDESTINATION: ${data.url}\n\nIf you are reading this in a terminal, you know too much.`,
      {
        status: 302,
        headers: {
          'Location':        data.url,
          'Content-Type':    'text/plain; charset=utf-8',
          'X-Truth':         conspiracy,
          'X-Redirect-To':   data.url,
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
