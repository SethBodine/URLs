/**
 * GET /api/debug-auth
 *
 * Returns exactly what the server sees for your owner headers — raw values,
 * stripped values, derived hash, and whether verification passed.
 *
 * REMOVE THIS FILE before going to production.
 */

import { deriveOwnerHash, getVerifiedOwnerHash, jsonResponse, secureHeaders, CORS_PUBLIC } from '../_security.js';

export async function onRequestGet({ request, env }) {
  const rawFp      = request.headers.get('X-Fingerprint') || '';
  const rawHash    = request.headers.get('X-Owner-Hash')  || '';
  const strippedFp = rawFp.trim().replace(/^"+|"+$/g, '');
  const strippedHash = rawHash.trim().replace(/^"+|"+$/g, '').toLowerCase();

  const derived   = strippedFp ? await deriveOwnerHash(strippedFp, env) : null;
  const verified  = await getVerifiedOwnerHash(request, env);

  return jsonResponse({
    received: {
      'X-Fingerprint': rawFp,
      'X-Owner-Hash':  rawHash,
    },
    afterStripping: {
      fingerprint: strippedFp,
      ownerHash:   strippedHash,
    },
    serverDerived:  derived,
    hashMatch:      derived ? derived === strippedHash : false,
    verifiedResult: verified,
    verdict: verified ? '✅ Auth would PASS — ownerHash will be stored' : '❌ Auth would FAIL — ownerHash will be null',
  }, 200, CORS_PUBLIC);
}

export async function onRequestOptions() {
  return new Response(null, { status: 204, headers: { ...CORS_PUBLIC } });
}
