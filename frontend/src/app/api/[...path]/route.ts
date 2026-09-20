import { NextRequest } from 'next/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

async function forward(
  request: NextRequest,
  context: { params: Promise<{ path?: string[] }> | { path?: string[] } }
) {
  try {
    const rawParams = await Promise.resolve(context.params);
    const path = Array.isArray(rawParams?.path) ? rawParams.path : [];
    const base = (process.env.BACKEND_API_URL || 'http://127.0.0.1:8000/api').replace(/\/$/, '');
    const url = `${base}/${path.map(encodeURIComponent).join('/')}${request.nextUrl.search}`;

    let body: Uint8Array | undefined;
    if (request.method === 'POST') {
      const reader = request.body?.getReader();
      const chunks: Uint8Array[] = [];
      let length = 0;
      if (reader) {
        while (true) {
          const chunk = await reader.read();
          if (chunk.done) break;
          length += chunk.value.byteLength;
          if (length > 520 * 1024 * 1024) {
            await reader.cancel();
            return Response.json({ detail: 'Request exceeds 500 MiB' }, { status: 413 });
          }
          chunks.push(chunk.value);
        }
      }
      body = new Uint8Array(length);
      let offset = 0;
      for (const chunk of chunks) {
        body.set(chunk, offset);
        offset += chunk.byteLength;
      }
    }

    const headers = new Headers();
    for (const key of ['content-type', 'authorization']) {
      const value = request.headers.get(key);
      if (value) headers.set(key, value);
    }

    const upstream = await fetch(url, {
      method: request.method,
      headers,
      body: body as BodyInit | undefined,
      cache: 'no-store',
      signal: AbortSignal.timeout(300000),
    });

    const contentType = upstream.headers.get('content-type') || '';
    if (!upstream.ok && !contentType.includes('application/json')) {
      const rawText = await upstream.text();
      let cleanDetail = rawText;
      if (/<title>Blocked<\/title>/i.test(rawText) || /cloudflare/i.test(rawText)) {
        const rayMatch = rawText.match(/Ray ID:\s*<code[^>]*>([a-f0-9]+)<\/code>|data-ray="([a-f0-9]+)"/i);
        const rayId = rayMatch ? (rayMatch[1] || rayMatch[2]) : '';
        cleanDetail = `Security Firewall Block (HTTP 403): Cloudflare WAF or network policy blocked the request${rayId ? ` (Ray ID: ${rayId})` : ''}. ` +
          `Scanning unencoded source code through Cloudflare tunnels triggers WAF rules. Payload encoding has been enabled, or you can access the dashboard directly at http://localhost:3000.`;
      } else if (/<[a-z][\s\S]*>/i.test(rawText)) {
        const titleMatch = rawText.match(/<title[^>]*>([^<]+)<\/title>/i);
        const title = titleMatch ? titleMatch[1].trim() : 'Upstream Error';
        const stripped = rawText
          .replace(/<style[\s\S]*?<\/style>/gi, '')
          .replace(/<script[\s\S]*?<\/script>/gi, '')
          .replace(/<svg[\s\S]*?<\/svg>/gi, '')
          .replace(/<[^>]+>/g, ' ')
          .replace(/\s+/g, ' ')
          .trim()
          .slice(0, 300);
        cleanDetail = `${title} (HTTP ${upstream.status}): ${stripped}`;
      }
      return Response.json(
        { detail: cleanDetail || `Upstream returned HTTP ${upstream.status} ${upstream.statusText}` },
        { status: upstream.status }
      );
    }

    return new Response(upstream.body, {
      status: upstream.status,
      headers: {
        'Content-Type': contentType || 'application/json',
        'Cache-Control': 'no-store',
      },
    });
  } catch (err: any) {
    return Response.json(
      { detail: err?.message || 'Backend unavailable. Check BACKEND_API_URL and backend health.' },
      { status: 502 }
    );
  }
}

export const GET = forward;
export const POST = forward;
