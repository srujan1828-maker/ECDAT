import { NextRequest } from 'next/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

async function forward(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  const { path } = await context.params;
  const base = (process.env.BACKEND_API_URL || 'http://127.0.0.1:8000/api').replace(/\/$/, '');
  const url = `${base}/${path.map(encodeURIComponent).join('/')}${request.nextUrl.search}`;
  try {
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
          if (length > 18 * 1024 * 1024) {
            await reader.cancel();
            return Response.json({ detail: 'Request exceeds 18 MiB' }, { status: 413 });
          }
          chunks.push(chunk.value);
        }
      }
      body = new Uint8Array(length);
      let offset = 0;
      for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.byteLength; }
    }
    const headers = new Headers();
    for (const key of ['content-type', 'authorization']) {
      const value = request.headers.get(key);
      if (value) headers.set(key, value);
    }
    const upstream = await fetch(url, { method: request.method, headers, body: body as BodyInit | undefined,
      cache: 'no-store', signal: AbortSignal.timeout(30000) });
    return new Response(upstream.body, { status: upstream.status, headers: { 'Content-Type': upstream.headers.get('content-type') || 'application/json', 'Cache-Control': 'no-store' } });
  } catch {
    return Response.json({ detail: 'Backend unavailable. Check BACKEND_API_URL and backend health.' }, { status: 502 });
  }
}

export const GET = forward;
export const POST = forward;
