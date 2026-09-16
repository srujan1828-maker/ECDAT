"""One bounded HEAD request to the same vetted IP used for TLS collection."""
import re
import time
from .network_prober import probe_tls_endpoint, _handshake, _context
import socket

MAX_HEADERS = 16 * 1024
ALLOWED_HEADERS = {'server', 'via', 'x-powered-by', 'cf-ray', 'x-vercel-id',
                   'x-amz-cf-id', 'x-cache', 'strict-transport-security', 'location'}


def inspect_http(host, port, address, timeout=3.0):
    started = time.monotonic()
    result = {'status': 'unavailable', 'method': 'HEAD', 'path': '/',
              'headers': {}, 'hosting_hints': [], 'origin_provider': None,
              'origin_region': None, 'deployment_method': None,
              'average_daily_requests': None,
              'limitations': ['Public headers can be hidden or spoofed; a CDN does not identify the origin.',
                             'One HEAD request is not average traffic or a performance benchmark.',
                             'Redirects are recorded but never followed. Only HTTPS root is checked.',
                             'Headers are collected without certificate verification; use TLS trust evidence separately.']}
    try:
        with _handshake(host, address, _context(), timeout) as conn:
            authority = f'[{host}]' if ':' in host else host
            authority += f':{port}' if port != 443 else ''
            conn.sendall(f'HEAD / HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: ECDAT/3.1\r\nConnection: close\r\n\r\n'.encode('ascii'))
            raw = bytearray()
            while b'\r\n\r\n' not in raw:
                remaining = timeout - (time.monotonic() - started)
                if remaining <= 0:
                    raise TimeoutError('HTTP header deadline exceeded')
                conn.settimeout(remaining)
                part = conn.recv(min(2048, MAX_HEADERS + 1 - len(raw)))
                if not part:
                    break
                raw.extend(part)
                if len(raw) > MAX_HEADERS:
                    raise ValueError('HTTP headers exceed 16 KiB')
            if b'\r\n\r\n' not in raw:
                raise ValueError('Incomplete HTTP headers')
            lines = raw.split(b'\r\n\r\n', 1)[0].decode('iso-8859-1').split('\r\n')
            status = re.fullmatch(r'HTTP/1\.[01] ([1-5][0-9]{2})(?: .*)?', lines[0])
            if not status:
                raise ValueError('Unsupported HTTP response')
            headers = {}
            for line in lines[1:]:
                name, sep, value = line.partition(':')
                if sep and name.lower() in ALLOWED_HEADERS:
                    headers[name.lower()] = re.sub(r'[\x00-\x1f\x7f]', '', value.strip())[:500]
            hints = []
            for header, provider in [('cf-ray', 'Cloudflare edge'), ('x-vercel-id', 'Vercel edge'), ('x-amz-cf-id', 'Amazon CloudFront edge')]:
                if header in headers:
                    hints.append({'provider': provider, 'confidence': 'inferred', 'evidence': f'{header}: {headers[header]}'})
            result.update(status='observed', status_code=int(status.group(1)), headers=headers,
                          hosting_hints=hints, response_header_ms=round((time.monotonic()-started)*1000, 1))
    except (OSError, ValueError) as exc:
        result['error'] = str(exc)
    return result


def scan_website(target, port=443):
    result = probe_tls_endpoint(target, port)
    if result.get('status') != 'error':
        # The TLS probe already resolved and vetted this exact address. Never resolve
        # the hostname a second time and never let a redirect select another target.
        ip = result['ip_address']
        address = (socket.AF_INET6, (ip, result['port'], 0, 0)) if ':' in ip else (socket.AF_INET, (ip, result['port']))
        result['deployment'] = inspect_http(result['host'], result['port'], address)
    return result
