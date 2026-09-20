"""Evidence-backed technology hints, not an assertion of private deployment state."""
import re


def discover_environment(headers, html='', dependencies=()):
    signals = []
    def add(category, value, evidence, source, confidence='inferred'):
        if not any(s['category'] == category and s['value'] == value for s in signals):
            signals.append({'category': category, 'value': value, 'evidence': evidence[:300],
                            'source': source, 'confidence': confidence})
    for name, provider in [('cf-ray', 'Cloudflare edge'), ('x-vercel-id', 'Vercel edge'),
                           ('x-amz-cf-id', 'Amazon CloudFront edge'), ('x-nf-request-id', 'Netlify edge'),
                           ('fly-request-id', 'Fly.io edge'), ('x-served-by', 'Cache/proxy tier')]:
        if headers.get(name):
            add('hosting', provider, f'{name}: {headers[name]}', 'HTTP header')
    for name in ('server', 'x-powered-by'):
        value = headers.get(name, '')
        if value:
            add('server', value, f'{name}: {value}', 'HTTP header')
        for marker, stack in [('express', 'Express / Node.js'), ('next.js', 'Next.js / Node.js'),
                              ('php', 'PHP'), ('asp.net', 'ASP.NET'), ('gunicorn', 'Python / Gunicorn'),
                              ('uvicorn', 'Python / ASGI')]:
            if marker in value.lower():
                add('stack', stack, f'{name}: {value}', 'HTTP header')
    # Explicit resource paths and framework metadata only; visible prose does not
    # count as a technology fingerprint. No linked resources are fetched.
    patterns = [(r'(?:src|href)=["\'][^"\']*/_next/', 'Next.js / Node.js', '_next resource path'),
                (r'(?:src|href)=["\'][^"\']*/_nuxt/', 'Nuxt / Vue', '_nuxt resource path'),
                (r'(?:src|href)=["\'][^"\']*/wp-(?:content|includes)/', 'WordPress / PHP', 'WordPress resource path'),
                (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Drupal', 'Drupal / PHP', 'Drupal generator metadata'),
                (r'\bng-version=["\'][0-9]', 'Angular', 'ng-version attribute'),
                (r'(?:src|href)=["\'][^"\']*cdn\.shopify\.com/', 'Shopify', 'Shopify CDN resource')]
    for pattern, stack, evidence in patterns:
        if re.search(pattern, html, re.I):
            add('stack', stack, evidence, 'HTML fingerprint')
    manifest_stacks = {'next': 'Next.js / Node.js', 'nuxt': 'Nuxt / Vue', 'express': 'Express / Node.js',
                       'react': 'React', 'vue': 'Vue', 'django': 'Django / Python',
                       'fastapi': 'FastAPI / Python', 'flask': 'Flask / Python'}
    db_drivers = {'pg': 'postgresql', 'psycopg': 'postgresql', 'psycopg2': 'postgresql',
                  'psycopg2-binary': 'postgresql', 'asyncpg': 'postgresql', 'mysql2': 'mysql',
                  'pymysql': 'mysql', 'mysqlclient': 'mysql', 'pymongo': 'mongodb', 'mongoose': 'mongodb', 'mongodb': 'mongodb'}
    for dep in dependencies:
        name = (dep.get('name') or re.split(r'[<>=!~\[;\s]', dep.get('requirement', ''))[0]).lower()
        evidence = f"{dep.get('file', 'manifest')}: {name} {dep.get('version', '')}".strip()
        if name in manifest_stacks:
            add('stack', manifest_stacks[name], evidence, 'Linked dependency manifest', 'declared_dependency')
        if name in db_drivers:
            add('database', db_drivers[name], evidence, 'Linked dependency manifest', 'inferred_from_driver')
    return {'status': 'signals_found' if signals else 'no_public_signals', 'signals': signals,
            'origin_provider': None, 'origin_region': None, 'deployment_method': None,
            'limitations': ['Headers and HTML are public claims that can be hidden, proxied or spoofed.',
                           'A CDN/edge provider is not proof of the origin hosting provider or region.',
                           'A dependency is evidence of declared software, not proof it is deployed or active.',
                           'Database servers, containers, CI/CD, traffic and data volumes are not exposed reliably by public web pages.']}


def plan_environment(records):
    network = next(r for r in records if r['kind'] == 'network')
    deployment = network['result'].get('deployment') or {}
    env = dict(deployment.get('environment') or discover_environment(deployment.get('headers') or {}))
    signals = list(env['signals'])
    deps = [d for r in records for d in r['result'].get('dependencies', [])]
    for signal in discover_environment({}, dependencies=deps)['signals']:
        if not any(s['category'] == signal['category'] and s['value'] == signal['value'] for s in signals):
            signals.append(signal)
    env['signals'] = signals
    env['status'] = 'signals_found' if signals else 'no_public_signals'
    return env
