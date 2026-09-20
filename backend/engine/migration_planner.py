"""Transparent, rule-based planning from saved observations and explicit inputs."""
from datetime import datetime, timezone
from .environment_discovery import plan_environment
from .pqc_migration import crypto_migration


def build_plan(records, inputs):
    network = next(r for r in records if r['kind'] == 'network')
    tls = network['result']
    deployment = tls.get('deployment') or {}
    findings = [dict(f, scan_id=r['id']) for r in records for f in r['result'].get('findings', r['result'].get('detections', []))]
    environment = plan_environment(records)
    inputs = dict(inputs)
    input_sources = {k: 'user_supplied' for k, v in inputs.items() if v is not None and v != 'unknown'}
    if not inputs.get('stack'):
        stacks = list(dict.fromkeys(s['value'] for s in environment['signals'] if s['category'] == 'stack'))
        if stacks:
            inputs['stack'] = ', '.join(stacks)
            input_sources['stack'] = 'automatically_discovered_hints'
    if inputs.get('database') == 'unknown':
        databases = set(s['value'] for s in environment['signals'] if s['category'] == 'database')
        if len(databases) == 1:
            inputs['database'] = databases.pop()
            input_sources['database'] = 'inferred_from_linked_driver_dependency'
    upgrades = crypto_migration(tls, findings)
    urgent = [f for f in findings if f.get('severity', '').upper() in ('CRITICAL', 'HIGH')]
    traffic = inputs.get('traffic')
    traffic_result = {'status': 'unknown', 'average_daily_requests': None, 'average_daily_gb': None,
                      'reason': 'Supply request and bandwidth totals from your analytics for a dated period.'}
    if traffic:
        days = (traffic['end_date'] - traffic['start_date']).days + 1
        traffic_result = {'status': 'user_supplied', 'source': traffic['source'],
                          'start_date': traffic['start_date'].isoformat(), 'end_date': traffic['end_date'].isoformat(),
                          'days': days, 'total_requests': traffic['total_requests'],
                          'average_daily_requests': round(traffic['total_requests'] / days, 2),
                          'average_daily_gb': round(traffic['total_gb'] / days, 3) if traffic.get('total_gb') is not None else None,
                          'reason': 'Computed from owner-supplied totals; not independently verified.'}
    unknowns = []
    for key, label in [('current_host', 'Current hosting provider'), ('target_host', 'Target hosting provider'),
                       ('stack', 'Application/runtime stack'), ('data_gb', 'Data volume'), ('database', 'Database engine')]:
        if inputs.get(key) is None or inputs.get(key) == 'unknown':
            unknowns.append(label)
    for field in ('stack', 'database'):
        if input_sources.get(field, '').startswith(('automatically', 'inferred')):
            unknowns.append('Confirm discovered ' + field)
    if not traffic:
        unknowns.append('Traffic baseline')
    if not deployment.get('origin_region'):
        unknowns.append('Origin region (confirm in hosting account)')
    apps = inputs['application_count']
    stateful = inputs['database'] not in ('none', 'unknown')
    # Planning heuristics, never a measured delivery date. The formula and each
    # component are exported so reviewers can replace the assumptions.
    hosting = [2 + apps, 5 + 3 * apps]
    if stateful:
        hosting = [hosting[0] + 3, hosting[1] + 8]
    elif inputs['database'] == 'unknown':
        hosting[1] += 8
    if inputs.get('data_gb', 0) is not None and inputs.get('data_gb', 0) > 100:
        hosting = [hosting[0] + 2, hosting[1] + 5]
    crypto_items = min(max(len(urgent), len(upgrades['upgrades'])), 10)
    crypto = [2 + crypto_items, 5 + crypto_items * 3]
    transfer = None
    if inputs.get('data_gb') is not None and inputs.get('transfer_mbps') is not None:
        transfer = round(inputs['data_gb'] * 8000 / inputs['transfer_mbps'] / 3600, 2)
    issues = []
    cert = tls.get('certificate') or {}
    if cert.get('trust_validated') is False:
        issues.append({'priority': 'high', 'title': 'Resolve certificate trust before cutover', 'evidence': cert.get('verification_error', 'Certificate trust did not validate'), 'scan_id': network['id']})
    legacy = [p['version'] for p in tls.get('protocol_tests', []) if p.get('status') == 'supported' and p.get('version') in ('TLSv1', 'TLSv1_1')]
    if legacy:
        issues.append({'priority': 'high', 'title': 'Retire negotiated legacy TLS versions after client compatibility testing', 'evidence': ', '.join(legacy), 'scan_id': network['id']})
    for f in urgent[:30]:
        issues.append({'priority': 'high', 'title': 'Review ' + f['primitive'] + ' usage',
                       'evidence': f"{f.get('file', 'artifact')}:{f.get('line', f.get('offset', '?'))} • {f.get('issue', f.get('description', 'Confirm usage and remediation'))}", 'scan_id': f['scan_id']})
    phases = [
        {'id': 'inventory', 'track': 'shared', 'title': 'Confirm scope and dependencies', 'days': [1, 3],
         'actions': ['Confirm ownership, origin hosting and region in the provider account.', 'Inventory DNS records, certificates, secrets, scheduled jobs, databases and third-party callbacks.', 'Confirm that every linked source/binary scan belongs to this website; review skipped files.'],
         'validation': 'An owner signs off the inventory and missing inputs.', 'rollback': 'No production changes in this phase.'},
        {'id': 'hosting', 'track': 'hosting', 'title': 'Rebuild in a staging environment', 'days': hosting,
         'actions': [f"Provision {inputs.get('target_host') or 'the target host (not selected)'} with the required runtime, regions and least-privilege access.", 'Reproduce build, environment variables, health checks and deployment automation.', 'Back up persistent data, rehearse restore/replication and measure transfer throughput.'],
         'validation': 'Smoke tests, data reconciliation and load tests pass against the supplied traffic baseline.', 'rollback': 'Keep the original environment and tested backups available.'},
        {'id': 'crypto', 'track': 'cryptography', 'title': 'Migrate classical cryptography to post-quantum algorithms', 'days': crypto,
         'actions': ['Triage linked findings by usage and confidence; repair weak algorithms and certificate failures.', 'Use the role-specific upgrade table: ML-KEM for key establishment, ML-DSA/SLH-DSA for signatures. Confirm vendor, protocol and client support before replacing APIs.', 'Test client interoperability, handshake size, latency and rollback in staging; rescan code, binaries and TLS.'],
         'validation': 'Explicit TLS group probes verify hybrid key exchange, and separate signature/trust-chain tests verify the intended authentication migration. Test regular client behavior as well.', 'rollback': 'Retain a reviewed prior configuration; do not re-enable known weak cryptography as a routine rollback.'},
        {'id': 'cutover', 'track': 'shared', 'title': 'Cut over gradually and verify', 'days': [1, 3],
         'actions': ['Choose a low-traffic window from actual analytics; account for DNS TTL and caches.', 'Freeze writes or complete final replication; check counts/checksums and switch a small traffic share first.', 'Monitor errors, latency, data integrity and TLS; keep an agreed rollback threshold and decision owner.'],
         'validation': 'A full observation window passes before decommissioning the old host.', 'rollback': 'Route traffic back and reconcile writes using the rehearsed recovery procedure.'},
    ]
    database_actions = {
        'none': 'Confirm the application is stateless; migrate static assets and externally managed state, if any.',
        'postgresql': 'Rehearse a PostgreSQL backup/restore or logical replication; verify extensions, roles, sequences and row counts before final synchronization.',
        'mysql': 'Rehearse a MySQL backup/restore or replication; verify engine/version compatibility, charset, users and row counts.',
        'mongodb': 'Rehearse a MongoDB backup/restore or supported sync; verify indexes, users and document counts.',
        'other': 'Choose a database-supported backup and synchronization method; rehearse restore and reconciliation.',
        'unknown': 'Identify the database engine and write paths before choosing a backup or replication strategy.'}
    phases[1]['actions'].append(database_actions[inputs['database']])
    if inputs.get('stack'):
        phases[1]['actions'].append('For the declared or discovered stack (' + inputs['stack'] + '), confirm runtime versions, build/start commands, ports, persistent paths and native dependencies on the target.')
    if traffic:
        phases[1]['actions'].append(f"The supplied baseline averages {traffic_result['average_daily_requests']} requests/day. Obtain peak requests/second, cache-hit ratio and error rates before sizing or load testing.")
    else:
        phases[1]['actions'].append('Collect a representative traffic period and peak load from owner-controlled logs; capacity sizing is blocked until these are available.')
    total = [sum(p['days'][i] for p in phases) for i in (0, 1)]
    return {'environment': environment, 'input_sources': input_sources, 'cryptographic_migration': upgrades, 'version': '1.1', 'status': 'draft', 'created_at': datetime.now(timezone.utc).isoformat(),
            'target': tls['target'], 'scan_ids': [r['id'] for r in records],
            'evidence': {'network_scan_id': network['id'], 'observed_at': tls.get('timestamp', network['created_at']),
                         'ip_address': tls.get('ip_address'), 'protocol': tls.get('protocol'), 'certificate': cert,
                         'deployment': deployment, 'linked_findings': len(findings), 'urgent_findings': len(urgent)},
            'traffic': traffic_result, 'inputs': inputs, 'missing_inputs': unknowns, 'priorities': issues, 'phases': phases,
            'estimate': {'confidence': 'low', 'person_days': total, 'sequential_working_days': total,
                         'minimum_transfer_hours': transfer, 'downtime_minutes': None,
                         'basis': 'One engineer working sequentially on the declared applications. ECDAT planning heuristic, not measured or vendor-quoted.',
                         'formula': 'Hosting: [2+apps, 5+3×apps] + [3,8] for a database; unknown database adds 8 upper days; data >100 GB adds [2,5]. Crypto: [2+n,5+3n], n=min(max(urgent findings, proposed algorithm upgrades),10). Inventory and cutover: [1,3] each.',
                         'assumptions': ['Source and infrastructure access are available.', 'No procurement, compliance approval, vendor development or major application rewrite is included.', 'Parallel staffing does not divide the estimate automatically.', 'Transfer minimum = decimal GB × 8000 / Mbps / 3600; excludes overhead, validation and live data changes.', 'Unknown dependencies may exceed the upper range. Downtime must be measured in rehearsal.']},
            'limitations': ['Public observation cannot prove origin provider, physical region, deployment method or average traffic.', 'Linked scans are explicitly selected by the user; ECDAT cannot prove they belong to the same application.', 'A draft plan does not execute a migration or establish post-quantum readiness.'],
            'references': [{'title': 'NIST NCCoE: Migration to post-quantum cryptography', 'url': 'https://www.nccoe.nist.gov/applied-cryptography/migration-to-pqc'},
                           {'title': 'Cloudflare: Website traffic metrics (one possible analytics source)', 'url': 'https://developers.cloudflare.com/analytics/account-and-zone-analytics/zone-analytics/'}]}
