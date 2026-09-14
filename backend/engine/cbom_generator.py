"""CycloneDX 1.6 export from persisted evidence, without invented security levels."""
import uuid
import json
from datetime import datetime, timezone


def generate_cyclonedx_cbom(records, target_name='ECDAT Project'):
    components = []
    for record in records:
        result = record['result']
        evidence = result.get('findings', result.get('detections', []))
        if record['kind'] == 'network':
            evidence = [{'primitive': result['cipher_name'], 'category': 'TLS cipher observation', 'file': result['target'], 'issue': result['hndl_rationale']}]
        for i, finding in enumerate(evidence):
            primitive = finding.get('primitive', 'Unknown')
            upper = primitive.upper()
            cdx_primitive = 'hash' if any(h in upper for h in ('MD5', 'SHA-1', 'SHA-256')) else 'block-cipher' if any(c in upper for c in ('AES', 'DES')) else 'pke' if 'RSA-' in upper else 'unknown'
            crypto = {'assetType': 'algorithm', 'algorithmProperties': {'primitive': cdx_primitive}}
            if record['kind'] == 'binary' and 'PRIVATE KEY' in upper:
                crypto = {'assetType': 'related-crypto-material'}
            elif record['kind'] == 'binary' and upper == 'CERTIFICATE':
                crypto = {'assetType': 'certificate'}
            props = {
                'ecdat:scanId': record['id'], 'ecdat:sourceType': record['kind'],
                'ecdat:inputHash': record['input_hash'], 'ecdat:engineVersion': record['engine_version'],
                'ecdat:observedAt': record['created_at'], 'ecdat:file': finding.get('file', ''),
                'ecdat:line': finding.get('line', ''), 'ecdat:offset': finding.get('offset', ''),
                'ecdat:confidence': finding.get('confidence', 'observed'),
                'ecdat:severity': finding.get('severity', 'unassessed'),
                'ecdat:sourceHash': finding.get('source_hash', ''),
                'ecdat:section': finding.get('section', '')}
            components.append({'type': 'cryptographic-asset', 'bom-ref': f"{record['id']}:{i}",
                'name': primitive, 'description': finding.get('issue', finding.get('description', 'Observed cryptographic indicator')),
                'cryptoProperties': crypto,
                'properties': [{'name': k, 'value': str(v)} for k, v in props.items() if v is not None]})
        if record['kind'] == 'network':
            cert = result.get('certificate', {})
            if cert.get('subject'):
                components.append({'type': 'cryptographic-asset', 'bom-ref': record['id'] + ':certificate', 'name': cert['subject'],
                    'cryptoProperties': {'assetType': 'certificate', 'certificateProperties': {
                        'subjectName': cert['subject'], 'issuerName': cert['issuer'],
                        'notValidBefore': cert['valid_from'], 'notValidAfter': cert['valid_to']}},
                    'properties': [{'name': 'ecdat:scanId', 'value': record['id']}, {'name': 'ecdat:sha256', 'value': cert.get('sha256', '')}]})
    return {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'serialNumber': 'urn:uuid:' + str(uuid.uuid4()), 'version': 1,
            'metadata': {'properties': [{'name': 'ecdat:scanCoverage', 'value': json.dumps([{'scan_id': r['id'], 'kind': r['kind'], 'status': r['result'].get('status', 'success'), 'coverage': r['result'].get('coverage')} for r in records])}], 'timestamp': datetime.now(timezone.utc).isoformat(), 'component': {'type': 'application', 'name': target_name},
                         'tools': {'components': [{'type': 'application', 'name': 'ECDAT', 'version': '3.0.0'}]}},
            'components': components}
