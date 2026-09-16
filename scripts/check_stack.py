import httpx, subprocess, os, sys, tempfile, time, json
from pathlib import Path
from tls_fixture import https_fixture
root=Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as temp, https_fixture(temp) as tls_port:
    env=dict(os.environ, ECDAT_DB=temp+'/scans.db', ECDAT_API_TOKEN='integration-token', ECDAT_ALLOWED_CIDRS='127.0.0.0/8', BACKEND_API_URL='http://127.0.0.1:18000/api')
    logs=open(temp+'/servers.log','w+')
    backend=subprocess.Popen([sys.executable,'-m','uvicorn','main:app','--host','127.0.0.1','--port','18000'],cwd=root/'backend',env=env,stdout=logs,stderr=logs)
    frontend=subprocess.Popen(['npm','run','start','--','--hostname','127.0.0.1','--port','13000'],cwd=root/'frontend',env=env,stdout=logs,stderr=logs)
    try:
        with httpx.Client(base_url='http://127.0.0.1:13000',trust_env=False,timeout=10) as c:
            for _ in range(100):
                try:
                    if c.get('/api/health').status_code==200: break
                except httpx.HTTPError: pass
                time.sleep(.1)
            else: raise AssertionError('Services did not start')
            assert c.get('/').status_code==200
            assert c.get('/dashboard').status_code==200
            assert c.get('/api/scans').status_code==401
            c.headers['Authorization']='Bearer integration-token'
            assert c.get('/api/scans').json()==[]
            response=c.post('/api/scan/code',json={'source_code':'from hashlib import md5 as h\nh(b"x")'})
            assert response.status_code==202,response.text
            scan=response.json()
            for _ in range(100):
                scan=c.get('/api/scans/'+scan['id']).json()
                if scan['status'] not in ('queued','running'): break
                time.sleep(.05)
            assert scan['status']=='completed',scan
            assert scan['result']['findings'][0]['primitive']=='MD5'
            response=c.post('/api/scan/binary/upload',files={'file':('real.bin',bytes.fromhex('637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0'))})
            assert response.status_code==202,response.text
            binary=response.json()
            for _ in range(100):
                binary=c.get('/api/scans/'+binary['id']).json()
                if binary['status'] not in ('queued','running'): break
                time.sleep(.05)
            assert binary['status']=='completed',binary
            response=c.post('/api/scan/network',json={'target':f'https://127.0.0.1:{tls_port}'})
            assert response.status_code==202,response.text
            network=response.json()
            for _ in range(200):
                network=c.get('/api/scans/'+network['id']).json()
                if network['status'] not in ('queued','running'): break
                time.sleep(.05)
            assert network['status']=='completed',network
            assert network['result']['post_quantum']['tests'][-1]['group']=='X25519'
            assert 'environment' in network['result']['deployment']
            assert network['result']['deployment']['status_code']==200
            assert network['result']['deployment']['hosting_hints'][0]['confidence']=='inferred'
            response=c.post('/api/migration/plans',json={'scan_ids':[network['id'],scan['id'],binary['id']], 'database':'none'})
            assert response.status_code==201,response.text
            plan=response.json()
            assert plan['environment']['signals']
            assert any('MLKEM' in row['target'] for row in plan['cryptographic_migration']['upgrades'])
            assert plan['traffic']['average_daily_requests'] is None
            assert plan['estimate']['downtime_minutes'] is None
            assert c.get('/api/migration/plans/'+plan['id']).json()==plan
            assert c.get('/api/migration/plans/'+plan['id']+'?project=other').status_code==404
            assert c.get('/api/migration/plans').json()[0]['id']==plan['id']
            exported=c.post('/api/export/cbom',json={'scan_ids':[scan['id'],binary['id'],network['id']]})
            assert exported.status_code==200,exported.text
            assert len(exported.json()['components'])==4
            assert c.post('/api/scan/binary',json={'raw_hex':'bad-hex'}).status_code==422
            print('PASS: production Next.js proxy → authenticated FastAPI → source/binary/TLS+HTTP jobs → persisted history → CBOM export → saved migration plan; invalid input remains 422')
    except Exception:
        logs.flush(); logs.seek(0); print(logs.read()); raise
    finally:
        frontend.terminate(); backend.terminate()
        for process in (frontend,backend):
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill()
