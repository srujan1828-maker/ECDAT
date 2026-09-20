import io
import time
import zipfile
import time


def _finish(client, response, project="default"):
    assert response.status_code == 202, response.text
    scan_id = response.json()["id"]
    for _ in range(200):
        record = client.get(f"/api/scans/{scan_id}?project={project}").json()
        if record["status"] not in ("queued", "running"):
            return record
        time.sleep(0.02)
    raise AssertionError("scan did not finish")


def test_project_crud_matches_frontend_contract(client):
    projects = client.get("/api/projects")
    assert projects.status_code == 200
    assert projects.json()[0]["id"] == "default"

    created = client.post("/api/projects", json={
        "id": "payments",
        "name": "Payment Gateway",
        "environment": "Production",
        "business_criticality": "Critical",
        "data_sensitivity": "Sensitive",
        "data_lifetime_years": 20,
        "tags": ["payments"],
    })
    assert created.status_code == 201
    assert created.json()["metrics"]["scan_count"] == 0

    updated = client.patch("/api/projects/payments", json={"environment": "Staging"})
    assert updated.status_code == 200
    assert updated.json()["environment"] == "Staging"
    assert client.get("/api/projects/payments/assets").json() == []
    assert client.get("/api/projects/payments/evidence").json() == []


def test_authentication_contract(client):
    login = client.post("/api/auth/login", json={
        "email": "admin@ecdat.local", "password": "admin123",
    })
    assert login.status_code == 200
    assert login.json()["role"] == "OWNER"
    assert login.json()["token"]

    registered = client.post("/api/auth/register", json={
        "email": "analyst@example.test", "password": "safe-password",
        "name": "Security Analyst", "role": "SECURITY_ANALYST",
    })
    assert registered.status_code == 201
    assert client.post("/api/auth/login", json={
        "email": "analyst@example.test", "password": "safe-password",
    }).status_code == 200
    assert client.post("/api/auth/login", json={
        "email": "analyst@example.test", "password": "wrong-password",
    }).status_code == 401


def test_scan_status_result_and_project_assessment_contracts(client):
    record = _finish(client, client.post("/api/scan/code", json={
        "source_code": "import hashlib\nhashlib.md5(b'legacy').hexdigest()",
        "language": "python",
    }))
    assert record["status"] == "completed"
    assert client.get("/api/scans?status=running").json() == []

    result = client.get(f"/api/scans/{record['id']}/result")
    assert result.status_code == 200
    assert "hashlib.md5" in result.json()["source_code"]
    assert result.json()["findings"]

    evidence = client.get(f"/api/evidence?scan_id={record['id']}")
    assert evidence.status_code == 200
    for item in evidence.json():
        assert {"evidence_type", "algorithm", "location", "rule_id"} <= item.keys()

    agility = client.get("/api/agility/assessment")
    assert agility.status_code == 200
    assert len(agility.json()["dimensions"]) == 7

    mosca = client.post("/api/quantum/mosca-project-scan", json={
        "project_id": "default", "data_sensitivity_years": 20,
        "migration_time_years": 3, "crqc_horizon_override": 10,
    })
    assert mosca.status_code == 200
    assert "results" in mosca.json()


def test_custom_loop_contract(client):
    response = client.post("/api/custom-loop/run", json={
        "target_type": "source", "file_name": "app.py", "language": "python",
        "source_code": "import hashlib\nhashlib.md5(b'legacy').hexdigest()",
    })
    assert response.status_code == 200
    result = response.json()
    assert result["verdict"] == "VERIFIED"
    assert result["before_state"]["critical_vulnerabilities"] == 1
    assert result["after_state"]["critical_vulnerabilities"] == 0
    assert "hashlib.sha256" in result["after_state"]["code"]
    assert result["regression_test"]["status"] == "passed"
    assert client.get("/api/custom-loop/latest").json()["run_id"] == result["run_id"]


def test_patch_from_scan_applies_selected_templates_and_queues_rescan(client):
    source = (
        "import hashlib\n"
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "hashlib.md5(b'legacy').hexdigest()\n"
        "rsa.generate_private_key(public_exponent=65537, key_size=1024)\n"
    )
    baseline = _finish(client, client.post("/api/scan/code", json={
        "source_code": source, "language": "python",
    }))
    response = client.post("/api/patch/from-scan", json={
        "scan_id": baseline["id"], "project_id": "default",
        "file_path": "app.py",
        "selected_patterns": ["MD5_TO_SHA256_PYTHON", "RSA_1024_UPGRADE_PYTHON"],
    })
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["applied"] is True
    assert result["total_patched"] == 2
    assert "hashlib.sha256" in result["patched_code"]
    assert "key_size=3072" in result["patched_code"]
    assert result["verification_status"] in ("passed", "static_verified")
    assert "simulated" not in result["verification_status"]

    post_scan = result["post_migration_scan_id"]
    for _ in range(200):
        record = client.get(f"/api/scans/{post_scan}").json()
        if record["status"] not in ("queued", "running"):
            break
        time.sleep(0.02)
    assert record["status"] == "completed"
    assert record["result"]["findings"][0]["primitive"] == "RSA-3072"


def test_folder_patch_preserves_entire_project_download(client):
    baseline = _finish(client, client.post("/api/scan/sources", json={"files": [
        {"path": "src/security.py", "content": "import hashlib\nhashlib.md5(b'x')\n", "language": "python"},
        {"path": "src/clean.py", "content": "print('keep me')\n", "language": "python"},
        {"path": "README.md", "content": "# Original project\n"},
    ]}))
    request = {
        "scan_id": baseline["id"], "project_id": "default",
        "selected_patterns": ["MD5_TO_SHA256_PYTHON"],
        "file_path": "project",
    }
    patched = client.post("/api/patch/from-scan", json=request)
    assert patched.status_code == 200, patched.text
    result = patched.json()
    assert result["project_file_count"] == 3
    assert [item["path"] for item in result["patched_files"]] == ["src/security.py"]

    stored_download = client.get(
        f"/api/scans/{result['post_migration_scan_id']}/source-archive?project=default"
    )
    assert stored_download.status_code == 200, stored_download.text
    with zipfile.ZipFile(io.BytesIO(stored_download.content)) as archive:
        assert "ECDAT_PATCH_AUDIT.json" in archive.namelist()
        assert "hashlib.sha256" in archive.read("src/security.py").decode()
        assert archive.read("src/clean.py").decode() == "print('keep me')\n"

    download = client.post("/api/patch/from-scan/download", json=request)
    assert download.status_code == 200, download.text
    assert download.headers["content-type"] == "application/zip"
    with zipfile.ZipFile(io.BytesIO(download.content)) as archive:
        assert set(archive.namelist()) >= {
            "src/security.py", "src/clean.py", "README.md",
            "POST_QUANTUM_MIGRATION_REPORT.md",
        }
        assert "hashlib.sha256" in archive.read("src/security.py").decode()
        assert archive.read("src/clean.py").decode() == "print('keep me')\n"
        assert archive.read("README.md").decode() == "# Original project\n"
