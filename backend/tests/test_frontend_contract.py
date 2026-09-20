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
