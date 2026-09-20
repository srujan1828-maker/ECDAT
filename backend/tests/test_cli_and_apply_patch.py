"""Tests for AutoPatch direct in-code application and CLI."""
import argparse
import os
import shutil
import tempfile
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.engine.patch_engine import AutoPatchEngine
from backend.cli import run_patch_command, discover_files


@pytest.fixture
def client():
    return TestClient(app)


def test_autopatch_apply_method():
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = os.path.join(tmpdir, "auth_service.py")
        original_code = (
            "import hashlib\n\n"
            "def hash_token(data: str):\n"
            "    return hashlib.md5(data.encode()).hexdigest()\n"
        )
        with open(test_file, "w", encoding="utf-8") as f:
            f.write(original_code)

        patch = AutoPatchEngine.create_patch(original_code, "auth_service.py", "python")
        assert patch is not None
        assert "sha256" in patch.patched_code

        # Apply patch with backup
        res = AutoPatchEngine.apply_patch(test_file, patch.patched_code, backup=True, workspace_root=tmpdir)
        assert res["status"] == "applied"
        assert res["backup_created"] is True
        assert os.path.exists(res["backup_path"])

        # Check backup content
        with open(res["backup_path"], "r", encoding="utf-8") as f:
            assert f.read() == original_code

        # Check applied content
        with open(test_file, "r", encoding="utf-8") as f:
            new_content = f.read()
            assert "hashlib.sha256" in new_content
            assert "hashlib.md5" not in new_content

        assert res["weakness_eliminated"] is True


def test_autopatch_apply_traversal_prevention():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Attempting path traversal outside workspace_root
        with pytest.raises(ValueError, match="Path traversal attempt detected"):
            AutoPatchEngine.apply_patch(
                "../../outside.py",
                "patched content",
                workspace_root=tmpdir
            )


def test_api_experimental_autopatch_apply(client):
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = os.path.join(tmpdir, "crypto_module.py")
        original_code = "import hashlib\nx = hashlib.md5(b'test')\n"
        with open(test_file, "w", encoding="utf-8") as f:
            f.write(original_code)

        patched_code = "import hashlib\nx = hashlib.sha256(b'test')\n"

        response = client.post(
            "/api/experimental/autopatch/apply",
            json={
                "file_path": test_file,
                "patched_code": patched_code,
                "backup": True,
                "workspace_root": tmpdir,
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "applied"
        assert data["backup_created"] is True

        with open(test_file, "r", encoding="utf-8") as f:
            assert "sha256" in f.read()


def test_cli_patch_dry_run_and_apply(capsys):
    with tempfile.TemporaryDirectory() as tmpdir:
        sample_file = os.path.join(tmpdir, "legacy_crypto.py")
        code = "import hashlib\ntoken = hashlib.md5(b'secret').hexdigest()\n"
        with open(sample_file, "w", encoding="utf-8") as f:
            f.write(code)

        # 1. Dry run
        args_dry = argparse.Namespace(
            path=tmpdir,
            apply=False,
            dry_run=True,
            no_tests=False,
            no_backup=False,
        )
        ret = run_patch_command(args_dry)
        assert ret == 0
        captured = capsys.readouterr().out
        assert "MD5_TO_SHA256_PYTHON" in captured
        assert "DRY RUN" in captured

        # Ensure file was not modified
        with open(sample_file, "r", encoding="utf-8") as f:
            assert f.read() == code

        # 2. Apply mode
        args_apply = argparse.Namespace(
            path=tmpdir,
            apply=True,
            dry_run=False,
            no_tests=False,
            no_backup=False,
        )
        ret_apply = run_patch_command(args_apply)
        assert ret_apply == 0
        captured_apply = capsys.readouterr().out
        assert "Successfully patched" in captured_apply
        assert "WEAKNESS ELIMINATED" in captured_apply

        # Verify file modified on disk
        with open(sample_file, "r", encoding="utf-8") as f:
            assert "hashlib.sha256" in f.read()

        # Verify backup exists
        assert os.path.exists(f"{sample_file}.bak")


def test_demo_target_api_flow(client):
    # 1. Status
    res_status = client.get('/api/demo/target/status?target=apex_pay')
    assert res_status.status_code == 200
    data_status = res_status.json()
    assert data_status["target"]["id"] == "apex_pay"
    assert data_status["file_exists"] is True

    # 2. Scan
    res_scan = client.post('/api/demo/target/scan?target=apex_pay')
    assert res_scan.status_code == 200
    data_scan = res_scan.json()
    assert "findings" in data_scan

    # 3. Patch
    res_patch = client.post('/api/demo/target/patch?target=apex_pay')
    assert res_patch.status_code == 200
    data_patch = res_patch.json()
    assert data_patch["status"] in ("patched", "unaltered")

    # 4. Reset
    res_reset = client.post('/api/demo/target/reset?target=apex_pay')
    assert res_reset.status_code == 200
    data_reset = res_reset.json()
    assert data_reset["status"] == "reset"


def test_nodejs_autopatch_and_regression_tests():
    # 1. MD5 -> SHA256 in Node.js
    js_md5 = "const crypto = require('crypto');\nconst h = crypto.createHash('md5').update('data').digest('hex');\n"
    patch_md5 = AutoPatchEngine.create_patch(js_md5, "server.js", "javascript")
    assert patch_md5 is not None
    assert patch_md5.pattern_id == "MD5_TO_SHA256_JS"
    assert "crypto.createHash('sha256')" in patch_md5.patched_code
    tested_md5 = AutoPatchEngine.run_regression_test(patch_md5)
    assert tested_md5.verification_status == "passed"
    assert "TEST PASSED" in (tested_md5.test_output or "")

    # 2. RSA 1024 -> 3072 in Node.js
    js_rsa = "const crypto = require('crypto');\nconst keys = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });\n"
    patch_rsa = AutoPatchEngine.create_patch(js_rsa, "server.js", "javascript")
    assert patch_rsa is not None
    assert patch_rsa.pattern_id == "RSA_1024_UPGRADE_JS"
    assert "modulusLength: 3072" in patch_rsa.patched_code
    tested_rsa = AutoPatchEngine.run_regression_test(patch_rsa)
    assert tested_rsa.verification_status == "passed"
    assert "TEST PASSED" in (tested_rsa.test_output or "")

    # 3. DES -> AES in Node.js
    js_des = "const crypto = require('crypto');\nconst cipher = crypto.createCipheriv('des-cbc', key, iv);\n"
    patch_des = AutoPatchEngine.create_patch(js_des, "server.js", "javascript")
    assert patch_des is not None
    assert patch_des.pattern_id == "DES_TO_AES_JS"
    assert "aes-256-cbc" in patch_des.patched_code
    tested_des = AutoPatchEngine.run_regression_test(patch_des)
    assert tested_des.verification_status == "passed"
    assert "TEST PASSED" in (tested_des.test_output or "")


def test_all_demo_targets_flow(client):
    for target_id in ("apex_pay", "med_vault", "cipher_cloud"):
        res_status = client.get(f"/api/demo/target/status?target={target_id}")
        assert res_status.status_code == 200
        assert res_status.json()["file_exists"] is True

        res_scan = client.post(f"/api/demo/target/scan?target={target_id}")
        assert res_scan.status_code == 200
        assert "findings" in res_scan.json()

