import ast
import time

from backend.engine.patch_engine import AutoPatchEngine


def test_node_cipher_upgrade_uses_fresh_material_and_flags_rotation():
    patch = AutoPatchEngine.create_patch(
        "const crypto = require('crypto');\nconst c = crypto.createCipheriv('des-cbc', key, iv);\n",
        "cipher.js",
        "javascript",
    )
    assert patch is not None
    assert "Buffer.alloc" not in patch.patched_code
    assert patch.patched_code.count("crypto.randomBytes") == 2
    assert "MANUAL KEY ROTATION REQUIRED" in patch.patched_code
    assert AutoPatchEngine.run_regression_test(patch).verification_status == "passed"


def test_generic_file_does_not_apply_foreign_language_templates():
    source = 'message = "MessageDigest.getInstance(\\\"MD5\\\")"\n'
    assert AutoPatchEngine.create_patch(source, "notes.txt", "generic") is None


def test_compounded_python_templates_remain_parseable():
    patch = AutoPatchEngine.create_patch(
        "import hashlib\nkey_size = 1024\ndigest = hashlib.md5(b'x')\n",
        "crypto.py",
        "python",
    )
    assert patch is not None
    ast.parse(patch.patched_code)
    assert "key_size = 3072" in patch.patched_code
    assert "hashlib.sha256" in patch.patched_code


def test_generic_rsa_pattern_is_bounded_on_adversarial_line():
    source = "key_size " + ("x" * 200_000) + " 1024"
    started = time.monotonic()
    AutoPatchEngine.create_patch(source, "symbols.txt", "generic")
    assert time.monotonic() - started < 1.0


def test_unexecuted_patch_never_claims_all_tests_passed():
    patch = AutoPatchEngine.create_patch('MessageDigest.getInstance("MD5");', "A.java", "java")
    assert patch is not None
    result = AutoPatchEngine.patch_entire_codebase([{"path": "A.java", "content": patch.original_code, "language": "java"}])
    assert result["patched_files"][0]["verification_status"] == "not_executed"
    assert result["summary"]["all_verified"] is False
    assert "ALL TESTS PASSED" not in AutoPatchEngine._generate_migration_markdown_report(result)
