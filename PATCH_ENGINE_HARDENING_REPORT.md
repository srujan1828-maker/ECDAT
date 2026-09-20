# Patch Engine Hardening Report

## Fixed behaviour

* Node DES/RC4 upgrades now use fresh random AES key and IV bytes and include a
  visible `MANUAL KEY ROTATION REQUIRED` marker; no `Buffer.alloc` fill-byte
  pseudo-KDF remains.
* Language dispatch is strict. Generic files use only generic symbol templates,
  preventing Java, Go, C/C++, and Python replacements from being applied to
  unrelated content.
* Runtime execution is reported as `not_executed` when no executable regression
  test/runtime is available. Batch reports say `ALL TESTS PASSED` only when
  every patch actually executed and passed.
* Templates which merely rename a cipher while leaving incompatible key, IV,
  nonce, padding, or ciphertext handling behind are withheld pending a
  migration plan with rotation and reencryption.

## Verification output

```text
$ PYTHONPATH=backend python - <<'PY' ...
DES_TO_AES_JS
... crypto.createCipheriv('aes-256-cbc', crypto.randomBytes(32), crypto.randomBytes(16)) ...
passed
generic None
MD5_TO_SHA256_PYTHON+RSA_1024_UPGRADE_PYTHON ...
passed
PY
```

The full pytest command is `python -m pytest backend/tests -v`. In this image,
collection is blocked before tests execute because the installed Starlette test
client requires the unavailable `httpx2` package.
