# Security Test Plan

Use only the local application and the supplied synthetic samples.

## Tool / Technique 1: pytest
Run:

```powershell
pytest -q
```

Capture the passing output.

## Tool / Technique 2: Bandit SAST
Run:

```powershell
bandit -r src -x tests
```

Record any finding, fix it if practical, then run the command again and capture the re-test output.

## Tool / Technique 3: pip-audit
Run:

```powershell
pip-audit
```

Record dependency findings. Do not claim a finding was fixed unless you actually update and re-run the audit.

## Manual OWASP-oriented checks

1. **Broken Access Control**: log in as the normal `user` role and browse to `/quarantine`. The application should return 403. The denial should be visible in the analyst Audit Logs after signing in as an analyst.
2. **Injection / unsafe input handling**: upload the supplied `.eml`/`.txt` samples only. The application does not execute message HTML, URLs, or attachments and displays text using Jinja escaping.
3. **Authentication Failures**: enter an incorrect password several times. Failed attempts are logged and a simple in-memory rate limit blocks repeated attempts.
4. **Unsafe file upload**: attempt to upload `data/samples/blocked_sample.exe`. It must be rejected and logged as a Zero Trust upload block.

Screenshots should be stored in `docs/screenshots/`.
