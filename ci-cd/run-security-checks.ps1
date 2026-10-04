Write-Host "=== Running pytest ==="
pytest -q

Write-Host "=== Running Bandit SAST ==="
bandit -r src -x tests

Write-Host "=== Running dependency audit ==="
pip-audit
