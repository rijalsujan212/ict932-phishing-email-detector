# ICT932 Assessment 3 - Explainable Phishing Email Detector

A compact Flask cybersecurity prototype built to demonstrate the core requirements of **ICT932 Cybersecurity Testing and Assurance Assessment 3, Project 3**.

## Implemented features

- Password authentication with Werkzeug hashing
- Two roles: `user` and `analyst`
- TOTP two-factor authentication with QR setup
- Server-side RBAC and least-privilege analyst pages
- Safe `.eml` / `.txt` parsing with 1 MB limit
- Attachment metadata + SHA-256 only; attachments are never executed
- URL/domain checks: raw IP, HTTP, shorteners, punycode, look-alike brands, redirect parameters
- Local offline threat-intelligence domain lookup
- Sender / Reply-To mismatch checks
- SPF / DKIM / DMARC result extraction when present in headers
- Suspicious keyword / structure rules
- Hybrid detection: 60% rules + 40% TF-IDF Logistic Regression probability
- Explainability view showing indicators behind the decision
- Automatic quarantine simulation for High Risk results
- Analyst Confirm Phishing / False Positive / Release workflow
- Dashboard with precision, recall, F1, confusion matrix and false-positive rate
- CSV, JSON and PDF exports
- Security audit log
- Zero Trust upload blocking and audit evidence
- pytest, Bandit and pip-audit support
- GitHub Actions security CI workflow

> The bundled ML dataset and threat-intelligence list are intentionally small, synthetic demonstration resources. They make the prototype safe and reproducible but are **not production benchmarks**.

## Windows quick start

From the repository root:

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run.py
```

Open:

```text
http://127.0.0.1:5000
```

### Demo credentials

On the **first run**, the application generates random passwords locally and prints them in the terminal. It also writes them to:

```text
instance/demo_credentials.txt
```

That folder is ignored by Git.

Accounts:

- `analyst@demo.local` - analyst role
- `user@demo.local` - normal user role

After entering the password, click **Set up / view QR code**, scan the QR with a TOTP authenticator app, and enter the current 6-digit code.

## Fast demonstration sequence

1. Sign in as `analyst@demo.local` and complete 2FA.
2. Open **Analyze**.
3. Upload `data/samples/phishing_sample.eml`.
4. Show the High Risk result, rules score, ML probability, explanations, SPF/DKIM/DMARC and URL flags.
5. Open **Quarantine** and show the automatic quarantine entry.
6. Use Confirm Phishing, False Positive, or Release.
7. Upload `data/samples/legitimate_sample.eml` and compare the lower risk score.
8. Attempt to upload `data/samples/blocked_sample.exe` to demonstrate Zero Trust blocking.
9. Open **Audit Logs** and show the blocked upload/security events.
10. Open **Dashboard** and show precision, recall, F1-score, confusion matrix and false-positive rate.
11. Export a CSV, JSON or PDF report.

## Security testing

Run:

```powershell
pytest -q
bandit -r src -x tests
pip-audit
```

See `docs/security-testing/SECURITY_TEST_PLAN.md` for manual OWASP-oriented checks and screenshot evidence.

## Repository structure

```text
src/                    Flask source code
src/services/           Safe parser + detection engine
src/templates/          HTML templates
src/static/             CSS
tests/                  pytest tests
data/                    Synthetic ML data and safe email samples
docs/                    Architecture, threat model and evidence guidance
ci-cd/                   Local security-check script
.github/workflows/       GitHub Actions CI
run.py                   Application entry point
requirements.txt         Python dependencies
```

## Zero Trust advanced security feature

Every email is treated as untrusted before analysis. The prototype enforces:

- explicit allow-list of `.eml` and `.txt`
- 1 MB request and parser limit
- no automatic URL browsing
- no attachment execution
- attachment hashing and metadata extraction only
- validation before scoring/storage
- security audit events for rejected uploads
- server-side RBAC for analyst functions

## Ethical use

Use only the provided synthetic samples or other data you are authorised to test. Do not use this prototype to target real individuals, accounts, networks or services.
