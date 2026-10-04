# Minimal Architecture

```text
Browser
  |
  | HTTPS in deployment / localhost in demo
  v
Flask Web Application
  |-- Authentication + TOTP 2FA + RBAC
  |-- Zero Trust file validation
  |-- Safe email parser
  |-- Rule-based phishing engine
  |-- TF-IDF + Logistic Regression model
  |-- Explainability layer
  |-- Quarantine / analyst review
  |-- Audit logging / export
  |
  +--> SQLite database (users, analyses, audit logs)
  +--> Local synthetic ML dataset
  +--> Local offline threat-intelligence domain list
```

Trust boundary: all uploaded email content, URLs, headers and attachment metadata are treated as untrusted input. URLs are not opened and attachments are not executed.
