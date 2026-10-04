# Security Requirements

- Hash passwords; never store them in plaintext.
- Require TOTP 2FA after password verification.
- Enforce role checks on the server.
- Treat all email input as untrusted.
- Allow only `.eml` and `.txt` up to 1 MB.
- Never automatically open URLs or execute attachments.
- Hash attachment bytes using SHA-256 and retain metadata only.
- Use CSRF tokens on POST forms and secure session cookie settings.
- Generate the Flask secret at runtime or supply it through an environment variable.
- Store generated demo credentials in the Git-ignored `instance/` directory.
- Log authentication failures, access-control denials, blocked uploads and analyst actions.
