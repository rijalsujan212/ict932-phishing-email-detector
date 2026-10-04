# Security Requirements

## SR-01 Password Protection
Passwords must never be stored in plaintext.

## SR-02 Two-Factor Authentication
TOTP-based 2FA must provide an additional authentication factor.

## SR-03 Least Privilege
Users must only access functions permitted by their assigned role.

## SR-04 Safe File Handling
Only permitted file types and file sizes will be accepted.

## SR-05 Untrusted Email Handling
All uploaded emails must be treated as untrusted.

## SR-06 Attachment Safety
Attachments must not be executed.

## SR-07 URL Safety
Extracted URLs must not be automatically opened.

## SR-08 Input Validation
User-controlled input must be validated before processing.

## SR-09 Secure Secrets
Application secrets must not be hard-coded into source code.

## SR-10 Security Logging
Relevant authentication and analysis security events must be recorded.

## SR-11 Authorised Testing
Security testing must only target the project environment.

## SR-12 Dependency Security
Project dependencies must be checked for known vulnerabilities.