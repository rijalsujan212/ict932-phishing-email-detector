# STRIDE Threat Model Summary

| STRIDE | Example Threat | Control |
|---|---|---|
| Spoofing | Stolen password | Password hashing + TOTP 2FA |
| Tampering | Manipulated upload | File type/size validation; no execution |
| Repudiation | User denies security action | Audit log with user/action/time |
| Information Disclosure | Secrets committed to Git | `.env` ignored; runtime-generated secret; instance directory ignored |
| Denial of Service | Oversized email upload | 1 MB maximum request size |
| Elevation of Privilege | Normal user opens analyst pages | Server-side RBAC decorator |

Phishing-specific threats include sender spoofing, look-alike domains, malicious URLs, failed SPF/DKIM/DMARC signals and dangerous attachment types.
