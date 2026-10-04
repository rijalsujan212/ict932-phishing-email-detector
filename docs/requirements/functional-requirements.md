# Functional Requirements

1. Secure password login followed by TOTP 2FA.
2. RBAC with normal user and analyst roles.
3. Upload and safely parse `.eml` / `.txt` email input.
4. Analyse sender, Reply-To, SPF/DKIM/DMARC evidence, URLs/domains, suspicious language and attachment metadata/hashes.
5. Combine rule-based scoring with an ML phishing probability.
6. Display a human-readable explainability view.
7. Automatically quarantine High Risk results.
8. Allow analyst confirmation, false-positive marking and release.
9. Display dashboard statistics and ML validation metrics.
10. Export analysis records as CSV, JSON and PDF.
11. Record security-relevant audit events.
