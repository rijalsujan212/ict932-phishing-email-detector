# Live Demo Checklist

1. Start the application and show the terminal-generated analyst credentials.
2. Log in with the analyst password.
3. Open the 2FA Setup page, scan QR, enter current TOTP code.
4. Screenshot Dashboard before analysis.
5. Analyze `data/samples/phishing_sample.eml`.
6. Screenshot High Risk result, explainability indicators, SPF/DKIM/DMARC, URL analysis and Zero Trust statement.
7. Open Quarantine and screenshot the quarantined message.
8. Mark it Confirmed Phishing or False Positive and show analyst workflow.
9. Analyze `data/samples/legitimate_sample.eml` and screenshot the lower-risk comparison.
10. Attempt to upload `blocked_sample.exe` and screenshot the blocked upload message.
11. Open Audit Logs and screenshot the blocked upload / login / analyst actions.
12. Screenshot Dashboard ML metrics (precision, recall, F1, confusion matrix, false-positive rate).
13. Export CSV or PDF and show the generated file.
14. Run pytest, Bandit and pip-audit in the terminal and capture evidence.
15. Capture GitHub commits, GitHub Actions, and Trello board.
