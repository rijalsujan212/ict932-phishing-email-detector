# Functional Requirements

## FR-01 User Authentication
Users must be able to securely log into the application.

## FR-02 Two-Factor Authentication
Users must complete TOTP-based two-factor authentication.

## FR-03 Role-Based Access Control
The application must support User and Analyst/Admin roles.

## FR-04 Email Input
Users must be able to upload supported .eml and .txt email files.

## FR-05 Safe Email Parsing
The application must safely extract email content and metadata.

## FR-06 Header Analysis
The application must analyse sender and authentication-related headers.

## FR-07 URL Analysis
The application must extract and analyse URLs from email content.

## FR-08 Rule-Based Detection
The system must identify suspicious phishing indicators using defined rules.

## FR-09 Machine Learning
The system must use a machine-learning classifier to estimate phishing risk.

## FR-10 Explainability
The system must explain why an email has been classified as suspicious.

## FR-11 Quarantine Simulation
High-risk emails may be placed into a simulated quarantine.

## FR-12 Analyst Feedback
Analysts must be able to confirm phishing or mark a result as a false positive.

## FR-13 Dashboard
The application must show basic phishing detection statistics.

## FR-14 Reports
Analysis results must be exportable in appropriate formats.