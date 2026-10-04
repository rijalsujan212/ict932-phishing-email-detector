from pathlib import Path

from src.services.detector import PhishingDetector
from src.services.email_parser import parse_uploaded_email


BASE = Path(__file__).resolve().parent.parent


def build_detector():
    return PhishingDetector(BASE / "data" / "training_emails.csv", BASE / "data" / "threat_intel_domains.txt")


def test_phishing_sample_is_high_risk():
    path = BASE / "data" / "samples" / "phishing_sample.eml"
    parsed = parse_uploaded_email(path.name, path.read_bytes())
    result = build_detector().analyze(parsed)
    assert result["classification"] == "High Risk"
    assert result["quarantined"] is True
    assert result["risk_score"] >= 60


def test_legitimate_sample_lower_than_phishing():
    detector = build_detector()
    phishing_path = BASE / "data" / "samples" / "phishing_sample.eml"
    legit_path = BASE / "data" / "samples" / "legitimate_sample.eml"
    phishing = detector.analyze(parse_uploaded_email(phishing_path.name, phishing_path.read_bytes()))
    legit = detector.analyze(parse_uploaded_email(legit_path.name, legit_path.read_bytes()))
    assert legit["risk_score"] < phishing["risk_score"]
