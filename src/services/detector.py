import csv
import ipaddress
import math
import re
from collections import Counter
from difflib import SequenceMatcher
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split


SUSPICIOUS_KEYWORDS = {
    "urgent": 8,
    "verify your account": 15,
    "account suspended": 15,
    "password expires": 10,
    "confirm identity": 12,
    "click here": 8,
    "login immediately": 10,
    "unusual activity": 8,
    "payment failed": 8,
    "gift card": 8,
    "wire transfer": 10,
    "security alert": 6,
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"
}

KNOWN_BRANDS = [
    "paypal", "microsoft", "google", "apple", "amazon", "facebook",
    "instagram", "dropbox", "netflix", "linkedin", "outlook", "office365"
]

RISKY_EXTENSIONS = {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".hta"}
REDIRECT_KEYS = {"url", "redirect", "redirect_url", "next", "target", "continue", "dest", "destination"}


def _extract_domain(address):
    match = re.search(r"@([A-Za-z0-9.-]+)", address or "")
    return match.group(1).lower().rstrip(".") if match else ""


def _base_label(domain):
    if not domain:
        return ""
    parts = domain.lower().split(".")
    return parts[-2] if len(parts) >= 2 else parts[0]


def _normalize_lookalike(text):
    return text.lower().replace("0", "o").replace("1", "l").replace("3", "e").replace("5", "s").replace("7", "t")


def _brand_lookalike(domain):
    label = _normalize_lookalike(_base_label(domain))
    if not label:
        return None
    for brand in KNOWN_BRANDS:
        if label == brand:
            return None
        ratio = SequenceMatcher(None, label, brand).ratio()
        if ratio >= 0.78 or (brand in label and label != brand):
            return brand
    return None


def _auth_status(headers, mechanism):
    text = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
    match = re.search(rf"\b{mechanism}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)", text)
    if match:
        return match.group(1)
    if mechanism == "spf":
        received_spf = str(headers.get("Received-SPF", "")).lower()
        for status in ["pass", "fail", "softfail", "neutral"]:
            if received_spf.startswith(status):
                return status
    return "unknown"


class MLClassifier:
    def __init__(self, csv_path):
        self.csv_path = Path(csv_path)
        self.vectorizer = TfidfVectorizer(ngram_range=(1, 2), max_features=2500, stop_words="english")
        self.model = LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42)
        self.metrics = {}
        self._train()

    def _train(self):
        data = pd.read_csv(self.csv_path)
        x_train, x_test, y_train, y_test = train_test_split(
            data["text"], data["label"], test_size=0.25, random_state=42, stratify=data["label"]
        )
        x_train_vec = self.vectorizer.fit_transform(x_train)
        self.model.fit(x_train_vec, y_train)
        x_test_vec = self.vectorizer.transform(x_test)
        predicted = self.model.predict(x_test_vec)
        cm = confusion_matrix(y_test, predicted, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()
        fpr = fp / (fp + tn) if (fp + tn) else 0
        self.metrics = {
            "precision": round(float(precision_score(y_test, predicted, zero_division=0)), 3),
            "recall": round(float(recall_score(y_test, predicted, zero_division=0)), 3),
            "f1": round(float(f1_score(y_test, predicted, zero_division=0)), 3),
            "false_positive_rate": round(float(fpr), 3),
            "confusion_matrix": [[int(v) for v in row] for row in cm.tolist()],
            "test_samples": int(len(y_test)),
            "dataset_note": "Small synthetic demonstration dataset. Metrics are not production benchmarks.",
        }

    def probability(self, text):
        vec = self.vectorizer.transform([text or ""])
        return float(self.model.predict_proba(vec)[0][1] * 100)


class PhishingDetector:
    def __init__(self, dataset_path, threat_intel_path):
        self.ml = MLClassifier(dataset_path)
        threat_path = Path(threat_intel_path)
        self.threat_domains = {
            line.strip().lower()
            for line in threat_path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        }

    @property
    def metrics(self):
        return self.ml.metrics

    def _analyze_urls(self, urls):
        score = 0
        indicators = []
        details = []

        for url in urls:
            try:
                parsed = urlparse(url)
                host = (parsed.hostname or "").lower()
                if not host:
                    continue
                item = {"url": url, "domain": host, "flags": []}

                try:
                    ipaddress.ip_address(host)
                    score += 18
                    item["flags"].append("IP-address URL")
                    indicators.append(f"URL uses a raw IP address: {host}")
                except ValueError:
                    pass

                if parsed.scheme.lower() == "http":
                    score += 5
                    item["flags"].append("unencrypted HTTP")
                    indicators.append(f"URL uses unencrypted HTTP: {host}")

                if host in SHORTENERS:
                    score += 12
                    item["flags"].append("URL shortener")
                    indicators.append(f"URL shortener detected: {host}")

                if host.startswith("xn--") or ".xn--" in host:
                    score += 15
                    item["flags"].append("punycode domain")
                    indicators.append(f"Punycode domain detected: {host}")

                lookalike = _brand_lookalike(host)
                if lookalike:
                    score += 18
                    item["flags"].append(f"look-alike of {lookalike}")
                    indicators.append(f"Possible look-alike domain for {lookalike}: {host}")

                if host in self.threat_domains:
                    score += 25
                    item["flags"].append("offline threat-intel match")
                    indicators.append(f"Domain appears in local threat-intelligence list: {host}")

                query_keys = {k.lower() for k in parse_qs(parsed.query).keys()}
                matched = sorted(query_keys & REDIRECT_KEYS)
                if matched:
                    score += 10
                    item["flags"].append("redirect-like parameter")
                    indicators.append(f"Suspicious redirect parameter in URL ({matched[0]}): {host}")

                if url.count("@") > 0:
                    score += 10
                    item["flags"].append("@ symbol in URL")
                    indicators.append(f"URL contains @ symbol: {host}")

                details.append(item)
            except Exception:
                details.append({"url": url, "domain": "", "flags": ["could not safely parse"]})

        return min(score, 55), indicators, details

    def analyze(self, parsed_email):
        indicators = []
        rule_score = 0
        body = parsed_email.get("body", "") or ""
        subject = parsed_email.get("subject", "") or ""
        combined_text = f"{subject}\n{body}".lower()

        keyword_hits = []
        for phrase, points in SUSPICIOUS_KEYWORDS.items():
            if phrase in combined_text:
                keyword_hits.append(phrase)
                rule_score += points
        if keyword_hits:
            shown = ", ".join(keyword_hits[:5])
            indicators.append(f"Suspicious phishing language detected: {shown}")

        sender_domain = _extract_domain(parsed_email.get("sender", ""))
        reply_domain = _extract_domain(parsed_email.get("reply_to", ""))
        if sender_domain and reply_domain and sender_domain != reply_domain:
            rule_score += 18
            indicators.append(f"Sender and Reply-To domains differ: {sender_domain} vs {reply_domain}")

        sender_lookalike = _brand_lookalike(sender_domain)
        if sender_lookalike:
            rule_score += 15
            indicators.append(f"Sender domain may imitate {sender_lookalike}: {sender_domain}")

        headers = parsed_email.get("headers", {}) or {}
        spf = _auth_status(headers, "spf")
        dkim = _auth_status(headers, "dkim")
        dmarc = _auth_status(headers, "dmarc")
        for name, status, points in [("SPF", spf, 12), ("DKIM", dkim, 10), ("DMARC", dmarc, 12)]:
            if status in {"fail", "softfail", "permerror"}:
                rule_score += points
                indicators.append(f"{name} authentication result is {status}")

        url_score, url_indicators, url_details = self._analyze_urls(parsed_email.get("urls", []))
        rule_score += url_score
        indicators.extend(url_indicators)

        attachments = parsed_email.get("attachments", []) or []
        for attachment in attachments:
            filename = (attachment.get("filename") or "").lower()
            suffix = Path(filename).suffix
            if suffix in RISKY_EXTENSIONS:
                rule_score += 20
                indicators.append(f"Potentially dangerous attachment type detected: {filename}")
            else:
                indicators.append(
                    f"Attachment analysed safely by metadata/hash only: {attachment.get('filename', 'unnamed')}"
                )

        rule_score = min(float(rule_score), 100.0)
        ml_probability = self.ml.probability(f"{subject} {body}")
        final_score = round((0.60 * rule_score) + (0.40 * ml_probability), 1)

        if final_score >= 60:
            classification = "High Risk"
        elif final_score >= 30:
            classification = "Medium Risk"
        else:
            classification = "Low Risk"

        if not indicators:
            indicators.append("No strong rule-based phishing indicators were found.")
        indicators.append(f"ML classifier phishing probability: {ml_probability:.1f}%")
        indicators.append("Hybrid score uses 60% rules and 40% ML probability.")
        indicators.append("Zero Trust controls validated file type/size and prevented URL or attachment execution.")

        return {
            "risk_score": final_score,
            "rule_score": round(rule_score, 1),
            "ml_probability": round(ml_probability, 1),
            "classification": classification,
            "indicators": indicators,
            "url_details": url_details,
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,
            "quarantined": classification == "High Risk",
        }
