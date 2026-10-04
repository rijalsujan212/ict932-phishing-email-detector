from datetime import datetime
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")
    totp_secret = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def is_analyst(self):
        return self.role == "analyst"


class Analysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    subject = db.Column(db.String(255), default="")
    sender = db.Column(db.String(255), default="")
    reply_to = db.Column(db.String(255), default="")
    risk_score = db.Column(db.Float, nullable=False)
    rule_score = db.Column(db.Float, nullable=False)
    ml_probability = db.Column(db.Float, nullable=False)
    classification = db.Column(db.String(20), nullable=False)
    indicators_json = db.Column(db.Text, nullable=False, default="[]")
    urls_json = db.Column(db.Text, nullable=False, default="[]")
    attachments_json = db.Column(db.Text, nullable=False, default="[]")
    content_preview = db.Column(db.Text, default="")
    spf = db.Column(db.String(20), default="unknown")
    dkim = db.Column(db.String(20), default="unknown")
    dmarc = db.Column(db.String(20), default="unknown")
    quarantined = db.Column(db.Boolean, default=False, nullable=False)
    review_status = db.Column(db.String(40), default="Unreviewed", nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(120), default="anonymous")
    action = db.Column(db.String(120), nullable=False)
    details = db.Column(db.Text, default="")
    severity = db.Column(db.String(20), default="INFO")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
