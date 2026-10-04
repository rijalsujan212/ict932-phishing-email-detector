import csv
import io
import json
import os
import secrets
import string
import time
from collections import Counter
from datetime import timedelta
from functools import wraps
from pathlib import Path

import pyotp
import qrcode
from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from src.models import Analysis, AuditLog, User, db
from src.services.detector import PhishingDetector
from src.services.email_parser import EmailParseError, parse_uploaded_email


BASE_DIR = Path(__file__).resolve().parent.parent
INSTANCE_DIR = BASE_DIR / "instance"
DATA_DIR = BASE_DIR / "data"
INSTANCE_DIR.mkdir(parents=True, exist_ok=True)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.login_message_category = "warning"
LOGIN_ATTEMPTS = {}


def _random_password(length=14):
    alphabet = string.ascii_letters + string.digits + "!@#$%"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def audit_event(action, details="", severity="INFO", user_email=None):
    email = user_email
    if not email:
        email = current_user.email if getattr(current_user, "is_authenticated", False) else "anonymous"
    log = AuditLog(user_email=email, action=action, details=details[:1000], severity=severity)
    db.session.add(log)
    db.session.commit()


def analyst_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            return login_manager.unauthorized()
        if current_user.role != "analyst":
            audit_event("RBAC access denied", f"Blocked access to {request.path}", "WARNING")
            abort(403)
        return view(*args, **kwargs)

    return wrapped


def _seed_demo_users():
    if User.query.count() > 0:
        return

    analyst_password = os.environ.get("DEMO_ANALYST_PASSWORD") or _random_password()
    user_password = os.environ.get("DEMO_USER_PASSWORD") or _random_password()

    analyst = User(
        email="analyst@demo.local",
        password_hash=generate_password_hash(analyst_password),
        role="analyst",
        totp_secret=pyotp.random_base32(),
    )
    standard = User(
        email="user@demo.local",
        password_hash=generate_password_hash(user_password),
        role="user",
        totp_secret=pyotp.random_base32(),
    )
    db.session.add_all([analyst, standard])
    db.session.commit()

    credentials = (
        "ICT932 DEMO CREDENTIALS - generated locally on first run\n"
        "=======================================================\n"
        f"Analyst email: analyst@demo.local\nAnalyst password: {analyst_password}\n\n"
        f"User email: user@demo.local\nUser password: {user_password}\n\n"
        "After password login, use the 2FA Setup link to scan the QR code with an authenticator app.\n"
        "This file is inside instance/ and is ignored by Git.\n"
    )
    (INSTANCE_DIR / "demo_credentials.txt").write_text(credentials, encoding="utf-8")
    print("\n" + credentials)


def create_app(test_config=None):
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{(INSTANCE_DIR / 'phishing_detector.db').as_posix()}",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        MAX_CONTENT_LENGTH=1 * 1024 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    )
    if test_config:
        app.config.update(test_config)

    db.init_app(app)
    login_manager.init_app(app)

    detector = PhishingDetector(DATA_DIR / "training_emails.csv", DATA_DIR / "threat_intel_domains.txt")
    app.extensions["phishing_detector"] = detector

    with app.app_context():
        db.create_all()
        _seed_demo_users()

    @app.context_processor
    def inject_helpers():
        return {"csrf_token": _csrf_token, "model_metrics": detector.metrics}

    @app.before_request
    def csrf_protection():
        session.permanent = True
        if request.method == "POST":
            submitted = request.form.get("_csrf", "")
            expected = session.get("csrf_token", "")
            if not expected or not secrets.compare_digest(submitted, expected):
                abort(400, description="Invalid CSRF token.")

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self'; "
            "script-src 'self'; form-action 'self'; frame-ancestors 'none'"
        )
        return response

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    @app.route("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            now = time.time()
            attempts = [t for t in LOGIN_ATTEMPTS.get(email, []) if now - t < 300]
            if len(attempts) >= 5:
                flash("Too many failed attempts. Try again in a few minutes.", "danger")
                audit_event("Login rate limit", f"Rate limit triggered for {email}", "WARNING", email)
                return render_template("login.html"), 429

            user = User.query.filter_by(email=email).first()
            if not user or not check_password_hash(user.password_hash, password):
                attempts.append(now)
                LOGIN_ATTEMPTS[email] = attempts
                audit_event("Failed login", f"Invalid credentials for {email}", "WARNING", email or "anonymous")
                flash("Invalid email or password.", "danger")
                return render_template("login.html"), 401

            LOGIN_ATTEMPTS.pop(email, None)
            session["pre_2fa_user_id"] = user.id
            session["pre_2fa_time"] = now
            audit_event("Password verified", "Awaiting TOTP verification", "INFO", user.email)
            return redirect(url_for("two_factor"))

        return render_template("login.html")

    @app.route("/two-factor", methods=["GET", "POST"])
    def two_factor():
        user_id = session.get("pre_2fa_user_id")
        started = session.get("pre_2fa_time", 0)
        if not user_id or time.time() - started > 300:
            session.pop("pre_2fa_user_id", None)
            flash("Please sign in again.", "warning")
            return redirect(url_for("login"))
        user = db.session.get(User, user_id)
        if not user:
            return redirect(url_for("login"))

        if request.method == "POST":
            token = request.form.get("token", "").strip().replace(" ", "")
            if pyotp.TOTP(user.totp_secret).verify(token, valid_window=1):
                login_user(user)
                session.pop("pre_2fa_user_id", None)
                session.pop("pre_2fa_time", None)
                audit_event("Successful login", "Password and TOTP verified", "INFO", user.email)
                flash("Login successful. Two-factor authentication verified.", "success")
                return redirect(url_for("dashboard"))
            audit_event("Failed 2FA", "Invalid TOTP code", "WARNING", user.email)
            flash("Invalid authentication code.", "danger")

        return render_template("two_factor.html", user=user)

    @app.route("/two-factor/setup")
    def two_factor_setup():
        user_id = session.get("pre_2fa_user_id")
        if not user_id:
            return redirect(url_for("login"))
        user = db.session.get(User, user_id)
        uri = pyotp.TOTP(user.totp_secret).provisioning_uri(name=user.email, issuer_name="ICT932 Phishing Detector")
        return render_template("two_factor_setup.html", user=user, secret=user.totp_secret, uri=uri)

    @app.route("/two-factor/qr")
    def two_factor_qr():
        user_id = session.get("pre_2fa_user_id")
        if not user_id:
            abort(403)
        user = db.session.get(User, user_id)
        uri = pyotp.TOTP(user.totp_secret).provisioning_uri(name=user.email, issuer_name="ICT932 Phishing Detector")
        image = qrcode.make(uri)
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        buffer.seek(0)
        return send_file(buffer, mimetype="image/png")

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        email = current_user.email
        logout_user()
        audit_event("Logout", "User signed out", "INFO", email)
        flash("You have been signed out.", "info")
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        query = Analysis.query if current_user.role == "analyst" else Analysis.query.filter_by(created_by=current_user.id)
        analyses = query.order_by(Analysis.created_at.desc()).all()
        total = len(analyses)
        high = sum(1 for a in analyses if a.classification == "High Risk")
        medium = sum(1 for a in analyses if a.classification == "Medium Risk")
        low = sum(1 for a in analyses if a.classification == "Low Risk")
        quarantined = sum(1 for a in analyses if a.quarantined)
        false_positives = sum(1 for a in analyses if a.review_status == "False Positive")
        indicator_counter = Counter()
        for analysis in analyses:
            for indicator in json.loads(analysis.indicators_json or "[]"):
                if not indicator.startswith("ML classifier") and not indicator.startswith("Hybrid score") and not indicator.startswith("Zero Trust"):
                    indicator_counter[indicator] += 1
        return render_template(
            "dashboard.html",
            analyses=analyses[:6],
            stats={
                "total": total,
                "high": high,
                "medium": medium,
                "low": low,
                "quarantined": quarantined,
                "false_positives": false_positives,
            },
            top_indicators=indicator_counter.most_common(5),
            metrics=detector.metrics,
        )

    @app.route("/analyze", methods=["GET", "POST"])
    @login_required
    def analyze():
        if request.method == "POST":
            upload = request.files.get("email_file")
            if not upload or not upload.filename:
                flash("Choose a .eml or .txt file.", "danger")
                return render_template("analyze.html")
            filename = secure_filename(upload.filename)
            raw = upload.read()
            try:
                parsed = parse_uploaded_email(filename, raw)
                result = detector.analyze(parsed)
            except EmailParseError as exc:
                audit_event("Zero Trust upload blocked", f"{filename}: {exc}", "WARNING")
                flash(str(exc), "danger")
                return render_template("analyze.html"), 400
            except Exception as exc:
                audit_event("Analysis error", f"{filename}: {type(exc).__name__}", "ERROR")
                flash("The email could not be analysed safely.", "danger")
                return render_template("analyze.html"), 400

            analysis = Analysis(
                filename=filename,
                subject=parsed.get("subject", "")[:255],
                sender=parsed.get("sender", "")[:255],
                reply_to=parsed.get("reply_to", "")[:255],
                risk_score=result["risk_score"],
                rule_score=result["rule_score"],
                ml_probability=result["ml_probability"],
                classification=result["classification"],
                indicators_json=json.dumps(result["indicators"]),
                urls_json=json.dumps(result["url_details"]),
                attachments_json=json.dumps(parsed.get("attachments", [])),
                content_preview=(parsed.get("body", "") or "")[:600],
                spf=result["spf"],
                dkim=result["dkim"],
                dmarc=result["dmarc"],
                quarantined=result["quarantined"],
                review_status="Pending Analyst Review" if result["quarantined"] else "Unreviewed",
                created_by=current_user.id,
            )
            db.session.add(analysis)
            db.session.commit()
            audit_event(
                "Email analysed",
                f"{filename}: {result['classification']} ({result['risk_score']}%)",
                "WARNING" if result["quarantined"] else "INFO",
            )
            return redirect(url_for("analysis_result", analysis_id=analysis.id))

        return render_template("analyze.html")

    @app.route("/analysis/<int:analysis_id>")
    @login_required
    def analysis_result(analysis_id):
        analysis = db.session.get(Analysis, analysis_id)
        if not analysis:
            abort(404)
        if current_user.role != "analyst" and analysis.created_by != current_user.id:
            abort(403)
        return render_template(
            "result.html",
            analysis=analysis,
            indicators=json.loads(analysis.indicators_json or "[]"),
            urls=json.loads(analysis.urls_json or "[]"),
            attachments=json.loads(analysis.attachments_json or "[]"),
        )

    @app.route("/history")
    @login_required
    def history():
        query = Analysis.query if current_user.role == "analyst" else Analysis.query.filter_by(created_by=current_user.id)
        analyses = query.order_by(Analysis.created_at.desc()).all()
        return render_template("history.html", analyses=analyses)

    @app.route("/quarantine")
    @login_required
    @analyst_required
    def quarantine():
        analyses = Analysis.query.filter_by(quarantined=True).order_by(Analysis.created_at.desc()).all()
        return render_template("quarantine.html", analyses=analyses)

    @app.route("/review/<int:analysis_id>/<action>", methods=["POST"])
    @login_required
    @analyst_required
    def review(analysis_id, action):
        analysis = db.session.get(Analysis, analysis_id)
        if not analysis:
            abort(404)
        mapping = {
            "confirm": ("Confirmed Phishing", True),
            "false-positive": ("False Positive", False),
            "release": ("Released", False),
        }
        if action not in mapping:
            abort(400)
        status, quarantined = mapping[action]
        analysis.review_status = status
        analysis.quarantined = quarantined
        db.session.commit()
        audit_event("Analyst review", f"Analysis #{analysis.id}: {status}", "INFO")
        flash(f"Analysis #{analysis.id} marked as {status}.", "success")
        return redirect(url_for("quarantine"))

    @app.route("/audit")
    @login_required
    @analyst_required
    def audit_logs():
        logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(100).all()
        return render_template("audit.html", logs=logs)

    def _export_query():
        if current_user.role == "analyst":
            return Analysis.query.order_by(Analysis.created_at.desc()).all()
        return Analysis.query.filter_by(created_by=current_user.id).order_by(Analysis.created_at.desc()).all()

    @app.route("/export/csv")
    @login_required
    def export_csv():
        rows = _export_query()
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["ID", "Date", "Filename", "Sender", "Subject", "Risk Score", "Classification", "ML Probability", "SPF", "DKIM", "DMARC", "Review Status"])
        for a in rows:
            writer.writerow([a.id, a.created_at.isoformat(), a.filename, a.sender, a.subject, a.risk_score, a.classification, a.ml_probability, a.spf, a.dkim, a.dmarc, a.review_status])
        audit_event("Report export", "CSV analysis report exported")
        return send_file(io.BytesIO(output.getvalue().encode("utf-8")), mimetype="text/csv", as_attachment=True, download_name="phishing-analysis-report.csv")

    @app.route("/export/json")
    @login_required
    def export_json():
        rows = _export_query()
        payload = [
            {
                "id": a.id,
                "date": a.created_at.isoformat(),
                "filename": a.filename,
                "sender": a.sender,
                "subject": a.subject,
                "risk_score": a.risk_score,
                "classification": a.classification,
                "ml_probability": a.ml_probability,
                "indicators": json.loads(a.indicators_json or "[]"),
                "review_status": a.review_status,
            }
            for a in rows
        ]
        audit_event("Report export", "JSON analysis report exported")
        data = json.dumps(payload, indent=2).encode("utf-8")
        return send_file(io.BytesIO(data), mimetype="application/json", as_attachment=True, download_name="phishing-analysis-report.json")

    @app.route("/export/pdf")
    @login_required
    def export_pdf():
        rows = _export_query()
        buffer = io.BytesIO()
        pdf = canvas.Canvas(buffer, pagesize=A4)
        width, height = A4
        y = height - 50
        pdf.setFont("Helvetica-Bold", 16)
        pdf.drawString(50, y, "ICT932 Phishing Email Detector Report")
        y -= 28
        pdf.setFont("Helvetica", 9)
        for a in rows:
            lines = [
                f"Analysis #{a.id} | {a.created_at.strftime('%Y-%m-%d %H:%M')} | {a.classification} | Risk {a.risk_score}%",
                f"File: {a.filename} | Sender: {a.sender[:70]}",
                f"SPF: {a.spf} | DKIM: {a.dkim} | DMARC: {a.dmarc} | Review: {a.review_status}",
            ]
            for line in lines:
                if y < 60:
                    pdf.showPage(); pdf.setFont("Helvetica", 9); y = height - 50
                pdf.drawString(50, y, line[:120]); y -= 14
            y -= 8
        pdf.save()
        buffer.seek(0)
        audit_event("Report export", "PDF analysis report exported")
        return send_file(buffer, mimetype="application/pdf", as_attachment=True, download_name="phishing-analysis-report.pdf")

    @app.errorhandler(403)
    def forbidden(_error):
        return render_template("403.html"), 403

    @app.errorhandler(413)
    def too_large(_error):
        try:
            audit_event("Zero Trust upload blocked", "Upload exceeded configured 1 MB limit", "WARNING")
        except Exception:
            pass
        return render_template("error.html", title="Upload blocked", message="The file exceeds the 1 MB upload limit."), 413

    @app.errorhandler(400)
    def bad_request(error):
        return render_template("error.html", title="Request blocked", message=getattr(error, "description", "Invalid request.")), 400

    return app
