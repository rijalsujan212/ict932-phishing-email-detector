import hashlib
import re
from email import policy
from email.parser import BytesParser
from pathlib import Path


URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)
ALLOWED_EXTENSIONS = {".eml", ".txt"}
MAX_FILE_BYTES = 1 * 1024 * 1024


class EmailParseError(ValueError):
    pass


def _extract_text_from_message(message):
    if message.is_multipart():
        chunks = []
        for part in message.walk():
            content_type = part.get_content_type()
            disposition = (part.get("Content-Disposition") or "").lower()
            if content_type == "text/plain" and "attachment" not in disposition:
                try:
                    chunks.append(part.get_content())
                except Exception:
                    payload = part.get_payload(decode=True) or b""
                    chunks.append(payload.decode("utf-8", errors="ignore"))
        return "\n".join(chunks)
    try:
        return message.get_content()
    except Exception:
        payload = message.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="ignore")


def _attachments_metadata(message):
    attachments = []
    for part in message.iter_attachments():
        payload = part.get_payload(decode=True) or b""
        attachments.append(
            {
                "filename": part.get_filename() or "unnamed",
                "content_type": part.get_content_type(),
                "size_bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    return attachments


def parse_uploaded_email(filename, raw_bytes):
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise EmailParseError("Only .eml and .txt files are permitted.")
    if not raw_bytes:
        raise EmailParseError("The uploaded file is empty.")
    if len(raw_bytes) > MAX_FILE_BYTES:
        raise EmailParseError("File exceeds the 1 MB Zero Trust upload limit.")

    if suffix == ".txt":
        body = raw_bytes.decode("utf-8", errors="ignore")
        return {
            "subject": Path(filename).stem,
            "sender": "",
            "reply_to": "",
            "headers": {},
            "body": body,
            "urls": URL_RE.findall(body),
            "attachments": [],
        }

    try:
        message = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    except Exception as exc:
        raise EmailParseError(f"Unable to safely parse email: {exc}") from exc

    body = _extract_text_from_message(message)
    headers = {str(k): str(v) for k, v in message.items()}
    combined = body + "\n" + "\n".join(headers.values())

    return {
        "subject": str(message.get("Subject", "")),
        "sender": str(message.get("From", "")),
        "reply_to": str(message.get("Reply-To", "")),
        "headers": headers,
        "body": body,
        "urls": sorted(set(URL_RE.findall(combined))),
        "attachments": _attachments_metadata(message),
    }
