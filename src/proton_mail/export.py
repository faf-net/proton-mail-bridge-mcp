"""Export-Lauf: schreibt alle Mails + Anhänge strukturiert auf die Platte/NAS.

Ablage pro Mail in einem eigenen Ordner:

    <export_dir>/<YYYY>/<YYYY-MM-DD>_<betreff-slug>_<id>/
        metadata.json     # Absender, Betreff, Datum, Ordner/Label, Anhangsliste
        body.txt          # Text-Teil (falls vorhanden)
        body.html         # HTML-Teil (falls vorhanden)
        raw.eml           # vollständige Originalnachricht
        attachments/<dateiname>

Dedupliziert global über die Message-ID (Proton-Labels führen dieselbe Mail
in mehreren Ordnern). Idempotent: existiert der Zielordner schon, wird die
Mail übersprungen — ein erneuter Lauf holt nur Neues nach.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from dataclasses import dataclass
from datetime import datetime
from email.utils import parsedate_to_datetime
from pathlib import Path

from .imap_client import Email, ProtonMailReader
from .message import parse_email

# Proton: "All Mail" enthält jede Mail zusätzlich — beim Iterieren überspringen,
# der Inhalt kommt über die echten Ordner/Labels. Virtuelle Ordner ebenso.
SKIP_FOLDERS = {"All Mail", "Labels", "Folders"}

_SLUG_RE = re.compile(r"[^\w\-]+", re.UNICODE)
_WIN_RESERVED = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


def _slug(text: str, max_len: int = 60) -> str:
    text = _SLUG_RE.sub("-", text.strip()).strip("-")
    return text[:max_len] or "ohne-betreff"


def safe_filename(name: str, fallback: str = "datei", max_len: int = 200) -> str:
    """Dateinamen für Windows UND Linux entschärfen und längenbegrenzen.

    Dateisysteme limitieren Namen meist auf 255 Bytes; überlange Anhang-Namen
    würden sonst beim Schreiben scheitern. Endung nach Möglichkeit erhalten.
    """
    name = _WIN_RESERVED.sub("_", name).strip(" .")
    if not name:
        return fallback
    if len(name) > max_len:
        stem, dot, ext = name.rpartition(".")
        if dot and 0 < len(ext) <= 20:
            name = stem[: max_len - len(ext) - 1] + "." + ext
        else:
            name = name[:max_len]
    return name


def _msg_id_hash(email: Email) -> str:
    basis = email.message_id or f"{email.from_}|{email.subject}|{email.date}"
    return hashlib.sha1(basis.encode("utf-8", "replace")).hexdigest()[:10]


def _parsed_date(email: Email) -> datetime | None:
    if not email.date:
        return None
    try:
        return parsedate_to_datetime(email.date)
    except (TypeError, ValueError):
        return None


@dataclass
class ExportStats:
    folders: int = 0
    seen: int = 0
    written: int = 0
    skipped_existing: int = 0
    duplicates: int = 0
    attachments: int = 0
    errors: int = 0


def _entry_dir(export_dir: Path, email: Email) -> Path:
    dt = _parsed_date(email)
    year = dt.strftime("%Y") if dt else "ohne-datum"
    day = dt.strftime("%Y-%m-%d") if dt else "0000-00-00"
    name = f"{day}_{_slug(email.subject)}_{_msg_id_hash(email)}"
    return export_dir / year / name


def _write_attachments(entry: Path, email: Email) -> int:
    if not email.attachments:
        return 0
    att_dir = entry / "attachments"
    att_dir.mkdir(parents=True, exist_ok=True)
    used: set[str] = set()
    count = 0
    for att in email.attachments:
        fname = safe_filename(att.filename)
        # Namenskollisionen innerhalb einer Mail auflösen.
        candidate = fname
        i = 1
        while candidate in used:
            stem, dot, ext = fname.partition(".")
            candidate = f"{stem}_{i}{dot}{ext}"
            i += 1
        used.add(candidate)
        (att_dir / candidate).write_bytes(att.content)
        count += 1
    return count


def _write_entry(entry: Path, email: Email, raw: bytes, folder: str) -> int:
    entry.mkdir(parents=True, exist_ok=True)
    (entry / "raw.eml").write_bytes(raw)
    if email.text_body:
        (entry / "body.txt").write_text(email.text_body, encoding="utf-8")
    if email.html_body:
        (entry / "body.html").write_text(email.html_body, encoding="utf-8")

    metadata = {
        "message_id": email.message_id,
        "subject": email.subject,
        "from": email.from_,
        "to": email.to,
        "date": email.date,
        "folder": folder,
        "uid": email.uid,
        "attachments": [
            {"filename": a.filename, "content_type": a.content_type, "size": a.size}
            for a in email.attachments
        ],
    }
    (entry / "metadata.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return _write_attachments(entry, email)


def export_all(
    reader: ProtonMailReader,
    export_dir: Path,
    *,
    folders: list[str] | None = None,
    progress=print,
) -> ExportStats:
    """Alle (oder ausgewählte) Ordner exportieren. Gibt eine Statistik zurück."""
    export_dir.mkdir(parents=True, exist_ok=True)
    stats = ExportStats()
    seen_ids: set[str] = set()

    targets = folders if folders is not None else reader.list_mailboxes()
    for folder in targets:
        if folders is None and folder in SKIP_FOLDERS:
            continue
        stats.folders += 1
        uids = reader.search(mailbox=folder, limit=10_000_000)
        progress(f"[{folder}] {len(uids)} Mails")
        for uid in uids:
            stats.seen += 1
            tmp = None
            try:
                raw = reader.fetch_raw(uid, folder)
                email = parse_email(uid, raw)

                dedup_key = email.message_id or _msg_id_hash(email)
                if dedup_key in seen_ids:
                    stats.duplicates += 1
                    continue
                seen_ids.add(dedup_key)

                entry = _entry_dir(export_dir, email)
                if entry.exists():
                    stats.skipped_existing += 1
                    continue

                # In Temp-Ordner schreiben und erst nach Vollständigkeit umbenennen.
                # So bleibt ein abgebrochener Lauf nicht als halbe (aber "vorhandene")
                # Mail liegen, die danach für immer übersprungen würde.
                tmp = entry.parent / (entry.name + ".partial")
                if tmp.exists():
                    shutil.rmtree(tmp, ignore_errors=True)
                stats.attachments += _write_entry(tmp, email, raw, folder)
                tmp.rename(entry)
                stats.written += 1
            except Exception as exc:  # noqa: BLE001 — ein Ausreißer darf den Lauf nicht abbrechen
                stats.errors += 1
                progress(f"  [Fehler] {folder} UID {uid}: {type(exc).__name__}: {exc}")
                if tmp is not None and tmp.exists():
                    shutil.rmtree(tmp, ignore_errors=True)

    return stats
