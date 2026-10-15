"""Alle PDF-Anhänge aus Mails von/an die Scanner-Adresse (SCANNER_ADDR) sichern.

Quellen: Archive, INBOX, Folders/RECHNUNGEN, Folders/STEUER. Keine Klassifikation
— einfach jeden PDF-Anhang dieser Mails in einen eigenen Ordner ablegen,
dedupliziert (gleiche Datei nur einmal) + index.csv mit Herkunft/Richtung.
"""

from __future__ import annotations

import csv
import hashlib
import os
import re
import sys
from datetime import datetime
from email.utils import parsedate_to_datetime
from pathlib import Path

from .config import ImapConfig
from .imap_client import ProtonMailReader
from .message import parse_email

# Aus der Umgebung (docker/.env) — die Adresse gehört nicht ins Repo.
ADDR = os.getenv("SCANNER_ADDR", "")
FOLDERS = ["Archive", "INBOX", "Folders/RECHNUNGEN", "Folders/STEUER"]
OUT = Path(os.getenv("EXPORT_DIR", "/export")) / "scanner-pdfs"


def _safe(name: str, maxlen: int = 80) -> str:
    name = re.sub(r"[<>:\"/\\|?*\x00-\x1f]", "_", name)
    return re.sub(r"\s+", " ", name).strip(" ._")[:maxlen] or "datei.pdf"


def _datestr(raw: str) -> str:
    try:
        return parsedate_to_datetime(raw).strftime("%Y%m%d")
    except (TypeError, ValueError):
        return "00000000"


def main() -> int:
    if not ADDR:
        sys.exit("SCANNER_ADDR fehlt (Adresse des Scanners, in docker/.env).")
    for s in (sys.stdout, sys.stderr):
        if hasattr(s, "reconfigure"):
            s.reconfigure(encoding="utf-8", errors="replace")
    OUT.mkdir(parents=True, exist_ok=True)
    seen_hash: set[str] = set()
    used: set[str] = set()
    rows = []
    mails = pdfs = written = 0

    with ProtonMailReader(ImapConfig.from_env()) as reader:
        for folder in FOLDERS:
            cand: dict[int, str] = {}
            for field, direction in (("from_", "von"), ("to", "an")):
                try:
                    uids = reader.search(mailbox=folder, **{field: ADDR}, limit=10_000_000)
                except Exception as exc:  # noqa: BLE001 — Bulk-Lauf: Mail überspringen, weiter
                    print(f"  [Warnung] Suche {folder} ({direction}): {exc}", flush=True)
                    continue
                for uid in uids:
                    cand[uid] = direction if uid not in cand else "von+an"
            print(f"  [{folder}] {len(cand)} Mail(s) von/an {ADDR}", flush=True)
            for uid, direction in cand.items():
                mails += 1
                try:
                    email = parse_email(uid, reader.fetch_raw(uid, folder))
                except Exception as exc:  # noqa: BLE001 — Bulk-Lauf: Mail überspringen, weiter
                    print(f"  [Fehler] {folder} UID {uid}: {exc}", flush=True)
                    continue
                ds = _datestr(email.date)
                for att in email.attachments:
                    if att.content_type != "application/pdf" and not att.filename.lower().endswith(
                        ".pdf"
                    ):
                        continue
                    pdfs += 1
                    h = hashlib.sha1(att.content).hexdigest()
                    if h in seen_hash:
                        continue
                    seen_hash.add(h)
                    base = f"{ds}_{_safe(att.filename)}"
                    if not base.lower().endswith(".pdf"):
                        base += ".pdf"
                    fname, i = base, 2
                    while fname in used:
                        stem = base[:-4]
                        fname = f"{stem}_{i}.pdf"
                        i += 1
                    used.add(fname)
                    (OUT / fname).write_bytes(att.content)
                    written += 1
                    rows.append(
                        {
                            "datei": fname,
                            "richtung": direction,
                            "ordner": folder,
                            "datum": email.date,
                            "von": email.from_,
                            "an": email.to,
                            "betreff": email.subject,
                            "original": att.filename,
                            "groesse": att.size,
                        }
                    )
                    print(f"  ✓ {fname}  [{direction}, {folder}]", flush=True)

    cols = ["datei", "richtung", "ordner", "datum", "von", "an", "betreff", "original", "groesse"]
    with open(OUT / "index.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    summary = (
        f"{ADDR} PDF-Sicherung — Quellen: {', '.join(FOLDERS)}\n"
        f"Mails von/an scanner: {mails} | PDF-Anhänge: {pdfs} | "
        f"geschrieben (dedupliziert): {written}\n"
        f"Erstellt: {datetime.now().astimezone().isoformat(timespec='seconds')}\n"
    )
    (OUT / "_summary.txt").write_text(summary, encoding="utf-8")
    print("\n" + summary, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
