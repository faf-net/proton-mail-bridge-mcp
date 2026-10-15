"""Smoke-Test: verbindet sich mit der Bridge, listet Ordner und die
letzten Mails mit Anzahl Anhänge. Bestätigt, dass der Lese-Pfad steht.

Aufruf:  uv run proton-check
"""

from __future__ import annotations

import sys

from proton_mail.config import ImapConfig
from proton_mail.imap_client import ProtonMailReader
from proton_mail.message import parse_email


def _force_utf8_console() -> None:
    """Windows-Konsole ist oft cp1252 und scheitert an Umlauten/✓."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def main() -> int:
    _force_utf8_console()
    try:
        config = ImapConfig.from_env()
    except RuntimeError as exc:
        print(f"[Konfig-Fehler] {exc}", file=sys.stderr)
        return 2

    print(f"Verbinde mit {config.host}:{config.port} als {config.user} ...")
    try:
        with ProtonMailReader(config) as reader:
            mailboxes = reader.list_mailboxes()
            print(f"\nOK — {len(mailboxes)} Ordner gefunden:")
            for name in mailboxes:
                print(f"  - {name}")

            print("\nLetzte 5 Mails in INBOX:")
            uids = reader.search(mailbox="INBOX", limit=5)
            if not uids:
                print("  (Postfach leer)")
            for uid in uids:
                email = parse_email(uid, reader.fetch_raw(uid, "INBOX"))
                n = len(email.attachments)
                marker = f" [{n} Anhang/Anhänge]" if n else ""
                print(f"  - UID {uid}: {email.subject!r} von {email.from_}{marker}")
                for att in email.attachments:
                    print(f"        * {att.filename} ({att.content_type}, {att.size} B)")
    except Exception as exc:  # noqa: BLE001 — Smoke-Test: jede Ursache anzeigen
        print(f"\n[Verbindungsfehler] {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    print("\nLese-Pfad steht. ✓")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
