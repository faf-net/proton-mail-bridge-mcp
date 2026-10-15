"""CLI für den Export-Lauf.

Aufruf:
    uv run python -m proton_mail.scripts.export_mail
    uv run python -m proton_mail.scripts.export_mail --folder INBOX --folder Archive
"""

from __future__ import annotations

import argparse
import sys

from proton_mail.config import ExportConfig, ImapConfig
from proton_mail.export import export_all
from proton_mail.imap_client import ProtonMailReader


def _force_utf8_console() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def main(argv: list[str] | None = None) -> int:
    _force_utf8_console()
    parser = argparse.ArgumentParser(description="Proton-Mail Export auf die Platte/NAS.")
    parser.add_argument(
        "--folder",
        action="append",
        dest="folders",
        help="Nur diese(n) Ordner exportieren (mehrfach möglich). Default: alle.",
    )
    args = parser.parse_args(argv)

    try:
        imap = ImapConfig.from_env()
        export = ExportConfig.from_env()
    except RuntimeError as exc:
        print(f"[Konfig-Fehler] {exc}", file=sys.stderr)
        return 2

    print(f"Export nach: {export.export_dir.resolve()}")
    try:
        with ProtonMailReader(imap) as reader:
            stats = export_all(reader, export.export_dir, folders=args.folders)
    except Exception as exc:  # noqa: BLE001
        print(f"\n[Fehler] {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    print(
        f"\nFertig. Ordner: {stats.folders} | gesehen: {stats.seen} | "
        f"geschrieben: {stats.written} | übersprungen (bereits da): {stats.skipped_existing} | "
        f"Duplikate (Label-Overlap): {stats.duplicates} | Anhänge: {stats.attachments} | "
        f"Fehler: {stats.errors}"
    )
    return 1 if stats.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
