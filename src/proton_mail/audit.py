"""Abruf-Protokoll: eine JSON-Zeile je Tool-Aufruf — wer, was, wann, wie groß.

Beantwortet „was hat der Agent wann gelesen" und macht sichtbar, wenn ein Modell (etwa nach einer
präparierten Mail) ungewöhnlich sucht oder liest. Es steht **nie Mailinhalt** darin: keine
Betreffzeilen, Absender, Texte oder Dateinamen — nur Ordner und UID, über die sich die Mail bei
Bedarf selbst nachschlagen lässt.

Suchbegriffe stehen bewusst im Klartext (gekürzt auf 100 Zeichen): Gerade sie zeigen, ob ein
Modell nach „Passwort" oder „Kontoauszug" gesucht hat. Ein Hash wäre bei einzelnen Wörtern per
Wörterbuch ohnehin umkehrbar und würde nur den Nutzen nehmen.

Fehler beim Schreiben brechen den Tool-Aufruf nicht ab (fail-open), werden aber geloggt.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Any

_log = logging.getLogger("proton_mail.audit")
_log.propagate = False  # nie ins Container-Log doppeln
_fehler = logging.getLogger("proton_mail.mcp")

MAX_FELD = 100


def _jetzt() -> datetime:
    """Ortszeit Europe/Berlin mit Zonenangabe; ohne Zeitzonen-Datenbank (Windows) Systemzeit."""
    try:
        from zoneinfo import ZoneInfo

        return datetime.now(ZoneInfo("Europe/Berlin"))
    except Exception:  # noqa: BLE001 — ohne tzdata (Windows) Systemzeit
        return datetime.now().astimezone()


def einrichten(pfad: str | None, max_bytes: int = 5 * 1024 * 1024, backups: int = 5) -> bool:
    """Protokolldatei öffnen (rotierend, 5 × 5 MB). Liefert False, wenn aus oder nicht schreibbar."""
    for h in list(_log.handlers):
        _log.removeHandler(h)
        h.close()
    if not pfad:
        return False
    try:
        h = RotatingFileHandler(pfad, maxBytes=max_bytes, backupCount=backups, encoding="utf-8")
    except OSError as e:
        _fehler.warning("Abruf-Protokoll %s nicht schreibbar (%s) — läuft ohne.", pfad, e)
        return False
    h.setFormatter(logging.Formatter("%(message)s"))
    _log.addHandler(h)
    _log.setLevel(logging.INFO)
    return True


def aktiv() -> bool:
    return bool(_log.handlers)


def _kurz(wert: Any) -> Any:
    if isinstance(wert, str) and len(wert) > MAX_FELD:
        return wert[:MAX_FELD] + "…"
    return wert


@contextmanager
def aufruf(tool: str, token: str, **felder: Any) -> Iterator[dict]:
    """Rahmen um einen Tool-Aufruf. Der Aufrufer ergänzt Ergebniszahlen im gelieferten dict."""
    eintrag: dict[str, Any] = {
        "zeit": _jetzt().isoformat(timespec="seconds"),
        "token": token,
        "tool": tool,
    }
    eintrag.update({k: _kurz(v) for k, v in felder.items() if v is not None})
    ergebnis: dict[str, Any] = {}
    t0 = time.monotonic()
    try:
        yield ergebnis
        eintrag["status"] = "ok"
    except Exception as e:
        eintrag["status"] = "abgewiesen" if isinstance(e, PermissionError) else "fehler"
        eintrag["fehler"] = type(e).__name__
        raise
    finally:
        eintrag.update(ergebnis)
        eintrag["dauer_ms"] = round((time.monotonic() - t0) * 1000)
        if _log.handlers:
            try:
                _log.info(json.dumps(eintrag, ensure_ascii=False))
            except Exception as e:  # noqa: BLE001 — Protokoll darf den Aufruf nie kippen
                _fehler.warning("Abruf-Protokoll: Schreiben scheiterte (%s)", type(e).__name__)
