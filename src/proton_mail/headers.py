"""Gemeinsames RFC-2047-Header-Decoding.

Von message.py (RFC822-Parsing) und imap_client.py (ENVELOPE-Felder) genutzt.
Eigenes Modul, um einen Zirkelimport zwischen beiden zu vermeiden.
"""

from __future__ import annotations

import re
from email.header import decode_header, make_header

_SURROGAT_RE = re.compile("[\ud800-\udfff]")


def bytes_lesen(roh: bytes) -> str:
    """Bytes unbekannter Kodierung lesbar machen: erst UTF-8, sonst Windows-1252.

    8-Bit-Kopfzeilen ohne RFC 2047 und falsch erklärte Zeichensätze sind in der Praxis
    fast immer eins von beiden; Windows-1252 deckt Latin-1 mit ab (plus € und „“).
    """
    try:
        return roh.decode("utf-8")
    except UnicodeDecodeError:
        return roh.decode("cp1252", "replace")


def ohne_surrogate(text: str) -> str:
    """Einzelne Surrogate entfernen, damit der Text als UTF-8 kodierbar bleibt.

    Die email-Stdlib legt nicht dekodierbare Kopf-Bytes per ``surrogateescape`` als
    ``\\udc80``–``\\udcff`` ab — die werden zurück in Bytes gewandelt und gelesen. Andere
    Surrogate (z. B. aus HTML-Entities oder exotischen Codecs) werden zu U+FFFD. Ohne das
    scheitert erst die JSON-/HTTP-Ausgabe, weit weg von der Ursache.
    """
    if not _SURROGAT_RE.search(text):
        return text
    try:
        return bytes_lesen(text.encode("utf-8", "surrogateescape"))
    except UnicodeEncodeError:
        return _SURROGAT_RE.sub("�", text)


def decode_mime_header(value: object) -> str:
    """RFC-2047-kodierte Header (Umlaute etc.) zu lesbarem Text dekodieren.

    Akzeptiert str (aus der email-Stdlib, auch mit surrogateescape), bytes (aus
    IMAP-ENVELOPE) oder ein ``email.header.Header``. Wirft nie; das Ergebnis ist
    immer als UTF-8 kodierbar.
    """
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = bytes_lesen(value)
    value = ohne_surrogate(str(value))
    try:
        return ohne_surrogate(str(make_header(decode_header(value))))
    except Exception:  # noqa: BLE001 — kaputte Kodierung → Rückfall statt Absturz
        return value
