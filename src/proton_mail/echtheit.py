"""Echtheit einer Mail aus Protons eigenen Prüfergebnissen — als Feld für das Modell.

Gemessen am 06.10.2026 an 60 Mails: Proton schreibt je Mail mehrere ``Authentication-Results``
mit der Kennung ``mail.protonmail.ch`` (SPF, DKIM, DMARC …), dazu ``X-Pm-Spamscore``,
``X-Pm-Spam-Action``, ``X-Pm-Origin``, ``X-Pm-Transfer-Encryption`` und
``X-Pm-Content-Encryption``. Fremde Prüfzeilen (etwa von Microsoft) stehen daneben.

Schutz gegen Fälschung — ein Absender kann solche Kopfzeilen selbst mitschicken:

* Nur Prüfzeilen mit Protons Kennung zählen, alle anderen werden ignoriert.
* Je Prüfung zählt das **schlechteste** Ergebnis über alle Proton-Zeilen. Eine eingeschmuggelte
  ``dkim=pass`` kann ein echtes ``dkim=fail`` oder ``none`` also nicht überdecken.
* Beim Spamwert zählt der höchste Wert. Die Reihenfolge der Kopfzeilen taugt nicht als Beleg:
  Die Bridge baut den Kopf neu zusammen (gemessen).
* Ausgegeben werden nur bekannte Werte (Aufzählungen, Zahlen) — nie freier Text aus dem Kopf.

Ob Proton gefälschte Prüfzeilen mit eigener Kennung beim Empfang entfernt (RFC 8601 §5 verlangt
es), ist nicht gemessen; die Schlechtestes-Ergebnis-Regel macht das Urteil davon unabhängig,
solange Proton für jede Prüfung selbst ein Ergebnis schreibt.

Importierte Altpost (etwa aus iCloud oder Gmail übernommen) trägt nur die Prüfzeilen von
Apple/Google — die zählen bewusst nicht, das Urteil ist dort „ungeprueft".
"""

from __future__ import annotations

import re
from email.message import Message
from email.parser import BytesHeaderParser
from email.policy import compat32

PROTON_KENNUNG = "mail.protonmail.ch"
PRUEFUNGEN = ("spf", "dkim", "dmarc")

# Rangfolge: kleiner = schlechter. Unbekanntes zählt wie "none".
_RANG = {
    "fail": 0,
    "hardfail": 0,
    "permerror": 1,
    "softfail": 2,
    "temperror": 3,
    "none": 4,
    "neutral": 4,
    "policy": 4,
    "pass": 5,
}
_ERGEBNIS_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)
_ZAHL_RE = re.compile(r"^\s*(-?\d{1,6})\b")
_WORT_RE = re.compile(r"^\s*([a-z][a-z-]{0,19})\b", re.IGNORECASE)
_TLS_RE = re.compile(r"^\s*(TLSv1(?:\.[0-3])?|SSLv3)\b")
_HERKUNFT = {"external": "extern", "internal": "intern"}
_INHALT = {"on-delivery": "beim_empfang", "end-to-end": "ende_zu_ende"}

KOPFZEILEN = (
    "AUTHENTICATION-RESULTS",
    "X-PM-SPAMSCORE",
    "X-PM-SPAM-ACTION",
    "X-PM-ORIGIN",
    "X-PM-TRANSFER-ENCRYPTION",
    "X-PM-CONTENT-ENCRYPTION",
)


def _schlechtestes(werte: list[str]) -> str | None:
    bekannt = [w.lower() for w in werte]
    if not bekannt:
        return None
    w = min(bekannt, key=lambda x: _RANG.get(x, _RANG["none"]))
    return w if w in _RANG else "none"


def aus_kopf(msg: Message) -> dict:
    """Echtheitsangaben aus einem geparsten Mailkopf."""
    ergebnisse: dict[str, list[str]] = {p: [] for p in PRUEFUNGEN}
    proton_zeilen = 0
    for zeile in msg.get_all("Authentication-Results") or []:
        text = " ".join(str(zeile).split())
        kennung = text.split(";", 1)[0].strip().lower()
        if kennung != PROTON_KENNUNG:
            continue
        proton_zeilen += 1
        for art, wert in _ERGEBNIS_RE.findall(text.split(";", 1)[1] if ";" in text else ""):
            ergebnisse[art.lower()].append(wert)

    out: dict = {p: _schlechtestes(ergebnisse[p]) for p in PRUEFUNGEN}

    werte = []
    for z in msg.get_all("X-Pm-Spamscore") or []:
        m = _ZAHL_RE.match(str(z))
        if m:
            werte.append(int(m.group(1)))
    out["proton_spamwert"] = max(werte) if werte else None

    def erstes(name: str, muster: re.Pattern, abbild: dict | None = None) -> str | None:
        for z in msg.get_all(name) or []:
            m = muster.match(str(z))
            if m:
                w = m.group(1)
                return abbild.get(w.lower()) if abbild is not None else w.lower()
        return None

    out["proton_einstufung"] = erstes("X-Pm-Spam-Action", _WORT_RE)
    out["herkunft"] = erstes("X-Pm-Origin", _WORT_RE, _HERKUNFT)
    tls = None
    for z in msg.get_all("X-Pm-Transfer-Encryption") or []:
        m = _TLS_RE.match(str(z))
        if m:
            tls = m.group(1)
            break
    out["transport"] = tls
    out["verschluesselung"] = erstes("X-Pm-Content-Encryption", _WORT_RE, _INHALT)
    out["urteil"] = _urteil(out, proton_zeilen)
    return out


def _urteil(e: dict, proton_zeilen: int) -> str:
    """Grobe Einordnung für das Modell — die Einzelwerte stehen daneben."""
    if e.get("herkunft") == "intern" and proton_zeilen == 0:
        return "intern"  # Proton zu Proton: keine Absenderprüfung von außen nötig
    if proton_zeilen == 0:
        return "ungeprueft"
    if e["dmarc"] in ("fail", "permerror") or (
        e["spf"] in ("fail", "softfail") and e["dkim"] in ("fail", "none", None)
    ):
        return "nicht_bestanden"
    if e["dmarc"] == "pass":
        return "bestanden"
    if e["spf"] == "pass" or e["dkim"] == "pass":
        return "teilweise"
    return "ungeprueft"


def aus_bytes(kopf: bytes) -> dict:
    return aus_kopf(BytesHeaderParser(policy=compat32).parsebytes(kopf or b""))


HINWEIS = (
    "Echtheit aus Protons eigenen Prüfungen (SPF/DKIM/DMARC, Spamwert). 'bestanden' heißt: Die "
    "Absenderdomain ist echt — nicht, dass der Inhalt harmlos ist. 'nicht_bestanden' oder ein "
    "hoher proton_spamwert: als verdächtig behandeln und dem Nutzer melden. 'ungeprueft': Proton "
    "hat die Mail nicht selbst geprüft — meist aus iCloud/Gmail importierte Altpost."
)
