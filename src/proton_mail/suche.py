"""Suche, die auch für deutsche Mails funktioniert — grob beim Server, genau beim Client.

Gemessen am 06.10.2026: Die Proton Bridge vergleicht SEARCH-Begriffe mit dem **noch kodierten**
Header bzw. Text (RFC 2047, Quoted-Printable, Base64). Im Betreff
``=?utf-8?q?Ihre_Bestellung_2026-48211_=E2=80=93_Best=C3=A4tigung?=`` findet sie deshalb weder
``"Ihre Bestellung"`` (Leerzeichen steht als ``_``) noch ``"Bestätigung"`` (Umlaut als ``=C3=A4``),
wohl aber ``"Ihre_Bestellung"``. Base64-kodierte Betreffe und Texte findet sie gar nicht.

Deshalb:

1. Kandidaten = die neuesten N Mails des Ordners (nach ``SINCE``), dazu für ältere Mails die
   Server-Treffer für das längste reine ASCII-Wort jedes Begriffs (findet die Bridge zuverlässig,
   solange der Header nicht Base64-kodiert ist).
2. Jeden Kandidaten — neueste zuerst — gegen den **dekodierten** Betreff/Absender/Empfänger
   (ENVELOPE) und, falls gefragt, den dekodierten Text (Anfang der Mail, ohne Anhänge) prüfen.
   Vergleich ohne Groß/klein, Unicode-normalisiert (``ß`` = ``ss``), Leerraum zusammengezogen.
3. Aufhören, sobald ``limit`` Treffer da sind.

Die Bridge liefert lokal schnell (gemessen: 1.000 ENVELOPEs 0,16 s, 300 Texte à 128 KB 0,3 s);
die Fenster sind danach bemessen.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date
from email import message_from_bytes
from typing import Any

from .headers import decode_mime_header

# Neueste N Mails, die immer vollständig geprüft werden.
FENSTER_KOPF = 25_000  # nur Betreff/Absender/Empfänger (ENVELOPE, billig)
FENSTER_TEXT = 3_000  # mit Mailtext (Teilabruf, teurer)
STAPEL_KOPF = 500
STAPEL_TEXT = 100
TEXT_BYTES = 131_072  # so viel vom Mailtext wird je Mail geprüft (Anhänge liegen meist dahinter)

_WS = re.compile(r"\s+")
_ASCII_WORT = re.compile(r"[A-Za-z0-9]{3,}")


ALLE_MAILS = "All Mail"  # Proton-Bridge-Ordner mit jeder Mail (auch Gesendetes)
_MSGID_RE = re.compile(r"<[^<>\s]+>")


@dataclass
class Ergebnis:
    uids: list[int]
    durchsucht: int  # wie viele Mails genau geprüft wurden
    ordner_ganz: bool  # True: jede Mail des Ordners (bzw. seit since_date) war Kandidat
    weitere: bool = False  # bei limit abgebrochen — mit vor_uid = letzter UID weiterblättern
    uidvalidity: int | None = None  # ändert sich, wenn die Bridge den Ordner neu aufbaut


def normalisieren(text: str | None) -> str:
    """Für den Vergleich: NFKC, ohne unsichtbare Zeichen, casefold (ß → ss), Leerraum zu einem."""
    if not text:
        return ""
    t = unicodedata.normalize("NFKC", text)
    t = "".join(ch for ch in t if unicodedata.category(ch) != "Cf")
    return _WS.sub(" ", t.casefold()).strip()


def server_wort(begriff: str) -> str | None:
    """Längstes reines ASCII-Wort (≥ 3 Zeichen) — das findet die Bridge auch im kodierten Header."""
    woerter = _ASCII_WORT.findall(begriff or "")
    return max(woerter, key=len) if woerter else None


def _adressen(addrs: Any) -> str:
    teile = []
    for a in addrs or ():
        name = decode_mime_header(getattr(a, "name", None))
        mb = getattr(a, "mailbox", b"") or b""
        host = getattr(a, "host", b"") or b""
        mb = mb.decode("utf-8", "replace") if isinstance(mb, bytes) else str(mb)
        host = host.decode("utf-8", "replace") if isinstance(host, bytes) else str(host)
        teile.append(f"{name} <{mb}@{host}>" if host else f"{name} {mb}")
    return " ".join(teile)


def text_aus_teilabruf(kopf: bytes, text: bytes) -> str:
    """Lesbaren Mailtext aus Header + (abgeschnittenem) Body gewinnen — tolerant gegen Kaputtes."""
    from .message import html_to_text

    try:
        msg = message_from_bytes((kopf or b"") + (text or b""))
    except Exception:  # noqa: BLE001 — kaputte Mail → Rohtext
        return (text or b"").decode("utf-8", "replace")
    teile: list[str] = []
    for part in msg.walk() if msg.is_multipart() else [msg]:
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        typ = part.get_content_type()
        if typ not in ("text/plain", "text/html"):
            continue
        try:
            roh = part.get_payload(decode=True) or b""
            inhalt = roh.decode(part.get_content_charset() or "utf-8", "replace")
        except Exception:  # noqa: BLE001, S112 — ein kaputter Teil darf die Suche nicht kippen
            continue
        teile.append(html_to_text(inhalt) if typ == "text/html" else inhalt)
    return "\n".join(teile)


def _stapel(seq: list[int], n: int) -> Iterable[list[int]]:
    for i in range(0, len(seq), n):
        yield seq[i : i + n]


def finde(
    conn: Any,
    *,
    subject: str | None = None,
    from_: str | None = None,
    to: str | None = None,
    body: str | None = None,
    text: str | None = None,
    since_date: date | None = None,
    before_date: date | None = None,
    vor_uid: int | None = None,
    limit: int = 50,
    fenster_kopf: int = FENSTER_KOPF,
    fenster_text: int = FENSTER_TEXT,
) -> Ergebnis:
    """Robuste Suche im bereits gewählten Ordner (``conn`` = imapclient, Ordner per EXAMINE offen).

    Liefert UIDs neueste zuerst, höchstens ``limit``. ``before_date`` = nur Mails vor diesem Tag
    (IMAP BEFORE, exklusiv). ``vor_uid`` = nur UIDs kleiner als dieser Wert (Blättern: die letzte
    UID der vorigen Seite übergeben)."""
    datum: list = []
    if since_date is not None:
        datum += ["SINCE", since_date]
    if before_date is not None:
        datum += ["BEFORE", before_date]
    alle = sorted(conn.search(datum or ["ALL"]), reverse=True)
    if vor_uid is not None:
        alle = [u for u in alle if u < vor_uid]
    kopf = {k: normalisieren(v) for k, v in (("subject", subject), ("from", from_), ("to", to))}
    kopf = {k: v for k, v in kopf.items() if v}
    body_n, text_n = normalisieren(body), normalisieren(text)

    if not kopf and not body_n and not text_n:
        n = max(limit, 0)
        return Ergebnis(alle[:n], 0, True, weitere=len(alle) > n)

    braucht_text = bool(body_n or text_n)
    fenster = fenster_text if braucht_text else fenster_kopf
    kandidaten = alle[:fenster]
    ordner_ganz = len(alle) <= fenster

    treffer: list[int] = []
    durchsucht = 0

    def pruefen(uids: list[int]) -> None:
        nonlocal durchsucht
        for teil in _stapel(uids, STAPEL_TEXT if braucht_text else STAPEL_KOPF):
            if len(treffer) >= limit:
                return
            uebrig = teil
            koepfe: dict[int, str] = {}
            if kopf or text_n:
                daten = conn.fetch(teil, ["ENVELOPE"])
                uebrig = []
                for uid in teil:
                    env = (daten.get(uid) or {}).get(b"ENVELOPE")
                    felder = {
                        "subject": normalisieren(decode_mime_header(getattr(env, "subject", None))),
                        "from": normalisieren(_adressen(getattr(env, "from_", None))),
                        "to": normalisieren(_adressen(getattr(env, "to", None))),
                    }
                    if all(v in felder[k] for k, v in kopf.items()):
                        uebrig.append(uid)
                        koepfe[uid] = " ".join(felder.values())
            if braucht_text and uebrig:
                daten = conn.fetch(
                    uebrig, ["BODY.PEEK[HEADER]", f"BODY.PEEK[TEXT]<0.{TEXT_BYTES}>"]
                )
                passend = []
                for uid in uebrig:
                    d = daten.get(uid) or {}
                    inhalt = normalisieren(
                        text_aus_teilabruf(
                            d.get(b"BODY[HEADER]", b""), d.get(b"BODY[TEXT]<0>", b"")
                        )
                    )
                    if body_n and body_n not in inhalt:
                        continue
                    if text_n and text_n not in inhalt and text_n not in koepfe.get(uid, ""):
                        continue
                    passend.append(uid)
                uebrig = passend
            durchsucht += len(teil)
            treffer.extend(uebrig)

    # 1. Die neuesten Mails vollständig prüfen (billig, findet auch Base64-Kodiertes).
    pruefen(kandidaten)

    # 2. Erst wenn das nicht reicht: ältere Mails über die Bridge grob vorfiltern. Das ist teuer
    #    (gemessen auf 101.000 Mails: SUBJECT 18 s, BODY 42 s), deshalb nur bei Bedarf.
    #    Base64-kodierte Betreffe/Texte jenseits des Fensters bleiben dabei unsichtbar.
    if len(treffer) < limit and not ordner_ganz:
        kriterien: list = list(datum)
        hat_wort = False
        for schluessel, wert in (
            ("SUBJECT", subject),
            ("FROM", from_),
            ("TO", to),
            ("BODY", body),
            ("TEXT", text),
        ):
            wort = server_wort(wert) if wert else None
            if wort:
                kriterien += [schluessel, wort]
                hat_wort = True
        if hat_wort:
            schon = set(kandidaten)
            aeltere = (
                u
                for u in conn.search(kriterien)
                if u not in schon and (vor_uid is None or u < vor_uid)
            )
            pruefen(sorted(aeltere, reverse=True))

    n = max(limit, 0)
    return Ergebnis(treffer[:n], durchsucht, ordner_ganz, weitere=len(treffer) >= n > 0)


def message_ids(wert: Any) -> list[str]:
    """Alle <message-id> aus einem Header- oder ENVELOPE-Wert (bytes/str/None)."""
    if not wert:
        return []
    if isinstance(wert, bytes):
        wert = wert.decode("utf-8", "replace")
    return _MSGID_RE.findall(str(wert))


def unterhaltung(
    conn: Any, start_ids: set[str], fenster: int = FENSTER_KOPF, limit: int = 100
) -> Ergebnis:
    """Mails einer Unterhaltung im gewählten Ordner (gedacht: „All Mail").

    Verfolgt Message-ID und In-Reply-To über die ENVELOPEs der neuesten ``fenster`` Mails:
    Vorgänger über die References der Startmail (stehen in ``start_ids``), Antworten über
    In-Reply-To, das auf eine bekannte ID zeigt. Liefert UIDs, älteste zuerst."""
    alle = sorted(conn.search(["ALL"]), reverse=True)
    kandidaten = alle[:fenster]
    eintraege: list[tuple[int, list[str], list[str]]] = []
    for teil in _stapel(kandidaten, STAPEL_KOPF):
        daten = conn.fetch(teil, ["ENVELOPE"])
        for uid in teil:
            env = (daten.get(uid) or {}).get(b"ENVELOPE")
            if env is None:
                continue
            eigene = message_ids(getattr(env, "message_id", None))
            bezug = message_ids(getattr(env, "in_reply_to", None))
            if eigene or bezug:
                eintraege.append((uid, eigene, bezug))
    bekannt = set(start_ids)
    drin: set[int] = set()
    geaendert = True
    while geaendert and len(drin) < limit:
        geaendert = False
        for uid, eigene, bezug in eintraege:
            if uid in drin:
                continue
            if bekannt.intersection(eigene) or bekannt.intersection(bezug):
                drin.add(uid)
                bekannt.update(eigene)
                geaendert = True
    return Ergebnis(sorted(drin)[:limit], len(kandidaten), len(alle) <= fenster)
