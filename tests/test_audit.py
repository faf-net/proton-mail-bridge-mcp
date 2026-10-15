"""Abruf-Protokoll: eine Zeile je Aufruf, nie Mailinhalt, Fehler und Abweisungen sichtbar."""

import asyncio
import json
from email.message import EmailMessage

import pytest
from mcp.server.auth.provider import AccessToken

from proton_mail import audit, mcp_server

GEHEIM_BETREFF = "Kontoauszug Sparkasse 4711"
GEHEIM_TEXT = "Ihr Kontostand beträgt 12.345,67 EUR"
GEHEIM_DATEI = "auszug-geheim.dat"


@pytest.fixture
def protokoll(tmp_path):
    pfad = tmp_path / "audit.jsonl"
    assert audit.einrichten(str(pfad))
    yield pfad
    audit.einrichten(None)


def _zeilen(pfad):
    return [json.loads(z) for z in pfad.read_text(encoding="utf-8").splitlines()]


class _Reader:
    def __init__(self, raw):
        self.raw = raw

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def fetch_raw(self, uid, mailbox, max_bytes=None):
        return self.raw

    def finde(self, mailbox, **kw):
        from proton_mail.suche import Ergebnis

        return Ergebnis([3, 2], 2, True)

    def fetch_echtheit(self, uids, mailbox):
        return {u: {"urteil": "bestanden", "proton_spamwert": 0, "dmarc": "pass"} for u in uids}

    def fetch_summaries(self, uids, mailbox):
        from proton_mail.imap_client import Summary

        return {
            u: Summary(u, GEHEIM_BETREFF, "bank@example", "frank@example", "x", True, 1)
            for u in uids
        }


def _mail():
    m = EmailMessage()
    m["Subject"] = GEHEIM_BETREFF
    m["From"] = "bank@example"
    m.set_content(GEHEIM_TEXT)
    m.add_attachment(b"abc", maintype="application", subtype="octet-stream", filename=GEHEIM_DATEI)
    return m.as_bytes()


def _token(*scopes):
    return AccessToken(token="t" * 32, client_id="static:hermes", scopes=list(scopes))


@pytest.fixture
def umgebung(monkeypatch):
    monkeypatch.setattr(mcp_server, "_reader", lambda: _Reader(_mail()))
    monkeypatch.setattr(mcp_server, "_access_token", lambda ctx: _token("proton.read"))


def test_get_email_eine_zeile_ohne_inhalt(protokoll, umgebung):
    asyncio.run(mcp_server.get_email(uid=42, mailbox="Belege"))
    (z,) = _zeilen(protokoll)
    assert z["tool"] == "get_email" and z["token"] == "static:hermes"
    assert z["mailbox"] == "Belege" and z["uid"] == 42 and z["status"] == "ok"
    assert z["anhaenge"] == 1 and z["zeichen"] > 0 and "dauer_ms" in z
    assert "+0" in z["zeit"]  # Zeit mit Zonenangabe (Europe/Berlin)
    roh = protokoll.read_text(encoding="utf-8")
    for geheim in (GEHEIM_BETREFF, "Kontostand", GEHEIM_DATEI, "bank@example"):
        assert geheim not in roh


def test_suche_protokolliert_begriffe_und_trefferzahl(protokoll, umgebung):
    asyncio.run(mcp_server.search_emails(text="Passwort", since_date="2026-10-01", limit=5))
    (z,) = _zeilen(protokoll)
    assert z["text"] == "Passwort" and z["since_date"] == "2026-10-01" and z["treffer"] == 2
    assert "subject" not in z  # nicht gesetzte Kriterien fehlen
    assert GEHEIM_BETREFF not in protokoll.read_text(encoding="utf-8")


def test_lange_suchbegriffe_gekuerzt(protokoll, umgebung):
    asyncio.run(mcp_server.search_emails(body="x" * 500))
    (z,) = _zeilen(protokoll)
    assert len(z["body"]) == audit.MAX_FELD + 1


def test_dateiname_nur_als_merkmal(protokoll, umgebung):
    asyncio.run(mcp_server.get_attachment_text(uid=1, filename=GEHEIM_DATEI))
    (z,) = _zeilen(protokoll)
    assert z["per_dateiname"] is True and GEHEIM_DATEI not in json.dumps(z)


def test_abweisung_sichtbar(protokoll, umgebung):
    with pytest.raises(PermissionError):
        asyncio.run(mcp_server.get_attachment(uid=7))
    (z,) = _zeilen(protokoll)
    assert z["status"] == "abgewiesen" and z["fehler"] == "PermissionError" and z["uid"] == 7


def test_fehler_sichtbar_und_weitergereicht(protokoll, monkeypatch):
    monkeypatch.setattr(mcp_server, "_access_token", lambda ctx: _token("proton.read"))

    def kaputt():
        raise ConnectionRefusedError("bridge weg")

    monkeypatch.setattr(mcp_server, "_reader", kaputt)
    with pytest.raises(ConnectionRefusedError):
        asyncio.run(mcp_server.list_mailboxes())
    (z,) = _zeilen(protokoll)
    assert z["status"] == "fehler" and z["fehler"] == "ConnectionRefusedError"
    assert "bridge weg" not in json.dumps(z)


def test_aus_ohne_pfad_und_nicht_schreibbar(tmp_path, umgebung):
    assert audit.einrichten(None) is False and not audit.aktiv()
    assert audit.einrichten(str(tmp_path / "fehlt" / "audit.jsonl")) is False
    # Ohne Protokoll laufen die Werkzeuge unverändert.
    assert asyncio.run(mcp_server.get_email(uid=1))["uid"] == 1
