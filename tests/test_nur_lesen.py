"""Beweistest: Der Server schickt NIE einen schreibenden Befehl ans Postfach.

Das ist das Alleinstellungsmerkmal des Projekts (Vergleich mit 22 Fremdprojekten, 06.10.2026):
kein Senden, Löschen, Verschieben, Markieren — nicht als Option, sondern weil der Code es nicht
kann. Zwei unabhängige Sicherungen gegen Rückfälle:

1. Statisch: Der Quelltext darf auf dem IMAP-Objekt nur eine feste Liste von Methoden benutzen,
   jedes ``select_folder`` braucht ``readonly=True`` (EXAMINE statt SELECT), und Abrufe dürfen
   nur ``BODY.PEEK[...]`` anfordern (``BODY[...]`` und ``RFC822`` setzen sonst ``\\Seen``).
2. Zur Laufzeit: Alle Werkzeuge laufen gegen einen IMAP-Nachbau, der bei jedem nicht erlaubten
   Aufruf sofort scheitert und jeden SELECT/EXAMINE mitschreibt.

Wer hier eine Methode freischalten muss, ändert bewusst das Sicherheitsversprechen.
"""

import ast
import asyncio
import dataclasses
import pathlib
from datetime import UTC, datetime
from email.message import EmailMessage
from typing import ClassVar

import pytest
from imapclient.response_types import Address, Envelope
from mcp.server.auth.provider import AccessToken

from proton_mail import imap_client, mcp_server
from proton_mail.config import ImapConfig
from proton_mail.imap_client import ProtonMailReader

SRC = pathlib.Path(__file__).resolve().parent.parent / "src" / "proton_mail"

# Alles, was der Code auf dem IMAP-Objekt benutzen darf. Bewusst NICHT dabei: append, store,
# add_flags, set_flags, remove_flags, delete_messages, expunge, uid_expunge, copy, move,
# create_folder, delete_folder, rename_folder, subscribe_folder, set_gmail_labels, idle …
ERLAUBT = {
    "starttls",
    "login",
    "logout",
    "shutdown",
    "select_folder",
    "list_folders",
    "search",
    "fetch",
    "normalise_times",
}
# Namen, unter denen der Code das IMAP-Objekt hält (je Datei).
IMAP_BASEN = {"self._conn", "self._client", "conn"}
IMAP_BASEN_JE_DATEI = {"imap_client.py": {"client"}}


def _quellen():
    return sorted(SRC.rglob("*.py"))


def test_statisch_nur_erlaubte_imap_methoden():
    verstoesse = []
    for p in _quellen():
        basen = IMAP_BASEN | IMAP_BASEN_JE_DATEI.get(p.name, set())
        for n in ast.walk(ast.parse(p.read_text(encoding="utf-8"))):
            if (
                isinstance(n, ast.Attribute)
                and ast.unparse(n.value) in basen
                and n.attr not in ERLAUBT
            ):
                verstoesse.append(f"{p.name}:{n.lineno} {ast.unparse(n)}")
    assert not verstoesse, "nicht erlaubte IMAP-Aufrufe: " + ", ".join(verstoesse)


def test_statisch_imapclient_nur_im_kern():
    for p in _quellen():
        text = p.read_text(encoding="utf-8")
        if p.name != "imap_client.py":
            assert "import imapclient" not in text and "from imapclient" not in text, p.name


def test_statisch_jedes_select_nur_lesend():
    funde = 0
    for p in _quellen():
        for n in ast.walk(ast.parse(p.read_text(encoding="utf-8"))):
            if isinstance(n, ast.Call) and getattr(n.func, "attr", None) == "select_folder":
                funde += 1
                kw = {k.arg: k.value for k in n.keywords}
                assert (
                    isinstance(kw.get("readonly"), ast.Constant) and kw["readonly"].value is True
                ), f"{p.name}:{n.lineno} select_folder ohne readonly=True"
    assert funde >= 5  # der Test prüft wirklich etwas


def test_statisch_abrufe_nur_mit_peek():
    for p in _quellen():
        for n in ast.walk(ast.parse(p.read_text(encoding="utf-8"))):
            if isinstance(n, ast.Constant) and isinstance(n.value, str):
                assert not n.value.upper().startswith("BODY["), f"{p.name}:{n.lineno} {n.value!r}"
            if isinstance(n, ast.JoinedStr) and n.values and isinstance(n.values[0], ast.Constant):
                anfang = str(n.values[0].value).upper()
                assert not anfang.startswith("BODY["), f"{p.name}:{n.lineno}"


# Abruf-Elemente, die den Mailinhalt holen UND \Seen setzen (RFC 3501, 6.4.5). RFC822.SIZE und
# RFC822.HEADER sind harmlos bzw. werden nicht benutzt; geprüft wird das nackte Element.
SETZT_SEEN = {"RFC822", "RFC822.TEXT", "BODY[]", "BODY[TEXT]"}


def test_statisch_kein_volltext_ohne_peek():
    funde = []
    peek = 0
    for p in _quellen():
        for n in ast.walk(ast.parse(p.read_text(encoding="utf-8"))):
            if isinstance(n, ast.Constant) and isinstance(n.value, str):
                wert = n.value.strip().upper()
                if wert in SETZT_SEEN:
                    funde.append(f"{p.name}:{n.lineno} {n.value!r}")
                peek += wert.startswith("BODY.PEEK[")
    assert not funde, "Abruf setzt \\Seen: " + ", ".join(funde)
    assert peek >= 3  # der Test prüft wirklich etwas (Volltext, Kopf, Textanfang)


# --- Laufzeit: IMAP-Nachbau, der Schreibversuche sofort meldet ------------------------


def _mail():
    m = EmailMessage()
    m["From"] = "Stadtwerke <info@sw.example>"
    m["To"] = "frank@example"
    m["Subject"] = "Jahresabrechnung – Bestätigung"
    m["Message-ID"] = "<a1@sw.example>"
    m["Authentication-Results"] = "mail.protonmail.ch; dmarc=pass header.from=sw.example"
    m.set_content("Anbei die Abrechnung.")
    m.add_attachment(b"Zeile 1\nZeile 2\n", maintype="text", subtype="plain", filename="a.txt")
    return m.as_bytes()


class LeseNachbau:
    """Kennt nur lesende Aufrufe. Alles andere → AssertionError, protokolliert in `verboten`."""

    protokoll: ClassVar[list] = []
    verboten: ClassVar[list] = []

    def __init__(self, host, port=None, ssl=None, timeout=None):
        object.__setattr__(self, "normalise_times", True)
        self.raw = _mail()

    def __getattr__(self, name):
        LeseNachbau.verboten.append(name)
        raise AssertionError(f"verbotener IMAP-Aufruf: {name}")

    def __setattr__(self, name, value):
        if name not in ("normalise_times", "raw"):
            LeseNachbau.verboten.append(f"setze {name}")
            raise AssertionError(f"verbotenes Setzen: {name}")
        object.__setattr__(self, name, value)

    def starttls(self, ssl_context=None):
        LeseNachbau.protokoll.append(("starttls",))

    def login(self, user, password):
        LeseNachbau.protokoll.append(("login",))

    def logout(self):
        LeseNachbau.protokoll.append(("logout",))

    def shutdown(self):
        LeseNachbau.protokoll.append(("shutdown",))

    def select_folder(self, name, readonly=False):
        LeseNachbau.protokoll.append(("select", name, readonly))
        return {b"EXISTS": 2, b"UIDVALIDITY": 1}

    def list_folders(self):
        return [((b"\\HasNoChildren",), b"/", "INBOX"), ((), b"/", "All Mail")]

    def search(self, criteria, charset=None):
        LeseNachbau.protokoll.append(("search", tuple(map(str, criteria))))
        return [1, 2]

    def fetch(self, uids, items):
        LeseNachbau.protokoll.append(("fetch", tuple(items)))
        kopf, rest = self.raw.split(b"\n\n", 1)
        out = {}
        for u in uids:
            d = {}
            for it in items:
                if it == "BODY.PEEK[]":
                    d[b"BODY[]"] = self.raw  # imapclient: Antwortschlüssel ohne PEEK
                elif it == "RFC822.SIZE":
                    d[b"RFC822.SIZE"] = len(self.raw)
                elif it == "INTERNALDATE":
                    d[b"INTERNALDATE"] = datetime(2026, 10, 6, 8, 0, tzinfo=UTC)
                elif it == "ENVELOPE":
                    d[b"ENVELOPE"] = Envelope(
                        None,
                        "Jahresabrechnung – Bestätigung".encode(),
                        (Address(b"Stadtwerke", None, b"info", b"sw.example"),),
                        None, None,
                        (Address(None, None, b"frank", b"example"),),
                        None, None, None, b"<a1@sw.example>",
                    )  # fmt: skip
                elif it == "BODYSTRUCTURE":
                    d[b"BODYSTRUCTURE"] = None
                elif it.startswith("BODY.PEEK[HEADER.FIELDS"):
                    d[("BODY" + it[9:]).encode()] = kopf + b"\n\n"
                elif it == "BODY.PEEK[HEADER]":
                    d[b"BODY[HEADER]"] = kopf + b"\n\n"
                elif it.startswith("BODY.PEEK[TEXT]"):
                    d[b"BODY[TEXT]<0>"] = rest
                else:
                    raise AssertionError(f"unbekannter Abruf: {it}")
            out[u] = d
        return out


@pytest.fixture
def nachbau(monkeypatch, tmp_path):
    LeseNachbau.protokoll = []
    LeseNachbau.verboten = []
    monkeypatch.setattr(imap_client, "IMAPClient", LeseNachbau)
    cfg = ImapConfig(host="x", port=1, user="u", password="p", tls_verify=False, timeout=5)
    monkeypatch.setattr(mcp_server, "_reader", lambda: ProtonMailReader(cfg))
    tok = AccessToken(
        token="t" * 32,
        client_id="static:test",
        scopes=["proton.read", "proton.attachments", "proton.ablage"],
    )
    monkeypatch.setattr(mcp_server, "_access_token", lambda ctx: tok)
    mcfg = dataclasses.replace(
        mcp_server._mcp_cfg, drop_dir=str(tmp_path), ready_max_post_alter_h=24.0
    )
    monkeypatch.setattr(mcp_server, "_mcp_cfg", mcfg)
    monkeypatch.setattr(mcp_server, "_aufgeraeumt", False)
    yield LeseNachbau


def test_alle_werkzeuge_nur_lesend(nachbau):
    run = asyncio.run
    assert "INBOX" in run(mcp_server.list_mailboxes())
    s = run(mcp_server.search_emails(subject="Bestätigung"))
    assert s["anzahl"] == 2 and s["treffer"][0]["echtheit"]["urteil"] == "bestanden"
    run(mcp_server.search_emails(body="Abrechnung", since_date="2026-10-01"))
    s2 = run(mcp_server.search_emails(before_date="2026-10-07", limit=1))
    run(mcp_server.search_emails(vor_uid=s2["naechste_vor_uid"], uidvalidity=s2["uidvalidity"]))
    assert run(mcp_server.get_thread(uid=1))["anzahl"] >= 1
    assert "Anbei" in run(mcp_server.get_email(uid=1, include_html=True))["text_body"]
    t = run(mcp_server.get_attachment_text(uid=1, index=0))
    assert t["method"] == "text" and "Zeile 2" in t["text"]
    assert run(mcp_server.get_attachment(uid=1, index=0))["size"] > 0
    assert run(mcp_server.anhang_ablegen(uid=1, index=0))["groesse"] > 0
    # Der Nachbau hat ein festes INTERNALDATE — mit der Zeit greift die Frische-Grenze.
    # Hier zählt nur, dass die Probe ohne Schreibaufruf durchläuft.
    ok, grund = mcp_server._bridge_pruefen()
    assert ok or grund.startswith("keine_neue_post_seit_")
    with ProtonMailReader(ImapConfig("x", 1, "u", "p", False, 5)) as r:  # Bulk-Pfade
        r.search("INBOX", from_="info@sw.example")
        r.fetch_size(1, "INBOX")

    assert nachbau.verboten == [], nachbau.verboten
    selects = [e for e in nachbau.protokoll if e[0] == "select"]
    assert selects and all(ro is True for _, _, ro in selects)  # nur EXAMINE, nie SELECT
    abrufe = {it for e in nachbau.protokoll if e[0] == "fetch" for it in e[1]}
    assert all(not it.startswith("BODY[") for it in abrufe), abrufe
    assert not abrufe & SETZT_SEEN, abrufe
    assert "BODY.PEEK[]" in abrufe  # Volltext lief wirklich über PEEK


def test_nachbau_schlaegt_bei_schreibversuch_an(nachbau):
    # Gegenprobe: würde Code doch schreiben, merkt es der Nachbau.
    c = LeseNachbau("x")
    for verboten in ("expunge", "add_flags", "append", "delete_messages", "move", "copy"):
        with pytest.raises(AssertionError):
            getattr(c, verboten)
    assert set(nachbau.verboten) >= {"expunge", "append", "move"}
