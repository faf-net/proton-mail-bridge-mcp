"""Mehr Angaben je Mail, Datumsfilter, Blättern, UIDVALIDITY und Unterhaltungen."""

from datetime import date
from email.message import EmailMessage
from typing import ClassVar

import pytest
from imapclient.response_types import Address, Envelope

from proton_mail import mcp_server, suche
from proton_mail.imap_client import ProtonMailReader
from proton_mail.message import parse_email


def test_parse_email_neue_felder():
    m = EmailMessage()
    m["From"] = "Shop <rechnung@shop.example>"
    m["To"] = "frank@example"
    m["Cc"] = "Buchhaltung <bh@example>"
    m["Reply-To"] = "Kasse <kasse@andere.example>"
    m["In-Reply-To"] = "<b@shop.example>"
    m["References"] = "<a@shop.example> <b@shop.example>"
    m["List-Unsubscribe"] = "<https://shop.example/abmelden>"
    m.set_content("x")
    e = parse_email(1, m.as_bytes())
    assert "bh@example" in e.cc and "kasse@andere.example" in e.reply_to
    assert e.in_reply_to == "<b@shop.example>"
    assert e.references == ["<a@shop.example>", "<b@shop.example>"]
    assert e.list_unsubscribe is True


@pytest.mark.parametrize(
    "von,antwort,erwartet",
    [
        ("Bank <info@bank.example>", "", False),
        ("Bank <info@bank.example>", "service@bank.example", False),
        ("Bank <info@bank.example>", "Bank <hilfe@b4nk-sicher.example>", True),
        ("A <a@x.example>, B <b@y.example>", "b@y.example", False),
    ],
)
def test_antwortadresse_weicht_ab(von, antwort, erwartet):
    assert mcp_server._antwort_woanders(von, antwort) is erwartet


# --- Suche: Datum und Blättern ----------------------------------------------------------


class Bridge:
    """Minimal: 450 Mails, Betreff 'Rechnung <uid>', Eingang = 1. Tag + uid Stunden."""

    def __init__(self, n=450, uidvalidity=7):
        self.n = n
        self.uidvalidity = uidvalidity

    def select_folder(self, name, readonly=False):
        assert readonly is True
        return {b"EXISTS": self.n, b"UIDVALIDITY": self.uidvalidity}

    def _datum(self, u):
        return date.fromordinal(date(2026, 1, 1).toordinal() + u // 24)

    def search(self, criteria, charset=None):
        uids = list(range(1, self.n + 1))
        it = iter(criteria)
        for k in it:
            if k == "ALL":
                continue
            v = next(it)
            if k == "SINCE":
                uids = [u for u in uids if self._datum(u) >= v]
            elif k == "BEFORE":
                uids = [u for u in uids if self._datum(u) < v]
            else:
                uids = [u for u in uids if v.lower() in f"rechnung {u}"]
        return uids

    def fetch(self, uids, items):
        return {
            u: {
                b"ENVELOPE": Envelope(
                    None,
                    f"Rechnung {u}".encode(),
                    (Address(b"S", None, b"s", b"x"),),
                    None,
                    None,
                    (Address(None, None, b"f", b"x"),),
                    None,
                    None,
                    None,
                    None,
                )
            }
            for u in uids
        }


def test_before_date_filtert():
    erg = suche.finde(Bridge(), subject="Rechnung", before_date=date(2026, 1, 3), limit=500)
    assert erg.uids and max(erg.uids) < 48 and not erg.weitere


def test_blaettern_ueber_200_vollstaendig_und_ohne_doppelte():
    b = Bridge()
    gesehen, vor, seiten = [], None, 0
    while True:
        erg = suche.finde(b, subject="Rechnung", vor_uid=vor, limit=200)
        gesehen += erg.uids
        seiten += 1
        if not erg.weitere:
            break
        vor = erg.uids[-1]
    assert seiten == 3 and len(gesehen) == 450 and len(set(gesehen)) == 450
    assert gesehen == sorted(gesehen, reverse=True)


def test_blaettern_ohne_kriterien():
    erg = suche.finde(Bridge(), limit=100)
    assert erg.weitere and erg.uids[-1] == 351
    erg2 = suche.finde(Bridge(), vor_uid=351, limit=1000)
    assert erg2.uids[0] == 350 and not erg2.weitere


class _Reader(ProtonMailReader):
    def __init__(self, conn):
        self._client = conn


def test_uidvalidity_wechsel_bricht_ab():
    r = _Reader(Bridge(uidvalidity=9))
    assert r.finde("INBOX", subject="Rechnung", limit=5).uidvalidity == 9
    with pytest.raises(ValueError, match="neu aufgebaut"):
        r.finde("INBOX", subject="Rechnung", vor_uid=100, uidvalidity=7)


# --- Unterhaltung -------------------------------------------------------------------------


class ThreadBridge:
    """All Mail: 1 Ursprung, 2 Antwort auf 1, 3 Antwort auf 2, 4 fremd, 5 Antwort auf 1."""

    MAILS: ClassVar[dict] = {
        1: ("<m1@x>", None),
        2: ("<m2@x>", "<m1@x>"),
        3: ("<m3@x>", "<m2@x>"),
        4: ("<m4@x>", None),
        5: ("<m5@x>", "<m1@x>"),
    }

    def search(self, criteria, charset=None):
        return list(self.MAILS)

    def fetch(self, uids, items):
        return {
            u: {
                b"ENVELOPE": Envelope(
                    None,
                    b"Betreff",
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    (self.MAILS[u][1] or "").encode() or None,
                    self.MAILS[u][0].encode(),
                )
            }
            for u in uids
        }


def test_unterhaltung_von_der_mitte_aus():
    # Start ist Mail 3: References nennen m1 und m2 → Vorgänger; m5 antwortet auf m1 → dabei.
    erg = suche.unterhaltung(ThreadBridge(), {"<m3@x>", "<m1@x>", "<m2@x>"})
    assert erg.uids == [1, 2, 3, 5] and erg.ordner_ganz


def test_unterhaltung_nur_mit_eigener_id_findet_antworten():
    erg = suche.unterhaltung(ThreadBridge(), {"<m1@x>"})
    assert erg.uids == [1, 2, 3, 5]  # 3 über 2 (Kette), 4 nicht


def test_message_ids_robust():
    assert suche.message_ids(b"<a@x> irgendwas <b@y>") == ["<a@x>", "<b@y>"]
    assert suche.message_ids(None) == [] and suche.message_ids("ohne") == []
