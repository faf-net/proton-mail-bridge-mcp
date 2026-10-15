"""Robuste Suche gegen eine nachgebaute Bridge, die — wie die echte — im KODIERTEN Text sucht."""

import base64
from datetime import UTC, date, datetime
from email import quoprimime
from email.message import EmailMessage

from imapclient.response_types import Address, Envelope

from proton_mail import suche


def _betreff_ersetzen(raw, kodiert):
    kopf, rest = raw.split(b"\n\n", 1)
    zeilen = [z for z in kopf.split(b"\n") if not z.lower().startswith(b"subject:")]
    return b"\n".join(zeilen + [b"Subject: " + kodiert.encode()]) + b"\n\n" + rest


def _mail(subject, body, *, sender="Paketdienst <info@paket.example>", html=False, b64=False):
    m = EmailMessage()
    m["From"] = sender
    m["To"] = "frank@example"
    m["Subject"] = "platzhalter"
    if html:
        m.set_content(f"<p>{body}</p>", subtype="html", cte="base64" if b64 else None)
    else:
        m.set_content(body, cte="base64" if b64 else "quoted-printable")
    raw = m.as_bytes()
    if subject.isascii():
        return _betreff_ersetzen(raw, subject)
    # Wie Proton: den GANZEN Betreff als Q-Encoded-Word (Leerzeichen → "_", Umlaute → =XX).
    return _betreff_ersetzen(raw, quoprimime.header_encode(subject.encode(), "utf-8"))


def _b64_betreff(raw, subject):
    """Betreff als Base64-Encoded-Word (wie viele Versender es tun)."""
    return _betreff_ersetzen(raw, "=?utf-8?b?" + base64.b64encode(subject.encode()).decode() + "?=")


class FakeBridge:
    """Sucht wie die Proton Bridge im rohen (kodierten) Text — und liefert ENVELOPE/Teilabrufe."""

    def __init__(self, mails):
        self.mails = mails  # uid -> (raw, internaldate)
        self.suchen = []

    def _kopf(self, raw):
        return raw.split(b"\n\n", 1)[0]

    def _feld(self, raw, name):
        out = []
        for zeile in self._kopf(raw).split(b"\n"):
            if zeile.lower().startswith(name.lower() + b":"):
                out.append(zeile.split(b":", 1)[1].strip())
        return b" ".join(out)

    def search(self, criteria):
        self.suchen.append(list(criteria))
        uids = sorted(self.mails)
        it = iter(criteria)
        for key in it:
            if key == "ALL":
                continue
            wert = next(it)
            if key == "SINCE":
                uids = [u for u in uids if self.mails[u][1].date() >= wert]
                continue
            w = wert.encode().lower()

            def roh(u, key=key):
                raw = self.mails[u][0]
                if key in ("SUBJECT", "FROM", "TO"):
                    return self._feld(raw, key.encode())
                if key == "BODY":
                    return raw.split(b"\n\n", 1)[1]
                return raw

            uids = [u for u in uids if w in roh(u).lower()]
        return uids

    def fetch(self, uids, items):
        out = {}
        for u in uids:
            raw = self.mails[u][0]
            d = {}
            if "ENVELOPE" in items:
                d[b"ENVELOPE"] = Envelope(
                    date=None,
                    subject=self._feld(raw, b"Subject"),
                    from_=(Address(b"Paketdienst", None, b"info", b"paket.example"),),
                    sender=None,
                    reply_to=None,
                    to=(Address(None, None, b"frank", b"example"),),
                    cc=None,
                    bcc=None,
                    in_reply_to=None,
                    message_id=None,
                )
            if any(i.startswith("BODY.PEEK[HEADER]") for i in items):
                kopf, rest = raw.split(b"\n\n", 1)
                d[b"BODY[HEADER]"] = kopf + b"\n\n"
                d[b"BODY[TEXT]<0>"] = rest[: suche.TEXT_BYTES]
            out[u] = d
        return out


def _bridge():
    t = datetime(2026, 10, 6, 9, 0, tzinfo=UTC)
    return FakeBridge(
        {
            1: (_mail("Rechnung September", "Betrag 12 EUR"), datetime(2026, 9, 1, tzinfo=UTC)),
            2: (_mail("Ihre Bestellung 2026-48211 – Bestätigung", "Viele Grüße"), t),
            3: (_mail("Zustellung fehlgeschlagen – Sendung 0034", "Bitte melden"), t),
            4: (
                _b64_betreff(_mail("Kündigung Ihres Vertrags", "x"), "Kündigung Ihres Vertrags"),
                t,
            ),
            5: (_mail("Newsletter", "Herzliche Grüße aus Köln", html=True, b64=True), t),
        }
    )


def test_bridge_attrappe_verhaelt_sich_wie_die_echte():
    b = _bridge()
    assert b.search(["SUBJECT", "Zustellung fehlgeschlagen"]) == []
    assert b.search(["SUBJECT", "Bestätigung"]) == []
    assert b.search(["SUBJECT", "Ihre_Bestellung"]) == [2]


def test_mehrere_woerter_und_umlaute_im_betreff():
    b = _bridge()
    assert suche.finde(b, subject="Zustellung fehlgeschlagen").uids == [3]
    assert suche.finde(b, subject="bestätigung").uids == [2]
    assert suche.finde(b, subject="Ihre Bestellung 2026-48211").uids == [2]


def test_base64_betreff_wird_gefunden():
    assert suche.finde(_bridge(), subject="Kündigung").uids == [4]


def test_text_mit_umlaut_auch_base64_html():
    b = _bridge()
    assert suche.finde(b, body="Grüße").uids == [5, 2]
    assert suche.finde(b, text="grüsse aus köln").uids == [5]  # ß = ss, ohne Groß/klein


def test_text_findet_auch_im_betreff():
    assert suche.finde(_bridge(), text="Zustellung fehlgeschlagen").uids == [3]


def test_und_verknuepfung_und_since():
    b = _bridge()
    assert suche.finde(b, subject="Rechnung", from_="paket.example").uids == [1]
    assert suche.finde(b, subject="Rechnung", since_date=date(2026, 10, 1)).uids == []


def test_limit_bricht_frueh_ab():
    b = FakeBridge(
        {
            u: (_mail(f"Rechnung {u}", "x"), datetime(2026, 10, 1, tzinfo=UTC))
            for u in range(1, 2001)
        }
    )
    erg = suche.finde(b, subject="rechnung", limit=3)
    assert erg.uids == [2000, 1999, 1998]
    assert erg.durchsucht == suche.STAPEL_KOPF and erg.ordner_ganz


def test_jenseits_des_fensters_nur_ascii_woerter():
    b = _bridge()
    # Fenster 2: nur UID 5 und 4 sind sicher Kandidaten; 3 (q-kodiert) kommt über "Zustellung".
    erg = suche.finde(b, subject="Zustellung fehlgeschlagen", fenster_kopf=2)
    assert erg.uids == [3] and not erg.ordner_ganz
    # Rein nicht-ASCII ("Grüße" hat kein ASCII-Wort ≥ 3) jenseits des Fensters: nicht gefunden,
    # und das Ergebnis sagt ehrlich, dass der Ordner nicht ganz durchsucht wurde.
    erg = suche.finde(b, body="Grüße", fenster_text=1)
    assert erg.uids == [5] and not erg.ordner_ganz


def test_ohne_kriterien_neueste():
    erg = suche.finde(_bridge(), limit=2)
    assert erg.uids == [5, 4] and erg.ordner_ganz


def test_normalisieren():
    assert suche.normalisieren("  Grüße\u200b  AUS\tKöln ") == "grüsse aus köln"
    assert suche.server_wort("Bestätigung 2026-48211") == "tigung"  # steht so auch kodiert da
    assert suche.server_wort("Grüße") is None


def test_teure_bridge_suche_nur_wenn_fenster_nicht_reicht():
    b = _bridge()
    assert suche.finde(b, subject="Zustellung", fenster_kopf=3, limit=1).uids == [3]
    assert b.suchen == [["ALL"]]  # Fenster reichte — keine Textsuche bei der Bridge
    b.suchen.clear()
    assert suche.finde(b, subject="Rechnung", fenster_kopf=3).uids == [1]
    assert b.suchen == [["ALL"], ["SUBJECT", "Rechnung"]]
