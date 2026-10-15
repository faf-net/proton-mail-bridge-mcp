"""P11 · Parser-Robustheit: feindliche und kaputte Mails dürfen nie zum Absturz führen.

Mails kommen aus fremder Hand. Jede Eigenart darf höchstens einzelne Zeichen kosten, aber nie
das Werkzeug abbrechen — und was herauskommt, muss sauberes UTF-8 ohne Surrogate sein, sonst
scheitert erst die JSON-/HTTP-Ausgabe an Hermes, weit weg von der Ursache.
"""

import dataclasses
import json

import pytest

from proton_mail.headers import decode_mime_header
from proton_mail.message import ZU_TIEF, html_to_text, parse_email


def _sauber(wert) -> None:
    """Wert (auch verschachtelt) ist als UTF-8 kodierbar und JSON-fähig."""
    if isinstance(wert, str):
        wert.encode("utf-8")  # wirft bei Lone-Surrogates
    elif isinstance(wert, (list, tuple)):
        for w in wert:
            _sauber(w)
    elif dataclasses.is_dataclass(wert):
        for f in dataclasses.fields(wert):
            if f.name != "content":  # Anhangsbytes bleiben Bytes
                _sauber(getattr(wert, f.name))


def _pruefe(raw: bytes):
    m = parse_email(7, raw)
    _sauber(m)
    daten = dataclasses.asdict(m)
    for a in daten["attachments"]:
        a["content"] = len(a["content"])
    json.dumps(daten, ensure_ascii=False).encode("utf-8")
    return m


# --- decode_mime_header ---------------------------------------------------------------


@pytest.mark.parametrize(
    "wert",
    [
        None,
        "",
        b"",
        "=?utf-8?B?kaputt!!?=",  # ungültiges base64
        "=?utf-8?Q?halb",  # nicht geschlossen
        "=?x-unbekannt?Q?Gr=FC=DFe?=",  # unbekannter Zeichensatz
        "=?utf-8?Q?=FC=FC?=",  # erklärt UTF-8, enthält Latin-1
        "=?iso-8859-1?Q?Gr=FC=DFe?= und =?utf-8?B?w7w=?=",
        "Gr\udcfc\udcdfe",  # surrogateescape aus der email-Stdlib (8-Bit-Kopf)
        "Text mit \ud800 Einzel-Surrogat",
        b"Gr\xfc\xdfe",  # Latin-1-Bytes aus ENVELOPE
        b"\xff\xfe\x00",
        "=?utf-8?B?" + "A" * 5000 + "?=",
    ],
)
def test_decode_mime_header_wirft_nie_und_ist_sauber(wert):
    _sauber(decode_mime_header(wert))


def test_decode_mime_header_8bit_wird_lesbar():
    # 8-Bit-Kopf ohne RFC 2047: Latin-1 (häufigster Fall) wird zu echten Umlauten.
    assert decode_mime_header("Gr\udcfc\udcdfe") == "Grüße"
    assert decode_mime_header(b"Gr\xfc\xdfe") == "Grüße"
    # Rohes UTF-8 im Kopf (auch häufig) bleibt UTF-8.
    assert decode_mime_header("Gr\udcc3\udcbc\udcc3\udc9fe") == "Grüße"


# --- parse_email mit feindlichen Mails -------------------------------------------------


KOPF = b"From: a@b.example\r\nTo: c@d.example\r\nSubject: Test\r\n"


def test_leere_mail():
    m = _pruefe(b"")
    assert m.subject == "" and m.text_body == "" and m.attachments == []


def test_nur_muell():
    _pruefe(b"\x00\xff\xfe" * 100)


def test_8bit_kopfzeilen_ohne_rfc2047():
    raw = (
        b"From: M\xfcller <m@b.example>\r\nSubject: Rechnung f\xfcr M\xe4rz\r\n"
        b"Message-ID: <\xfc@x>\r\n\r\nText\r\n"
    )
    m = _pruefe(raw)
    assert m.subject == "Rechnung für März"
    assert "Müller" in m.from_


def test_utf8_erklaert_cp1252_geliefert():
    raw = (
        KOPF + b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: 8bit\r\n\r\nGr\xfc\xdfe \x80 50\r\n"
    )
    m = _pruefe(raw)
    assert m.text_body == "Grüße € 50"


def test_unbekannter_zeichensatz():
    raw = (
        KOPF + b"Content-Type: text/plain; charset=x-unknown\r\n"
        b"Content-Transfer-Encoding: 8bit\r\n\r\nHallo \xfc\r\n"
    )
    assert "Hallo" in _pruefe(raw).text_body


def test_zeichensatz_mit_nicht_ascii_namen():
    raw = KOPF + b'Content-Type: text/plain; charset="utf-\xfc"\r\n\r\nHallo\r\n'
    assert "Hallo" in _pruefe(raw).text_body


def test_utf16_mit_einzel_surrogat():
    koerper = "Hallo ".encode("utf-16-le") + b"\x00\xd8" + " Ende".encode("utf-16-le")
    raw = (
        KOPF + b"Content-Type: text/plain; charset=utf-16-le\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n"
        + __import__("base64").b64encode(koerper)
        + b"\r\n"
    )
    m = _pruefe(raw)
    assert "Hallo" in m.text_body and "Ende" in m.text_body


def test_utf8_kodiertes_surrogat_im_text():
    raw = (
        KOPF + b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: 8bit\r\n\r\nA\xed\xa0\x80B\r\n"
    )
    _pruefe(raw)


def test_html_entity_auf_surrogat():
    assert "\ud800" not in html_to_text("<p>A&#xD800;B&#55296;C</p>")
    _sauber(html_to_text("<p>A&#xD800;B&#55296;C&#x110000;D</p>"))


def test_html_only_in_multipart_mixed():
    raw = (
        KOPF + b'Content-Type: multipart/mixed; boundary="g"\r\n\r\n'
        b"--g\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
        b"<p>Nur <b>HTML</b></p><script>boese()</script>\r\n"
        b"--g\r\nContent-Type: application/pdf\r\n"
        b'Content-Disposition: attachment; filename="r.pdf"\r\n\r\n%PDF\r\n'
        b"--g--\r\n"
    )
    m = _pruefe(raw)
    assert m.text_body == ""
    assert "HTML" in html_to_text(m.html_body) and "boese" not in html_to_text(m.html_body)
    assert [a.filename for a in m.attachments] == ["r.pdf"]


def test_kaputte_rfc2047_und_rfc2231_dateinamen():
    raw = (
        KOPF + b'Content-Type: multipart/mixed; boundary="g"\r\n\r\n'
        b"--g\r\nContent-Type: text/plain\r\n\r\nx\r\n"
        b"--g\r\nContent-Type: application/octet-stream\r\n"
        b'Content-Disposition: attachment; filename="=?utf-8?B?kaputt?="\r\n\r\nA\r\n'
        b"--g\r\nContent-Type: application/octet-stream\r\n"
        b"Content-Disposition: attachment; filename*=x-unbekannt''Gr%FC%DFe.txt\r\n\r\nB\r\n"
        b"--g\r\nContent-Type: application/octet-stream\r\n"
        b'Content-Disposition: attachment; filename="R\xfcckgabe.pdf"\r\n\r\nC\r\n'
        b"--g--\r\n"
    )
    m = _pruefe(raw)
    namen = [a.filename for a in m.attachments]
    assert len(namen) == 3 and namen[2] == "Rückgabe.pdf", namen


@pytest.mark.parametrize(
    "mid",
    [b"", b"<>", b"kein-spitz", b"<a@b", b"<\xff\xfe@x>", b"<" + b"a" * 5000 + b"@x>"],
)
def test_kaputte_message_id(mid):
    raw = (
        KOPF + b"Message-ID: " + mid + b"\r\nIn-Reply-To: " + mid + b"\r\n"
        b"References: " + mid + b" <ok@x>\r\n\r\nText\r\n"
    )
    m = _pruefe(raw)
    assert "<ok@x>" in m.references


def test_fehlende_kopfzeilen():
    m = _pruefe(b"\r\nNur ein Text ohne Kopf\r\n")
    assert m.subject == "" and m.message_id == "" and m.references == []


def test_kaputtes_base64_und_quoted_printable():
    raw = (
        KOPF + b'Content-Type: multipart/mixed; boundary="g"\r\n\r\n'
        b"--g\r\nContent-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n!!!kein base64###\r\n"
        b"--g\r\nContent-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: quoted-printable\r\n\r\nGr=FC=XXe =\r\n"
        b"--g--\r\n"
    )
    _pruefe(raw)


@pytest.mark.parametrize("tiefe", [50, 300, 900, 2000, 5000])
def test_tiefe_multipart_verschachtelung(tiefe):
    teile = [KOPF + b'Content-Type: multipart/mixed; boundary="b0"\r\n\r\n']
    for i in range(1, tiefe):
        teile.append(
            f'--b{i - 1}\r\nContent-Type: multipart/mixed; boundary="b{i}"\r\n\r\n'.encode()
        )
    teile.append(f"--b{tiefe - 1}\r\nContent-Type: text/plain\r\n\r\nInnen\r\n".encode())
    for i in reversed(range(tiefe)):
        teile.append(f"--b{i}--\r\n".encode())
    m = _pruefe(b"".join(teile))
    assert m.subject == "Test"  # Köpfe kommen immer an
    assert m.text_body in ("Innen", ZU_TIEF)
    assert m.attachments == []


def test_viele_teile():
    raw = KOPF + b'Content-Type: multipart/mixed; boundary="g"\r\n\r\n'
    raw += b"--g\r\nContent-Type: text/plain\r\n\r\nx\r\n" * 3000 + b"--g--\r\n"
    assert _pruefe(raw).text_body.count("x") == 3000
