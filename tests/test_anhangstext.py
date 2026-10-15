"""Anhangstext: neue Formate, Seitenangaben, gemischte PDFs (OCR als Attrappe — kein Tesseract)."""

from email.message import EmailMessage

import pymupdf
import pytest

from proton_mail import ocr


@pytest.fixture
def ocr_attrappe(monkeypatch):
    aufrufe = []

    def falsch_ocr(png):
        aufrufe.append(len(png))
        return f"OCR-SEITE-{len(aufrufe)}"

    monkeypatch.setattr(ocr, "_ocr", falsch_ocr)
    return aufrufe


def _pdf(seiten_texte):
    """PDF mit einer Seite je Eintrag; None = Seite ohne Text (wie ein Scan)."""
    doc = pymupdf.open()
    for t in seiten_texte:
        page = doc.new_page()
        if t:
            page.insert_text((72, 72), t)
    daten = doc.tobytes()
    doc.close()
    return daten


def test_digitales_pdf_alle_seiten(ocr_attrappe):
    a = ocr.extract(
        _pdf(["Rechnung Seite eins mit Betrag", "Seite zwei Summe 12,00 EUR"]), "application/pdf"
    )
    assert a.methode == "pdf-text" and a.seiten_gesamt == 2 and a.seiten_gelesen == 2
    assert not a.unvollstaendig and ocr_attrappe == []


def test_gemischtes_pdf_ocr_nur_fuer_leere_seiten(ocr_attrappe):
    a = ocr.extract(
        _pdf(["Deckblatt der Rechnung mit Text", None, "Letzte Seite mit Text dabei"]),
        "application/pdf",
    )
    assert a.methode == "pdf-text+ocr" and len(ocr_attrappe) == 1
    assert "OCR-SEITE-1" in a.text and "Deckblatt" in a.text
    assert a.seiten_gelesen == 3 and not a.unvollstaendig


def test_gemischtes_pdf_zu_viele_scanseiten(ocr_attrappe):
    a = ocr.extract(_pdf(["Text auf der ersten Seite vorhanden"] + [None] * 7), "application/pdf")
    assert len(ocr_attrappe) == ocr.MAX_OCR_PAGES
    assert a.seiten_gesamt == 8 and a.seiten_gelesen == 8 - 2 and a.unvollstaendig
    assert "2 Seiten fehlen" in a.hinweis


def test_gescanntes_pdf_meldet_abschnitt(ocr_attrappe):
    a = ocr.extract(_pdf([None] * 7), "application/pdf")
    assert a.methode == "ocr-pdf" and a.seiten_gesamt == 7 and a.seiten_gelesen == 5
    assert a.unvollstaendig and "ersten 5 von 7" in a.hinweis


def test_kurzes_gescanntes_pdf_vollstaendig(ocr_attrappe):
    a = ocr.extract(_pdf([None, None]), "application/pdf")
    assert a.methode == "ocr-pdf" and not a.unvollstaendig and a.hinweis is None


@pytest.mark.parametrize(
    "roh,erwartet",
    [
        ("Größe;Betrag\nÄpfel;1,50\n".encode(), "Äpfel"),
        ("Größe;Betrag\nÄpfel;1,50\n".encode("cp1252"), "Äpfel"),  # Excel-CSV
        (b"\xef\xbb\xbfMit BOM \xc3\xa4", "Mit BOM ä"),
        ("UTF-16 Grüße".encode("utf-16"), "UTF-16 Grüße"),
    ],
)
def test_textformate_und_kodierungen(roh, erwartet):
    a = ocr.extract(roh, "text/csv", "liste.csv")
    assert a.methode == "text" and erwartet in a.text


def test_endung_reicht_wenn_typ_unklar():
    a = ocr.extract(
        b"BEGIN:VCALENDAR\nSUMMARY:Termin\n", "application/octet-stream", "einladung.ics"
    )
    assert a.methode == "text" and "Termin" in a.text


def test_html_anhang_ohne_versteckten_text():
    a = ocr.extract(b"<p>Sichtbar</p><script>alert(1)</script>", "text/html", "x.html")
    assert a.methode == "html" and a.text == "Sichtbar"


def test_weitergeleitete_mail():
    m = EmailMessage()
    m["From"] = "Vermieter <v@example.org>"
    m["Subject"] = "Nebenkosten 2025"
    m.set_content("Die Abrechnung liegt bei.")
    m.add_attachment(b"%PDF", maintype="application", subtype="pdf", filename="nk.pdf")
    a = ocr.extract(m.as_bytes(), "message/rfc822", "weitergeleitet.eml")
    assert a.methode == "eml"
    assert "Betreff: Nebenkosten 2025" in a.text and "Abrechnung" in a.text and "nk.pdf" in a.text


def test_nicht_lesbares_mit_hinweis():
    a = ocr.extract(b"PK\x03\x04", "application/zip", "x.zip")
    assert a.methode == "unsupported" and a.hinweis


@pytest.mark.parametrize(
    "typ,name,erwartet",
    [
        ("application/pdf", "a.pdf", "pdf"),
        ("image/jpeg", "a.jpg", "bild"),
        ("text/plain", "a.txt", "text"),
        ("message/rfc822", "a.eml", "text"),
        ("application/octet-stream", "a.csv", "text"),
        (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "a.docx",
            "nein",
        ),
    ],
)
def test_lesbarkeit(typ, name, erwartet):
    assert ocr.lesbarkeit(typ, name) == erwartet
