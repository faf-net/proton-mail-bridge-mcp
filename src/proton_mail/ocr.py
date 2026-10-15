"""Anhänge lesbar machen: PDF-Text, OCR für Scans/Bilder, Render fürs Sehen.

Strategie (Hybrid):
- Digitales PDF  -> eingebetteter Text (pymupdf).
- Gescanntes PDF -> Seiten rendern -> Tesseract-OCR.
- Bild           -> Tesseract-OCR.
Zusätzlich render_png() liefert eine PNG-Ansicht (erste Seite bzw. das Bild),
damit ein bild-fähiges Modell den Anhang direkt *sehen* kann (Vision).

Alle Eingaben stammen aus fremden Mails — deshalb harte Grenzen: Pixelzahl je
Render (Speicher), OCR-Timeout (CPU), Seitenzahl, PIL-Bombenschutz. Ein
verschlüsseltes PDF wird als solches gemeldet statt sinnlos durch OCR zu laufen.

Tesseract muss als System-Binär vorhanden sein (im Docker-Image installiert).

Seit 06.10.2026 zusätzlich: Textformate (TXT, CSV, Markdown, JSON, XML, ICS, VCF, HTML) und
weitergeleitete Mails (.eml) werden gelesen; `extract()` meldet Seitenzahlen und ob etwas
abgeschnitten wurde; Seiten eines digitalen PDFs ohne Text (eingescannte Einlagen) gehen
gezielt durch die OCR, statt still wegzufallen.
"""

from __future__ import annotations

import io
import math
from dataclasses import dataclass

import pymupdf
import pytesseract
from PIL import Image as PILImage

OCR_LANG = "deu+eng"
MIN_TEXT_LEN = 30  # darunter gilt ein PDF als "kein echter Text" -> OCR
MAX_OCR_PAGES = 5
OCR_TIMEOUT = 60  # Sekunden je Seite/Bild
DEFAULT_DPI = 200
MAX_RENDER_PIXELS = 20_000_000  # je gerenderter Seite (≈ A4 bei 200 dpi = 3,9 MP)
MIN_SEITEN_TEXT = 15  # weniger Zeichen auf einer PDF-Seite → vermutlich Scan → OCR

TEXT_TYPEN = {
    "text/plain": "text",
    "text/csv": "text",
    "text/tab-separated-values": "text",
    "text/markdown": "text",
    "text/x-markdown": "text",
    "application/json": "text",
    "application/xml": "text",
    "text/xml": "text",
    "text/calendar": "text",
    "text/vcard": "text",
    "text/x-vcard": "text",
    "text/html": "html",
    "message/rfc822": "eml",
}
TEXT_ENDUNGEN = {
    ".txt": "text", ".csv": "text", ".tsv": "text", ".md": "text", ".json": "text",
    ".xml": "text", ".ics": "text", ".vcf": "text", ".log": "text",
    ".htm": "html", ".html": "html", ".eml": "eml",
}  # fmt: skip

# PIL wirft ab dem Doppelten dieses Werts DecompressionBombError, warnt ab dem Wert.
PILImage.MAX_IMAGE_PIXELS = 30_000_000


def fit_dpi(
    width_pt: float, height_pt: float, dpi: int = DEFAULT_DPI, max_pixels: int = MAX_RENDER_PIXELS
) -> int:
    """dpi so wählen, dass eine Seite (in PDF-Punkten, 72/Zoll) höchstens
    `max_pixels` Bildpunkte ergibt. Normale Seiten bleiben bei `dpi`, riesige
    oder manipulierte Seitenformate werden herunterskaliert statt den Speicher
    zu sprengen."""
    if width_pt <= 0 or height_pt <= 0:
        return dpi
    pixels = (width_pt * dpi / 72.0) * (height_pt * dpi / 72.0)
    if pixels <= max_pixels:
        return dpi
    return max(1, int(dpi * math.sqrt(max_pixels / pixels)))


def _is_pdf(content_type: str, filename: str) -> bool:
    return (content_type or "").lower() == "application/pdf" or filename.lower().endswith(".pdf")


def _is_image(content_type: str) -> bool:
    return (content_type or "").lower().startswith("image/")


def _textart(content_type: str, filename: str) -> str | None:
    art = TEXT_TYPEN.get((content_type or "").lower().split(";")[0].strip())
    if art:
        return art
    name = (filename or "").lower()
    return next((a for e, a in TEXT_ENDUNGEN.items() if name.endswith(e)), None)


def lesbarkeit(content_type: str, filename: str = "") -> str:
    """Für die Anhangsliste: text | pdf | bild | nein — was get_attachment_text daraus macht."""
    if _is_pdf(content_type, filename):
        return "pdf"
    if _is_image(content_type):
        return "bild"
    return "text" if _textart(content_type, filename) else "nein"


def _dekodieren(roh: bytes) -> str:
    """Textanhang ohne verlässliche Charset-Angabe: BOM, UTF-8, sonst Windows-1252 (Excel-CSV)."""
    if roh.startswith((b"\xff\xfe", b"\xfe\xff")):
        return roh.decode("utf-16", "replace")
    if roh.startswith(b"\xef\xbb\xbf"):
        return roh[3:].decode("utf-8", "replace")
    try:
        return roh.decode("utf-8")
    except UnicodeDecodeError:
        return roh.decode("cp1252", "replace")


def _eml_text(roh: bytes) -> str:
    from .message import html_to_text, parse_email

    m = parse_email(0, roh)
    koerper = m.text_body or html_to_text(m.html_body)
    kopf = (
        f"Weitergeleitete Mail\nVon: {m.from_}\nAn: {m.to}\nDatum: {m.date}\nBetreff: {m.subject}"
    )
    anh = ", ".join(a.filename for a in m.attachments)
    return kopf + (f"\nAnhänge: {anh}" if anh else "") + "\n\n" + koerper


@dataclass
class Auszug:
    text: str
    # pdf-text | pdf-text+ocr | ocr-pdf | ocr-image | text | html | eml | encrypted | unsupported
    methode: str
    seiten_gesamt: int | None = None
    seiten_gelesen: int | None = None
    hinweis: str | None = None

    @property
    def unvollstaendig(self) -> bool:
        return (
            self.seiten_gesamt is not None
            and self.seiten_gelesen is not None
            and self.seiten_gelesen < self.seiten_gesamt
        )


def _pdf_pngs(doc: pymupdf.Document, max_pages: int, dpi: int = DEFAULT_DPI) -> list[bytes]:
    out: list[bytes] = []
    for i in range(min(max_pages, doc.page_count)):
        page = doc[i]
        rect = page.rect
        d = fit_dpi(rect.width, rect.height, dpi)
        out.append(page.get_pixmap(dpi=d).tobytes("png"))
    return out


def _ocr(png: bytes) -> str:
    with PILImage.open(io.BytesIO(png)) as img:
        return pytesseract.image_to_string(img, lang=OCR_LANG, timeout=OCR_TIMEOUT)


def _pdf_auszug(doc: pymupdf.Document) -> Auszug:
    n = doc.page_count
    seiten = [doc[i].get_text() for i in range(n)]
    gesamt_text = "\n".join(seiten)
    if len(gesamt_text.strip()) < MIN_TEXT_LEN:
        # Ganz gescannt: die ersten MAX_OCR_PAGES Seiten per OCR.
        k = min(MAX_OCR_PAGES, n)
        text = "\n".join(_ocr(p) for p in _pdf_pngs(doc, k))
        hinweis = (
            f"Gescanntes PDF: nur die ersten {k} von {n} Seiten gelesen (OCR)." if k < n else None
        )
        return Auszug(text, "ocr-pdf", n, k, hinweis)
    # Digital — aber einzelne Seiten ohne Text (eingescannte Einlagen) gezielt per OCR.
    leer = [i for i, t in enumerate(seiten) if len(t.strip()) < MIN_SEITEN_TEXT]
    if not leer:
        return Auszug(gesamt_text, "pdf-text", n, n)
    per_ocr = leer[:MAX_OCR_PAGES]
    for i in per_ocr:
        page = doc[i]
        d = fit_dpi(page.rect.width, page.rect.height)
        seiten[i] = _ocr(page.get_pixmap(dpi=d).tobytes("png"))
    fehlen = len(leer) - len(per_ocr)
    hinweis = None
    if fehlen:
        hinweis = (
            f"{len(leer)} Seiten ohne Text (Scan), {len(per_ocr)} davon per OCR gelesen; "
            f"{fehlen} Seiten fehlen."
        )
    return Auszug("\n".join(seiten), "pdf-text+ocr", n, n - fehlen, hinweis)


def extract(content: bytes, content_type: str, filename: str = "") -> Auszug:
    """Text eines Anhangs samt Methode, Seitenzahlen und Hinweis auf Unvollständiges."""
    if _is_pdf(content_type, filename):
        with pymupdf.open(stream=content, filetype="pdf") as doc:
            if doc.needs_pass:
                return Auszug("", "encrypted", doc.page_count, 0, "PDF ist passwortgeschützt.")
            return _pdf_auszug(doc)
    if _is_image(content_type):
        return Auszug(_ocr(content), "ocr-image")
    art = _textart(content_type, filename)
    if art == "text":
        return Auszug(_dekodieren(content), "text")
    if art == "html":
        from .message import html_to_text

        return Auszug(html_to_text(_dekodieren(content)), "html")
    if art == "eml":
        return Auszug(_eml_text(content), "eml")
    return Auszug("", "unsupported", hinweis="Format nicht lesbar (z. B. Office, ZIP).")


def extract_text(content: bytes, content_type: str, filename: str = "") -> tuple[str, str]:
    """(Text, Methode) — Kurzform von extract() für die Bulk-Skripte."""
    a = extract(content, content_type, filename)
    return a.text, a.methode


def render_png(
    content: bytes, content_type: str, filename: str = "", dpi: int = DEFAULT_DPI
) -> bytes | None:
    """PNG-Ansicht des Anhangs (erste PDF-Seite bzw. das Bild) für Vision. None, wenn ungeeignet."""
    if _is_pdf(content_type, filename):
        with pymupdf.open(stream=content, filetype="pdf") as doc:
            if doc.needs_pass:
                return None
            pngs = _pdf_pngs(doc, max_pages=1, dpi=dpi)
        return pngs[0] if pngs else None
    if _is_image(content_type):
        with PILImage.open(io.BytesIO(content)) as src:
            img = src.convert("RGB")
        buf = io.BytesIO()
        img.save(buf, "PNG")
        return buf.getvalue()
    return None
