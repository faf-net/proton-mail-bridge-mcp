"""MIME-/Anhang-Parsing über die `email`-Stdlib.

Das fehleranfällige Parsing (multipart, Encodings, RFC-2047-Dateinamen,
base64) liegt bewusst in der ausgereiften Stdlib, nicht in Eigencode.
"""

from __future__ import annotations

import re
from email import message_from_bytes
from email.message import Message
from email.parser import BytesParser
from html.parser import HTMLParser

from .headers import bytes_lesen, decode_mime_header, ohne_surrogate
from .imap_client import Attachment, Email
from .suche import message_ids

# Tags, deren Inhalt kein sichtbarer Text ist.
_SKIP_TAGS = {"script", "style", "head", "title", "template", "noscript"}
# Tags, die einen Zeilenumbruch erzeugen.
_BLOCK_TAGS = {
    "p",
    "div",
    "br",
    "li",
    "tr",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "blockquote",
    "pre",
    "table",
    "section",
    "article",
    "header",
    "footer",
    "hr",
}
# Geschütztes Leerzeichen (&nbsp;) zählt als Leerzeichen — Modelle stolpern sonst über \xa0.
_WS_RE = re.compile(r"[ \t\r\f\v\xa0]+")
# Leerzeilen komplett zusammenziehen: für ein Modell zählt Kompaktheit, nicht Typografie.
_NL_RE = re.compile(r"\n\s*\n+")
# Anfang eines Tags, Kommentars oder einer Deklaration (wie HTMLParser ihn erkennt).
_OFFENES_TAG_RE = re.compile(r"<[A-Za-z/!?]")


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag in _SKIP_TAGS:
            self._skip += 1
        elif tag in _BLOCK_TAGS:
            self._parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIP_TAGS and self._skip:
            self._skip -= 1
        elif tag in _BLOCK_TAGS:
            self._parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._skip:
            self._parts.append(data)

    def text(self) -> str:
        raw = "".join(self._parts)
        lines = [_WS_RE.sub(" ", ln).strip() for ln in raw.split("\n")]
        return _NL_RE.sub("\n", "\n".join(lines)).strip()


def html_to_text(html: str) -> str:
    """HTML zu lesbarem Text reduzieren — ohne Skripte, Styles und versteckte Köpfe.

    Bewusst konservativ: Es geht nicht um perfekte Darstellung, sondern darum,
    dem Modell nicht den kompletten HTML-Quelltext (Tracking, CSS, versteckte
    Elemente — die klassische Injection-Fläche) vorzusetzen.
    """
    if not html:
        return ""
    p = _TextExtractor()
    try:
        p.feed(html)
        # Ein bis zum Ende offenes Tag ("… <b ohne Ende") zeigt kein Mailprogramm an — es ist
        # nach HTML5 Teil des Tags. Python behandelt den Rest je nach Patch-Stand verschieden
        # (ältere Stände als Text, 3.12.14 verwirft ihn). Hier einheitlich verwerfen: so sieht
        # das Modell nichts, was der Mensch nicht sieht — versteckter Text am Mailende ist ein
        # bekannter Injection-Trick. Ein einzelnes "<" ohne Tag-Anfang bleibt Text.
        if _OFFENES_TAG_RE.match(p.rawdata) and ">" not in p.rawdata:
            p.rawdata = ""
        p.close()
    except Exception:  # noqa: BLE001 — kaputtes HTML → Regex-Rückfall
        return _WS_RE.sub(" ", re.sub(r"<[^>]+>", " ", html)).strip()
    return p.text()


def _decode_filename(raw: str | None) -> str:
    """Wie decode_mime_header, aber für Dateinamen: gefaltete Header hinterlassen
    eingebettete Zeilenumbrüche/Mehrfach-Spaces — die zu einem Space glätten,
    sonst entstehen ungültige Dateinamen beim Export."""
    return " ".join(decode_mime_header(raw).split())


def _dateiname(part: Message) -> str | None:
    """Dateiname eines Teils — auch wenn er als rohes 8-Bit im Kopf steht.

    ``get_filename`` liest aus dem bereinigten Kopf, in dem 8-Bit-Zeichen schon U+FFFD sind.
    Dann die beiden Köpfe aus den Rohbytes neu aufbauen und noch einmal fragen.
    """
    name = part.get_filename()
    if name is None or "�" not in name:
        return name
    neu = Message()
    for kopf in ("Content-Disposition", "Content-Type"):
        roh = _kopf(part, kopf)
        if roh is not None:
            neu[kopf] = ohne_surrogate(roh)
    return neu.get_filename() or name


def _is_attachment(part: Message) -> bool:
    """Echte Anhänge erkennen — inkl. eingebettetem Excel, aber OHNE inline
    angezeigte Bilder (Logos/Tracking-Pixel mit Content-ID)."""
    disposition = (part.get_content_disposition() or "").lower()
    if disposition == "attachment":
        return True
    if part.get_filename():
        # Inline MIT Content-ID = im HTML angezeigtes Bild, kein Anhang.
        return not (disposition == "inline" and part.get("Content-ID"))
    return False


def _kopf(msg: Message, name: str) -> str | None:
    """Erste Kopfzeile ``name`` als Rohtext.

    ``msg.get`` macht aus 8-Bit-Köpfen ohne RFC 2047 ein ``Header``-Objekt, dessen Text die
    Umlaute schon durch U+FFFD ersetzt hat. Der Rohwert trägt die Bytes noch (als
    surrogateescape) — ``decode_mime_header`` liest sie dann als UTF-8 oder Windows-1252.
    """
    name = name.lower()
    for k, v in msg.raw_items():
        if k.lower() == name:
            return v if isinstance(v, str) else str(v)
    return None


# Nachricht, wenn die Mail tiefer verschachtelt ist, als der Stdlib-Parser verkraftet.
ZU_TIEF = "[Mail zu tief verschachtelt — Inhalt nicht gelesen, nur die Kopfzeilen]"


def parse_email(uid: int, raw: bytes) -> Email:
    """Rohe RFC822-Bytes in ein strukturiertes Email-Objekt überführen. Wirft nie bei
    kaputten oder feindlichen Mails; alle Texte sind als UTF-8 kodierbar."""
    try:
        return _parse(uid, message_from_bytes(raw))
    except RecursionError:
        # Tausende verschachtelte multipart-Ebenen sprengen den rekursiven Parser der
        # Stdlib (gemessen ab ~1.000). Dann nur die Köpfe lesen — das geht ohne Rekursion.
        kopf = BytesParser().parsebytes(raw, headersonly=True)
        kopf.set_type("text/x-zu-tief")  # Rumpf weder als Text noch als Anhang werten
        mail = _parse(uid, kopf)
        mail.text_body = ZU_TIEF
        return mail


def _parse(uid: int, msg: Message) -> Email:
    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[Attachment] = []

    for part in msg.walk():
        if part.is_multipart():
            continue

        content_type = part.get_content_type()

        if _is_attachment(part):
            payload = part.get_payload(decode=True) or b""
            attachments.append(
                Attachment(
                    filename=_decode_filename(_dateiname(part)) or "unbenannt",
                    content_type=content_type,
                    size=len(payload),
                    content=payload,
                )
            )
            continue

        if content_type == "text/plain":
            text_parts.append(_decode_part_text(part))
        elif content_type == "text/html":
            html_parts.append(_decode_part_text(part))

    return Email(
        uid=uid,
        message_id=decode_mime_header(_kopf(msg, "Message-ID")),
        subject=decode_mime_header(_kopf(msg, "Subject")),
        from_=decode_mime_header(_kopf(msg, "From")),
        to=decode_mime_header(_kopf(msg, "To")),
        date=decode_mime_header(_kopf(msg, "Date")),
        text_body="\n".join(text_parts).strip(),
        html_body="\n".join(html_parts).strip(),
        attachments=attachments,
        cc=decode_mime_header(_kopf(msg, "Cc")),
        reply_to=decode_mime_header(_kopf(msg, "Reply-To")),
        in_reply_to=" ".join(message_ids(ohne_surrogate(_kopf(msg, "In-Reply-To") or ""))),
        references=message_ids(ohne_surrogate(_kopf(msg, "References") or "")),
        list_unsubscribe=bool(_kopf(msg, "List-Unsubscribe")),
    )


# Erklärte Zeichensätze, bei denen sich ein Rückfall auf Windows-1252 lohnt: Mailprogramme
# schreiben gern "utf-8" oder "us-ascii" in den Kopf und liefern dann Latin-1-Bytes.
_UTF8_ERKLAERT = {"utf-8", "utf8", "us-ascii", "ascii"}


def _decode_part_text(part: Message) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        text = payload.decode(charset)
    except UnicodeDecodeError:
        if charset in _UTF8_ERKLAERT:
            text = bytes_lesen(payload)
        else:
            text = payload.decode(charset, errors="replace")
    except LookupError:  # unbekannter Zeichensatz (auch Nicht-Text-Codecs wie base64_codec)
        text = bytes_lesen(payload)
    # Codecs wie utf-16 oder unicode_escape können einzelne Surrogate liefern.
    return ohne_surrogate(text)
