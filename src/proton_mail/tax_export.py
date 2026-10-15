"""Steuerlauf: 2025-Rechnungen aus definierten Quellen finden und exportieren.

Läuft direkt auf der NAS (Container im mailnet-Netz, IMAP gegen bridge:143) —
keine 200-Treffer-Deckelung wie im MCP-Tool, alles lokal. Pro PDF-Anhang:
Text/OCR lesen, prüfen ob Rechnung mit Belegdatum 2025, Felder extrahieren,
strukturiert ablegen als <Lieferant>_<RechnungsNr>_<YYYYMMDD>.pdf + index.csv.
Unsichere Fälle landen in zur_pruefung.csv (nicht exportiert) — fürs Finanzamt
soll nichts still verschwinden.
"""

from __future__ import annotations

import csv
import hashlib
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import date
from email.utils import parseaddr
from pathlib import Path

from .config import ImapConfig
from .imap_client import ProtonMailReader
from .message import parse_email
from .ocr import extract_text

YEAR = 2025
SINCE = date(2025, 1, 1)
# Absender des Scanners und Quellordner kommen aus der Umgebung (docker/.env,
# nicht eingecheckt) — persönliche Adressen und Ordnernamen gehören nicht ins Repo.
SENDER = os.getenv("SCANNER_ADDR", "")
FOLDERS = [
    f.strip()
    for f in os.getenv(
        "TAX_FOLDERS", "Folders/RECHNUNGEN,Folders/STEUER,Folders/FINANZEN,INBOX"
    ).split(",")
    if f.strip()
]
OUT = Path(os.getenv("EXPORT_DIR", "/export")) / "rechnungen-2025"

# --- Klassifikation ---------------------------------------------------------
POS = [
    "rechnung",
    "rechnungsnummer",
    "rechnungs-nr",
    "rg.-nr",
    "rg-nr",
    "betrag",
    "mwst",
    "ust",
    "umsatzsteuer",
    "netto",
    "brutto",
    "gesamtbetrag",
    "rechnungsbetrag",
    "zahlbar",
    "fällig",
    "iban",
    "zu zahlen",
    "steuersatz",
]
# Dokumenttypen, die KEINE Rechnung sind (auch wenn 'Rechnung' im Text vorkommt).
STRONG_NEG = [
    "allgemeine geschäftsbedingungen",
    "vorvertragliche information",
    "bedingungen und information",
    "auszahlungsübersicht",
    "widerrufsbelehrung",
    "datenschutzerklärung",
    "datenschutzhinweis",
    "lieferschein",
    "kostenvoranschlag",
    "mahnung",
    "zahlungserinnerung",
    "kontoauszug",
    "angebot über",
]

MONTHS = {
    "januar": 1,
    "februar": 2,
    "märz": 3,
    "maerz": 3,
    "april": 4,
    "mai": 5,
    "juni": 6,
    "juli": 7,
    "august": 8,
    "september": 9,
    "oktober": 10,
    "november": 11,
    "dezember": 12,
    "jan": 1,
    "feb": 2,
    "mär": 3,
    "apr": 4,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "okt": 10,
    "nov": 11,
    "dez": 12,
}

_AMOUNT = r"(\d{1,3}(?:[.\s]\d{3})*,\d{2}|\d+,\d{2})"
_LEGAL = r"(?:GmbH(?:\s*&\s*Co\.?\s*KG)?|mbH|AG|KGaA|KG|SE|UG|e\.\s?K\.|e\.\s?V\.|GbR|Inc\.?|Ltd\.?|B\.V\.)"
# Zeilen, die als Lieferant verworfen werden (Überschriften/Labels/Floskeln).
_GENERIC = re.compile(
    r"^(rechnung|seite|kundennr|kunden-nr|kundennummer|auftragsnr|auftragsnummer|"
    r"vorvertragliche|versicherungsnummer|kennzeichen|datum|betrag|summe|gesamtbetrag|"
    r"rechnungsnummer|rechnungsdatum|diese seite|bedingungen|allgemeine|information|"
    r"datenschutz|widerruf|betreff|sehr geehrte|guten tag|ihre|seite:)\b",
    re.IGNORECASE,
)


def _is_invoice(text: str, has_nr: bool, has_amount: bool) -> tuple[bool, bool, str]:
    """(streng, locker, Begründung). streng = echte Rechnung; locker = sieht nach
    Rechnung aus, zur Prüfung."""
    low = text.lower()
    head = low[:500]
    is_neg = any(n in low for n in STRONG_NEG)
    has_kw = "rechnung" in low or "invoice" in low
    pos = sorted({m for m in POS if m in low})
    loose = has_kw and len(pos) >= 2 and not (is_neg and "rechnung" not in low)
    strict = has_kw and (has_nr or has_amount) and len(pos) >= 3
    if is_neg and any(n in head for n in STRONG_NEG):
        strict = False  # AGB/Bedingungen o. Ä. im Titelbereich -> sicher keine Rechnung
    return strict, loose, f"kw={has_kw} nr={has_nr} betrag={has_amount} pos={len(pos)} neg={is_neg}"


def _find_dates(text: str) -> list[date]:
    out: list[date] = []
    for d, m, y in re.findall(r"\b(\d{1,2})[.\-/](\d{1,2})[.\-/](\d{2,4})\b", text):
        y = int(y) + (2000 if len(y) == 2 else 0)
        try:
            out.append(date(y, int(m), int(d)))
        except ValueError:
            pass
    for y, m, d in re.findall(r"\b(\d{4})-(\d{2})-(\d{2})\b", text):
        try:
            out.append(date(int(y), int(m), int(d)))
        except ValueError:
            pass
    for d, mon, y in re.findall(r"\b(\d{1,2})\.?\s+([A-Za-zäöü]+)\s+(\d{4})\b", text):
        mm = MONTHS.get(mon.lower())
        if mm:
            try:
                out.append(date(int(y), mm, int(d)))
            except ValueError:
                pass
    return out


def _belegdatum(text: str) -> tuple[date | None, str, bool]:
    """(Datum, Begründung, sicher?). Sicher nur, wenn nahe einem Datums-Stichwort
    oder einziges Datum — Fallback-Datum gilt als unsicher."""
    low = text.lower()
    for kw in (
        "rechnungsdatum",
        "belegdatum",
        "rechnung vom",
        "ausgestellt am",
        "invoice date",
        "datum",
    ):
        i = low.find(kw)
        if i >= 0:
            ds = _find_dates(text[i : i + 60])
            if ds:
                return ds[0], f"nahe '{kw}'", True
    ds = _find_dates(text)
    if len(set(ds)) == 1:
        return ds[0], "einziges Datum", True
    in2025 = sorted({d for d in ds if d.year == YEAR})
    if in2025:
        return in2025[0], "unsicher: frühestes 2025-Datum", False
    if ds:
        return max(ds), "unsicher: spätestes Datum", False
    return None, "kein Datum", False


def _sender_name(from_header: str) -> str:
    name, _addr = parseaddr(from_header or "")
    return name.strip().strip('"') if name else ""


def _supplier(text: str, from_header: str) -> str:
    lines = [ln.strip() for ln in text.strip().splitlines() if ln.strip()]
    # 1) Firmenzeile mit Rechtsform in den ersten ~25 Zeilen
    for ln in lines[:25]:
        m = re.search(r"([A-ZÄÖÜ][\wäöüßÄÖÜ&.\-/ ]{1,46}?\s" + _LEGAL + r")", ln)
        if m and not _GENERIC.match(m.group(1)):
            return re.sub(r"\s+", " ", m.group(1)).strip(" .-")
    # 2) Absender-Anzeigename (Vendor-Mails), außer Scanner
    nm = _sender_name(from_header)
    if (
        nm
        and len(nm) >= 3
        and not _GENERIC.match(nm)
        and "scanner" not in (from_header or "").lower()
    ):
        return nm[:46]
    # 3) erste namensartige Zeile (kein Label, nicht mit Ziffer beginnend)
    for ln in lines[:15]:
        if (
            len(ln) >= 4
            and not ln[0].isdigit()
            and ":" not in ln[:18]
            and "@" not in ln
            and not _GENERIC.match(ln)
            and sum(ch.isalpha() for ch in ln) >= 4
        ):
            return re.sub(r"\s+", " ", ln)[:46]
    # 4) Absender-Domain
    _n, addr = parseaddr(from_header or "")
    dom = addr.split("@")[-1] if "@" in addr else ""
    return dom.split(".")[-2] if dom.count(".") >= 1 else (dom or "unbekannt")


def _field(text: str, *kws: str) -> str:
    for kw in kws:
        m = re.search(kw + r"[:\s.#]*([A-Za-z0-9][\w./\-]{2,30})", text, re.IGNORECASE)
        if m:
            return m.group(1).strip(" .-")
    return ""


def _amount(text: str, *kws: str) -> str:
    for kw in kws:
        m = re.search(kw + r"[^\d\-]{0,40}?" + _AMOUNT + r"\s*(?:eur|€)?", text, re.IGNORECASE)
        if m:
            return m.group(1)
    return ""


def _safe(name: str, maxlen: int = 60) -> str:
    name = re.sub(r"[<>:\"/\\|?*\x00-\x1f]", "_", name)
    name = re.sub(r"\s+", "-", name.strip()).strip("-_.")
    return name[:maxlen] or "unbekannt"


@dataclass
class Stats:
    mails: int = 0
    pdfs: int = 0
    invoices_2025: int = 0
    review: int = 0
    errors: int = 0
    seen_hashes: set = field(default_factory=set)


def _candidates(reader: ProtonMailReader):
    """(mailbox, uid) ohne Duplikate über alle Quellen. Jede Suche einzeln
    abgesichert — eine langsame/fehlschlagende Suche (z. B. das langsame
    'All Mail') darf den Lauf nicht abbrechen."""
    seen = set()
    searches = [("All Mail", {"from_": SENDER, "since_date": SINCE, "limit": 10_000_000})]
    searches += [(f, {"since_date": SINCE, "limit": 10_000_000}) for f in FOLDERS]
    for mailbox, kw in searches:
        try:
            uids = reader.search(mailbox=mailbox, **kw)
        except Exception as exc:  # noqa: BLE001 — Bulk-Lauf: Mail überspringen, weiter
            print(
                f"  [Warnung] Suche in {mailbox!r} fehlgeschlagen ({exc}) — übersprungen.",
                flush=True,
            )
            continue
        print(f"  [Quelle] {mailbox}: {len(uids)} Mails", flush=True)
        for uid in uids:
            if (mailbox, uid) not in seen:
                seen.add((mailbox, uid))
                yield mailbox, uid


def main() -> int:
    if not SENDER:
        sys.exit("SCANNER_ADDR fehlt (Absenderadresse des Scanners, in docker/.env).")
    for s in (sys.stdout, sys.stderr):
        if hasattr(s, "reconfigure"):
            s.reconfigure(encoding="utf-8", errors="replace")
    OUT.mkdir(parents=True, exist_ok=True)
    st = Stats()
    used_names: set[str] = set()
    inv_rows, review_rows = [], []

    with ProtonMailReader(ImapConfig.from_env()) as reader:
        for mailbox, uid in _candidates(reader):
            st.mails += 1
            try:
                email = parse_email(uid, reader.fetch_raw(uid, mailbox))
            except Exception as exc:  # noqa: BLE001 — Bulk-Lauf: Mail überspringen, weiter
                st.errors += 1
                print(f"  [Fehler] {mailbox} UID {uid}: {exc}", flush=True)
                continue
            for att in email.attachments:
                if att.content_type != "application/pdf" and not att.filename.lower().endswith(
                    ".pdf"
                ):
                    continue
                st.pdfs += 1
                digest = hashlib.sha1(att.content).hexdigest()
                if digest in st.seen_hashes:
                    continue
                st.seen_hashes.add(digest)
                try:
                    text, method = extract_text(att.content, att.content_type, att.filename)
                except Exception as exc:  # noqa: BLE001 — Bulk-Lauf: Mail überspringen, weiter
                    st.errors += 1
                    print(f"  [OCR-Fehler] {mailbox} UID {uid} {att.filename}: {exc}", flush=True)
                    continue
                nr = _field(
                    text, "rechnungs-?nummer", "rechnungs-?nr", "rg\\.?-?nr", "beleg-?nr", "invoice"
                )
                netto = _amount(text, "nettobetrag", "netto", "zwischensumme")
                ust = _amount(text, "umsatzsteuer", "mehrwertsteuer", "mwst", "ust")
                brutto = _amount(
                    text,
                    "gesamtbetrag",
                    "rechnungsbetrag",
                    "zu zahlender betrag",
                    "zu zahlen",
                    "endbetrag",
                    "gesamtsumme",
                    "brutto",
                    "summe",
                )
                strict, loose, why = _is_invoice(text, bool(nr), bool(brutto or netto))
                bd, bdwhy, conf = _belegdatum(text)
                lieferant = _supplier(text, email.from_)
                row = {
                    "lieferant": lieferant,
                    "rechnungsnummer": nr,
                    "belegdatum": bd.isoformat() if bd else "",
                    "netto": netto,
                    "ust": ust,
                    "brutto": brutto,
                    "quelle": mailbox,
                    "uid": uid,
                    "betreff": email.subject,
                    "absender": email.from_,
                    "anhang": att.filename,
                    "ocr": method,
                    "begruendung": f"{why}; Datum {bdwhy}",
                }
                if strict and bd and bd.year == YEAR and conf:
                    base = f"{_safe(lieferant)}_{_safe(nr, 20) if nr else 'ohne-nr'}_{bd.strftime('%Y%m%d')}"
                    fname = base + ".pdf"
                    i = 2
                    while fname in used_names:
                        fname = f"{base}_{i}.pdf"
                        i += 1
                    used_names.add(fname)
                    (OUT / fname).write_bytes(att.content)
                    row["datei"] = fname
                    inv_rows.append(row)
                    st.invoices_2025 += 1
                    print(f"  ✓ {fname}  ({mailbox})", flush=True)
                elif loose:
                    row["datei"] = ""
                    review_rows.append(row)
                    st.review += 1

    # CSVs schreiben
    cols = [
        "datei",
        "lieferant",
        "rechnungsnummer",
        "belegdatum",
        "netto",
        "ust",
        "brutto",
        "quelle",
        "uid",
        "betreff",
        "absender",
        "anhang",
        "ocr",
        "begruendung",
    ]
    for path, rows in [(OUT / "index.csv", inv_rows), (OUT / "zur_pruefung.csv", review_rows)]:
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            w.writerows(rows)

    summary = (
        f"Steuerlauf 2025 — Quellen: {SENDER} + {', '.join(FOLDERS)}\n"
        f"Mails geprüft: {st.mails} | PDFs: {st.pdfs} | "
        f"2025-Rechnungen exportiert: {st.invoices_2025} | "
        f"zur Prüfung (Rechnung, aber Datum != 2025/unklar): {st.review} | Fehler: {st.errors}\n"
    )
    (OUT / "_summary.txt").write_text(summary, encoding="utf-8")
    print("\n" + summary, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
