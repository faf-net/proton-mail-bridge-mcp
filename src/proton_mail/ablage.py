"""Anhänge serverseitig in ein Ablageverzeichnis schreiben (Werkzeug `anhang_ablegen`).

Der Zweck: Der Agent soll einen Anhang in den Austauschordner legen können, OHNE dass die
Rohdaten durch das Modell laufen. Der Server holt die Bytes selbst, schreibt sie und gibt
nur Pfad, Größe, MIME-Typ und sha256 zurück.

Alles hier ist bewusst ohne IMAP testbar: reine Namensfunktionen plus `ablegen()`, das nur
Bytes, einen Wunschnamen und ein Zielverzeichnis kennt.

Schutzregeln (siehe README, Abschnitt „anhang_ablegen"):
- jeder Pfadbestandteil wird sanitisiert (NFC, keine Steuer-/Format-/unsichtbaren Zeichen,
  keine Pfadtrenner, keine Windows-verbotenen Zeichen, keine reservierten DOS-Namen,
  höchstens 200 UTF-8-Bytes); der Gesamtpfad relativ zur Freigabe bleibt unter 240
  UTF-16-Einheiten;
- Endungen nach POSITIVLISTE: alles andere (auch ohne Endung) bekommt ".blockiert";
  Agenten-Steuerdateien (CLAUDE.md, AGENTS.md …) werden zu ".txt", führende Punkte zu "_";
- kein Überschreiben (" (2)", " (3)" …), gleicher Inhalt im Zielordner wird nicht doppelt
  abgelegt, atomares Schreiben über eine Temp-Datei, verwaiste Temp-Dateien werden geräumt;
- es wird nie außerhalb des Ablageverzeichnisses geschrieben (realpath-Prüfung).
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import stat
import threading
import time
import unicodedata
from dataclasses import dataclass, field
from datetime import date, datetime
from email.utils import parseaddr, parsedate_to_datetime

# Längen in Zeichen — zusätzlich gilt je Bestandteil die Byte-Grenze (CJK/Emoji brauchen
# 3–4 Bytes je Zeichen) und für den ganzen Pfad die UTF-16-Grenze.
MAX_DATEINAME = 120
MAX_ORDNER = 100
MAX_ABSENDER = 40
MAX_DOMAIN = 60
MAX_BETREFF = 60
MAX_UNTERORDNER_EBENEN = 3
MAX_BESTANDTEIL_BYTES = 200  # UTF-8 je Pfadbestandteil (ext4/btrfs: 255, SMB: 255 UTF-16)
MAX_PFAD_UTF16 = 240  # relativ zur Freigabe, also inkl. "Anhänge/" — Windows-260er-Grenze
KONFLIKT_RESERVE = 6  # Platz für " (999)" beim Ausweichen auf einen freien Namen
MAX_ORIGINAL_ANZEIGE = 200
TEMP_MAX_ALTER = 3600  # Sekunden; ältere ".~ablage-*"-Reste gelten als verwaist

# Positivliste: nur diese Endungen bleiben unverändert. Alles andere bekommt ".blockiert".
ERLAUBTE_ENDUNGEN = frozenset(
    {
        "pdf", "jpg", "jpeg", "png", "gif", "webp", "heic", "heif", "tif", "tiff", "bmp",
        "txt", "csv", "md", "xml", "json", "docx", "xlsx", "pptx", "odt", "ods", "odp",
        "rtf", "zip", "eml", "ics", "vcf", "mp3", "m4a", "mp4", "mov",
    }
)  # fmt: skip
BLOCKIERT_SUFFIX = ".blockiert"

# Dateien, die Coding-Agenten als Anweisung lesen — in einem Austauschordner gefährlich.
# Werden VOR der Endungsprüfung erkannt (".md" steht auf der Positivliste).
AGENTEN_DATEIEN = frozenset(
    {
        "claude.md", "claude.local.md", "agents.md", "agent.md", ".mcp.json", "gemini.md",
        "qwen.md", "hermes.md", "soul.md", "conventions.md", "crush.md",
    }
)  # fmt: skip

TEMP_PRAEFIX = ".~ablage-"

_WINDOWS_VERBOTEN = re.compile(r'[<>:"/\\|?*]')
_LEERRAUM = re.compile(r"\s+")
_RESERVIERT = re.compile(
    r"^(con|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³]|conin\$|conout\$)\s*(\..*)?$", re.IGNORECASE
)
_BETREFF_PRAEFIX = re.compile(r"^\s*((re|aw|wg|fw|fwd|antw)\s*(\[\d+\])?\s*:\s*)+", re.IGNORECASE)

# Unicode Default_Ignorable_Code_Point (DerivedCoreProperties) — unsichtbar, aber nicht alle
# in Kategorie Cf: Hangul-Füllzeichen (Lo), Variationsselektoren und CGJ (Mn) u. a.
_UNSICHTBAR = (
    (0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160),
    (0x17B4, 0x17B5), (0x180B, 0x180F), (0x200B, 0x200F), (0x202A, 0x202E),
    (0x2060, 0x206F), (0x3164, 0x3164), (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)  # fmt: skip
# Punkt-Doppelgänger: sähen wie eine Endung aus, sind aber keine → "_".
_PUNKT_DOPPELGAENGER = frozenset({"․", "﹒", "．"})
_WEG_KATEGORIEN = frozenset({"Cc", "Cf", "Cs", "Cn", "Co"})

# Ein Prozess, mehrere Threads (anyio): Namenswahl + rename unter einer Sperre, damit zwei
# gleichzeitige Ablagen desselben Namens sich nicht gegenseitig überschreiben.
_SPERRE = threading.Lock()


class AblageFehler(RuntimeError):
    """Ablage nicht möglich (Verzeichnis fehlt, nicht beschreibbar, zu groß …)."""


# --- Zeichen und Längen ------------------------------------------------------------


def _unsichtbar(ch: str) -> bool:
    cp = ord(ch)
    return any(a <= cp <= b for a, b in _UNSICHTBAR)


def _u16(s: str) -> int:
    """Länge in UTF-16-Einheiten (so zählen Windows/SMB)."""
    return sum(2 if ord(ch) > 0xFFFF else 1 for ch in s)


def _kuerze(s: str, max_zeichen: int, max_bytes: int) -> str:
    """Auf Zeichen- und UTF-8-Byte-Grenze kürzen, immer an einer Zeichengrenze."""
    s = s[: max(max_zeichen, 0)]
    b = s.encode("utf-8")
    if len(b) > max_bytes:
        s = b[: max(max_bytes, 0)].decode("utf-8", "ignore")
    return s.rstrip(" .")


def _kuerze_u16(s: str, max_einheiten: int) -> str:
    out, n = [], 0
    for ch in s:
        n += 2 if ord(ch) > 0xFFFF else 1
        if n > max_einheiten:
            break
        out.append(ch)
    return "".join(out).rstrip(" .")


def _reserviert_entschaerfen(s: str, max_zeichen: int, max_bytes: int) -> str:
    if _RESERVIERT.match(s):
        s = "_" + _kuerze(s, max_zeichen - 1, max_bytes - 1)
    return s


def bereinige(text: str, max_len: int, max_bytes: int = MAX_BESTANDTEIL_BYTES) -> str:
    """Einen einzelnen Pfadbestandteil sanitisieren. Kann einen Leerstring liefern."""
    s = unicodedata.normalize("NFC", text or "")
    # Steuerzeichen (Cc), Formatzeichen (Cf, u. a. RTL-Override U+202E), Surrogate, nicht
    # zugeordnete und private Zeichen sowie alle Default_Ignorable-Zeichen raus;
    # Zeilenumbrüche/Tabs werden zu Leerzeichen, Punkt-Doppelgänger zu "_".
    zeichen = []
    for ch in s:
        if ch in "\t\r\n":
            zeichen.append(" ")
        elif unicodedata.category(ch) in _WEG_KATEGORIEN or _unsichtbar(ch):
            continue
        elif ch in _PUNKT_DOPPELGAENGER:
            zeichen.append("_")
        else:
            zeichen.append(ch)
    s = unicodedata.normalize("NFC", "".join(zeichen))
    s = _WINDOWS_VERBOTEN.sub("_", s)  # enthält auch / und \ (Pfadtrenner)
    s = _LEERRAUM.sub(" ", s).strip()
    # Windows verträgt keine Punkte/Leerzeichen am Ende; ".." und "." fallen hier weg.
    s = _kuerze(s.rstrip(" ."), max_len, max_bytes)
    return _reserviert_entschaerfen(s, max_len, max_bytes)


def ordner_teil(text: str) -> str:
    """Ordnernamen-Bestandteil: wie `bereinige`, zusätzlich ohne führende Punkte
    (keine versteckten Ordner, kein Rest von "..")."""
    s = bereinige(text, MAX_ORDNER).lstrip(". ")
    return _reserviert_entschaerfen(s, MAX_ORDNER, MAX_BESTANDTEIL_BYTES)


def anzeige_original(roh: str) -> str:
    """Originalnamen für die Rückgabe: höchstens 200 Zeichen, unsichtbare und Steuerzeichen
    als \\uXXXX sichtbar — ein RTL-Override soll dem Modell nicht den Namen umdrehen."""
    s = roh or ""
    gekuerzt = len(s) > MAX_ORIGINAL_ANZEIGE
    out = []
    for ch in s[:MAX_ORIGINAL_ANZEIGE]:
        if unicodedata.category(ch) in _WEG_KATEGORIEN or _unsichtbar(ch):
            cp = ord(ch)
            out.append(f"\\u{cp:04x}" if cp <= 0xFFFF else f"\\U{cp:08x}")
        else:
            out.append(ch)
    return "".join(out) + ("…" if gekuerzt else "")


# --- Dateinamen ----------------------------------------------------------------------


def _letzte_endung(name: str) -> str:
    stamm, punkt, endung = name.rpartition(".")
    return endung.lower() if punkt and stamm else ""


def _teile_endung(name: str) -> tuple[str, str]:
    """(Stamm, Endung); ".pdf.blockiert" bleibt als Ganzes Endung."""
    rest, zusatz = name, ""
    if name.endswith(BLOCKIERT_SUFFIX):
        rest, zusatz = name[: -len(BLOCKIERT_SUFFIX)], BLOCKIERT_SUFFIX
    stamm, punkt, endung = rest.rpartition(".")
    if punkt and stamm and 0 < len(endung) <= 16:
        return stamm, "." + endung + zusatz
    return rest, zusatz


def _kuerze_mit_endung(name: str, max_zeichen: int, max_bytes: int) -> str:
    if len(name) <= max_zeichen and len(name.encode("utf-8")) <= max_bytes:
        return name
    stamm, endung = _teile_endung(name)
    if endung:
        stamm = _kuerze(stamm, max_zeichen - len(endung), max_bytes - len(endung.encode()))
        return (stamm or "_") + endung
    return _kuerze(name, max_zeichen, max_bytes)


def sicherer_dateiname(roh: str) -> tuple[str, list[str]]:
    """Dateinamen sanitisieren und Verbote anwenden. Liefert (Name, Hinweise)."""
    hinweise: list[str] = []
    # Sanitisieren ohne Längengrenze, Kürzen danach mit Rücksicht auf die Endung.
    name = bereinige(roh, 10_000, 40_000)
    if not name or set(name) <= {".", "_", " "}:
        name = "anhang"
        hinweise.append("Dateiname leer oder unbrauchbar — ersetzt durch 'anhang'.")
    # Agenten-Namen VOR der Endungsprüfung: ".md" steht auf der Positivliste.
    if name.lower() in AGENTEN_DATEIEN:
        name = name + ".txt"
        hinweise.append(f"Agenten-Steuerdatei {anzeige_original(roh)!r} — als .txt abgelegt.")
    if name.startswith("."):
        name = "_" + name.lstrip(".")
        hinweise.append("Führender Punkt im Dateinamen ersetzt (keine versteckten Dateien).")
    # Maßgeblich ist die LETZTE Endung nach der Sanitisierung (rechnung.pdf.exe → exe).
    endung = _letzte_endung(name)
    if endung not in ERLAUBTE_ENDUNGEN:
        name = name + BLOCKIERT_SUFFIX
        was = f"Endung .{endung} steht" if endung else "Keine Endung — der Name steht"
        hinweise.append(
            f"{was} nicht auf der Positivliste — mit '{BLOCKIERT_SUFFIX}' abgelegt, "
            "per Doppelklick nicht zu öffnen."
        )
    name = _kuerze_mit_endung(name, MAX_DATEINAME, MAX_BESTANDTEIL_BYTES - KONFLIKT_RESERVE)
    # Selbstprüfung: das Ergebnis endet entweder auf .blockiert oder auf einer erlaubten Endung.
    if not name.endswith(BLOCKIERT_SUFFIX) and _letzte_endung(name) not in ERLAUBTE_ENDUNGEN:
        name = name + BLOCKIERT_SUFFIX
    return name, hinweise


# --- Ordnernamen ---------------------------------------------------------------------


def absender_kurz(from_header: str) -> str:
    """Anzeigename plus Domain der Adresse: 'Finanzamt Musterstadt (evil.example)' — der
    Anzeigename ist frei wählbar, die Domain zeigt, wer wirklich geschickt hat."""
    name, adresse = parseaddr(from_header or "")
    kurz = name.strip().strip('"').strip() or adresse.split("@", 1)[0]
    kurz = bereinige(kurz, MAX_ABSENDER) or "unbekannt"
    domain = bereinige(adresse.rpartition("@")[2].lower(), MAX_DOMAIN) if "@" in adresse else ""
    return f"{kurz} ({domain})" if domain else kurz


def _lokal(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt
    try:
        from zoneinfo import ZoneInfo

        return dt.astimezone(ZoneInfo("Europe/Berlin"))
    except Exception:  # noqa: BLE001 — Fremddaten dürfen den Dienst nie abbrechen
        return dt


def mail_datum(date_header: str, heute: date | None = None, eingang: datetime | None = None) -> str:
    """Datum für den Ordnernamen: INTERNALDATE (Eingang beim Server, nicht fälschbar),
    sonst der Date-Header, sonst heute."""
    if eingang is not None:
        return _lokal(eingang).date().isoformat()
    try:
        return parsedate_to_datetime(date_header).date().isoformat()
    except (TypeError, ValueError, IndexError, OverflowError):
        return (heute or date.today()).isoformat()  # noqa: DTZ011 — Rückfall, Ortsdatum gewollt


@dataclass(frozen=True)
class MailOrdner:
    """Ordner '<Datum> <Absender (Domain)> – <Betreff>'. Bei zu langem Pfad wird zuerst
    der Betreff gekürzt — deshalb bleiben Kopf und Betreff getrennt."""

    kopf: str
    betreff: str

    def name(self) -> str:
        return ordner_teil(f"{self.kopf} – {self.betreff}")

    def gekuerzt(self, max_u16: int) -> str:
        voll = self.name()
        kopf = ordner_teil(self.kopf)
        grenze = max(max_u16, _u16(kopf))
        if _u16(voll) <= grenze:
            return voll
        return ordner_teil(_kuerze_u16(voll, grenze).rstrip(" –")) or kopf


def mail_ordner_teil(
    date_header: str, from_header: str, betreff: str, eingang: datetime | None = None
) -> MailOrdner:
    b = bereinige(_BETREFF_PRAEFIX.sub("", betreff or ""), MAX_BETREFF) or "ohne Betreff"
    return MailOrdner(f"{mail_datum(date_header, eingang=eingang)} {absender_kurz(from_header)}", b)


def mail_ordner(
    date_header: str, from_header: str, betreff: str, eingang: datetime | None = None
) -> str:
    """'<JJJJ-MM-TT> <Absender> (<Domain>) – <Betreff gekürzt>' — ein Bestandteil."""
    return mail_ordner_teil(date_header, from_header, betreff, eingang).name()


def unterordner_teile(unterordner: str | None) -> list[str]:
    """Optionalen Unterordner in sanitisierte Bestandteile zerlegen (max. 3 Ebenen)."""
    if not unterordner:
        return []
    teile = [ordner_teil(t) for t in re.split(r"[/\\]+", unterordner)]
    teile = [t for t in teile if t]
    if len(teile) > MAX_UNTERORDNER_EBENEN:
        raise AblageFehler(
            f"unterordner darf höchstens {MAX_UNTERORDNER_EBENEN} Ebenen haben, bekam {len(teile)}."
        )
    return teile


# --- Schreiben -----------------------------------------------------------------------


@dataclass
class Ablage:
    """Ergebnis einer Ablage — enthält nie den Inhalt."""

    pfad: str  # relativ zum Eltern-Ordner des Ablageverzeichnisses, z. B. "Anhänge/…/x.pdf"
    groesse: int
    mime: str
    sha256: str
    dateiname_original: str
    hinweise: list[str] = field(default_factory=list)


def _innerhalb(wurzel: str, pfad: str) -> bool:
    try:
        return os.path.commonpath([wurzel, pfad]) == wurzel
    except ValueError:
        return False


def pruefe_ablageverzeichnis(ablage_dir: str | None) -> str:
    """Ablageverzeichnis prüfen und dessen realpath liefern."""
    if not ablage_dir:
        raise AblageFehler(
            "Keine Ablage konfiguriert (ATTACHMENT_DROP_DIR fehlt) — Werkzeug ist abgeschaltet."
        )
    wurzel = os.path.realpath(ablage_dir)
    if not os.path.isdir(wurzel):
        raise AblageFehler(
            f"Ablageverzeichnis {ablage_dir} existiert nicht — ist die Freigabe eingehängt "
            "(Mount fehlt?)."
        )
    if not os.access(wurzel, os.W_OK | os.X_OK):
        raise AblageFehler(
            f"Ablageverzeichnis {ablage_dir} ist nicht beschreibbar — Mount fehlt oder "
            "Rechte (Gruppe) stimmen nicht."
        )
    return wurzel


def aufraeumen(ablage_dir: str | None, max_alter: float = TEMP_MAX_ALTER) -> int:
    """Verwaiste Temp-Dateien (".~ablage-*", älter als `max_alter` Sekunden) im ganzen
    Ablagebaum löschen. Folgt keinen Symlinks. Liefert die Zahl gelöschter Dateien."""
    wurzel = pruefe_ablageverzeichnis(ablage_dir)
    grenze = time.time() - max_alter
    geloescht = 0
    for ordner, _dirs, dateien in os.walk(wurzel, followlinks=False):
        for name in dateien:
            if not name.startswith(TEMP_PRAEFIX):
                continue
            pfad = os.path.join(ordner, name)
            try:
                st = os.lstat(pfad)
                if stat.S_ISREG(st.st_mode) and st.st_mtime < grenze:
                    os.unlink(pfad)
                    geloescht += 1
            except FileNotFoundError:
                continue
    return geloescht


def _freier_name(ordner: str, name: str) -> str:
    if not os.path.lexists(os.path.join(ordner, name)):
        return name
    stamm, endung = _teile_endung(name)
    for n in range(2, 1000):
        kandidat = f"{stamm} ({n}){endung}"
        if not os.path.lexists(os.path.join(ordner, kandidat)):
            return kandidat
    raise AblageFehler(f"Zu viele gleichnamige Dateien für {name!r} in {ordner}.")


def _gleicher_inhalt(ordner: str, sha: str, groesse: int) -> str | None:
    """Name einer regulären Datei im Ordner mit gleichem sha256 — oder None."""
    try:
        eintraege = sorted(os.scandir(ordner), key=lambda e: e.name)
    except FileNotFoundError:
        return None
    for e in eintraege:
        if e.name.startswith(TEMP_PRAEFIX) or not e.is_file(follow_symlinks=False):
            continue
        try:
            if e.stat(follow_symlinks=False).st_size != groesse:
                continue
            h = hashlib.sha256()
            with open(e.path, "rb") as f:
                for block in iter(lambda: f.read(1 << 20), b""):
                    h.update(block)
        except OSError:
            continue
        if h.hexdigest() == sha:
            return e.name
    return None


def _pfad_einpassen(
    basis: str, ordner_teile: list[str | MailOrdner], name: str
) -> tuple[list[str], str, bool]:
    """Gesamtpfad (relativ zur Freigabe, inkl. Konflikt-Reserve) auf MAX_PFAD_UTF16
    bringen: zuerst den Betreff im Mail-Ordner kürzen, dann den Dateistamm."""
    eintraege: list[tuple[str, MailOrdner | None]] = [
        (t.name(), t) if isinstance(t, MailOrdner) else (ordner_teil(t), None) for t in ordner_teile
    ]
    teile = [s for s, _ in eintraege if s]
    mail = [(s, m) for s, m in eintraege if s and m is not None]

    def zuviel() -> int:
        return _u16("/".join([basis, *teile, name])) + KONFLIKT_RESERVE - MAX_PFAD_UTF16

    gekuerzt = False
    for s, m in mail:
        if zuviel() > 0:
            j = teile.index(s)
            neu = m.gekuerzt(_u16(s) - zuviel())
            if neu != s:
                teile[j], gekuerzt = neu, True
    if zuviel() > 0:
        stamm, endung = _teile_endung(name)
        stamm = _kuerze_u16(stamm, _u16(stamm) - zuviel())
        if stamm:
            name = stamm + endung
            gekuerzt = True
    if zuviel() > 0:
        raise AblageFehler(
            f"Zielpfad wäre länger als {MAX_PFAD_UTF16} Zeichen — kürzeren unterordner wählen."
        )
    return teile, name, gekuerzt


def ablegen(
    inhalt: bytes,
    dateiname: str,
    mime: str,
    ablage_dir: str | None,
    ordner_teile: list[str | MailOrdner],
    max_bytes: int,
) -> Ablage:
    """Bytes unter `<ablage_dir>/<ordner_teile…>/<sicherer Dateiname>` ablegen."""
    if len(inhalt) > max_bytes:
        raise AblageFehler(
            f"Anhang {anzeige_original(dateiname)!r} ist {len(inhalt) / 1_048_576:.1f} MB groß; "
            f"die Grenze für die Ablage liegt bei {max_bytes / 1_048_576:.0f} MB."
        )
    wurzel = pruefe_ablageverzeichnis(ablage_dir)
    name, hinweise = sicherer_dateiname(dateiname)
    teile, name, gekuerzt = _pfad_einpassen(os.path.basename(wurzel), ordner_teile, name)
    if gekuerzt:
        hinweise.append(f"Pfad gekürzt (Grenze {MAX_PFAD_UTF16} Zeichen ab der Freigabe).")

    ziel_ordner = os.path.realpath(os.path.join(wurzel, *teile))
    if not _innerhalb(wurzel, ziel_ordner):
        raise AblageFehler("Zielordner läge außerhalb des Ablageverzeichnisses — abgelehnt.")
    os.makedirs(ziel_ordner, exist_ok=True)
    # Nach dem Anlegen noch einmal: ein untergeschobener Symlink fiele hier auf.
    if not _innerhalb(wurzel, os.path.realpath(ziel_ordner)):
        raise AblageFehler("Zielordner läge außerhalb des Ablageverzeichnisses — abgelehnt.")

    sha = hashlib.sha256(inhalt).hexdigest()
    tmp = os.path.join(ziel_ordner, f"{TEMP_PRAEFIX}{secrets.token_hex(6)}.tmp")
    vorhanden: str | None = None
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(fd, "wb") as f:
            f.write(inhalt)
            f.flush()
            os.fsync(f.fileno())
        with _SPERRE:
            # Gleicher Inhalt schon da? Dann keine zweite Kopie (unter der Sperre, damit
            # zwei gleichzeitige Ablagen derselben Datei nicht beide schreiben).
            vorhanden = _gleicher_inhalt(ziel_ordner, sha, len(inhalt))
            if vorhanden is not None:
                final_name = vorhanden
                os.unlink(tmp)
            else:
                final_name = _freier_name(ziel_ordner, name)
            ziel = os.path.join(ziel_ordner, final_name)
            if not _innerhalb(wurzel, os.path.realpath(ziel)):
                raise AblageFehler("Zieldatei läge außerhalb des Ablageverzeichnisses — abgelehnt.")
            if vorhanden is None:
                os.rename(tmp, ziel)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
    if vorhanden is not None:
        hinweise.append(
            f"Datei bereits vorhanden — gleicher Inhalt (sha256) liegt schon als {vorhanden!r} "
            "im Zielordner; keine neue Kopie angelegt."
        )
    elif final_name != name:
        hinweise.append(f"Name war belegt — abgelegt als {final_name!r}.")

    basis = os.path.dirname(wurzel)
    rel = os.path.relpath(ziel, basis).replace(os.sep, "/")
    return Ablage(
        pfad=rel,
        groesse=len(inhalt),
        mime=mime,
        sha256=sha,
        dateiname_original=anzeige_original(dateiname),
        hinweise=hinweise,
    )
