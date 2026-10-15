"""Read-only IMAP-Zugriff auf Proton Mail über die Proton Bridge.

Dieser Kern kennt ausschließlich Lese-Operationen. Es gibt bewusst keine
Methoden zum Senden, Löschen, Verschieben oder Taggen — die stärkste
Anti-Exfiltrations-Garantie ist, dass solche Pfade gar nicht existieren.
"""

from __future__ import annotations

import ssl
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Self

from imapclient import IMAPClient

from .config import ImapConfig
from .headers import decode_mime_header


def _build_ssl_context(verify: bool) -> ssl.SSLContext:
    """SSL-Kontext für STARTTLS.

    Proton Bridge liefert ein selbstsigniertes Zertifikat. `verify=False`
    überspringt die Prüfung — nur fürs lokale/Docker-interne Bridge-IMAP
    akzeptabel, nirgends sonst.
    """
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


@dataclass
class Attachment:
    """Ein Mail-Anhang."""

    filename: str
    content_type: str
    size: int
    content: bytes = field(repr=False)


@dataclass
class Email:
    """Eine geparste E-Mail inkl. Anhänge."""

    uid: int
    message_id: str
    subject: str
    from_: str
    to: str
    date: str
    text_body: str
    html_body: str
    attachments: list[Attachment]
    cc: str = ""
    reply_to: str = ""
    in_reply_to: str = ""
    references: list[str] = field(default_factory=list)
    list_unsubscribe: bool = False


@dataclass
class Summary:
    """Leichte Kurzinfo zu einer Mail (aus ENVELOPE + BODYSTRUCTURE, ohne
    Body-/Anhang-Download)."""

    uid: int
    subject: str
    from_: str
    to: str
    date: str
    has_attachment: bool
    attachment_count: int


# --- BODYSTRUCTURE-Helfer (Anhänge zählen ohne Download) ------------------


def _to_str(value) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return "" if value is None else str(value)


def _has_param(params, key: str) -> bool:
    """Param-Liste [name, wert, name, wert, ...] auf einen Schlüssel prüfen."""
    if not isinstance(params, (list, tuple)):
        return False
    for i in range(0, len(params) - 1, 2):
        if _to_str(params[i]).lower() == key:
            return True
    return False


def _iter_leaves(bs):
    """Über die Einzelteile einer (ggf. verschachtelten) BODYSTRUCTURE laufen."""
    if not isinstance(bs, (list, tuple)) or not bs:
        return
    if isinstance(bs[0], (list, tuple)):
        # multipart: führende Elemente sind Kind-Teile, danach kommt der Subtyp.
        for child in bs:
            if isinstance(child, (list, tuple)):
                yield from _iter_leaves(child)
            else:
                break
    else:
        yield bs


def _leaf_is_attachment(part) -> bool:
    """Wie message._is_attachment, aber auf BODYSTRUCTURE-Ebene (heuristisch):
    echter Anhang, wenn ein Dateiname vorliegt — außer inline-Bilder mit
    Content-ID."""
    if not isinstance(part, (list, tuple)) or len(part) < 7:
        return False

    has_name = _has_param(part[2] if len(part) > 2 else None, "name")
    disp_type = ""
    for el in part[7:]:
        if isinstance(el, (list, tuple)) and el and isinstance(el[0], (bytes, str)):
            t = _to_str(el[0]).lower()
            if t in ("attachment", "inline"):
                disp_type = t
                has_name = has_name or _has_param(el[1] if len(el) > 1 else None, "filename")
                break

    if not has_name:
        return False
    content_id = part[3] if len(part) > 3 else None
    return not (disp_type == "inline" and content_id)


def _count_attachments(bs) -> int:
    return sum(1 for leaf in _iter_leaves(bs) if _leaf_is_attachment(leaf))


def _format_addresses(addrs) -> str:
    """IMAP-ENVELOPE-Adressen ('Address'-Tupel) zu 'Name <a@b>' formatieren."""
    if not addrs:
        return ""
    out = []
    for a in addrs:
        name = decode_mime_header(getattr(a, "name", None))
        mailbox = _to_str(getattr(a, "mailbox", None))
        host = _to_str(getattr(a, "host", None))
        email = f"{mailbox}@{host}" if mailbox and host else (mailbox or host)
        out.append(f"{name} <{email}>" if name and email else (name or email))
    return ", ".join(p for p in out if p)


def _format_date(dt) -> str:
    if dt is None:
        return ""
    try:
        return dt.isoformat()
    except Exception:  # noqa: BLE001 — Aufräumen/Fremddaten dürfen nie werfen
        return str(dt)


class ProtonMailReader:
    """Read-only Client gegen die Proton-Bridge-IMAP-Schnittstelle."""

    def __init__(self, config: ImapConfig) -> None:
        self._config = config
        self._client: IMAPClient | None = None

    # --- Verbindung -------------------------------------------------------

    def connect(self) -> None:
        # ssl=False + explizites STARTTLS, weil Bridge auf 1143 STARTTLS spricht.
        # timeout verhindert hängende Requests bei nicht erreichbarer Bridge.
        client = IMAPClient(
            self._config.host,
            port=self._config.port,
            ssl=False,
            timeout=self._config.timeout,
        )
        try:
            client.starttls(ssl_context=_build_ssl_context(self._config.tls_verify))
            client.login(self._config.user, self._config.password)
        except Exception:
            # Scheitert STARTTLS/Login, ruft der Context-Manager close() nicht auf
            # (kein erfolgreiches __enter__) — Socket hier selbst schließen, sonst leakt er.
            try:
                client.shutdown()
            except Exception:  # noqa: BLE001, S110 — Aufräumen/Fremddaten dürfen nie werfen
                pass
            raise
        self._client = client

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.logout()
            except Exception:  # noqa: BLE001, S110 — Aufräumen darf nie werfen
                # Verbindung evtl. schon tot — Aufräumen darf nicht werfen.
                pass
            finally:
                self._client = None

    def __enter__(self) -> Self:
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    @property
    def _conn(self) -> IMAPClient:
        if self._client is None:
            raise RuntimeError(
                "Nicht verbunden. connect() aufrufen oder als Context-Manager nutzen."
            )
        return self._client

    # --- Lese-Operationen -------------------------------------------------

    def probe(self) -> None:
        """Bereitschaftsprobe für /readyz: angemeldet und INBOX lesend auswählbar (EXAMINE)."""
        self._conn.select_folder("INBOX", readonly=True)

    def neuester_eingang(self, mailbox: str = "All Mail") -> datetime | None:
        """INTERNALDATE der zuletzt eingegangenen Mail (höchste UID) — Frische-Signal für /readyz.

        Gemessen 06.10.2026: Ohne Internet nimmt die Bridge IMAP-Login und EXAMINE weiter an;
        dass sie keine Post mehr von Proton bekommt, sieht man nur am Alter der neuesten Mail.
        """
        self._conn.select_folder(mailbox, readonly=True)
        uids = self._conn.search(["ALL"])
        return self.fetch_internaldate(max(uids), mailbox) if uids else None

    def list_mailboxes(self) -> list[str]:
        """Alle Ordner/Labels auflisten."""
        return [name for _flags, _delim, name in self._conn.list_folders()]

    def search(
        self,
        mailbox: str = "INBOX",
        *,
        subject: str | None = None,
        from_: str | None = None,
        to: str | None = None,
        body: str | None = None,
        text: str | None = None,
        since_date: date | None = None,
        limit: int = 50,
    ) -> list[int]:
        """UIDs passender Mails zurückgeben (neueste zuerst) — ROHE Bridge-Suche.

        Achtung: Die Proton Bridge vergleicht mit dem kodierten Header/Text; Mehrwort- und
        Umlautbegriffe finden dort oft nichts (gemessen 06.10.2026). Für Menschen- und
        Agentensuchen `finde()` nehmen; `search()` bleibt für die Bulk-Skripte (Adressen, ALL).
        """
        self._conn.select_folder(mailbox, readonly=True)

        criteria: list = []
        text_values: list[str] = []
        for value, key in (
            (subject, "SUBJECT"),
            (from_, "FROM"),
            (to, "TO"),
            (body, "BODY"),
            (text, "TEXT"),
        ):
            if value:
                criteria.extend([key, value])
                text_values.append(value)
        if since_date is not None:
            criteria.extend(["SINCE", since_date])
        if not criteria:
            criteria = ["ALL"]

        # Umlaut-/Nicht-ASCII-Suchbegriffe brauchen ein explizites Charset.
        needs_utf8 = any(isinstance(v, str) and not v.isascii() for v in text_values)
        uids = (
            self._conn.search(criteria, charset="UTF-8")
            if needs_utf8
            else self._conn.search(criteria)
        )

        uids = sorted(uids, reverse=True)
        if limit is not None and limit >= 0:
            uids = uids[:limit]
        return uids

    def finde(
        self,
        mailbox: str = "INBOX",
        *,
        subject: str | None = None,
        from_: str | None = None,
        to: str | None = None,
        body: str | None = None,
        text: str | None = None,
        since_date: date | None = None,
        before_date: date | None = None,
        vor_uid: int | None = None,
        uidvalidity: int | None = None,
        limit: int = 50,
    ):
        """Robuste Suche, die auch deutsche Betreffe und Texte findet (siehe suche.py).

        ``uidvalidity`` (vom vorigen Blättern) wird geprüft: Hat die Bridge den Ordner neu
        aufgebaut, gelten alte UIDs nicht mehr — dann ValueError statt falscher Treffer."""
        from . import suche

        info = self._conn.select_folder(mailbox, readonly=True) or {}
        aktuell = info.get(b"UIDVALIDITY")
        if uidvalidity is not None and aktuell is not None and int(aktuell) != uidvalidity:
            raise ValueError(
                f"Ordner {mailbox!r} wurde neu aufgebaut (UIDVALIDITY geändert) — Suche ohne "
                "vor_uid neu beginnen."
            )
        erg = suche.finde(
            self._conn,
            subject=subject,
            from_=from_,
            to=to,
            body=body,
            text=text,
            since_date=since_date,
            before_date=before_date,
            vor_uid=vor_uid,
            limit=limit,
        )
        erg.uidvalidity = int(aktuell) if aktuell is not None else None
        return erg

    def unterhaltung(self, uid: int, mailbox: str = "INBOX", limit: int = 100):
        """Alle Mails der Unterhaltung, zu der ``uid`` gehört — gesucht in „All Mail"."""
        from . import suche

        self._conn.select_folder(mailbox, readonly=True)
        felder = "BODY.PEEK[HEADER.FIELDS (MESSAGE-ID IN-REPLY-TO REFERENCES)]"
        resp = self._conn.fetch([uid], [felder])
        kopf = next(
            (v for k, v in (resp.get(uid) or {}).items() if k.startswith(b"BODY[HEADER.FIELDS")),
            b"",
        )
        ids = set(suche.message_ids(kopf))
        if not ids:
            raise ValueError(
                f"Mail UID {uid} in {mailbox} hat keine Message-ID — keine Unterhaltung."
            )
        self._conn.select_folder(suche.ALLE_MAILS, readonly=True)
        return suche.unterhaltung(self._conn, ids, limit=limit)

    def fetch_echtheit(self, uids: list[int], mailbox: str = "INBOX") -> dict[int, dict]:
        """Echtheitsangaben (siehe echtheit.py) für mehrere Mails — nur die nötigen Kopfzeilen."""
        from . import echtheit

        if not uids:
            return {}
        self._conn.select_folder(mailbox, readonly=True)
        felder = " ".join(echtheit.KOPFZEILEN)
        resp = self._conn.fetch(uids, [f"BODY.PEEK[HEADER.FIELDS ({felder})]"])
        out: dict[int, dict] = {}
        for uid, data in resp.items():
            kopf = next((v for k, v in data.items() if k.startswith(b"BODY[HEADER.FIELDS")), b"")
            out[uid] = echtheit.aus_bytes(kopf)
        return out

    def fetch_summaries(self, uids: list[int], mailbox: str = "INBOX") -> dict[int, Summary]:
        """Kurzinfos (ENVELOPE + BODYSTRUCTURE) zu mehreren UIDs holen — ohne
        Body oder Anhänge herunterzuladen. attachment_count ist heuristisch
        (exakte Liste liefert get_email)."""
        if not uids:
            return {}
        self._conn.select_folder(mailbox, readonly=True)
        resp = self._conn.fetch(uids, ["ENVELOPE", "BODYSTRUCTURE"])
        out: dict[int, Summary] = {}
        for uid, data in resp.items():
            env = data.get(b"ENVELOPE")
            n = _count_attachments(data.get(b"BODYSTRUCTURE"))
            out[uid] = Summary(
                uid=uid,
                subject=decode_mime_header(getattr(env, "subject", None)) if env else "",
                from_=_format_addresses(getattr(env, "from_", None) if env else None),
                to=_format_addresses(getattr(env, "to", None) if env else None),
                date=_format_date(getattr(env, "date", None) if env else None),
                has_attachment=n > 0,
                attachment_count=n,
            )
        return out

    def fetch_size(self, uid: int, mailbox: str = "INBOX") -> int:
        """Größe einer Nachricht in Bytes (RFC822.SIZE) — ohne Download."""
        self._conn.select_folder(mailbox, readonly=True)
        resp = self._conn.fetch([uid], ["RFC822.SIZE"])
        if uid not in resp:
            raise KeyError(f"UID {uid} nicht in {mailbox} gefunden.")
        return int(resp[uid].get(b"RFC822.SIZE", 0))

    def fetch_raw(self, uid: int, mailbox: str = "INBOX", max_bytes: int | None = None) -> bytes:
        """Rohe RFC822-Nachricht zu einer UID holen.

        Abruf per ``BODY.PEEK[]`` statt ``RFC822``: ``RFC822`` entspricht ``BODY[]`` und setzt
        beim Server ``\\Seen`` — PEEK liest, ohne das Postfach zu verändern. imapclient liefert
        die Antwort trotzdem unter dem Schlüssel ``BODY[]``.

        `max_bytes` prüft vor dem Download die Servergröße und lehnt zu große
        Nachrichten ab — schützt den Server vor Speicherfressern aus fremder Hand.
        Bulk-Läufe lassen es weg (sie laufen lokal und wollen alles).
        """
        if max_bytes is not None:
            size = self.fetch_size(uid, mailbox)
            if size > max_bytes:
                raise ValueError(
                    f"Mail UID {uid} in {mailbox} ist {size / 1_048_576:.1f} MB groß; "
                    f"die Grenze liegt bei {max_bytes / 1_048_576:.0f} MB."
                )
        self._conn.select_folder(mailbox, readonly=True)
        resp = self._conn.fetch([uid], ["BODY.PEEK[]"])
        if uid not in resp or b"BODY[]" not in resp[uid]:
            raise KeyError(f"UID {uid} nicht in {mailbox} gefunden.")
        return resp[uid][b"BODY[]"]

    def fetch_internaldate(self, uid: int, mailbox: str = "INBOX") -> datetime | None:
        """Eingangszeitpunkt beim Server (INTERNALDATE), zeitzonenbewusst.

        Anders als der Date-Header setzt ihn nicht der Absender — taugt deshalb für
        Ordnernamen, die nach Eingang sortieren sollen.
        """
        self._conn.select_folder(mailbox, readonly=True)
        alt = self._conn.normalise_times
        self._conn.normalise_times = False  # Offset behalten statt in Ortszeit umrechnen
        try:
            resp = self._conn.fetch([uid], ["INTERNALDATE"])
        finally:
            self._conn.normalise_times = alt
        wert = resp.get(uid, {}).get(b"INTERNALDATE")
        return wert if isinstance(wert, datetime) else None

    @contextmanager
    def selected(self, mailbox: str) -> Iterator[None]:
        self._conn.select_folder(mailbox, readonly=True)
        yield
