"""Konfiguration aus Umgebungsvariablen (12-factor, keine Secrets im Code)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

# .env aus dem Projekt-Root laden, falls vorhanden (lokale Entwicklung).
load_dotenv()

# Scopes des MCP-Servers. `proton.read` deckt Listen, Suchen, Mailtext und
# Anhangs-TEXT ab; `proton.attachments` zusätzlich rohe Anhänge (base64) und
# Bild-Rendering. Ein textbasiertes lokales Modell (Hermes/qwen) braucht nur
# `proton.read` — so bleibt ein kompromittierter Client ohne Rohdaten-Abzug.
# `proton.ablage` (06.10.2026) erlaubt `anhang_ablegen`: der Server schreibt einen
# Anhang selbst ins Ablageverzeichnis, das Modell sieht nur Pfad/Größe/sha256.
SCOPE_READ = "proton.read"
SCOPE_ATTACHMENTS = "proton.attachments"
SCOPE_ABLAGE = "proton.ablage"
ALL_SCOPES = frozenset({SCOPE_READ, SCOPE_ATTACHMENTS, SCOPE_ABLAGE})
# Was das Alt-Token und OAuth-Clients (Variante B) bekommen bzw. anfordern dürfen.
# `proton.ablage` schreibt auf eine Platte — das gibt es nur ausdrücklich je Token.
LEGACY_SCOPES = frozenset({SCOPE_READ, SCOPE_ATTACHMENTS})

MIN_TOKEN_LEN = 24


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        raise RuntimeError(
            f"Umgebungsvariable {name} muss eine ganze Zahl sein, bekam {raw!r}."
        ) from None


def _required(name: str) -> str:
    val = os.getenv(name)
    if not val:
        raise RuntimeError(
            f"Pflicht-Umgebungsvariable {name} fehlt. Siehe .env.example und lege eine .env an."
        )
    return val


@dataclass(frozen=True)
class StaticToken:
    """Ein benanntes statisches Bearer-Token mit Scopes — je Konsument eines."""

    name: str
    token: str
    scopes: frozenset[str]


def parse_static_tokens(raw: str | None, legacy: str | None = None) -> tuple[StaticToken, ...]:
    """`MCP_STATIC_TOKENS` parsen.

    Format: ``name=token[:scope,scope];name2=token2`` — Einträge durch ``;`` getrennt,
    Scopes optional (Standard: nur ``proton.read``). Tokens dürfen kein ``:`` und
    kein ``;`` enthalten (Hex-Tokens aus ``openssl rand -hex 24`` sind unkritisch).
    ``legacy`` ist das alte Einzel-Token ``MCP_AUTH_TOKEN`` und erhält die Lese-Scopes
    (``LEGACY_SCOPES``), nicht ``proton.ablage``.
    """
    out: list[StaticToken] = []
    for entry in (raw or "").split(";"):
        entry = entry.strip()
        if not entry:
            continue
        if "=" not in entry:
            raise RuntimeError(f"MCP_STATIC_TOKENS: Eintrag ohne '=': {entry[:16]!r}…")
        name, rest = entry.split("=", 1)
        token, _, scope_part = rest.partition(":")
        name, token = name.strip(), token.strip()
        if not name:
            raise RuntimeError("MCP_STATIC_TOKENS: Eintrag ohne Namen.")
        if len(token) < MIN_TOKEN_LEN:
            raise RuntimeError(
                f"MCP_STATIC_TOKENS: Token für {name!r} fehlt oder ist kürzer als "
                f"{MIN_TOKEN_LEN} Zeichen."
            )
        scopes = frozenset(s.strip() for s in scope_part.split(",") if s.strip()) or frozenset(
            {SCOPE_READ}
        )
        unknown = scopes - ALL_SCOPES
        if unknown:
            raise RuntimeError(
                f"MCP_STATIC_TOKENS: unbekannte Scopes für {name!r}: {sorted(unknown)} "
                f"(erlaubt: {sorted(ALL_SCOPES)})."
            )
        out.append(StaticToken(name=name, token=token, scopes=scopes))
    if legacy:
        out.append(StaticToken(name="legacy", token=legacy, scopes=LEGACY_SCOPES))
    names = [t.name for t in out]
    if len(set(names)) != len(names):
        raise RuntimeError("MCP_STATIC_TOKENS: Token-Namen müssen eindeutig sein.")
    return tuple(out)


@dataclass(frozen=True)
class ImapConfig:
    """Verbindungsdaten zur Proton-Bridge-IMAP-Schnittstelle."""

    host: str
    port: int
    user: str
    password: str
    tls_verify: bool
    timeout: int

    @classmethod
    def from_env(cls) -> ImapConfig:
        return cls(
            host=os.getenv("IMAP_HOST", "127.0.0.1"),
            port=_int("IMAP_PORT", 1143),
            user=_required("BRIDGE_USER"),
            password=_required("BRIDGE_PASSWORD"),
            tls_verify=_bool("IMAP_TLS_VERIFY", default=False),
            # Socket-Timeout (Sek.): verhindert hängende Requests bei toter Bridge.
            timeout=_int("IMAP_TIMEOUT", 30),
        )


@dataclass(frozen=True)
class McpConfig:
    """Einstellungen für den read-only MCP-Server."""

    host: str
    port: int
    static_tokens: tuple[StaticToken, ...]
    oauth_enabled: bool
    oauth_issuer_url: str
    oauth_resource_url: str
    oauth_state_file: str | None
    oauth_allowed_redirect_uris: tuple[str, ...]
    max_attachment_bytes: int
    max_message_bytes: int
    log_level: str
    # anhang_ablegen: Zielverzeichnis (None = Werkzeug meldet "abgeschaltet"),
    # Größengrenze und optional der Pfad, unter dem der Konsument die Ablage sieht.
    drop_dir: str | None = None
    drop_max_bytes: int = 50 * 1024 * 1024
    drop_view: str | None = None
    # Abruf-Protokoll (JSON-Zeilen, rotierend); None = aus.
    audit_log: str | None = None
    # /readyz: nicht bereit, wenn im Frische-Ordner seit so vielen Stunden keine Mail kam
    # (Bridge ohne Verbindung zu Proton). 0 = aus.
    ready_frische_ordner: str = "All Mail"
    ready_max_post_alter_h: float = 0.0

    @classmethod
    def from_env(cls) -> McpConfig:
        # Standard-Issuer aus 127.0.0.1 (für lokale Tests); im Container via Env überschrieben.
        issuer = os.getenv("OAUTH_ISSUER_URL", "http://127.0.0.1:8080").rstrip("/")
        redirects = tuple(
            u.strip()
            for u in os.getenv(
                "OAUTH_ALLOWED_REDIRECT_URIS", "https://claude.ai/api/mcp/auth_callback"
            ).split(",")
            if u.strip()
        )
        return cls(
            host=os.getenv("MCP_HOST", "0.0.0.0"),
            port=_int("MCP_PORT", 8080),
            static_tokens=parse_static_tokens(
                os.getenv("MCP_STATIC_TOKENS"), os.getenv("MCP_AUTH_TOKEN") or None
            ),
            # OAuth-Authorization-Server (für claude.ai, Variante B) — standardmäßig AUS.
            # In Variante A prüft der Server nur statische Tokens.
            oauth_enabled=_bool("MCP_OAUTH_ENABLED", default=False),
            oauth_issuer_url=issuer,
            oauth_resource_url=os.getenv("OAUTH_RESOURCE_URL", issuer + "/mcp"),
            oauth_state_file=os.getenv("OAUTH_STATE_FILE") or None,
            oauth_allowed_redirect_uris=redirects,
            max_attachment_bytes=_int("MAX_ATTACHMENT_MB", 10) * 1024 * 1024,
            max_message_bytes=_int("MAX_MESSAGE_MB", 50) * 1024 * 1024,
            log_level=os.getenv("MCP_LOG_LEVEL", "info").lower(),
            drop_dir=os.getenv("ATTACHMENT_DROP_DIR") or None,
            drop_max_bytes=_int("ATTACHMENT_DROP_MAX_MB", 50) * 1024 * 1024,
            drop_view=(os.getenv("ATTACHMENT_DROP_VIEW") or "").rstrip("/") or None,
            audit_log=os.getenv("MCP_AUDIT_LOG") or None,
            ready_frische_ordner=os.getenv("READY_FRISCHE_ORDNER") or "All Mail",
            ready_max_post_alter_h=float(os.getenv("READY_MAX_POST_ALTER_H") or 0),
        )


@dataclass(frozen=True)
class ExportConfig:
    """Zielverzeichnis für den Export-Lauf."""

    export_dir: Path

    @classmethod
    def from_env(cls) -> ExportConfig:
        return cls(export_dir=Path(os.getenv("EXPORT_DIR", "./export")))
