"""Token-Verifikation und minimaler OAuth-2.1-Provider für den MCP-Server.

Zwei Betriebsarten:

* **Variante A (Standard, `MCP_OAUTH_ENABLED=false`)** — der Server ist reiner
  Resource-Server. `StaticTokenVerifier` prüft benannte statische Bearer-Tokens
  mit Scopes (ein Token je Konsument, einzeln widerrufbar). Keine OAuth-Routen.

* **Variante B (`MCP_OAUTH_ENABLED=true`)** — zusätzlich der eingebaute
  Authorization-Server `MinimalOAuthProvider` für claude.ai: dynamische
  Client-Registrierung, Authorize/Token/Refresh, PKCE (vom SDK geprüft).
  `/authorize` genehmigt ohne eigenes Consent-UI — das setzt zwingend voraus,
  dass Cloudflare Access davor steht UND dass ein Gate den Access-JWT prüft
  (siehe DEPLOY.md, Anhang Variante B). Ohne beides ist B nicht freizugeben.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import secrets
import tempfile
import time
from collections.abc import Iterable
from pathlib import Path

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    RegistrationError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from .config import LEGACY_SCOPES, StaticToken

log = logging.getLogger("proton_mail.auth")

# OAuth-Clients (Variante B) bekommen nie proton.ablage — nur die Lese-Scopes.
DEFAULT_SCOPES = sorted(LEGACY_SCOPES)
CODE_TTL = 600  # Sekunden, Autorisierungscode kurzlebig
ACCESS_TTL = 3600
REFRESH_TTL = 30 * 24 * 3600
MAX_CLIENTS = 50


class StaticTokenVerifier:
    """Prüft benannte statische Bearer-Tokens (TokenVerifier-Protokoll des SDK).

    Der Vergleich läuft über ALLE Tokens ohne vorzeitigen Abbruch und mit
    `hmac.compare_digest`, damit die Antwortzeit nichts über Treffer verrät.
    """

    def __init__(self, tokens: Iterable[StaticToken]) -> None:
        self._tokens = tuple(tokens)

    def __len__(self) -> int:
        return len(self._tokens)

    def lookup(self, token: str) -> AccessToken | None:
        match: StaticToken | None = None
        for t in self._tokens:
            if hmac.compare_digest(token.encode("utf-8"), t.token.encode("utf-8")):
                match = t
        if match is None:
            return None
        return AccessToken(
            token=token,
            client_id=f"static:{match.name}",
            scopes=sorted(match.scopes),
            expires_at=None,
        )

    async def verify_token(self, token: str) -> AccessToken | None:
        return self.lookup(token)


class MinimalOAuthProvider(OAuthAuthorizationServerProvider):
    def __init__(
        self,
        static: StaticTokenVerifier | None = None,
        state_file: str | None = None,
        token_ttl: int = ACCESS_TTL,
        refresh_ttl: int = REFRESH_TTL,
        allowed_redirect_uris: Iterable[str] = (),
        max_clients: int = MAX_CLIENTS,
    ) -> None:
        self._clients: dict[str, OAuthClientInformationFull] = {}
        self._codes: dict[str, AuthorizationCode] = {}
        self._access: dict[str, AccessToken] = {}
        self._refresh: dict[str, RefreshToken] = {}
        self._static = static
        self._state_file = Path(state_file) if state_file else None
        self._ttl = token_ttl
        self._refresh_ttl = refresh_ttl
        self._allowed_redirects = frozenset(str(u).rstrip("/") for u in allowed_redirect_uris)
        self._max_clients = max_clients
        self._load()

    # --- Persistenz (überlebt Container-Neustarts) -----------------------

    def _load(self) -> None:
        if not self._state_file or not self._state_file.exists():
            return
        try:
            data = json.loads(self._state_file.read_text(encoding="utf-8"))
            self._clients = {
                k: OAuthClientInformationFull.model_validate(v)
                for k, v in data.get("clients", {}).items()
            }
            self._access = {
                k: AccessToken.model_validate(v) for k, v in data.get("access", {}).items()
            }
            self._refresh = {
                k: RefreshToken.model_validate(v) for k, v in data.get("refresh", {}).items()
            }
            self._prune()
        except Exception:
            # Korrupter/alter State darf den Start nicht verhindern — aber er
            # darf auch nicht STILL verschwinden: claude.ai muss dann neu autorisieren.
            log.exception("OAuth-State %s unlesbar — starte ohne Clients/Tokens", self._state_file)
            self._clients, self._access, self._refresh = {}, {}, {}

    def _prune(self) -> None:
        """Abgelaufene Codes und Tokens entfernen, damit der State nicht unbegrenzt wächst."""
        now = time.time()
        self._codes = {k: v for k, v in self._codes.items() if v.expires_at >= now}
        self._access = {
            k: v for k, v in self._access.items() if v.expires_at is None or v.expires_at >= now
        }
        self._refresh = {
            k: v for k, v in self._refresh.items() if v.expires_at is None or v.expires_at >= now
        }

    def _save(self) -> None:
        if not self._state_file:
            return
        self._prune()
        try:
            data = {
                "clients": {k: v.model_dump(mode="json") for k, v in self._clients.items()},
                "access": {k: v.model_dump(mode="json") for k, v in self._access.items()},
                "refresh": {k: v.model_dump(mode="json") for k, v in self._refresh.items()},
            }
            self._state_file.parent.mkdir(parents=True, exist_ok=True)
            # Atomar: erst Temp-Datei im selben Verzeichnis, dann umbenennen.
            fd, tmp = tempfile.mkstemp(dir=self._state_file.parent, prefix=".oauth_state.")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(data, fh)
                os.chmod(tmp, 0o600)
                os.replace(tmp, self._state_file)
            finally:
                if os.path.exists(tmp):
                    os.unlink(tmp)
        except Exception:
            # Persistenz ist best-effort; im Zweifel weiter in-memory.
            log.exception("OAuth-State %s konnte nicht geschrieben werden", self._state_file)

    # --- Client-Registrierung (RFC 7591) ---------------------------------

    def _live_client_ids(self) -> set[str]:
        return (
            {t.client_id for t in self._access.values()}
            | {t.client_id for t in self._refresh.values()}
            | {c.client_id for c in self._codes.values()}
        )

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self._clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        # Redirect-URIs nur aus der Allowlist — sonst kann sich jeder, der die
        # Registrierungs-Route erreicht, Codes auf eine eigene Adresse umleiten lassen.
        uris = [str(u).rstrip("/") for u in (client_info.redirect_uris or [])]
        if not self._allowed_redirects:
            raise RegistrationError(
                error="invalid_redirect_uri",
                error_description="Registrierung deaktiviert: keine erlaubten Redirect-URIs konfiguriert.",
            )
        bad = [u for u in uris if u not in self._allowed_redirects]
        if bad or not uris:
            log.warning("Client-Registrierung abgelehnt, redirect_uris=%s", uris)
            raise RegistrationError(
                error="invalid_redirect_uri",
                error_description="redirect_uri nicht erlaubt.",
            )
        if len(self._clients) >= self._max_clients:
            live = self._live_client_ids()
            for cid in [c for c in self._clients if c not in live]:
                del self._clients[cid]
        if len(self._clients) >= self._max_clients:
            raise RegistrationError(
                error="invalid_client_metadata",
                error_description="Zu viele registrierte Clients.",
            )
        self._clients[client_info.client_id] = client_info
        self._save()

    # --- Authorization Code Flow -----------------------------------------

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        # Kein eigenes Consent-UI: Der Zugriffsschutz für diesen Schritt liegt
        # bei Cloudflare Access plus JWT-Gate (Variante B, siehe DEPLOY.md).
        code = secrets.token_urlsafe(32)  # ~256 bit Entropie
        self._codes[code] = AuthorizationCode(
            code=code,
            scopes=params.scopes or DEFAULT_SCOPES,
            expires_at=time.time() + CODE_TTL,
            client_id=client.client_id,
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=params.resource,
        )
        return construct_redirect_uri(str(params.redirect_uri), code=code, state=params.state)

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        ac = self._codes.get(authorization_code)
        if ac and ac.client_id == client.client_id and ac.expires_at >= time.time():
            return ac
        return None

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        self._codes.pop(authorization_code.code, None)
        return self._issue(client.client_id, authorization_code.scopes)

    # --- Refresh ----------------------------------------------------------

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        rt = self._refresh.get(refresh_token)
        if (
            rt
            and rt.client_id == client.client_id
            and (rt.expires_at is None or rt.expires_at >= time.time())
        ):
            return rt
        return None

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        self._refresh.pop(refresh_token.token, None)  # Rotation
        return self._issue(client.client_id, scopes or refresh_token.scopes)

    # --- Token-Verifikation (auch fürs statische Token) ------------------

    async def load_access_token(self, token: str) -> AccessToken | None:
        if self._static is not None:
            hit = self._static.lookup(token)
            if hit is not None:
                return hit
        at = self._access.get(token)
        if at and (at.expires_at is None or at.expires_at >= time.time()):
            return at
        return None

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        self._access.pop(token.token, None)
        self._refresh.pop(token.token, None)
        self._save()

    # --- intern -----------------------------------------------------------

    def _issue(self, client_id: str, scopes: list[str]) -> OAuthToken:
        access = secrets.token_urlsafe(32)
        refresh = secrets.token_urlsafe(32)
        now = int(time.time())
        self._access[access] = AccessToken(
            token=access, client_id=client_id, scopes=scopes, expires_at=now + self._ttl
        )
        self._refresh[refresh] = RefreshToken(
            token=refresh, client_id=client_id, scopes=scopes, expires_at=now + self._refresh_ttl
        )
        self._save()
        return OAuthToken(
            access_token=access,
            token_type="Bearer",
            expires_in=self._ttl,
            scope=" ".join(scopes),
            refresh_token=refresh,
        )
