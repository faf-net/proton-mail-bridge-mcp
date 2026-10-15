import asyncio
import json
import sys
import time

import pytest
from mcp.server.auth.provider import AccessToken, RefreshToken, RegistrationError
from mcp.shared.auth import OAuthClientInformationFull

from proton_mail.config import parse_static_tokens
from proton_mail.oauth import MinimalOAuthProvider, StaticTokenVerifier

CLAUDE_CB = "https://claude.ai/api/mcp/auth_callback"
TOK = "s" * 48


def _client(cid="c1", uri=CLAUDE_CB):
    return OAuthClientInformationFull(client_id=cid, redirect_uris=[uri])


def _provider(tmp_path, **kw):
    return MinimalOAuthProvider(
        static=StaticTokenVerifier(parse_static_tokens(f"h={TOK}")),
        state_file=str(tmp_path / "state.json"),
        allowed_redirect_uris=[CLAUDE_CB],
        **kw,
    )


def test_register_allowlisted_client_ok(tmp_path):
    p = _provider(tmp_path)
    asyncio.run(p.register_client(_client()))
    assert asyncio.run(p.get_client("c1")) is not None
    assert (tmp_path / "state.json").exists()


def test_register_rejects_foreign_redirect(tmp_path):
    p = _provider(tmp_path)
    with pytest.raises(RegistrationError) as e:
        asyncio.run(p.register_client(_client("evil", "https://attacker.example/cb")))
    assert e.value.error == "invalid_redirect_uri"
    assert asyncio.run(p.get_client("evil")) is None


def test_register_disabled_without_allowlist(tmp_path):
    p = MinimalOAuthProvider(state_file=str(tmp_path / "s.json"), allowed_redirect_uris=[])
    with pytest.raises(RegistrationError):
        asyncio.run(p.register_client(_client()))


def test_client_cap_evicts_only_idle_clients(tmp_path):
    p = _provider(tmp_path, max_clients=2)
    asyncio.run(p.register_client(_client("a")))
    asyncio.run(p.register_client(_client("b")))
    p._issue("b", ["proton.read"])  # b hat ein lebendes Token
    asyncio.run(p.register_client(_client("c")))  # verdrängt a (idle), nicht b
    assert asyncio.run(p.get_client("a")) is None
    assert asyncio.run(p.get_client("b")) is not None
    assert asyncio.run(p.get_client("c")) is not None


def test_static_token_via_provider(tmp_path):
    p = _provider(tmp_path)
    at = asyncio.run(p.load_access_token(TOK))
    assert at is not None and at.client_id == "static:h"
    assert asyncio.run(p.load_access_token("x" * 48)) is None


def test_issue_sets_refresh_expiry_and_prunes(tmp_path):
    p = _provider(tmp_path, token_ttl=1, refresh_ttl=1)
    tok = p._issue("c1", ["proton.read"])
    assert p._refresh[tok.refresh_token].expires_at is not None
    # abgelaufene Einträge künstlich altern lassen
    p._access[tok.access_token] = AccessToken(
        token=tok.access_token,
        client_id="c1",
        scopes=["proton.read"],
        expires_at=int(time.time()) - 5,
    )
    p._refresh[tok.refresh_token] = RefreshToken(
        token=tok.refresh_token,
        client_id="c1",
        scopes=["proton.read"],
        expires_at=int(time.time()) - 5,
    )
    assert asyncio.run(p.load_access_token(tok.access_token)) is None
    assert asyncio.run(p.load_refresh_token(_client(), tok.refresh_token)) is None
    p._save()
    data = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    assert data["access"] == {} and data["refresh"] == {}


def test_state_survives_reload_and_is_private(tmp_path):
    p = _provider(tmp_path)
    asyncio.run(p.register_client(_client()))
    tok = p._issue("c1", ["proton.read"])
    q = _provider(tmp_path)
    assert asyncio.run(q.get_client("c1")) is not None
    assert asyncio.run(q.load_access_token(tok.access_token)) is not None
    if sys.platform != "win32":
        assert (tmp_path / "state.json").stat().st_mode & 0o777 == 0o600
    # keine Temp-Reste vom atomaren Schreiben
    assert [f.name for f in tmp_path.iterdir()] == ["state.json"]


def test_corrupt_state_does_not_crash(tmp_path):
    (tmp_path / "state.json").write_text("{kaputt", encoding="utf-8")
    p = _provider(tmp_path)
    assert asyncio.run(p.get_client("c1")) is None
