import asyncio

import pytest

from proton_mail.config import (
    LEGACY_SCOPES,
    SCOPE_ABLAGE,
    SCOPE_READ,
    parse_static_tokens,
)
from proton_mail.oauth import StaticTokenVerifier

TOK_A = "a" * 48
TOK_B = "b" * 48


def test_parse_two_tokens_with_scopes():
    toks = parse_static_tokens(
        f"hermes={TOK_A}:proton.read;desktop={TOK_B}:proton.read,proton.attachments"
    )
    assert [t.name for t in toks] == ["hermes", "desktop"]
    assert toks[0].scopes == frozenset({SCOPE_READ})
    assert toks[1].scopes == LEGACY_SCOPES


def test_default_scope_is_read_only():
    (t,) = parse_static_tokens(f"x={TOK_A}")
    assert t.scopes == frozenset({SCOPE_READ})


def test_legacy_token_gets_all_scopes():
    toks = parse_static_tokens(None, legacy=TOK_A)
    assert toks[0].name == "legacy" and toks[0].scopes == LEGACY_SCOPES
    assert SCOPE_ABLAGE not in toks[0].scopes  # Schreiben nur ausdrücklich


def test_scope_ablage_parsebar():
    (t,) = parse_static_tokens(f"hermes={TOK_A}:proton.read,proton.ablage")
    assert t.scopes == frozenset({SCOPE_READ, SCOPE_ABLAGE})


def test_empty_is_fine():
    assert parse_static_tokens("") == ()
    assert parse_static_tokens(None) == ()


@pytest.mark.parametrize(
    "raw",
    [
        "kurz=abc",  # Token zu kurz
        f"x={TOK_A}:proton.write",  # unbekannter Scope
        f"x={TOK_A};x={TOK_B}",  # doppelter Name
        TOK_A,  # kein '='
        f"={TOK_A}",  # kein Name
    ],
)
def test_rejects_bad_entries(raw):
    with pytest.raises(RuntimeError):
        parse_static_tokens(raw)


def test_verifier_accepts_and_rejects():
    v = StaticTokenVerifier(parse_static_tokens(f"hermes={TOK_A}:proton.read;desk={TOK_B}"))
    hit = v.lookup(TOK_A)
    assert hit is not None
    assert hit.client_id == "static:hermes"
    assert hit.scopes == [SCOPE_READ]
    assert hit.expires_at is None
    assert v.lookup("c" * 48) is None
    assert v.lookup(TOK_A[:-1]) is None
    assert asyncio.run(v.verify_token(TOK_B)).client_id == "static:desk"
    assert len(v) == 2
