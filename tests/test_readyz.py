"""/readyz-Frische: Bridge nimmt Logins auch ohne Internet an — erst das Alter der Post verrät es."""

import dataclasses
from datetime import UTC, datetime, timedelta

from proton_mail import mcp_server


class _Reader:
    def __init__(self, neueste):
        self.neueste = neueste
        self.gefragt = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def probe(self):
        pass

    def neuester_eingang(self, mailbox):
        self.gefragt.append(mailbox)
        return self.neueste


def _mit(monkeypatch, grenze_h, neueste):
    r = _Reader(neueste)
    cfg = dataclasses.replace(mcp_server._mcp_cfg, ready_max_post_alter_h=grenze_h)
    monkeypatch.setattr(mcp_server, "_mcp_cfg", cfg)
    monkeypatch.setattr(mcp_server, "_reader", lambda: r)
    return r


def test_frische_post_ist_bereit(monkeypatch):
    r = _mit(monkeypatch, 36, datetime.now(UTC) - timedelta(hours=2))
    assert mcp_server._bridge_pruefen() == (True, "ok")
    assert r.gefragt == ["All Mail"]


def test_alte_post_ist_nicht_bereit(monkeypatch):
    _mit(monkeypatch, 36, datetime.now(UTC) - timedelta(hours=50))
    ok, grund = mcp_server._bridge_pruefen()
    assert ok is False and grund == "keine_neue_post_seit_50h"


def test_frische_aus_fragt_nicht(monkeypatch):
    r = _mit(monkeypatch, 0, None)
    assert mcp_server._bridge_pruefen() == (True, "ok")
    assert r.gefragt == []


def test_leerer_ordner_zaehlt_nicht_als_ausfall(monkeypatch):
    _mit(monkeypatch, 36, None)
    assert mcp_server._bridge_pruefen() == (True, "ok")
