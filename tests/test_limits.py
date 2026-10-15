import pytest

from proton_mail import mcp_server
from proton_mail.message import html_to_text
from proton_mail.ocr import DEFAULT_DPI, MAX_RENDER_PIXELS, fit_dpi

MB = 1024 * 1024


def test_attachment_cap():
    mcp_server.check_attachment_size(9 * MB, 10 * MB, "ok.pdf")
    with pytest.raises(ValueError) as e:
        mcp_server.check_attachment_size(11 * MB, 10 * MB, "gross.pdf")
    assert "10 MB" in str(e.value) and "gross.pdf" in str(e.value)


def test_truncate():
    text = "x" * 100
    assert mcp_server._truncate(text, 200) == (text, False)
    cut, truncated = mcp_server._truncate(text, 40)
    assert truncated and cut.startswith("x" * 40) and "60 Zeichen" in cut
    # 0/negativ hiess frueher "ungekuerzt" - jetzt greift die harte Obergrenze.
    assert mcp_server._truncate(text, 0) == (text, False)
    big = "y" * (mcp_server.MAX_CHARS_CAP + 10)
    for wert in (0, -1, 10**9):
        cut, truncated = mcp_server._truncate(big, wert)
        assert truncated and cut.startswith("y" * mcp_server.MAX_CHARS_CAP) and "10 Zeichen" in cut


def test_parse_since():
    assert mcp_server._parse_since(None) is None
    assert str(mcp_server._parse_since("2026-09-13")) == "2026-09-13"
    with pytest.raises(ValueError):
        mcp_server._parse_since("13.09.2026")


def test_html_to_text_strips_noise_and_keeps_structure():
    html = (
        "<html><head><title>T</title><style>p{display:none}</style></head><body>"
        "<script>alert('x')</script><p>Hallo&nbsp;Frank,</p><div>Rechnung <b>1.234,56 EUR</b></div>"
        "<ul><li>eins</li><li>zwei</li></ul><span style='display:none'>versteckt</span></body></html>"
    )
    out = html_to_text(html)
    assert "alert" not in out and "display:none" not in out and "T\n" not in out
    assert "Hallo Frank," in out or "Hallo Frank," in out
    assert "Rechnung 1.234,56 EUR" in out
    assert "eins\nzwei" in out
    # Versteckter Text bleibt Text — das ist bewusst: kein CSS-Verständnis, keine Illusion.
    assert "versteckt" in out


def test_html_to_text_empty_and_broken():
    assert html_to_text("") == ""
    # Bis zum Ende offenes Tag: wie im Mailprogramm unsichtbar - auf jedem Python-Patch-Stand.
    assert html_to_text("<p nur text") == ""
    assert html_to_text("sichtbar <b versteckt bis zum Ende") == "sichtbar"
    assert html_to_text("<p>sichtbar</p><!-- offen bis zum Ende") == "sichtbar"
    # Ein "<" ohne Tag-Anfang bleibt Text, ein geschlossenes Tag wird normal behandelt.
    assert html_to_text("a < b und c") == "a < b und c"
    assert html_to_text("Preis <b>5 EUR</b>") == "Preis 5 EUR"


def test_fit_dpi_normal_page_unchanged():
    # A4 = 595 x 842 pt -> bei 200 dpi 1654 x 2339 = 3,9 MP < 20 MP
    assert fit_dpi(595, 842) == DEFAULT_DPI


def test_fit_dpi_giant_page_is_reduced():
    # 200 x 200 Zoll "Seite" -> bei 200 dpi 1,6 Gigapixel
    w = h = 200 * 72
    d = fit_dpi(w, h)
    assert 1 <= d < DEFAULT_DPI
    pixels = (w * d / 72) * (h * d / 72)
    assert pixels <= MAX_RENDER_PIXELS * 1.01


def test_fit_dpi_degenerate():
    assert fit_dpi(0, 0) == DEFAULT_DPI
    assert fit_dpi(-1, 10) == DEFAULT_DPI


def test_scope_check_without_token_denies():
    with pytest.raises(PermissionError):
        mcp_server._require_scope(None, "proton.attachments")


def test_eight_tools_registered():
    names = {t.name for t in mcp_server.mcp._tool_manager.list_tools()}
    assert names == {
        "list_mailboxes",
        "search_emails",
        "get_email",
        "get_attachment",
        "get_attachment_text",
        "get_attachment_image",
        "get_thread",
        "anhang_ablegen",
    }
