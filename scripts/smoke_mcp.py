"""End-to-End-Smoke-Test des MCP-Servers über echtes Streamable-HTTP.

Verbindet sich mit Bearer-Token, listet die sechs Tools, ruft list_mailboxes,
search_emails, get_email, get_attachment_text auf und prüft, dass get_attachment
je nach Token-Scope entweder liefert oder mit Scope-Fehler abgelehnt wird.

    MCP_URL           Default http://127.0.0.1:8080/mcp
    MCP_SMOKE_TOKEN   das Token, mit dem getestet wird (Pflicht)

Im Docker-Netz des Agenten (per docker run im selben Netz):
    MCP_URL=http://proton-mcp:8080/mcp MCP_SMOKE_TOKEN=… python scripts/smoke_mcp.py
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import sys

from dotenv import load_dotenv
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

load_dotenv()

for _s in (sys.stdout, sys.stderr):
    if hasattr(_s, "reconfigure"):
        _s.reconfigure(encoding="utf-8", errors="replace")

URL = os.getenv("MCP_URL", f"http://127.0.0.1:{os.getenv('MCP_PORT', '8080')}/mcp")
TOKEN = os.getenv("MCP_SMOKE_TOKEN") or os.getenv("MCP_AUTH_TOKEN", "")
EXPECTED_TOOLS = {
    "list_mailboxes",
    "search_emails",
    "get_email",
    "get_attachment",
    "get_attachment_text",
    "get_attachment_image",
}


def _unwrap(result):
    """Strukturierte Tool-Ausgabe holen — erst structuredContent, sonst Text-JSON."""
    if result.isError:
        raise RuntimeError(result.content[0].text if result.content else "Tool-Fehler")
    sc = result.structuredContent
    if sc is not None:
        return sc.get("result", sc) if isinstance(sc, dict) else sc
    return json.loads(result.content[0].text)


async def main() -> int:
    if not TOKEN:
        sys.exit("MCP_SMOKE_TOKEN fehlt.")
    ok = True
    headers = {"Authorization": f"Bearer {TOKEN}"}
    async with streamablehttp_client(URL, headers=headers) as (read, write, _):  # noqa: SIM117
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = {t.name for t in (await session.list_tools()).tools}
            print("Tools:", sorted(tools))
            if tools != EXPECTED_TOOLS:
                print("  ✗ erwartet:", sorted(EXPECTED_TOOLS))
                ok = False

            mbx = _unwrap(await session.call_tool("list_mailboxes", {}))
            print(f"Mailboxes: {len(mbx)}")

            rows = _unwrap(
                await session.call_tool("search_emails", {"mailbox": "INBOX", "limit": 5})
            )
            print(f"search_emails -> {len(rows)} Treffer")
            att_uid = None
            for r in rows:
                print(f"  UID {r['uid']}: {r['subject'][:50]!r} att={r['attachment_count']}")
                if r["attachment_count"] and att_uid is None:
                    att_uid = r["uid"]

            if att_uid is None:
                print("(keine Mail mit Anhang in den letzten 5 — Anhangstests übersprungen)")
            else:
                email = _unwrap(await session.call_tool("get_email", {"uid": att_uid}))
                print(
                    f"get_email UID {att_uid}: {len(email['attachments'])} Anhang(e), "
                    f"text {len(email['text_body'])} Zeichen, quelle={email['text_source']}, "
                    f"gekürzt={email['truncated']}"
                )
                txt = _unwrap(await session.call_tool("get_attachment_text", {"uid": att_uid}))
                print(
                    f"get_attachment_text: {txt['filename']} method={txt['method']} "
                    f"{len(txt['text'])} Zeichen"
                )

                res = await session.call_tool("get_attachment", {"uid": att_uid})
                if res.isError:
                    msg = res.content[0].text if res.content else ""
                    if "Scope" in msg or "scope" in msg:
                        print("get_attachment: abgelehnt wie erwartet ohne proton.attachments ✓")
                    else:
                        print(f"  ✗ get_attachment unerwarteter Fehler: {msg[:200]}")
                        ok = False
                else:
                    data = _unwrap(res)
                    raw = base64.b64decode(data["content_base64"])
                    print(
                        f"get_attachment: {data['filename']} ({data['size']} B) magic={raw[:4]!r} "
                        f"— Token hat proton.attachments"
                    )
    print("\nMCP-Server end-to-end OK. ✓" if ok else "\nMCP-Server end-to-end: FEHLER ✗")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
