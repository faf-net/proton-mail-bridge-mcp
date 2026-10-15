"""Anhangstest über den laufenden MCP: sucht in mehreren Ordnern die erste Mail mit
Anhang, holt Text und Anhangs-Text und prüft, dass die Scope-gebundenen Tools
(get_attachment, get_attachment_image) mit einem reinen proton.read-Token abgelehnt werden.

    MCP_URL, MCP_SMOKE_TOKEN wie bei smoke_mcp.py
    MCP_CHECK_MAILBOXES  Komma-Liste, Default "RECHNUNGEN,STEUER,FINANZEN,INBOX,Archive"
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

for _s in (sys.stdout, sys.stderr):
    if hasattr(_s, "reconfigure"):
        _s.reconfigure(encoding="utf-8", errors="replace")

URL = os.getenv("MCP_URL", "http://proton-mcp:8080/mcp")
TOKEN = os.getenv("MCP_SMOKE_TOKEN", "")
MAILBOXES = [
    m.strip()
    for m in os.getenv("MCP_CHECK_MAILBOXES", "RECHNUNGEN,STEUER,FINANZEN,INBOX,Archive").split(",")
    if m.strip()
]


def un(r):
    if r.isError:
        return {"_error": r.content[0].text if r.content else "?"}
    sc = r.structuredContent
    return sc.get("result", sc) if isinstance(sc, dict) else json.loads(r.content[0].text)


async def main() -> int:
    if not TOKEN:
        sys.exit("MCP_SMOKE_TOKEN fehlt.")
    ok = True
    async with streamablehttp_client(URL, headers={"Authorization": f"Bearer {TOKEN}"}) as (  # noqa: SIM117
        r,
        w,
        _,
    ):
        async with ClientSession(r, w) as s:
            await s.initialize()
            hit = None
            for mb in MAILBOXES:
                rows = un(await s.call_tool("search_emails", {"mailbox": mb, "limit": 30}))
                if isinstance(rows, dict):
                    print(f"{mb}: Fehler {rows['_error'][:100]}")
                    continue
                cand = [x for x in rows if x["attachment_count"]]
                print(f"{mb}: {len(rows)} Treffer, {len(cand)} mit Anhang")
                if cand and hit is None:
                    hit = (mb, cand[0]["uid"], cand[0]["subject"][:40])
            if not hit:
                print("Keine Mail mit Anhang gefunden — Sync läuft vermutlich noch.")
                return 2
            mb, uid, subj = hit
            print(f"Test-Mail: {mb} UID {uid} {subj!r}")
            e = un(await s.call_tool("get_email", {"uid": uid, "mailbox": mb}))
            print(
                f"get_email: quelle={e['text_source']} text={len(e['text_body'])} Zeichen "
                f"gekürzt={e['truncated']} Anhänge={[(a['filename'][:30], a['size']) for a in e['attachments']][:3]}"
            )
            t = un(await s.call_tool("get_attachment_text", {"uid": uid, "mailbox": mb}))
            if "_error" in t:
                print("get_attachment_text: FEHLER", t["_error"][:120])
                ok = False
            else:
                print(
                    f"get_attachment_text: {t['filename'][:30]} method={t['method']} "
                    f"{len(t['text'])} Zeichen, Anfang: {t['text'][:80]!r}"
                )
            for tool in ("get_attachment", "get_attachment_image"):
                res = un(await s.call_tool(tool, {"uid": uid, "mailbox": mb}))
                err = res.get("_error", "") if isinstance(res, dict) else ""
                if "Scope" in err or "scope" in err:
                    print(f"{tool}: abgelehnt (Scope) ✓")
                elif err:
                    print(f"{tool}: unerwarteter Fehler: {err[:120]}")
                    ok = False
                else:
                    print(f"{tool}: LIEFERT — Token hat proton.attachments")
    print("\nAnhangstest OK ✓" if ok else "\nAnhangstest: FEHLER ✗")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
