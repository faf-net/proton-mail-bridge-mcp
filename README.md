# Proton Mail Bridge MCP (read-only)

**English** · [Deutsch](#deutsch)

> **Unofficial.** This project is not affiliated with, endorsed by or supported by Proton AG.
> „Proton“ and „Proton Mail“ are trademarks of Proton AG.

A read-only connector that lets AI agents read a Proton Mail mailbox through the official
**Proton Mail Bridge** (IMAP). It provides an **MCP server** (Model Context Protocol, Streamable
HTTP) and a few **bulk export scripts** on top of a shared read-only core.

**Design principles**

- **No write path to the mailbox.** The core knows no method to send, delete, move, flag or tag.
  A test proves it statically and at runtime (`tests/test_nur_lesen.py`). Only `BODY.PEEK` is
  used, so reading never sets `\Seen`. SMTP is not exposed.
- **One token per consumer, with scopes:** `proton.read`, `proton.attachments`, `proton.ablage`.
  Checked inside every tool, not just at the transport.
- **Mail content is untrusted input.** Bodies are wrapped in random-nonce markers, invisible
  Unicode is stripped, every response carries `content_trust=untrusted_email`. Size, pixel and
  time limits against hostile attachments; a parser that survives broken and malicious mails.
- **No published port.** The MCP joins the agent's Docker network only.
- **Audit log** per tool call — who, what, when, how much — never mail content.
- **Authenticity per mail** from Proton's own SPF/DKIM/DMARC results, evaluated worst-case so a
  forged „pass“ header cannot mask a „fail“.
- **Search that works with umlauts and multiple words** — the Bridge compares IMAP `SEARCH`
  against encoded headers, so the server matches decoded text itself (see below, German).

**Tools:** `list_mailboxes`, `search_emails`, `get_thread`, `get_email`, `get_attachment_text`
(PDF text or OCR), `get_attachment`, `get_attachment_image` (render for vision models) and
`anhang_ablegen` (store an attachment in a shared folder without passing the bytes through the
model; strict file-name sanitising, extension allow-list, atomic writes, never outside the drop
directory).

**Quick start:** `uv sync --group dev`, copy `.env.example` to `.env`, then
`uv run proton-check` and `uv run python -m proton_mail.mcp_server`. Docker deployment with a
headless Bridge built from Proton's signed Debian package: [`docker/DEPLOY.md`](docker/DEPLOY.md).

The code comments and the detailed documentation below are in German.

**License:** MIT, see [`LICENSE`](LICENSE). Note: the dependency
[PyMuPDF](https://github.com/pymupdf/PyMuPDF) is licensed under **AGPL-3.0** (or a commercial
license from Artifex). The MIT license covers this project's own code; if you distribute or run
it as a network service together with PyMuPDF, the AGPL-3.0 terms of PyMuPDF apply to that
combination. Proton Mail Bridge itself is GPL-3.0 and is downloaded at build time, not included.

---

<a id="deutsch"></a>

## Deutsch

> **Inoffiziell.** Dieses Projekt steht in keiner Verbindung zur Proton AG und wird von ihr
> weder unterstützt noch gebilligt. „Proton“ und „Proton Mail“ sind Marken der Proton AG.

Eigenbau-Connector für **lesenden** Zugriff auf Proton Mail über die offizielle
**Proton Mail Bridge** (IMAP). Zwei Frontends auf einem gemeinsamen Lese-Kern:

1. **MCP-Server** — sieben Lese-Tools und `anhang_ablegen` (schreibt einen Anhang in einen
   Austauschordner, nie ins Postfach). Gedacht als Dienst ohne LAN-Port im Docker-Netz eines
   Agenten. Eine Anbindung von claude.ai über OAuth (Variante B) ist vorbereitet.
2. **Bulk-Läufe** — `export.py`, `tax_export.py`, `scanner_pdfs.py` laden Mails/Anhänge
   strukturiert auf die Platte (z. B. für Steuer oder ein Dokumentenarchiv).

Betrieb und Aufbau mit Docker: [`docker/DEPLOY.md`](docker/DEPLOY.md).

## Designprinzipien

- **Kein Schreibpfad ins Postfach.** Der Lese-Kern (`imap_client.py`) kennt keine Methode zum Senden,
  Löschen, Verschieben oder Taggen. Auch im Netz nicht: die Bridge exponiert nur IMAP (143),
  kein SMTP.
- **Ein Token je Konsument, mit Scopes.** `proton.read` (Listen, Suchen, Mailtext,
  Anhangs-Text), `proton.attachments` (rohe Anhänge, Bild-Rendering) und `proton.ablage`
  (`anhang_ablegen`, nur ausdrücklich je Token — nie für das Alt-Token oder OAuth-Clients).
  Die Prüfung sitzt im Tool, nicht nur im Client.
- **Grenzen gegen fremde Eingaben.** Mail-Cap 50 MB, Anhang-Cap 10 MB, Render-Cap 20 MP,
  OCR-Timeout, Textkürzung, HTML wird zu Text reduziert.
- **Kein Port ins LAN.** Der MCP tritt nur dem Docker-Netz des Agenten bei.

## Tools

| Tool | Scope | Liefert |
|---|---|---|
| `list_mailboxes` | read | Ordner und Labels |
| `get_thread` | read | ganze Unterhaltung (Message-ID/References/In-Reply-To in „All Mail“), älteste zuerst |
| `search_emails` | read | `{treffer, anzahl, durchsucht, ordner_ganz_durchsucht}`, Treffer mit uid, subject, from, to, date, Anhangszahl, max. 200 — Teiltext ohne Groß/klein, **Umlaute und mehrere Wörter funktionieren** (siehe unten); `before_date`; Blättern über 200 mit `vor_uid`/`naechste_vor_uid`, `uidvalidity` als Schutz |
| `get_email` | read | Text (bei Bedarf HTML→Text), Anhang-Metadaten; `include_html`, `max_chars` |
| `get_attachment_text` | read | PDF-Text oder OCR (`method`: pdf-text, ocr-pdf, ocr-image, encrypted, unsupported) |
| `get_attachment` | attachments | Anhang als base64 |
| `get_attachment_image` | attachments | erste PDF-Seite / Bild als PNG (Vision) |
| `anhang_ablegen` | ablage | legt einen Anhang im Austauschordner ab; liefert nur Pfad, Größe, MIME, sha256 |

### `anhang_ablegen`

Damit ein Agent einen Anhang „in den Ordner legen" kann, **ohne dass die Rohdaten durch das
Modell laufen**: Der Server holt die Bytes selbst und schreibt sie nach
`$ATTACHMENT_DROP_DIR` (z. B. eine Netzfreigabe, die der Agent ebenfalls eingehängt hat).

- **Adressierung** wie `get_attachment`: `uid`, `mailbox`, `index` ODER `filename`.
- **Ziel:** `Anhänge/<JJJJ-MM-TT> <Absender> (<Domain>) – <Betreff>/<Datei>`; das Datum
  ist der Eingang beim Server (IMAP `INTERNALDATE`, Europe/Berlin), nicht der fälschbare
  Date-Header (der nur als Rückfall); die Domain stammt aus der Absenderadresse. Mit
  `unterordner` (max. 3 Ebenen, z. B. `Steuer 2026`) stattdessen `Anhänge/<unterordner>/<Datei>`.
- **Sanitisierung** jedes Bestandteils: Unicode NFC, Steuer-, Format- und alle
  Default_Ignorable-Zeichen raus (RTL-Override, Nullbreite, Hangul-Füllzeichen, CGJ,
  Variationsselektoren), Punkt-Doppelgänger (U+2024, U+FE52, U+FF0E) → `_`,
  `< > : " / \ | ? *` → `_`, keine Punkte/Leerzeichen am Ende, reservierte Namen (`CON`,
  `NUL`, `COM¹`, `CONIN$` … auch mit Endung) mit `_` davor.
- **Längen:** je Bestandteil höchstens 200 UTF-8-Bytes (an Zeichengrenze, Endung bleibt;
  zusätzlich Datei 120, Ordner 100 Zeichen); der ganze Pfad ab der Freigabe (`Anhänge/…`)
  höchstens 240 UTF-16-Einheiten inkl. Reserve für ` (999)` — erst wird der Betreff gekürzt,
  dann der Dateistamm; reicht das nicht (langer `unterordner`), kommt ein Fehler.
- **Endungen nach Positivliste:** unverändert bleiben nur `pdf jpg jpeg png gif webp heic heif
  tif tiff bmp txt csv md xml json docx xlsx pptx odt ods odp rtf zip eml ics vcf mp3 m4a mp4
  mov`. Alles andere — auch ohne Endung, `.docm`, `.html`, `.svg`, `desktop.ini` — bekommt
  `.blockiert` angehängt; maßgeblich ist die letzte Endung (`rechnung.pdf.exe` → blockiert).
- **Agenten-Steuerdateien** (`CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md`, `AGENT.md`,
  `.mcp.json`, `GEMINI.md`, `QWEN.md`, `HERMES.md`, `SOUL.md`, `CONVENTIONS.md`, `CRUSH.md`,
  groß/klein egal) → `.txt` angehängt — geprüft vor der Positivliste. Führender Punkt → `_`.
  Jede Umbenennung steht in `hinweise`.
- **Kein Überschreiben** (` (2)`, ` (3)` …); liegt **derselbe Inhalt** (sha256) schon im
  Zielordner, kommt dessen Pfad mit Hinweis „bereits vorhanden" zurück, keine zweite Kopie.
  **Atomar** (Temp-Datei `.~ablage-*.tmp` im Zielordner, dann `rename`); verwaiste
  Temp-Dateien älter als 1 h räumt der Server vor der ersten Ablage je Prozess weg.
  **Nie außerhalb** des Ablageverzeichnisses (realpath-Prüfung, auch gegen Symlinks).
- **Grenze** `ATTACHMENT_DROP_MAX_MB` (Standard 50); die Mail-Grenze wird für dieses
  Werkzeug passend angehoben (base64 +33 %).
- **Fehlt die Ablage** (Freigabe nicht eingehängt, nicht beschreibbar, Variable leer), kommt
  eine klare Fehlermeldung — vor jeder Bridge-Abfrage.
- Rückgabe: `pfad`, `pfad_konsument`, `groesse`, `mime`, `sha256`, `dateiname_original`
  (höchstens 200 Zeichen, unsichtbare/Steuerzeichen als `‮` usw. sichtbar),
  `hinweise`. **Nie der Inhalt.** Das Log enthält nur UID, Größe und sha256-Präfix.

### Warum die Suche nicht einfach die Bridge fragt

Die Proton Bridge vergleicht IMAP-`SEARCH`-Begriffe mit dem **kodierten** Header/Text
(RFC 2047, Quoted-Printable, Base64). Gemessen: `SUBJECT "Zustellung fehlgeschlagen"` → 0,
`"Bestätigung"` → 0, `TEXT "Grüße"` → 0, aber `"Ihre_Bestellung"` → 1.
`suche.py` prüft deshalb die neuesten 25.000 Mails (mit Textsuche 3.000) selbst gegen den
dekodierten Betreff/Absender/Empfänger und den Mailtext (erste 128 KB) und fragt die Bridge
nur für Ältere grob nach dem längsten ASCII-Wort — teuer (auf rund 100.000 Mails 18–42 s), daher
nur, wenn das Fenster nicht reicht. Typisch 0,3–2 s, Worst Case (seltenes Wort in „All Mail")
rund 22 s. `reader.search()` bleibt die rohe Bridge-Suche für die Bulk-Skripte.

## Lokale Entwicklung

```bash
uv sync --group dev
cp .env.example .env            # Bridge-Zugangsdaten + MCP_STATIC_TOKENS eintragen
uv run proton-check             # IMAP gegen die lokale Bridge (127.0.0.1:1143)
uv run python -m proton_mail.mcp_server
MCP_SMOKE_TOKEN=… uv run python scripts/smoke_mcp.py
uv run ruff check src scripts tests && uv run pytest -q
```

Der Server startet auch ohne erreichbare Bridge — die IMAP-Verbindung wird erst beim
ersten Tool-Aufruf geöffnet.

## Konfiguration (Umgebung)

| Variable | Zweck |
|---|---|
| `BRIDGE_USER`, `BRIDGE_PASSWORD` | Bridge-Mailbox-Zugangsdaten (nicht das Proton-Passwort) |
| `IMAP_HOST`, `IMAP_PORT`, `IMAP_TLS_VERIFY`, `IMAP_TIMEOUT` | Bridge-IMAP; im Container `bridge:143` |
| `MCP_STATIC_TOKENS` | `name=token[:scope,scope];…` — siehe `docker/.env.example` |
| `MCP_AUTH_TOKEN` | Altform, ein Token mit `proton.read` + `proton.attachments` (Name `legacy`) |
| `MCP_OAUTH_ENABLED` | `true` schaltet den OAuth-Authorization-Server ein (Variante B) |
| `MCP_ALLOWED_HOSTS` | erlaubte Host-Header (DNS-Rebinding-Schutz) |
| `MAX_ATTACHMENT_MB`, `MAX_MESSAGE_MB` | Größen-Caps (10 / 50) |
| `ATTACHMENT_DROP_DIR` | Ablageverzeichnis für `anhang_ablegen`; leer = Werkzeug meldet „abgeschaltet" |
| `ATTACHMENT_DROP_MAX_MB` | Grenze für `anhang_ablegen` (50) |
| `ATTACHMENT_DROP_VIEW` | Pfad, unter dem der Konsument den Eltern-Ordner der Ablage sieht |
| `MCP_AUDIT_LOG` | Abruf-Protokoll (JSON-Zeilen), leer = aus |
| `READY_FRISCHE_ORDNER`, `READY_MAX_POST_ALTER_H` | `/readyz`: Ordner und Höchstalter der neuesten Mail |
| `OAUTH_ISSUER_URL`, `OAUTH_RESOURCE_URL`, `OAUTH_STATE_FILE`, `OAUTH_ALLOWED_REDIRECT_URIS` | nur Variante B |
| `EXPORT_DIR`, `SCANNER_ADDR`, `TAX_FOLDERS` | Bulk-Läufe |

## Projektstruktur

```
src/proton_mail/
  config.py          # Env-Konfiguration, Token-Parsing, Scopes
  imap_client.py     # Read-only IMAP-Kern (Proton Bridge), Größenprüfung
  message.py         # MIME-/Anhang-Parsing, HTML→Text
  ocr.py             # PDF-Text, OCR, Render — mit Pixel-/Zeit-Grenzen
  oauth.py           # StaticTokenVerifier (A) + MinimalOAuthProvider (B)
  mcp_server.py      # die Tools (async, Threads), /healthz, /readyz
  untrusted.py       # Mailinhalt als fremd kennzeichnen (Rahmen, unsichtbare Zeichen raus)
  audit.py           # Abruf-Protokoll: eine JSON-Zeile je Tool-Aufruf, nie Mailinhalt
  suche.py           # Suche trotz Bridge: grob beim Server, genau gegen dekodierten Text
  echtheit.py        # SPF/DKIM/DMARC + Proton-Spamwert je Mail, fälschungsfest ausgewertet
  ablage.py          # anhang_ablegen: Namensregeln, Verbote, atomares Schreiben
  export.py, tax_export.py, scanner_pdfs.py   # Bulk-Läufe
docker/
  Dockerfile, bridge.Dockerfile, bridge-entrypoint.sh, gpgparams
  compose.bridge.yaml  # Bridge-Stack — selten ändern (Recreate behält den Login)
  compose.mcp.yaml     # MCP-Stack — beliebig neu baubar
  DEPLOY.md, .env.example
scripts/
  smoke_mcp.py         # End-to-End-Test
  check_attachments.py # Anhangs-Text über viele Mails prüfen
tests/                 # pytest: Tokens/Scopes, Grenzen, OAuth, Ablage, Suche, nie schreibend
```

## Sicherheit

- Secrets nur in `.env`-Dateien, nie im Repo.
- Bridge-TLS ist selbstsigniert → `IMAP_TLS_VERIFY=false` nur im internen Docker-Netz.
- Kein Logging von Mailinhalten; Access-Log des Servers ist aus.
- Mailinhalt ist fremder Text: Text, HTML und Anhangstext stehen in einem Rahmen mit Zufallsmarke
  (`<<<MAILINHALT …>>>`), unsichtbare Unicode-Zeichen (Zero-Width, Bidi, Tag-Zeichen) werden
  entfernt, Kurzfelder geglättet, jede Antwort trägt `content_trust=untrusted_email`; dazu
  Server-Instructions und Tool-Annotationen. Das ist ein Hinweis ans Modell, kein Schutz — der
  Schutz bleibt der fehlende Schreibpfad ins Postfach.
- `max_chars` ist auf 100.000 gedeckelt, auch bei 0 oder negativen Werten.
- Abruf-Protokoll je Tool-Aufruf (`MCP_AUDIT_LOG`): wer, was, wann, wie groß — ohne Mailinhalt.
- Echtheit je Mail (`echtheit`): nur Protons eigene Prüfzeilen (`mail.protonmail.ch`), je Prüfung
  das schlechteste Ergebnis — eine vom Absender eingeschmuggelte „pass"-Zeile überdeckt kein
  „fail". Urteil `bestanden | teilweise | nicht_bestanden | ungeprueft | intern`; importierte
  Altpost (iCloud/Gmail) ist `ungeprueft`.
- **Beweistest „nie schreibend"** (`tests/test_nur_lesen.py`): statisch nur erlaubte IMAP-Methoden,
  jedes `select_folder` mit `readonly=True`, nur `BODY.PEEK`; zur Laufzeit alle Werkzeuge gegen
  einen IMAP-Nachbau, der jeden anderen Aufruf meldet.
- **CI** (`.github/workflows/tests.yml`): ruff, pytest, pip-audit bei jedem Push; Actions auf
  Commit-SHA gepinnt. Dependabot wöchentlich, ohne Major-Sprünge für mcp/imapclient.
- Abhängigkeiten gepinnt (`uv.lock`), Basis-Images auf Digest, Container read-only ohne Capabilities.

## Lizenz

MIT, siehe [`LICENSE`](LICENSE). Hinweis: Die Abhängigkeit
[PyMuPDF](https://github.com/pymupdf/PyMuPDF) steht unter **AGPL-3.0** (oder einer
kommerziellen Lizenz von Artifex). Die MIT-Lizenz gilt für den Code dieses Projekts; wer ihn
zusammen mit PyMuPDF weitergibt oder als Netzwerkdienst betreibt, unterliegt für diese
Kombination den AGPL-3.0-Bedingungen von PyMuPDF. Die Proton Mail Bridge selbst steht unter
GPL-3.0 und wird beim Bau heruntergeladen, nicht mitgeliefert.
