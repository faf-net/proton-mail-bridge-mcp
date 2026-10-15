# Betrieb mit Docker Compose

Zwei Compose-Stacks im Verzeichnis `docker/`, bewusst getrennt:

```
  compose.bridge.yaml   proton-bridge   nach dem Login selten anfassen
  compose.mcp.yaml      proton-mcp      frei, beliebig oft neu baubar

  Netze   proton_mailnet (internal, beide)   bridge:143 <- mcp
          proton-bridge_egress (nur bridge)  Proton-API (Internet)
          agent-net (extern, nur mcp)        das Netz des Agenten, der den MCP nutzt
  Daten   ${PROTON_DATA_DIR:-../data}/bridge-data (700)   Postfach-Cache + Keyring
          ${PROTON_DATA_DIR:-../data}/mcp-data    (700)   OAuth-State, Abruf-Protokoll
```

Der MCP veröffentlicht **keinen** Port. Er tritt dem Docker-Netz des Agenten bei und ist nur
dort unter `http://proton-mcp:8080/mcp` erreichbar.

## 1. Vorbereitung (einmalig)

```bash
cd docker
sudo install -d -m 700 ../data/bridge-data
sudo install -d -m 700 -o 10001 -g 10001 ../data/mcp-data
docker network create --internal proton_mailnet
docker network create agent_net          # oder ein bestehendes Netz per AGENT_NETWORK
```

## 2. Bridge-Stack und Login (interaktiv)

```bash
docker compose -f compose.bridge.yaml build
docker compose -f compose.bridge.yaml up -d
docker attach proton-bridge
#   Enter drücken -> >>> erscheint
>>> login          # Proton-Adresse, Passwort, 2FA-Code
>>> info           # zeigt IMAP-Benutzername und BRIDGE-PASSWORT — notieren
#   DETACHEN mit  Strg-P  dann  Strg-Q.  NIEMALS `exit` — das beendet die Bridge.
```

Login und Betrieb laufen in **einem** Prozess (eigener Entrypoint). Grund: Bei großen
Postfächern rotiert Proton das Refresh-Token während des ersten Syncs; ein getrennter
Init-Container verliert es („Invalid refresh token").

Der Entrypoint startet den Bridge-**Kern** (`bridge --cli`) direkt, nicht den Launcher
`proton-bridge`, der Updates selbst lädt. Updates kommen nur über einen Image-Rebuild mit
neuer `BRIDGE_VERSION`/`BRIDGE_SHA256`.

## 3. MCP-Stack

`docker/.env` aus `docker/.env.example` anlegen (`chmod 600`):

```
BRIDGE_USER=<Benutzername aus info>
BRIDGE_PASSWORD=<Bridge-Passwort aus info>
MCP_STATIC_TOKENS=agent=<openssl rand -hex 24>:proton.read
MCP_OAUTH_ENABLED=false
```

```bash
docker compose -f compose.mcp.yaml up -d --build
```

## 4. Prüfen

```bash
# aus einem Container im Agenten-Netz:
docker run --rm --network agent_net curlimages/curl -s http://proton-mcp:8080/healthz   # {"status":"ok"}
docker run --rm --network agent_net curlimages/curl -s -o /dev/null -w '%{http_code}\n' \
  -X POST http://proton-mcp:8080/mcp -H 'Host: proton-mcp:8080' \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' -d '{}'   # 401
# Ende-zu-Ende:
MCP_URL=http://proton-mcp:8080/mcp MCP_SMOKE_TOKEN=<Token> python scripts/smoke_mcp.py
```

## Betrieb

- **MCP neu bauen/starten:** `docker compose -f compose.mcp.yaml up -d --build`. Die Bridge bleibt
  unangetastet.
- **Bridge neu starten / neu erzeugen:** `restart` und auch ein Recreate behalten den Login
  (gemessen), weil Keyring (`.gnupg`, `.password-store`) und Bridge-Vault (`.config/protonmail`)
  im Bind-Mount `/root` liegen. Vorher `bridge-data` sichern.
- **Token rotieren:** neuen Wert in `MCP_STATIC_TOKENS`, MCP neu starten, Agent umstellen. Mehrere
  Konsumenten = mehrere Einträge, einzeln widerrufbar.
- **Bereitschaft:** `/healthz` ist reine Liveness (Docker-Healthcheck, prüft die Bridge bewusst
  nicht). `/readyz` macht eine IMAP-Probe (Login + EXAMINE INBOX), gecacht 60 s, und prüft das
  Alter der neuesten Mail in „All Mail" (`READY_MAX_POST_ALTER_H`). Grund: Eine Bridge ohne
  Verbindung zu Proton nimmt IMAP-Logins weiter an (gemessen). `/readyz` eignet sich als Ziel
  für einen Push-Monitor.
- **Abruf-Protokoll:** `MCP_AUDIT_LOG=/data/audit.jsonl`. Eine JSON-Zeile je Tool-Aufruf: Zeit,
  Token-Name, Tool, Ordner, UID, Suchkriterien (≤ 100 Zeichen), Mengen, Status, Dauer. Nie
  Betreff, Absender, Text oder Dateiname. Rotiert 5 × 5 MB.
- **Sicherung:** `bridge-data` enthält den kompletten Mail-Cache und den Keyring — nur
  verschlüsselt sichern (z. B. restic). Wichtig: Nach einem Zurückholen ist immer ein neuer
  Login nötig — Proton wechselt das Refresh-Token bei jedem Bridge-Start, ein gesichertes ist
  schnell ungültig (gemessen). Die Sicherung bewahrt Keyring, Konfiguration und Cache.
- **Bridge-Update:** `BRIDGE_VERSION` und `BRIDGE_SHA256` in `bridge.Dockerfile` setzen; der Bau
  prüft zusätzlich Protons Signatur gegen den festen Fingerabdruck `BRIDGE_KEY_FPR`
  (Release-Notes: github.com/ProtonMail/proton-bridge/releases). Ablauf: `build` → `docker stop
  -t 60 proton-bridge` → `bridge-data` sichern → `up -d` → IMAP-Probe. Rückweg: altes Image in
  die Compose-Datei, `up -d`.

## Bulk-Läufe (Export / Steuer / Scanner-PDFs)

Einmal-Container vom MCP-Image im Netz `proton_mailnet`, direkt am Bridge-IMAP — ohne die
200-Treffer-Deckelung des MCP-Tools, OCR im Image.

```bash
sudo install -d -m 700 -o 10001 -g 10001 ../data/export
docker run -d --name proton-tax-export --network proton_mailnet \
  --env-file .env \
  -e IMAP_HOST=bridge -e IMAP_PORT=143 -e IMAP_TLS_VERIFY=false -e IMAP_TIMEOUT=900 \
  -e EXPORT_DIR=/export -e HOME=/tmp --user 10001:10001 \
  -v "$PWD/../data/export:/export" \
  --entrypoint python proton-mail-mcp:2026-10-06 -m proton_mail.tax_export
#   scanner_pdfs.py: gleiches Muster, -m proton_mail.scanner_pdfs
```

Die Bridge muss voll synchronisiert sein. Scanner-Adresse (`SCANNER_ADDR`) und Quellordner
(`TAX_FOLDERS`, Komma-Liste) kommen aus `docker/.env`.

## Anhang: Anbindung über OAuth (Variante B)

`MCP_OAUTH_ENABLED=true` schaltet einen minimalen OAuth-2.1-Authorization-Server ein, etwa
für claude.ai. **Nur hinter einem Zugangsschutz betreiben**, der den Benutzer vor
`/authorize` prüft (z. B. ein Reverse Proxy mit Access-Gate und JWT-Prüfung). Der Server
selbst kennt keine Benutzer. Variablen: `OAUTH_ISSUER_URL`, `OAUTH_RESOURCE_URL`,
`OAUTH_STATE_FILE`, `OAUTH_ALLOWED_REDIRECT_URIS`.
