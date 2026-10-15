#!/bin/bash
# Eigener Bridge-Entrypoint: EIN Dauerprozess für Login UND Betrieb.
#
# Bei großen Postfächern rotiert Proton das Refresh-Token während des Login-Syncs;
# ein getrennter init-Container persistiert das neue Token nicht, und der Daemon
# scheitert dann an "Invalid refresh token". Lösung: gpg/pass einmalig
# initialisieren, socat starten, und die Bridge im CLI-Modus als laufenden
# Prozess halten (echtes TTY via compose tty/stdin_open). Login erfolgt per
# `docker attach`, danach mit Ctrl-P Ctrl-Q detachen — der Prozess bleibt.
#
# Nur IMAP (143) wird im Netz exponiert. Bewusst KEIN SMTP (25): der MCP hat
# keinen Sendepfad, und das Netz soll auch keinen haben.
set -euo pipefail

: "${BRIDGE_BIN:=bridge}"

# gpg/pass nur beim ersten Start (frisches Volume) initialisieren.
if [ ! -f /root/.password-store/.gpg-id ]; then
    gpg --generate-key --batch /protonmail/gpgparams
    pass init pass-key
fi

# Bridge lauscht intern auf 1143; socat exponiert 143 im Netz.
socat TCP-LISTEN:143,fork,reuseaddr TCP:127.0.0.1:1143 &

exec "/protonmail/${BRIDGE_BIN}" --cli
