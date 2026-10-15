# Proton Bridge headless — eigener Bau aus dem OFFIZIELLEN Debian-Paket von Proton.
#
# Warum nicht mehr shenxn/protonmail-bridge: das Fremdimage wurde zuletzt am
# 02.04.2025 gebaut (Bridge 3.19.0) und ließ die Bridge sich zur Laufzeit selbst
# aktualisieren — das brach im Juni 2026 wegen fehlendem libfido2. Hier ist die
# Version festgenagelt, die Prüfsumme wird beim Bau verifiziert, und Updates
# kommen nur noch über einen Image-Rebuild mit neuer Version.
#
# Das .deb enthält drei Programme:
#   proton-bridge   Launcher (prüft und installiert Updates, startet dann bridge)
#   bridge          der eigentliche Kern (Go, IMAP/SMTP, --cli)
#   bridge-gui      Qt-Oberfläche — nicht kopiert, keine Qt-Abhängigkeiten
# Der Entrypoint startet standardmäßig den KERN direkt (BRIDGE_BIN=bridge) und
# umgeht so den Launcher-Autoupdate. Ob der Kern auch ohne Launcher restart-fähig
# ist, wurde im Betrieb gemessen (siehe DEPLOY.md).

# debian:bookworm-slim (12.15), Digest vom 06.10.2026.
ARG DEBIAN_DIGEST=sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

FROM debian:bookworm-slim@${DEBIAN_DIGEST} AS deb
ARG BRIDGE_VERSION=3.27.0-1
# sha256 von protonmail-bridge_3.27.0-1_amd64.deb, am 06.10.2026 aus dem Download berechnet.
ARG BRIDGE_SHA256=4ae1f9a38392379a08ab6cfb61b44078a339f55d1d366bbba0a0d9acf901e900
# Zweite Sicherung (seit 06.10.2026): Protons Signatur. Primärschlüssel der Bridge-Entwickler
# ("Proton Technologies AG (ProtonMail Bridge developers)"), Kennung E2C75D68E6234B07 wie in
# https://proton.me/support/verifying-bridge-package. Der Schlüssel wird mitgeladen, zählt
# aber nur, wenn die Signatur von genau diesem Fingerabdruck stammt.
ARG BRIDGE_KEY_FPR=D51E64D3E63EDC3EEF7864CEE2C75D68E6234B07
RUN apt-get update && apt-get install -y --no-install-recommends gnupg \
    && rm -rf /var/lib/apt/lists/*
ADD https://proton.me/download/bridge/protonmail-bridge_${BRIDGE_VERSION}_amd64.deb /tmp/bridge.deb
ADD https://proton.me/download/bridge/protonmail-bridge_${BRIDGE_VERSION}_amd64.deb.sig /tmp/bridge.deb.sig
ADD https://proton.me/download/bridge/bridge_pubkey.gpg /tmp/bridge_pubkey.gpg
RUN echo "${BRIDGE_SHA256}  /tmp/bridge.deb" | sha256sum -c - \
    && export GNUPGHOME="$(mktemp -d)" \
    && gpg -q --import /tmp/bridge_pubkey.gpg \
    && gpg --status-fd 1 --verify /tmp/bridge.deb.sig /tmp/bridge.deb 2>/dev/null \
       | grep -qE "^\[GNUPG:\] VALIDSIG .* ${BRIDGE_KEY_FPR}$" \
    && echo "Proton-Signatur gueltig (${BRIDGE_KEY_FPR})" \
    && mkdir -p /x && dpkg-deb -x /tmp/bridge.deb /x \
    && test -x /x/usr/lib/protonmail/bridge/bridge \
    && test -x /x/usr/lib/protonmail/bridge/proton-bridge

FROM debian:bookworm-slim@${DEBIAN_DIGEST}
# Laufzeit des Go-Kerns (keine Qt): Keyring über pass/gpg (libsecret als Fallback),
# libfido2 (seit Bridge 3.25 verlangt), socat exponiert 1143 als 143 im Netz.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates libsecret-1-0 libglib2.0-0 libfido2-1 pass gnupg socat \
    && rm -rf /var/lib/apt/lists/*
COPY --from=deb /x/usr/lib/protonmail/bridge/bridge /protonmail/bridge
COPY --from=deb /x/usr/lib/protonmail/bridge/proton-bridge /protonmail/proton-bridge
COPY docker/gpgparams docker/bridge-entrypoint.sh /protonmail/
RUN chmod +x /protonmail/bridge-entrypoint.sh /protonmail/bridge /protonmail/proton-bridge
ENV BRIDGE_BIN=bridge
EXPOSE 143
ENTRYPOINT ["/protonmail/bridge-entrypoint.sh"]
