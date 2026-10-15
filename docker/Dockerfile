# Multi-Stage: schlankes Laufzeit-Image für den read-only MCP-Server (amd64).
# Build-Kontext = Repo-Root. Basis-Images auf Digest gepinnt (13.09.2026).

ARG PYTHON_DIGEST=sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea

FROM python:3.12-slim@${PYTHON_DIGEST} AS build
COPY --from=ghcr.io/astral-sh/uv@sha256:b485bd65cc2cf1c9a93b3554012c9c3778cf7b1b5fd3d3096ce9e1226c97e1e6 /uv /bin/uv
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

# Erst nur Manifeste -> Layer-Cache für Dependencies.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project --no-dev

# Dann Projektcode und Projekt selbst installieren.
COPY src ./src
COPY README.md ./
RUN uv sync --frozen --no-dev

FROM python:3.12-slim@${PYTHON_DIGEST}
WORKDIR /app
# Tesseract-OCR (inkl. Deutsch) für gescannte PDFs / Bild-Anhänge.
RUN apt-get update \
    && apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-deu \
    && rm -rf /var/lib/apt/lists/*
# Unprivilegierter Nutzer; /data nimmt den OAuth-State (Variante B), sonst leer.
RUN useradd --create-home --uid 10001 app && mkdir -p /data && chown app:app /data
COPY --from=build /app/.venv /app/.venv
COPY src ./src
# HOME=/tmp: der Container läuft read-only, /tmp ist tmpfs (Tesseract, Caches).
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOME=/tmp
USER app
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3).status == 200 else 1)"]
CMD ["python", "-m", "proton_mail.mcp_server"]
