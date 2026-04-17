# ─────────────────────────────────────────────────────────────────────────────
# Stage 1 — Dependency builder
#   Compiles wheels in an isolated layer so the final image never carries
#   build-time compilers or headers.  Keeps the shipped image under 300 MB.
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

# Prevents .pyc files and enables unbuffered stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

# Install only the tools needed to compile C-extension wheels
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy the pinned manifest first — Docker layer-caches this step as long as
# requirements.txt is unchanged, so rebuilds are fast.
COPY requirements.txt .

# Build wheels into an isolated prefix so we can COPY --from=builder cleanly
RUN pip install --upgrade pip --quiet \
 && pip install --prefix=/install --no-cache-dir -r requirements.txt


# ─────────────────────────────────────────────────────────────────────────────
# Stage 2 — Runtime image
#   Start from a fresh slim base, drop in the pre-built packages, then copy
#   only the application source.  No compiler, no build artifacts.
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    # /app — project root so `import shared`, `import agents` etc. always resolve
    # /install/... — wheels built in Stage 1 (aiosqlite, fastapi, streamlit …)
    PYTHONPATH=/app:/install/lib/python3.11/site-packages \
    # Default DB path — overridden by docker-compose env / .env file
    DB_PATH=/app/data/sentinel_audit.db

WORKDIR /app

# Pull compiled packages from the builder stage (no compiler needed here)
COPY --from=builder /install /install

# Symlink executables so `uvicorn` and `streamlit` are on PATH
RUN ln -s /install/bin/uvicorn   /usr/local/bin/uvicorn   2>/dev/null || true \
 && ln -s /install/bin/streamlit /usr/local/bin/streamlit 2>/dev/null || true

# Copy application source — intentionally ordered from least-changed to
# most-changed so Docker caches the expensive layers on top.
COPY agents/     ./agents/
COPY gateway/    ./gateway/
COPY judge/      ./judge/
COPY shared/     ./shared/
COPY frontend/   ./frontend/
# pages/ must live next to the main script so Streamlit's multi-page router
# finds Admin_Dashboard.py.  Copy into frontend/pages/ not project root.
COPY pages/      ./frontend/pages/
COPY data/       ./data/

# MED-01: Create a dedicated non-root user so that a container escape does not
# grant root-level access to the host filesystem.
# --home-dir /app sets a writable home so Streamlit can create ~/.streamlit.
RUN groupadd --system sentinel && \
    useradd --system --gid sentinel --no-create-home --home-dir /tmp sentinel

# Pre-create the data directory with correct ownership before switching user
RUN mkdir -p /app/data && chown -R sentinel:sentinel /app/data

USER sentinel

# Expose both service ports so the Compose file can map them without touching
# the image.  The actual binding is controlled by the CMD in Compose.
EXPOSE 8000 8501

# ── Default CMD (overridden per-service in docker-compose.yml) ────────────────
# Running the gateway by default makes `docker run` useful in isolation.
CMD ["uvicorn", "gateway.main:app", "--host", "0.0.0.0", "--port", "8000"]
