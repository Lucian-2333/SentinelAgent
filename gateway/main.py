"""
gateway/main.py
─────────────────────────────────────────────────────────────────────────────
SentinelAgent — Layer 1 (Traffic Interception Gateway)
FastAPI application that receives raw packets, stamps them with metadata,
and dispatches them into the N-agent audit pipeline.
─────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import JSONResponse

from gateway.router import audit_router
from shared.schemas import Packet, PacketMetadata, SourceType

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("sentinel.gateway")


# ──────────────────────────────────────────────────────────────────────────────
# Security Headers Middleware  (MED-06)
# Adds defensive HTTP headers to every response. Does not touch body or routing.
# ──────────────────────────────────────────────────────────────────────────────

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=()"
        # CSP: API-only service — no inline scripts, no external resources needed
        response.headers["Content-Security-Policy"] = "default-src 'none'"
        return response


# ──────────────────────────────────────────────────────────────────────────────
# API Key authentication
# Set SENTINEL_API_KEY in .env to enable.  Leave blank to disable (open access).
# Callers must send:  Authorization: Bearer <key>
# ──────────────────────────────────────────────────────────────────────────────

_API_KEY = os.getenv("SENTINEL_API_KEY", "").strip()


def _require_api_key(request: Request) -> None:
    """FastAPI dependency — rejects requests with a wrong or missing API key."""
    if not _API_KEY:
        return  # key not configured → open access (backward compatible)
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header. Use: Authorization: Bearer <api-key>",
            headers={"WWW-Authenticate": "Bearer"},
        )
    import secrets as _secrets
    if not _secrets.compare_digest(auth[len("Bearer "):].strip(), _API_KEY):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key.",
        )





@asynccontextmanager
async def lifespan(app: FastAPI):
    from shared.database import init_db  # deferred to keep imports tidy

    logger.info("🛡️  SentinelAgent Gateway starting up…")
    await init_db()  # ensure audit_logs table exists before first request
    yield
    logger.info("🛡️  SentinelAgent Gateway shutting down.")


app = FastAPI(
    title="SentinelAgent Gateway",
    description=(
        "Layer-1 traffic interception node for the SentinelAgent "
        "multi-agent firewall.  All inbound payloads are wrapped into "
        "immutable Packet objects before being dispatched to expert agents."
    ),
    version="0.1.0",
    lifespan=lifespan,
    # INFO-04: disable interactive API docs in all deployments.
    # The schema is still available programmatically via /openapi.json if needed.
    docs_url=None,
    redoc_url=None,
)

# CRIT-01: Restrict CORS to explicitly configured origins.
# Set CORS_ALLOWED_ORIGINS in .env as a comma-separated list, e.g.:
#   CORS_ALLOWED_ORIGINS=http://localhost:8501,https://your-domain.com
# Falls back to localhost-only when the variable is absent.
_raw_origins = os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:8501")
_allowed_origins = [o.strip() for o in _raw_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=False,     # no cookies / auth headers needed for this API
    allow_methods=["POST", "GET"],
    allow_headers=["Content-Type"],
)

app.add_middleware(SecurityHeadersMiddleware)

# Register sub-routers — attach API key dependency to every route in the router
app.include_router(
    audit_router,
    prefix="/api/v1",
    dependencies=[Depends(_require_api_key)],
)


# ──────────────────────────────────────────────────────────────────────────────
# Health & introspection
# ──────────────────────────────────────────────────────────────────────────────


@app.get("/health", tags=["meta"])
async def health_check():
    return {"status": "ok", "service": "sentinel-gateway"}


@app.get("/api/v1/demo/stream", tags=["demo"])
async def stream_mock_attacks():
    """
    Return the pre-canned attack stream from data/mock_attack_stream.json.
    Used by the scripted demo to drive the frontend without a live attacker.
    """
    stream_path = Path(__file__).parent.parent / "data" / "mock_attack_stream.json"
    if not stream_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Mock attack stream not found.  Run the project setup first.",
        )
    data = json.loads(stream_path.read_text(encoding="utf-8"))
    return JSONResponse(content=data)


# ──────────────────────────────────────────────────────────────────────────────
# Raw proxy endpoint — wraps arbitrary POST bodies into Packets
# ──────────────────────────────────────────────────────────────────────────────


@app.post("/api/v1/intercept", tags=["gateway"],
          dependencies=[Depends(_require_api_key)])
async def intercept(request: Request):
    """
    Universal interception endpoint.

    Accepts any JSON body with a `text` field (plus optional metadata),
    wraps it into a canonical Packet, and forwards it through the full
    audit pipeline synchronously, returning the ConsensusVerdict.
    """
    from judge.consensus import run_consensus_pipeline  # lazy import avoids cycles

    body = await request.json()
    raw_text = body.get("text", "")
    if not raw_text or not raw_text.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Request body must include a non-empty 'text' field.",
        )

    # HIGH-07: Validate source enum before constructing PacketMetadata.
    # An invalid value raises ValueError → return 422 instead of a 500.
    raw_source = body.get("source", SourceType.API_CALL)
    try:
        source = SourceType(raw_source)
    except ValueError:
        valid = [e.value for e in SourceType]
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid 'source' value '{raw_source}'. Must be one of: {valid}",
        )

    meta = PacketMetadata(
        source=source,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        endpoint=str(request.url.path),
        extra=body.get("extra", {}),
    )

    packet = Packet(
        packet_id=str(uuid.uuid4()),
        raw_text=raw_text,
        metadata=meta,
    )
    logger.info("Intercepted packet %s from %s", packet.packet_id, meta.source)

    verdict = await run_consensus_pipeline(packet)

    # ── Persist audit record (fire-and-forget; never blocks the response) ──
    from shared.database import log_request  # deferred — same pattern as above

    try:
        await log_request({
            "source_ip":    meta.ip_address,
            "payload":      packet.raw_text,
            "risk_score":   verdict.aggregate_confidence,
            "reasoning":    verdict.judge_reasoning,
            "final_action": verdict.status,
        })
    except Exception:
        logger.exception("Audit log write failed for packet %s — verdict still returned", packet.packet_id)

    return verdict.model_dump(mode="json")
