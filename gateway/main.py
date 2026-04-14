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
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from gateway.router import audit_router
from shared.schemas import Packet, PacketMetadata, SourceType

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("sentinel.gateway")


# ──────────────────────────────────────────────────────────────────────────────
# App lifecycle
# ──────────────────────────────────────────────────────────────────────────────


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
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Tighten in production
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register sub-routers
app.include_router(audit_router, prefix="/api/v1")


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


@app.post("/api/v1/intercept", tags=["gateway"])
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

    meta = PacketMetadata(
        source=SourceType(body.get("source", SourceType.API_CALL)),
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
