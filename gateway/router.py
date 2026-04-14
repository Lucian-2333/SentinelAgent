"""
gateway/router.py
─────────────────────────────────────────────────────────────────────────────
SentinelAgent — Gateway API Routes
Defines audit-specific endpoints separate from the app bootstrap so that
main.py stays clean and individual route groups can be versioned/mocked
independently.
─────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, status

from shared.schemas import ConsensusVerdict, Packet

logger = logging.getLogger("sentinel.gateway.router")

audit_router = APIRouter(tags=["audit"])


@audit_router.post(
    "/audit",
    response_model=ConsensusVerdict,
    summary="Submit a pre-formed Packet for full multi-agent audit",
)
async def audit_packet(packet: Packet) -> ConsensusVerdict:
    """
    Accept a fully-formed Packet (e.g. from another agent or the demo runner)
    and return the ConsensusVerdict after all expert agents have been consulted.
    """
    from judge.consensus import run_consensus_pipeline  # deferred to avoid circular

    try:
        verdict = await run_consensus_pipeline(packet)
        logger.info(
            "Verdict for %s → %s (confidence=%.2f)",
            packet.packet_id,
            verdict.status,
            verdict.aggregate_confidence,
        )
    except Exception as exc:
        logger.exception("Pipeline failure for packet %s", packet.packet_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Audit pipeline error: {exc}",
        ) from exc

    # ── Persist audit record ──────────────────────────────────────────────────
    from shared.database import log_request  # deferred to avoid circular

    try:
        await log_request({
            "source_ip":    packet.metadata.ip_address,
            "payload":      packet.raw_text,
            "risk_score":   verdict.aggregate_confidence,
            "reasoning":    verdict.judge_reasoning,
            "final_action": verdict.status,
        })
    except Exception:
        logger.exception(
            "Audit log write failed for packet %s — verdict still returned",
            packet.packet_id,
        )

    return verdict
