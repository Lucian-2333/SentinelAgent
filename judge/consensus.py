"""
judge/consensus.py
─────────────────────────────────────────────────────────────────────────────
SentinelAgent — Layer 1 (Consensus Judge)
Aggregates AuditResult objects from all expert agents and produces a single,
authoritative ConsensusVerdict.  This is the "closing bracket" of the 1+N+1
architecture.

Consensus Algorithm
───────────────────
1.  Dispatch the Packet to ALL registered agents concurrently (asyncio.gather).
2.  Compute per-threat-category weighted confidence sums.
3.  Select the dominant threat category.
4.  Apply threshold rules to derive a VerdictStatus:
      aggregate_confidence ≥ BLOCK_THRESHOLD    → BLOCK
      aggregate_confidence ≥ QUARANTINE_THRESHOLD → QUARANTINE
      else                                       → ALLOW
5.  Flag dissenting agents (those whose category differs from the dominant).
─────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict

from agents.context_agent.agent import ContextAgent
from agents.pattern_agent.agent import PatternAgent
from shared.schemas import (
    AuditResult,
    ConsensusVerdict,
    Packet,
    ThreatCategory,
    VerdictStatus,
)

logger = logging.getLogger("sentinel.judge")

# ──────────────────────────────────────────────────────────────────────────────
# Tunable thresholds  (move to config/env vars before production)
# ──────────────────────────────────────────────────────────────────────────────

BLOCK_THRESHOLD = 0.70        # aggregate_confidence ≥ this → BLOCK
QUARANTINE_THRESHOLD = 0.45   # aggregate_confidence ≥ this → QUARANTINE (else ALLOW)

# Agent weights: higher weight = more influence on the final verdict
AGENT_WEIGHTS: dict[str, float] = {
    "pattern_agent_v1": 1.0,   # Deterministic, high precision — full weight
    "context_agent_v1": 1.2,   # Semantic reasoning — slightly boosted
}
DEFAULT_WEIGHT = 1.0

# ──────────────────────────────────────────────────────────────────────────────
# Agent registry — add new agents here
# ──────────────────────────────────────────────────────────────────────────────

_AGENTS = [
    PatternAgent(),
    ContextAgent(),
]


# ──────────────────────────────────────────────────────────────────────────────
# Core aggregation — accepts pre-computed results (used by UI step-by-step flow)
# ──────────────────────────────────────────────────────────────────────────────

def build_verdict(results: list[AuditResult], packet_id: str) -> ConsensusVerdict:
    """
    Pure aggregation: compute a ConsensusVerdict from a list of AuditResults.

    Decoupled from agent dispatch so the frontend can run agents one-by-one
    (showing intermediate results) and call this once at the end.
    """
    # ── Step 1: Weighted confidence aggregation per threat category ───────────
    category_scores: dict[ThreatCategory, float] = defaultdict(float)
    category_weight_totals: dict[ThreatCategory, float] = defaultdict(float)

    for result in results:
        weight = AGENT_WEIGHTS.get(result.agent_id, DEFAULT_WEIGHT)
        category_scores[result.threat_category] += result.confidence * weight
        category_weight_totals[result.threat_category] += weight

    category_avg: dict[ThreatCategory, float] = {
        cat: category_scores[cat] / category_weight_totals[cat]
        for cat in category_scores
    }

    # ── Step 2: Dominant threat selection ─────────────────────────────────────
    threat_cats = {k: v for k, v in category_avg.items() if k != ThreatCategory.BENIGN}

    if threat_cats:
        dominant_threat = max(threat_cats, key=lambda c: threat_cats[c])
        aggregate_confidence = threat_cats[dominant_threat]
    else:
        dominant_threat = ThreatCategory.BENIGN
        aggregate_confidence = 1.0 - category_avg.get(ThreatCategory.BENIGN, 0.0)

    # ── Step 3: Verdict decision ───────────────────────────────────────────────
    if dominant_threat == ThreatCategory.BENIGN:
        status = VerdictStatus.ALLOW
        aggregate_confidence = 0.0
    elif aggregate_confidence >= BLOCK_THRESHOLD:
        status = VerdictStatus.BLOCK
    elif aggregate_confidence >= QUARANTINE_THRESHOLD:
        status = VerdictStatus.QUARANTINE
    else:
        status = VerdictStatus.ALLOW

    # ── Step 4: Dissent detection ──────────────────────────────────────────────
    contributing = [r.agent_id for r in results if r.threat_category == dominant_threat]
    dissenting   = [r.agent_id for r in results if r.threat_category != dominant_threat]

    # ── Step 5: Judge reasoning ────────────────────────────────────────────────
    agent_summaries = "; ".join(
        f"{r.agent_id}->{r.threat_category}({r.confidence:.2f})" for r in results
    )
    judge_reasoning = (
        f"Consensus over {len(results)} agent(s): [{agent_summaries}].  "
        f"Dominant threat '{dominant_threat}' reached aggregate confidence "
        f"{aggregate_confidence:.2f} (block≥{BLOCK_THRESHOLD}, "
        f"quarantine≥{QUARANTINE_THRESHOLD}).  "
        f"Verdict: {status}.  "
        f"Dissenters: {dissenting if dissenting else 'none'}."
    )

    return ConsensusVerdict(
        packet_id=packet_id,
        status=status,
        dominant_threat=dominant_threat,
        aggregate_confidence=round(aggregate_confidence, 4),
        contributing_agents=contributing,
        dissenting_agents=dissenting,
        judge_reasoning=judge_reasoning,
        raw_audits=results,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Public pipeline entry-point (used by gateway / demo_runner)
# ──────────────────────────────────────────────────────────────────────────────

async def run_consensus_pipeline(packet: Packet) -> ConsensusVerdict:
    """
    Run all registered agents concurrently and return a ConsensusVerdict.
    Used by the Gateway router and demo_runner; the frontend uses build_verdict
    directly after running agents step-by-step.
    """
    logger.info("Starting consensus pipeline for packet %s", packet.packet_id)

    results: list[AuditResult] = await asyncio.gather(
        *[agent.analyse(packet) for agent in _AGENTS],
        return_exceptions=False,
    )

    verdict = build_verdict(list(results), packet.packet_id)

    logger.info(
        "Verdict for %s: %s | threat=%s | confidence=%.2f | dissenters=%s",
        packet.packet_id, verdict.status, verdict.dominant_threat,
        verdict.aggregate_confidence, verdict.dissenting_agents,
    )
    return verdict

