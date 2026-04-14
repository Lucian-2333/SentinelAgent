"""
agents/base_agent.py
─────────────────────────────────────────────────────────────────────────────
SentinelAgent — Abstract Base Agent
All expert agents (Pattern, Context, …) inherit from this class.  It enforces
the anti-hallucination contract: every non-benign verdict MUST include
evidence substrings traceable back to the original Packet.raw_text.
─────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod

from shared.schemas import AuditResult, Packet, ThreatCategory

logger = logging.getLogger("sentinel.agent.base")


class BaseAgent(ABC):
    """
    Contract that every SentinelAgent expert agent must fulfill.

    Subclasses implement `_analyse()` — a pure async function that receives an
    immutable Packet and returns an AuditResult.  The base class wraps that
    call with:
      • Logging
      • Evidence-anchor validation (anti-hallucination guard)
      • Timing instrumentation (future: Prometheus metrics)
    """

    #: Override in subclasses with a stable, unique identifier.
    agent_id: str = "base_agent"

    async def analyse(self, packet: Packet) -> AuditResult:
        """Public entry-point called by the Judge pipeline."""
        logger.debug("[%s] Analysing packet %s", self.agent_id, packet.packet_id)
        result = await self._analyse(packet)
        self._validate_evidence_anchor(packet, result)
        logger.info(
            "[%s] packet=%s threat=%s confidence=%.2f",
            self.agent_id,
            packet.packet_id,
            result.threat_category,
            result.confidence,
        )
        return result

    @abstractmethod
    async def _analyse(self, packet: Packet) -> AuditResult:
        """Perform the actual analysis.  Must return a fully-populated AuditResult."""
        ...

    # ── Anti-hallucination guard ──────────────────────────────────────────────

    def _validate_evidence_anchor(self, packet: Packet, result: AuditResult) -> None:
        """
        Verify that every evidence fragment actually appears in the raw_text.

        This is the core anti-hallucination mechanism: agents cannot fabricate
        evidence strings that were never present in the original payload.
        """
        if result.threat_category == ThreatCategory.BENIGN:
            return  # No evidence required for benign verdicts

        violations: list[str] = []
        for fragment in result.evidence:
            if fragment not in packet.raw_text:
                violations.append(fragment)

        if violations:
            logger.warning(
                "[%s] EVIDENCE ANCHOR VIOLATION — fragments not found in raw_text: %s",
                self.agent_id,
                violations,
            )
            # Demote confidence to signal unreliable output rather than hard-crashing
            # (a hard crash would make the pipeline unavailable; demotion keeps it auditable)
            object.__setattr__(result, "confidence", 0.0)  # Pydantic frozen model workaround
