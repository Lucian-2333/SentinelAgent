"""
shared/schemas.py
─────────────────────────────────────────────────────────────────────────────
SentinelAgent — Core Contract Definitions
All data flowing between the Gateway, Expert Agents, and Judge MUST conform
to these Pydantic models.  They are the single source of truth for the
entire 1+N+1 pipeline.
─────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


# ──────────────────────────────────────────────────────────────────────────────
# Enumerations
# ──────────────────────────────────────────────────────────────────────────────


class SourceType(str, Enum):
    """Where the packet originated."""

    HUMAN_USER = "human_user"          # Typed by a real person
    AGENT_UPSTREAM = "agent_upstream"  # Sent by another AI agent
    API_CALL = "api_call"              # Direct API invocation
    WEBHOOK = "webhook"                # External webhook payload
    INTERNAL = "internal"              # System-generated (tests, mocks)


class ThreatCategory(str, Enum):
    """Canonical attack / anomaly categories that agents MUST choose from."""

    BENIGN = "benign"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    UNKNOWN = "unknown"


class VerdictStatus(str, Enum):
    """Final enforcement decision produced by the Judge layer."""

    ALLOW = "allow"          # Traffic is clean — pass through
    BLOCK = "block"          # High-confidence threat — hard block
    QUARANTINE = "quarantine"  # Ambiguous — hold for human review
    PENDING = "pending"      # Judge has not yet reached consensus


# ──────────────────────────────────────────────────────────────────────────────
# Layer 1 — Gateway Input Contract
# ──────────────────────────────────────────────────────────────────────────────


class PacketMetadata(BaseModel):
    """Contextual envelope around a raw payload.

    Agents use metadata as *secondary evidence* — never as a substitute for
    analysing the raw text itself.
    """

    source: SourceType = Field(
        ...,
        description="Origin class of the packet.",
    )
    session_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique session identifier (agent conversation thread).",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of when the gateway received the packet.",
    )
    ip_address: str | None = Field(
        default=None,
        description="Originating IP, if available.",
        examples=["192.168.1.42"],
    )
    user_agent: str | None = Field(
        default=None,
        description="HTTP User-Agent header value, if present.",
    )
    endpoint: str | None = Field(
        default=None,
        description="API endpoint or route that was targeted.",
        examples=["/api/v1/query"],
    )
    extra: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary key-value pairs for future extensibility.",
    )


class Packet(BaseModel):
    """
    The atomic unit of traffic flowing through SentinelAgent.

    Every agent receives a *complete, immutable* Packet so that all reasoning
    is grounded in the same factual record (anti-hallucination anchor).
    """

    packet_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Globally unique packet identifier (UUID-4).",
    )
    raw_text: str = Field(
        ...,
        min_length=1,
        # MED-04: Cap payload size to prevent memory exhaustion on the 400 MB
        # container and runaway LLM token costs. 32 KB covers any realistic
        # prompt or HTTP body while blocking multi-megabyte flood attacks.
        max_length=32_768,
        description=(
            "The verbatim, unmodified payload.  Agents MUST reference exact "
            "substrings from this field as evidence — never paraphrase."
        ),
    )
    metadata: PacketMetadata = Field(
        ...,
        description="Contextual envelope (source, timing, routing info).",
    )

    @field_validator("raw_text")
    @classmethod
    def strip_and_nonempty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("raw_text must contain at least one non-whitespace character.")
        return v

    model_config = {"frozen": True}  # Packets are immutable once created


# ──────────────────────────────────────────────────────────────────────────────
# Layer N — Expert Agent Output Contract
# ──────────────────────────────────────────────────────────────────────────────


class AuditResult(BaseModel):
    """
    Structured verdict produced by a single expert agent.

    ┌──────────────────────────────────────────────────────────────┐
    │  ANTI-HALLUCINATION REQUIREMENT                              │
    │  • `evidence` MUST contain verbatim substrings from          │
    │    Packet.raw_text — no paraphrasing or invented fragments.  │
    │  • `reasoning` MUST explain *why* those substrings are       │
    │    suspicious in plain, auditable language.                  │
    └──────────────────────────────────────────────────────────────┘
    """

    agent_id: str = Field(
        ...,
        description="Unique identifier of the agent that produced this result.",
        examples=["pattern_agent_v1", "context_agent_v1"],
    )
    packet_id: str = Field(
        ...,
        description="packet_id of the Packet that was analysed.",
    )
    threat_category: ThreatCategory = Field(
        ...,
        description="Agent's classification of the detected (or absent) threat.",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description=(
            "Confidence score in [0.0, 1.0].  "
            "0.0 = certainly benign, 1.0 = certainly malicious."
        ),
    )
    reasoning: str = Field(
        ...,
        min_length=10,
        description=(
            "Step-by-step, human-readable explanation of the agent's decision. "
            "Must reference the evidence field explicitly."
        ),
    )
    evidence: list[str] = Field(
        default_factory=list,
        description=(
            "Verbatim substrings extracted from Packet.raw_text that support "
            "the verdict.  Empty list is only acceptable when threat_category "
            "is BENIGN."
        ),
    )
    analysed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of when this audit completed.",
    )

    @field_validator("evidence")
    @classmethod
    def evidence_required_for_threats(cls, v: list[str], info: Any) -> list[str]:
        """Enforce that non-benign verdicts must supply evidence."""
        # Access sibling field via info.data (pydantic v2 style)
        threat = info.data.get("threat_category")
        if threat and threat != ThreatCategory.BENIGN and len(v) == 0:
            raise ValueError(
                f"AuditResult with threat_category='{threat}' must include "
                "at least one evidence substring from the original raw_text."
            )
        return v


# ──────────────────────────────────────────────────────────────────────────────
# Layer 1 — Judge Output Contract
# ──────────────────────────────────────────────────────────────────────────────


class ConsensusVerdict(BaseModel):
    """
    The final, authoritative decision emitted by the Judge layer.

    Produced by aggregating all AuditResult objects for a single Packet and
    applying the consensus algorithm (see judge/consensus.py).
    """

    packet_id: str = Field(
        ...,
        description="packet_id of the adjudicated Packet.",
    )
    status: VerdictStatus = Field(
        ...,
        description="Enforcement action to take on the packet.",
    )
    dominant_threat: ThreatCategory = Field(
        ...,
        description="Highest-weighted threat category among all agents.",
    )
    aggregate_confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Weighted average confidence across all contributing agents.",
    )
    contributing_agents: list[str] = Field(
        default_factory=list,
        description="List of agent_ids whose AuditResults influenced this verdict.",
    )
    dissenting_agents: list[str] = Field(
        default_factory=list,
        description="Agents that disagreed with the majority — flagged for review.",
    )
    judge_reasoning: str = Field(
        ...,
        min_length=10,
        description="Plain-language explanation of how the Judge reached its verdict.",
    )
    decided_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of the consensus decision.",
    )
    raw_audits: list[AuditResult] = Field(
        default_factory=list,
        description="Full AuditResult objects for traceability and dashboard rendering.",
    )
