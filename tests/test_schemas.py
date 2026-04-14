"""
tests/test_schemas.py
─────────────────────────────────────────────────────────────────────────────
Contract tests for shared/schemas.py.
These are the minimum passing bar — they validate the anti-hallucination
invariants without requiring a live LLM or running server.

Run:  pytest tests/test_schemas.py -v
─────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from shared.schemas import (
    AuditResult,
    ConsensusVerdict,
    Packet,
    PacketMetadata,
    SourceType,
    ThreatCategory,
    VerdictStatus,
)


# ──────────────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def benign_packet() -> Packet:
    return Packet(
        raw_text="What is the capital of France?",
        metadata=PacketMetadata(source=SourceType.HUMAN_USER),
    )


@pytest.fixture
def sqli_packet() -> Packet:
    return Packet(
        raw_text="SELECT * FROM users WHERE id = 1 OR 1=1 --",
        metadata=PacketMetadata(source=SourceType.API_CALL, endpoint="/login"),
    )


# ──────────────────────────────────────────────────────────────────────────────
# Packet contract tests
# ──────────────────────────────────────────────────────────────────────────────


def test_packet_is_immutable(benign_packet):
    """Packets must be frozen (anti-tampering)."""
    with pytest.raises(Exception):  # ValidationError or TypeError depending on Pydantic version
        benign_packet.raw_text = "modified"  # type: ignore[misc]


def test_packet_rejects_empty_text():
    with pytest.raises(ValidationError):
        Packet(
            raw_text="   ",
            metadata=PacketMetadata(source=SourceType.INTERNAL),
        )


def test_packet_auto_generates_id(benign_packet):
    assert benign_packet.packet_id
    assert len(benign_packet.packet_id) == 36  # UUID-4 format


# ──────────────────────────────────────────────────────────────────────────────
# AuditResult anti-hallucination contract tests
# ──────────────────────────────────────────────────────────────────────────────


def test_audit_result_benign_needs_no_evidence(benign_packet):
    result = AuditResult(
        agent_id="test_agent",
        packet_id=benign_packet.packet_id,
        threat_category=ThreatCategory.BENIGN,
        confidence=0.05,
        reasoning="No suspicious patterns detected in the payload.",
        evidence=[],
    )
    assert result.threat_category == ThreatCategory.BENIGN
    assert result.evidence == []


def test_audit_result_threat_requires_evidence(sqli_packet):
    """Non-benign verdicts with no evidence must fail validation."""
    with pytest.raises(ValidationError, match="evidence"):
        AuditResult(
            agent_id="test_agent",
            packet_id=sqli_packet.packet_id,
            threat_category=ThreatCategory.SQL_INJECTION,
            confidence=0.9,
            reasoning="Detected SQL injection keywords.",
            evidence=[],  # ← This should fail
        )


def test_audit_result_confidence_bounds(sqli_packet):
    with pytest.raises(ValidationError):
        AuditResult(
            agent_id="test_agent",
            packet_id=sqli_packet.packet_id,
            threat_category=ThreatCategory.SQL_INJECTION,
            confidence=1.5,  # ← Out of [0, 1]
            reasoning="Test.",
            evidence=["OR 1=1"],
        )


def test_valid_threat_audit_result(sqli_packet):
    result = AuditResult(
        agent_id="pattern_agent_v1",
        packet_id=sqli_packet.packet_id,
        threat_category=ThreatCategory.SQL_INJECTION,
        confidence=0.93,
        reasoning="SQL comment bypass detected via '--' pattern after tautological clause.",
        evidence=["OR 1=1", "1=1 --"],
    )
    assert result.confidence == 0.93
    assert len(result.evidence) == 2


# ──────────────────────────────────────────────────────────────────────────────
# ConsensusVerdict contract tests
# ──────────────────────────────────────────────────────────────────────────────


def test_consensus_verdict_structure(sqli_packet):
    audit = AuditResult(
        agent_id="pattern_agent_v1",
        packet_id=sqli_packet.packet_id,
        threat_category=ThreatCategory.SQL_INJECTION,
        confidence=0.93,
        reasoning="SQL pattern detected.",
        evidence=["OR 1=1"],
    )
    verdict = ConsensusVerdict(
        packet_id=sqli_packet.packet_id,
        status=VerdictStatus.BLOCK,
        dominant_threat=ThreatCategory.SQL_INJECTION,
        aggregate_confidence=0.93,
        contributing_agents=["pattern_agent_v1"],
        dissenting_agents=[],
        judge_reasoning="High confidence SQL injection — block enforced.",
        raw_audits=[audit],
    )
    assert verdict.status == VerdictStatus.BLOCK
    assert verdict.aggregate_confidence == 0.93
    assert len(verdict.raw_audits) == 1
