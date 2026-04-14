"""
agents/pattern_agent/agent.py
─────────────────────────────────────────────────────────────────────────────
SentinelAgent — Pattern Agent (Rule Expert)
Layer-N Expert #1: signature-based detection of known attack patterns.
Uses compiled regex rules to identify SQLi, XSS, and other lexical threats
with high speed and determinism.  Deliberately keeps NO LLM dependency so
it acts as a fast, reliable first-pass filter.
─────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from agents.base_agent import BaseAgent
from shared.schemas import AuditResult, Packet, ThreatCategory


# ──────────────────────────────────────────────────────────────────────────────
# Rule definitions
# ──────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class PatternRule:
    name: str
    pattern: re.Pattern[str]
    threat_category: ThreatCategory
    base_confidence: float
    description: str


# All patterns use re.IGNORECASE | re.DOTALL for robustness
_F = re.IGNORECASE | re.DOTALL

RULES: list[PatternRule] = [
    # ── SQL Injection ────────────────────────────────────────────────────────
    PatternRule(
        name="sqli_comment_bypass",
        pattern=re.compile(r"(--|#|/\*).{0,80}(select|insert|update|delete|drop|union)", _F),
        threat_category=ThreatCategory.SQL_INJECTION,
        base_confidence=0.93,
        description="SQL comment used to bypass authentication conditions",
    ),
    PatternRule(
        name="sqli_tautology",
        pattern=re.compile(r"(or|and)\s+[\'\"]?\w+[\'\"]?\s*=\s*[\'\"]?\w+[\'\"]?", _F),
        threat_category=ThreatCategory.SQL_INJECTION,
        base_confidence=0.80,
        description="Tautological WHERE clause (OR 1=1, AND 'x'='x')",
    ),
    PatternRule(
        name="sqli_union_select",
        pattern=re.compile(r"union\s+(all\s+)?select", _F),
        threat_category=ThreatCategory.SQL_INJECTION,
        base_confidence=0.95,
        description="UNION SELECT exfiltration attempt",
    ),
    PatternRule(
        name="sqli_stacked_queries",
        pattern=re.compile(r";\s*(select|insert|update|delete|exec|execute|drop)\b", _F),
        threat_category=ThreatCategory.SQL_INJECTION,
        base_confidence=0.88,
        description="Stacked query injection via semicolon delimiter",
    ),

    # ── Cross-Site Scripting ─────────────────────────────────────────────────
    PatternRule(
        name="xss_script_tag",
        pattern=re.compile(r"<\s*script[^>]*>", _F),
        threat_category=ThreatCategory.XSS,
        base_confidence=0.90,
        description="Raw <script> tag injection",
    ),
    PatternRule(
        name="xss_event_handler",
        pattern=re.compile(r"on(load|click|mouseover|error|focus)\s*=", _F),
        threat_category=ThreatCategory.XSS,
        base_confidence=0.85,
        description="Inline event-handler attribute injection",
    ),
    PatternRule(
        name="xss_javascript_uri",
        pattern=re.compile(r"javascript\s*:", _F),
        threat_category=ThreatCategory.XSS,
        base_confidence=0.88,
        description="javascript: URI scheme in attribute value",
    ),

    # ── Prompt Injection (lexical signals only — semantic handled by ContextAgent)
    PatternRule(
        name="prompt_injection_ignore_prev",
        pattern=re.compile(r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)", _F),
        threat_category=ThreatCategory.PROMPT_INJECTION,
        base_confidence=0.82,
        description="Direct instruction-override command",
    ),
    PatternRule(
        name="prompt_injection_new_instructions",
        pattern=re.compile(r"(your\s+new\s+instructions?|new\s+system\s+prompt|forget\s+your\s+(training|instructions?))", _F),
        threat_category=ThreatCategory.PROMPT_INJECTION,
        base_confidence=0.78,
        description="Attempt to replace system-level instructions",
    ),
]


# ──────────────────────────────────────────────────────────────────────────────
# Agent implementation
# ──────────────────────────────────────────────────────────────────────────────


class PatternAgent(BaseAgent):
    """
    Signature-based rule engine.

    Scans raw_text against all compiled regex rules.  When multiple rules fire,
    the highest-confidence match wins; evidence from ALL fired rules is collected
    so the Judge has full visibility into which signatures triggered.
    """

    agent_id = "pattern_agent_v1"

    async def _analyse(self, packet: Packet) -> AuditResult:
        fired: list[tuple[PatternRule, list[str]]] = []

        for rule in RULES:
            matches = rule.pattern.findall(packet.raw_text)
            if matches:
                # Flatten tuples (regex groups) into plain strings
                flat = [m if isinstance(m, str) else "".join(m) for m in matches]
                fired.append((rule, flat))

        if not fired:
            return AuditResult(
                agent_id=self.agent_id,
                packet_id=packet.packet_id,
                threat_category=ThreatCategory.BENIGN,
                confidence=0.05,
                reasoning=(
                    "No known attack signatures matched the raw_text. "
                    "Payload appears syntactically benign based on pattern rules."
                ),
                evidence=[],
            )

        # Select the highest-confidence rule as the dominant signal
        dominant_rule, dominant_matches = max(fired, key=lambda x: x[0].base_confidence)

        # Aggregate all match fragments as evidence
        all_evidence: list[str] = []
        rule_names: list[str] = []
        for rule, matches in fired:
            all_evidence.extend(matches)
            rule_names.append(rule.name)

        # De-duplicate while preserving order
        seen: set[str] = set()
        unique_evidence = [e for e in all_evidence if not (e in seen or seen.add(e))]  # type: ignore[func-returns-value]

        reasoning_lines = [
            f"Pattern scan fired {len(fired)} rule(s): {', '.join(rule_names)}.",
            f"Dominant rule: '{dominant_rule.name}' — {dominant_rule.description}.",
            f"Matched fragments serve as verbatim evidence (see evidence field).",
        ]

        return AuditResult(
            agent_id=self.agent_id,
            packet_id=packet.packet_id,
            threat_category=dominant_rule.threat_category,
            confidence=dominant_rule.base_confidence,
            reasoning=" ".join(reasoning_lines),
            evidence=unique_evidence[:10],  # Cap at 10 to keep payloads readable
        )
