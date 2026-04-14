"""
demo_runner.py
─────────────────────────────────────────────────────────────────────────────
SentinelAgent — Scripted Demo Runner
Loads mock_attack_stream.json, reconstructs Packet objects, and runs each
through the full 1+N+1 pipeline.  Prints a colour-coded verdict table.

Usage:
    SENTINEL_DEMO_MODE=1 python demo_runner.py
─────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import asyncio
import sys
import pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent))
if sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")
import json
import os
from pathlib import Path

from shared.schemas import Packet, PacketMetadata, SourceType, VerdictStatus


STREAM_PATH = Path(__file__).parent / "data" / "mock_attack_stream.json"

# ANSI colours
_RED = "\033[91m"
_YEL = "\033[93m"
_GRN = "\033[92m"
_CYN = "\033[96m"
_RST = "\033[0m"
_BLD = "\033[1m"


def _colour_status(status: VerdictStatus) -> str:
    mapping = {
        VerdictStatus.BLOCK: f"{_RED}{_BLD}BLOCK{_RST}",
        VerdictStatus.QUARANTINE: f"{_YEL}{_BLD}QUARANTINE{_RST}",
        VerdictStatus.ALLOW: f"{_GRN}{_BLD}ALLOW{_RST}",
        VerdictStatus.PENDING: f"{_CYN}PENDING{_RST}",
    }
    return mapping.get(status, str(status))


async def run_demo() -> None:
    from judge.consensus import run_consensus_pipeline

    os.environ["SENTINEL_DEMO_MODE"] = "1"

    raw_stream: list[dict] = json.loads(STREAM_PATH.read_text(encoding="utf-8"))

    print(f"\n{_BLD}{'=' * 70}{_RST}")
    print(f"{_BLD}  SentinelAgent -- Demo Pipeline Run{_RST}")
    print(f"{_BLD}{'=' * 70}{_RST}\n")

    for entry in raw_stream:
        # Skip comment-only keys
        meta_raw = entry.get("metadata", {})
        meta = PacketMetadata(
            source=SourceType(meta_raw.get("source", "internal")),
            session_id=meta_raw.get("session_id", "demo"),
            ip_address=meta_raw.get("ip_address"),
            user_agent=meta_raw.get("user_agent"),
            endpoint=meta_raw.get("endpoint"),
            extra=meta_raw.get("extra", {}),
        )
        packet = Packet(
            packet_id=entry["packet_id"],
            raw_text=entry["raw_text"],
            metadata=meta,
        )

        print(f"{_CYN}Packet:{_RST} {packet.packet_id}")
        print(f"{_CYN}Payload:{_RST} {packet.raw_text[:80]}{'…' if len(packet.raw_text) > 80 else ''}")

        verdict = await run_consensus_pipeline(packet)

        print(f"{_CYN}Verdict:{_RST} {_colour_status(verdict.status)}")
        print(f"  Threat      : {verdict.dominant_threat}")
        print(f"  Confidence  : {verdict.aggregate_confidence:.2%}")
        print(f"  Contributors: {', '.join(verdict.contributing_agents) or '-'}")
        print(f"  Dissenters  : {', '.join(verdict.dissenting_agents) or 'none'}")
        print(f"  Judge says  : {verdict.judge_reasoning[:120]}...")
        print()
        for audit in verdict.raw_audits:
            print(
                f"    [{audit.agent_id}] {audit.threat_category} "
                f"({audit.confidence:.2f}) - {audit.reasoning[:60]}..."
            )
            if audit.evidence:
                for ev in audit.evidence[:3]:
                    print(f"      evidence: [{ev}]")
        print(f"\n{'-' * 70}\n")


if __name__ == "__main__":
    asyncio.run(run_demo())
