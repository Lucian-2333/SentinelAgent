"""
shared/database.py
─────────────────────────────────────────────────────────────────────────────
SentinelAgent — SQLite Audit Log Persistence Layer

Provides a single async interface for recording every packet that passes
through the SentinelAgent pipeline.  All writes are non-blocking (aiosqlite)
so the audit log never adds latency to the critical path.

Table: audit_logs
  id            INTEGER  PRIMARY KEY AUTOINCREMENT
  timestamp     TEXT     DEFAULT CURRENT_TIMESTAMP  (ISO-8601 UTC)
  source_ip     TEXT     DEFAULT '127.0.0.1'
  payload       TEXT     NOT NULL   — the raw_text that was analysed
  risk_score    REAL     NOT NULL   — aggregate_confidence in [0.0, 1.0]
  reasoning     TEXT     NOT NULL   — judge_reasoning from ConsensusVerdict
  final_action  TEXT     NOT NULL   — 'BLOCK' | 'PASS' (normalised VerdictStatus)

Usage:
  from shared.database import init_db, log_request

  # Once at startup (call from FastAPI lifespan):
  await init_db()

  # After every verdict:
  await log_request({
      "source_ip":    "1.2.3.4",
      "payload":      packet.raw_text,
      "risk_score":   verdict.aggregate_confidence,
      "reasoning":    verdict.judge_reasoning,
      "final_action": verdict.status,   # VerdictStatus enum or str
  })
─────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import aiosqlite

# Load .env early so os.getenv picks up DB_PATH when the module is imported
# directly (e.g. by Streamlit).  Safe to call multiple times — dotenv is a no-op
# if the environment variable is already set.
try:
    from dotenv import load_dotenv as _load_dotenv
    _load_dotenv(Path(__file__).parent.parent / ".env", override=False)
except ImportError:
    pass  # python-dotenv optional; rely on real env vars in that case

logger = logging.getLogger("sentinel.database")

# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────────

# DB_PATH env var lets ops teams pin an absolute path on the production server
# (e.g. /opt/sentinel/data/sentinel_audit.db) without touching source code.
# Falls back to sentinel_audit.db in the project root for local development.
_DEFAULT_DB = str(Path(__file__).parent.parent / "sentinel_audit.db")
_DB_PATH: Path = Path(os.getenv("DB_PATH", "").strip() or _DEFAULT_DB)

# DDL for the audit log table — created once on startup, idempotent.
_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS audit_logs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    source_ip    TEXT    NOT NULL DEFAULT '127.0.0.1',
    payload      TEXT    NOT NULL,
    risk_score   REAL    NOT NULL CHECK (risk_score >= 0.0 AND risk_score <= 1.0),
    reasoning    TEXT    NOT NULL,
    final_action TEXT    NOT NULL CHECK (final_action IN ('BLOCK', 'PASS'))
);
"""

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────


def _normalise_action(raw: Any) -> str:
    """
    Map VerdictStatus values → 'BLOCK' | 'PASS'.

    VerdictStatus.BLOCK                → 'BLOCK'
    VerdictStatus.QUARANTINE           → 'BLOCK'  (held for review = blocked)
    VerdictStatus.ALLOW / PENDING / *  → 'PASS'

    Handles all input forms:
      - VerdictStatus enum  → .value = 'block' / 'quarantine' / 'allow'
      - plain string        → 'BLOCK' / 'block' / 'PASS' etc.
      - "VerdictStatus.BLOCK" (str(enum) fallback) — also handled
    """
    # Prefer .value if it's an enum, otherwise stringify
    value = (raw.value if hasattr(raw, "value") else str(raw)).upper().strip()
    # Strip any "VERDICTSTATUS." prefix produced by str(enum) on older Python
    if "." in value:
        value = value.split(".")[-1]
    if value in {"BLOCK", "QUARANTINE"}:
        return "BLOCK"
    return "PASS"


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────


async def init_db() -> None:
    """
    Create the audit_logs table if it does not already exist.

    Call this once during application startup (FastAPI lifespan).
    Safe to call multiple times — uses CREATE TABLE IF NOT EXISTS.
    """
    logger.info("Initialising audit database at %s", _DB_PATH)
    async with aiosqlite.connect(_DB_PATH) as db:
        # LOW-03: Enable WAL (Write-Ahead Log) mode so concurrent readers
        # (dashboard) never block the gateway writer, and vice-versa.
        # WAL is persistent — this PRAGMA only needs to be set once per file.
        await db.execute("PRAGMA journal_mode=WAL;")
        await db.execute(_CREATE_TABLE_SQL)
        await db.commit()
    logger.info("Audit database ready (WAL mode enabled).")


async def log_request(data: dict[str, Any]) -> int:
    """
    Insert one audit record and return the new row's id.

    Parameters
    ----------
    data : dict with the following keys:
        source_ip    str   — originating IP address (default: '127.0.0.1')
        payload      str   — raw_text that was analysed (required)
        risk_score   float — aggregate_confidence from ConsensusVerdict (required)
        reasoning    str   — judge_reasoning from ConsensusVerdict (required)
        final_action       — VerdictStatus enum, its .value, or a plain string

    Returns
    -------
    int — the ROWID / id of the newly inserted row.

    Raises
    ------
    ValueError  if any required key is missing or risk_score is out of [0, 1].
    """
    # ── Validate required fields ──────────────────────────────────────────────
    for key in ("payload", "risk_score", "reasoning", "final_action"):
        if key not in data:
            raise ValueError(f"log_request: missing required field '{key}'")

    risk_score: float = float(data["risk_score"])
    if not (0.0 <= risk_score <= 1.0):
        raise ValueError(
            f"log_request: risk_score must be in [0.0, 1.0], got {risk_score}"
        )

    source_ip: str = str(data.get("source_ip") or "127.0.0.1")
    payload: str = str(data["payload"])
    reasoning: str = str(data["reasoning"])
    final_action: str = _normalise_action(data["final_action"])

    # ── Persist ───────────────────────────────────────────────────────────────
    async with aiosqlite.connect(_DB_PATH) as db:
        cursor = await db.execute(
            """
            INSERT INTO audit_logs (source_ip, payload, risk_score, reasoning, final_action)
            VALUES (?, ?, ?, ?, ?)
            """,
            (source_ip, payload, risk_score, reasoning, final_action),
        )
        await db.commit()
        row_id: int = cursor.lastrowid  # type: ignore[assignment]

    logger.debug(
        "Audit log #%d written — action=%s risk=%.3f ip=%s",
        row_id,
        final_action,
        risk_score,
        source_ip,
    )
    return row_id


async def get_recent_logs(limit: int = 100) -> list[dict[str, Any]]:
    """
    Retrieve the most recent audit log entries (newest first).

    Opens the database in read-only URI mode (?mode=ro) so that this
    function works on a read-only filesystem mount (the dashboard container
    mounts ./data:ro).  In read-only mode SQLite uses in-process memory for
    the WAL index instead of requiring a writable -shm sidecar file.
    """
    limit = min(max(1, limit), 1000)  # clamp to [1, 1000]

    # file: URI with mode=ro — works on read-only mounts, WAL-safe on Linux
    ro_uri = f"file:{_DB_PATH}?mode=ro"

    async with aiosqlite.connect(ro_uri, uri=True) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        rows = await cursor.fetchall()

    return [dict(row) for row in rows]
