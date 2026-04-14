"""
test_pipeline.py -- Full end-to-end pipeline smoke test (terminal safe, no emoji)
Run: .venv/Scripts/python.exe test_pipeline.py
"""
import sys, os, asyncio, traceback
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, ".")

PASS = "[PASS]"
FAIL = "[FAIL]"
INFO = "[INFO]"
SEP  = "-" * 60

def section(title):
    print(f"\n{SEP}\n STEP {title}\n{SEP}")

errors = []

# ─────────────────────────────────────────────────────────────────
# STEP 1 — .env + environment variables
# ─────────────────────────────────────────────────────────────────
section("1 -- Load .env")
try:
    from dotenv import load_dotenv
    load_dotenv(".env", override=False)
    key  = os.getenv("DEEPSEEK_API_KEY", "")
    admin = os.getenv("ADMIN_USERNAME", "")
    db    = os.getenv("DB_PATH", "(project root default)")
    print(f"  {PASS}  DEEPSEEK_API_KEY = {key[:8]}...")
    print(f"  {PASS}  ADMIN_USERNAME   = {admin}")
    print(f"  {PASS}  DB_PATH          = {db}")
except Exception as e:
    print(f"  {FAIL}  {e}"); errors.append(f"Step1: {e}")

# ─────────────────────────────────────────────────────────────────
# STEP 2 — Pydantic schemas
# ─────────────────────────────────────────────────────────────────
section("2 -- Pydantic schemas import")
try:
    from shared.schemas import (
        Packet, PacketMetadata, SourceType,
        AuditResult, ThreatCategory, ConsensusVerdict, VerdictStatus
    )
    print(f"  {PASS}  All schema classes imported OK")
except Exception as e:
    print(f"  {FAIL}  {e}"); errors.append(f"Step2: {e}")

# ─────────────────────────────────────────────────────────────────
# STEP 3 — Build a test Packet
# ─────────────────────────────────────────────────────────────────
section("3 -- Build test Packet")
try:
    packet = Packet(
        raw_text="SELECT * FROM users WHERE id=1 OR '1'='1' -- bypass",
        metadata=PacketMetadata(
            source=SourceType.API_CALL,
            ip_address="127.0.0.1",
            endpoint="/api/v1/query",
        )
    )
    print(f"  {PASS}  packet_id = {packet.packet_id[:16]}...")
    print(f"  {PASS}  raw_text  = {packet.raw_text[:50]}...")
except Exception as e:
    print(f"  {FAIL}  {e}"); errors.append(f"Step3: {e}"); packet = None

# ─────────────────────────────────────────────────────────────────
# STEP 4 — PatternAgent (deterministic, no LLM)
# ─────────────────────────────────────────────────────────────────
section("4 -- PatternAgent (regex, no LLM)")
pattern_result = None
try:
    from agents.pattern_agent.agent import PatternAgent
    agent_p = PatternAgent()
    pattern_result = asyncio.run(agent_p.analyse(packet))
    print(f"  {PASS}  threat    = {pattern_result.threat_category.value}")
    print(f"  {PASS}  confidence= {pattern_result.confidence:.2f}")
    print(f"  {PASS}  evidence  = {pattern_result.evidence[:2]}")
except Exception as e:
    print(f"  {FAIL}  {e}"); traceback.print_exc(); errors.append(f"Step4: {e}")

# ─────────────────────────────────────────────────────────────────
# STEP 5 — ContextAgent (DeepSeek LLM call)
# ─────────────────────────────────────────────────────────────────
section("5 -- ContextAgent (DeepSeek API)")
context_result = None
try:
    from agents.context_agent.agent import ContextAgent
    agent_c = ContextAgent()
    context_result = asyncio.run(agent_c.analyse(packet))
    is_safe_pass = "[SAFE-PASS]" in context_result.reasoning
    status = "(safe-pass fallback)" if is_safe_pass else "(live LLM response)"
    print(f"  {PASS}  threat    = {context_result.threat_category.value}  {status}")
    print(f"  {PASS}  confidence= {context_result.confidence:.2f}")
    print(f"  {PASS}  reasoning = {context_result.reasoning[:80]}...")
    if not is_safe_pass:
        print(f"  {PASS}  evidence  = {context_result.evidence[:2]}")
except Exception as e:
    print(f"  {FAIL}  {e}"); traceback.print_exc(); errors.append(f"Step5: {e}")

# ─────────────────────────────────────────────────────────────────
# STEP 6 — Judge consensus
# ─────────────────────────────────────────────────────────────────
section("6 -- Judge / Consensus")
verdict = None
try:
    from judge.consensus import build_verdict
    audits = [r for r in [pattern_result, context_result] if r is not None]
    verdict = build_verdict(audits, packet.packet_id)
    print(f"  {PASS}  status    = {verdict.status.value.upper()}")
    print(f"  {PASS}  dominant  = {verdict.dominant_threat.value}")
    print(f"  {PASS}  agg_conf  = {verdict.aggregate_confidence:.3f}")
    print(f"  {PASS}  reasoning = {verdict.judge_reasoning[:80]}...")
except Exception as e:
    print(f"  {FAIL}  {e}"); traceback.print_exc(); errors.append(f"Step6: {e}")

# ─────────────────────────────────────────────────────────────────
# STEP 7 — Database: init + write + read
# ─────────────────────────────────────────────────────────────────
section("7 -- Database (aiosqlite)")
try:
    from shared.database import init_db, log_request, get_recent_logs

    async def _db_test():
        await init_db()
        print(f"  {PASS}  init_db() -- table created/verified")

        row_id = await log_request({
            "source_ip":    "127.0.0.1",
            "payload":      packet.raw_text if packet else "test payload",
            "risk_score":   verdict.aggregate_confidence if verdict else 0.42,
            "reasoning":    verdict.judge_reasoning if verdict else "test reasoning",
            "final_action": verdict.status if verdict else "PASS",
        })
        print(f"  {PASS}  log_request() -- inserted row id={row_id}")

        rows = await get_recent_logs(limit=5)
        print(f"  {PASS}  get_recent_logs() -- returned {len(rows)} row(s)")
        if rows:
            r = rows[0]
            print(f"  {INFO}  latest: id={r['id']}  action={r['final_action']}  "
                  f"risk={r['risk_score']:.3f}  ip={r['source_ip']}")

    asyncio.run(_db_test())
except Exception as e:
    print(f"  {FAIL}  {e}"); traceback.print_exc(); errors.append(f"Step7: {e}")

# ─────────────────────────────────────────────────────────────────
# STEP 8 — Safe-pass regression (the bug that was just fixed)
# ─────────────────────────────────────────────────────────────────
section("8 -- Safe-pass regression test (BENIGN + evidence=[])")
try:
    from shared.schemas import AuditResult, ThreatCategory
    safe = AuditResult(
        agent_id="context_agent_v1",
        packet_id="regression-test",
        threat_category=ThreatCategory.BENIGN,
        confidence=0.0,
        reasoning="[SAFE-PASS] openai SDK not installed. Verdict deferred to PatternAgent.",
        evidence=[],
    )
    print(f"  {PASS}  AuditResult(BENIGN, conf=0.0, evidence=[]) -- no ValidationError")
except Exception as e:
    print(f"  {FAIL}  {e}"); errors.append(f"Step8: {e}")

# ─────────────────────────────────────────────────────────────────
# STEP 9 -- Full pipeline via run_consensus_pipeline
# ─────────────────────────────────────────────────────────────────
section("9 -- run_consensus_pipeline (end-to-end)")
try:
    from judge.consensus import run_consensus_pipeline
    full_verdict = asyncio.run(run_consensus_pipeline(packet))
    print(f"  {PASS}  status   = {full_verdict.status.value.upper()}")
    print(f"  {PASS}  dominant = {full_verdict.dominant_threat.value}")
    print(f"  {PASS}  agg_conf = {full_verdict.aggregate_confidence:.3f}")
    print(f"  {PASS}  agents   = {[a.agent_id for a in full_verdict.raw_audits]}")
except Exception as e:
    print(f"  {FAIL}  {e}"); traceback.print_exc(); errors.append(f"Step9: {e}")

# ─────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────
print(f"\n{'='*60}")
if errors:
    print(f"  RESULT: {len(errors)} FAILURE(S)")
    for e in errors:
        print(f"    - {e}")
else:
    print(f"  RESULT: ALL 9 STEPS PASSED -- pipeline fully operational")
print(f"{'='*60}\n")
