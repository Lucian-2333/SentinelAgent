"""
frontend/app.py — SentinelAgent Dual-Screen Narrative UI
Run: streamlit run frontend/app.py
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
import time
from pathlib import Path

import streamlit as st

# ── Path bootstrap ─────────────────────────────────────────────────────────
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("SENTINEL_DEMO_MODE", "1")

from agents.pattern_agent.agent import PatternAgent        # noqa: E402
from agents.context_agent.agent import ContextAgent        # noqa: E402
from judge.consensus import build_verdict                   # noqa: E402
from shared.schemas import Packet, PacketMetadata, SourceType, VerdictStatus  # noqa: E402

_pattern_agent = PatternAgent()
_context_agent = ContextAgent()


# ── Async helper ────────────────────────────────────────────────────────────
# HIGH-01: asyncio.run() raises RuntimeError when an event loop is already
# running (Streamlit ≥1.18 uses one internally).  Use a dedicated loop that
# runs in a background thread to stay safe across all Streamlit versions.

def _run(coro):
    """Run an async coroutine from synchronous Streamlit code, safely."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        # We're inside a running loop (Streamlit's internal one).
        # Submit the work to a fresh thread-local event loop instead.
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(asyncio.run, coro)
            return future.result()
    else:
        return asyncio.run(coro)

# ── Page config ────────────────────────────────────────────────────────────
st.set_page_config(page_title="SentinelAgent", page_icon="🛡️", layout="wide",
                   initial_sidebar_state="collapsed")

css_path = Path(__file__).parent / "styles.css"
st.markdown(f"<style>{css_path.read_text(encoding='utf-8')}</style>", unsafe_allow_html=True)
logo_path = Path(__file__).parent / "水晶盾.png"
LOGO_BASE64 = (
    base64.b64encode(logo_path.read_bytes()).decode("ascii")
    if logo_path.exists()
    else ""
)

# ── Load mock stream ───────────────────────────────────────────────────────
STREAM: list[dict] = json.loads(
    (ROOT / "data" / "mock_attack_stream.json").read_text(encoding="utf-8")
)

# ── Session state ──────────────────────────────────────────────────────────
if "idx" not in st.session_state:
    st.session_state.idx = 0
if "history" not in st.session_state:
    st.session_state.history = []
if "animating" not in st.session_state:
    st.session_state.animating = False
if "view_mode" not in st.session_state:
    st.session_state.view_mode = "滚动浏览"
if "selected_attack_idx" not in st.session_state:
    st.session_state.selected_attack_idx = 0


# ── Helpers ────────────────────────────────────────────────────────────────

def _build_packet(entry: dict) -> Packet:
    m = entry.get("metadata", {})
    return Packet(
        packet_id=entry["packet_id"],
        raw_text=entry["raw_text"],
        metadata=PacketMetadata(
            source=SourceType(m.get("source", "internal")),
            session_id=m.get("session_id", "demo"),
            ip_address=m.get("ip_address"),
            user_agent=m.get("user_agent"),
            endpoint=m.get("endpoint"),
            extra=m.get("extra", {}),
        ),
    )


def _attacker_thinking(entry: dict) -> list[str]:
    cat = entry.get("_expected_verdict", {}).get("dominant_threat", "unknown")
    payload = entry["raw_text"][:60]
    lines = {
        "sql_injection": [
            "> 正在扫描目标登录接口...",
            "> 尝试通过 SQL 注释截断进行认证绕过。",
            f'> 正在构造攻击载荷: "{payload}..."',
            "> 注入恒真 WHERE 条件。",
            "> 预期返回 200 OK 并获得管理员会话。",
        ],
        "jailbreak": [
            "> 目标: LLM 安全防护层。",
            "> 策略: DAN 角色覆盖 + 虚构场景包装。",
            "> 第1层 - 角色替换: 'Imagine you are DAN'",
            "> 第2层 - 虚构包装: 'creative writing exercise'",
            "> 第3层 - 显式弱化安全策略。",
            "> 发送多向量越狱攻击载荷...",
        ],
        "benign": [
            "> 合法的安全分析会话。",
            "> 查询安全最佳实践文档。",
            "> 无需使用绕过技术。",
        ],
    }
    return lines.get(cat, [f"> 正在发送载荷: {payload}..."])


def _verdict_css_class(status: VerdictStatus) -> str:
    return {VerdictStatus.BLOCK: "block", VerdictStatus.ALLOW: "allow",
            VerdictStatus.QUARANTINE: "quarantine"}.get(status, "allow")


def _status_zh(status: VerdictStatus) -> str:
    return {
        VerdictStatus.BLOCK: "阻断",
        VerdictStatus.ALLOW: "放行",
        VerdictStatus.QUARANTINE: "隔离",
    }.get(status, status.value.upper())


def _threat_zh(threat: str) -> str:
    mapping = {
        "BENIGN": "正常",
        "SQL INJECTION": "SQL 注入",
        "XSS": "跨站脚本",
        "PROMPT INJECTION": "提示词注入",
        "JAILBREAK": "越狱攻击",
        "DATA EXFILTRATION": "数据外泄",
        "PRIVILEGE ESCALATION": "权限提升",
        "UNKNOWN": "未知",
    }
    return mapping.get(threat, threat)


def _thinking_html(lines: list[str]) -> str:
    rows = "".join(f'<div class="thinking-line">{l}</div>' for l in lines)
    return (f'<div class="section-card">'
            f'<div class="section-title">思考过程</div>'
            f'{rows}'
            f'</div>')


def _payload_html(entry: dict) -> str:
    metadata = entry.get("metadata", {})
    formatted = json.dumps(
        {
            "id": entry.get("packet_id", "unknown"),
            "source": metadata.get("source", "internal"),
            "payload": entry.get("raw_text", ""),
            "type": metadata.get("type", "jailbreak_attempt"),
        },
        ensure_ascii=False,
        indent=2,
    )
    return (f'<div class="section-card" style="margin-top:1rem">'
            f'<div class="section-title">攻击动作 (原始载荷)</div>'
            f'<div class="payload-box">{formatted}</div>'
            f'</div>')


def _bubble_html(audits: list) -> str:
    html = ""
    for audit in audits:
        is_ctx = "context" in audit.agent_id
        cls = "expert-card context" if is_ctx else "expert-card"
        label = "上下文专家 (ContextAgent)" if is_ctx else "规则专家 (PatternAgent)"
        ev = ", ".join(audit.evidence[:4]) if audit.evidence else "[]"
        pct = int(audit.confidence * 100)
        risk_cls = "risk-high" if audit.confidence >= 0.7 else "risk-low" if audit.confidence <= 0.35 else "risk-mid"
        risk_txt = "高" if audit.confidence >= 0.7 else "低" if audit.confidence <= 0.35 else "中"
        bar_cls = "confidence-bar-fill high" if audit.confidence >= 0.7 else "confidence-bar-fill"
        html += (f'<div class="{cls}">'
             f'<div class="agent-name">{label}</div>'
             f'<div class="agent-risk">风险: <span class="{risk_cls}">{risk_txt} ({audit.confidence:.2f})</span></div>'
                 f'<div class="confidence-bar-wrap">'
                 f'<div class="confidence-bar-bg"><div class="{bar_cls}" style="width:{pct}%"></div></div>'
             f'<div class="confidence-pct">{pct}% 加权置信度</div></div>'
             f'<div class="agent-text"><strong>推理:</strong> {audit.reasoning[:170]}...</div>'
             f'<div class="agent-evidence"><strong>证据:</strong> {ev}</div>'
                 f'</div>')
    return html


def _gateway_html(entry: dict, packet) -> str:
    m = entry.get("metadata", {})
    endpoint = m.get("endpoint", "/api/v1/query")
    ip = m.get("ip_address", "0.0.0.0")
    session = m.get("session_id", packet.metadata.session_id)[:8]
    source = m.get("source", "internal")
    return (f'<div class="gateway-box">'
            f'<div class="gw-label">流量拦截 (网关 L1)</div>'
            f'<div class="gw-status">状态: <span>运行中</span></div>'
            f'<div class="gw-value">[已接收] {packet.packet_id[:16]} | {endpoint}</div>'
            f'<div class="gw-meta">IP: {ip} · 会话: {session} · 来源: {source}</div>'
            f'</div>')


def _gauge_html(confidence: float, status: VerdictStatus) -> str:
    pct = int(confidence * 100)
    if status == VerdictStatus.BLOCK or confidence >= 0.70:
        cls = "danger"
    elif confidence >= 0.45:
        cls = "warn"
    else:
        cls = "safe"
    return (
        f'<div class="gauge-wrap">'
        f'<div class="gauge-label">聚合威胁置信度</div>'
        f'<div class="gauge-track"><div class="gauge-fill {cls}" style="width:{pct}%"></div></div>'
        f'<div class="gauge-ticks"><span class="gauge-tick">0%</span><span class="gauge-tick">隔离</span><span class="gauge-tick">阻断</span><span class="gauge-tick">100%</span></div>'
        f'<div class="gauge-value {cls}">{pct}%</div>'
        f'</div>'
    )


def _verdict_html(verdict) -> str:
    css_cls = _verdict_css_class(verdict.status)
    threat = verdict.dominant_threat.value.upper().replace("_", " ")
    threat_text = _threat_zh(threat)
    status_text = _status_zh(verdict.status)
    dissenters = ", ".join(verdict.dissenting_agents) or "无"
    gauge = _gauge_html(verdict.aggregate_confidence, verdict.status)
    return (f'<div class="judge-wrap">'
            f'<div class="judge-card">'
            f'<div class="judge-title">共识裁决 (LAYER 1)</div>'
            f'{gauge}'
            f'<div class="judge-meta">结论: <strong>{status_text}</strong></div>'
            f'<div class="judge-meta">威胁类型: <strong>{threat_text}</strong></div>'
            f'<div class="judge-meta">异议代理: <strong>{dissenters}</strong></div>'
            f'</div>'
            f'<div class="verdict-block {css_cls}">'
            f'<div class="verdict-label">{status_text}</div>'
            f'<div class="verdict-meta">防御摘要: {verdict.judge_reasoning[:140]}...</div>'
            f'</div>'
            f'</div>')


def _history_items_for_view(history: list[dict]) -> list[dict]:
    if not history:
        return []
    if st.session_state.view_mode == "按攻击切换":
        idx = max(0, min(st.session_state.selected_attack_idx, len(history) - 1))
        return [history[idx]]
    return list(reversed(history))


def _brand_html() -> str:
    logo_html = (
        f'<img class="brand-logo" src="data:image/png;base64,{LOGO_BASE64}" alt="Crystal Shield" />'
        if LOGO_BASE64
        else '<div class="brand-logo-fallback">🛡️</div>'
    )
    return (
        '<div class="app-brand-fixed">'
        '<div class="app-brand-card">'
        f'{logo_html}'
        '<div class="brand-text">'
        '<div class="brand-title">SentinelAgent</div>'
        '<div class="brand-subtitle">AIWAF Defense Core</div>'
        '</div>'
        '</div>'
        '</div>'
    )


# ── Layout ─────────────────────────────────────────────────────────────────

st.markdown(_brand_html(), unsafe_allow_html=True)

col1, col2 = st.columns([1, 1])

# ── LEFT PANEL: Rogue Agent ────────────────────────────────────────────────
with col1:
    st.markdown(
        '<div class="panel-head rogue-head">'
        '<div class="hero-title">THE ROGUE AGENT</div>'
        '<div class="hero-sub">(ATTACKER)</div>'
        '</div>',
        unsafe_allow_html=True,
    )

    # Live animation area is pinned above history so new attack always starts at top.
    left_live = st.container()
    with left_live:
        left_thinking = st.empty()
        left_payload = st.empty()

    visible_history = _history_items_for_view(st.session_state.history)

    if not visible_history:
        st.markdown('<div class="idle-hint">等待首次攻击事件...</div>', unsafe_allow_html=True)
    for item in visible_history:
        st.markdown(_thinking_html(item["thinking"]), unsafe_allow_html=True)
        st.markdown(_payload_html(item["entry"]), unsafe_allow_html=True)
        st.markdown("<hr style='border-color:#333;margin:1.2rem 0'>", unsafe_allow_html=True)

# ── RIGHT PANEL: SentinelAgent ─────────────────────────────────────────────
with col2:
    st.markdown(
        '<div class="panel-head sentinel-head">'
        '<div class="hero-title">SENTINELAGENT</div>'
        '<div class="hero-sub">(DEFENDER)</div>'
        '</div>',
        unsafe_allow_html=True,
    )

    remaining = len(STREAM) - st.session_state.idx
    btn_label = (f"执行下一次攻击  (剩余 {remaining})"
                 if remaining > 0 else "所有数据包已处理")

    mode_col, pick_col = st.columns([1.05, 1.55])
    with mode_col:
        st.radio(
            "历史查看",
            ["滚动浏览", "按攻击切换"],
            key="view_mode",
            horizontal=True,
            label_visibility="collapsed",
        )
    with pick_col:
        if st.session_state.history:
            options = list(range(len(st.session_state.history) - 1, -1, -1))
            default_attack_idx = (
                st.session_state.selected_attack_idx
                if st.session_state.selected_attack_idx in options
                else options[0]
            )
            selected_attack = st.selectbox(
                "攻击批次",
                options=options,
                index=options.index(default_attack_idx),
                format_func=lambda i: f"第{i + 1}次攻击 · {st.session_state.history[i]['entry'].get('packet_id', 'unknown')[:14]}",
                disabled=(st.session_state.view_mode != "按攻击切换"),
                label_visibility="collapsed",
            )
            st.session_state.selected_attack_idx = selected_attack
        else:
            st.selectbox(
                "攻击批次",
                options=[0],
                format_func=lambda _: "暂无历史攻击",
                disabled=True,
                label_visibility="collapsed",
            )

    if st.button(btn_label, disabled=(remaining == 0)):
        entry  = STREAM[st.session_state.idx]
        packet = _build_packet(entry)
        thinking = _attacker_thinking(entry)

        # ── 左侧：攻击者思考打字机动画 ────────────────────────────────
        revealed: list[str] = []
        for line in thinking:
            revealed.append(line)
            left_thinking.markdown(_thinking_html(revealed), unsafe_allow_html=True)
            time.sleep(0.22)

        time.sleep(0.3)
        left_payload.markdown(_payload_html(entry), unsafe_allow_html=True)

        # ── 右侧：网关拦截信息 + 专家会诊槽位 ────────────────────────
        anim_gateway = st.empty()
        anim_bubbles = st.empty()
        anim_verdict = st.empty()

        anim_gateway.markdown(_gateway_html(entry, packet), unsafe_allow_html=True)

        # ── Step A：PatternAgent 先跑（本地正则，极快）────────────────
        anim_bubbles.markdown(
            '<div class="blurred idle-hint">规则专家分析中...</div>',
            unsafe_allow_html=True,
        )
        pattern_result = _run(_pattern_agent.analyse(packet))
        anim_bubbles.markdown(_bubble_html([pattern_result]), unsafe_allow_html=True)
        time.sleep(0.4)

        # ── Step B：ContextAgent（DeepSeek），右侧显示等待状态 ─────────
        anim_bubbles.markdown(
            _bubble_html([pattern_result])
            + '<div class="deepseek-waiting">⏳ 正在连接 DeepSeek API，语义分析中...</div>',
            unsafe_allow_html=True,
        )
        context_result = _run(_context_agent.analyse(packet))
        anim_bubbles.markdown(
            _bubble_html([pattern_result, context_result]),
            unsafe_allow_html=True,
        )
        time.sleep(0.4)

        # ── Step C：共识裁决 ──────────────────────────────────────────
        verdict = build_verdict([pattern_result, context_result], packet.packet_id)
        time.sleep(0.3)
        anim_verdict.markdown(_verdict_html(verdict), unsafe_allow_html=True)

        # ── Step D：写入审计日志数据库 ───────────────────────────────
        try:
            from shared.database import init_db, log_request
            _run(init_db())
            _run(log_request({
                "source_ip":    packet.metadata.ip_address or "127.0.0.1",
                "payload":      packet.raw_text,
                "risk_score":   verdict.aggregate_confidence,
                "reasoning":    verdict.judge_reasoning,
                "final_action": verdict.status,
            }))
        except Exception:
            pass  # DB 写入失败不影响 UI 展示

        time.sleep(1.0)

        # ── 写入历史并 rerun ──────────────────────────────────────────
        st.session_state.history.append({"entry": entry, "verdict": verdict, "thinking": revealed})
        st.session_state.selected_attack_idx = len(st.session_state.history) - 1
        st.session_state.idx += 1
        st.rerun()

    # ── Persistent history — newest first ─────────────────────────────────
    visible_history = _history_items_for_view(st.session_state.history)
    if not visible_history:
        st.markdown('<div class="idle-hint">专家会诊结果将在这里显示。</div>', unsafe_allow_html=True)
    for item in visible_history:
        st.markdown(_gateway_html(item["entry"], _build_packet(item["entry"])), unsafe_allow_html=True)
        st.markdown('<div class="expert-banner">专家会诊 (LAYER N)</div>', unsafe_allow_html=True)
        st.markdown(_bubble_html(item["verdict"].raw_audits), unsafe_allow_html=True)
        st.markdown(_verdict_html(item["verdict"]), unsafe_allow_html=True)
        st.markdown("<hr style='border-color:#1e2d3d;margin:1.2rem 0'>", unsafe_allow_html=True)
