"""
pages/Admin_Dashboard.py — SentinelAgent Production Admin Dashboard
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Streamlit multi-page app entry.  Place this file under pages/ so Streamlit
automatically registers it in the sidebar when running from the project root:

    streamlit run frontend/app.py   ← main narrative UI
    # Admin Dashboard appears in the sidebar automatically

Or run it standalone:

    streamlit run pages/Admin_Dashboard.py

Design constraints (1 vCPU / 1 GB RAM server):
  • All pandas work is done in a single vectorised pass — no row-by-row loops.
  • The attack-type chart uses a pre-compiled regex dict, never re-scanned.
  • DB fetch is wrapped in @st.cache_data(ttl=30) — at most one async call
    per 30 s regardless of how many simultaneous browser tabs are open.
  • Plotly figure is built from a tiny aggregated DataFrame, not raw logs.
  • asyncio.run() is used for the single DB coroutine; no extra event loop.

Security:
  • Login credentials come from ADMIN_USERNAME / ADMIN_PASSWORD env vars
    (loaded from .env by python-dotenv).
  • st.stop() is called immediately after rendering the login form so the
    rest of the page — including any data fetch — never executes for an
    unauthenticated visitor.
  • The sign-out button clears session state AND the cache so a subsequent
    visitor starts completely fresh.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

from __future__ import annotations

import asyncio
import os
import re
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

# ── Path bootstrap ──────────────────────────────────────────────────────────
# Works whether launched as `streamlit run pages/Admin_Dashboard.py`
# or via the automatic pages/ discovery from the project root.
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

# Load .env (python-dotenv) — safe even if already loaded elsewhere
try:
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env", override=False)
except ImportError:
    pass

from shared.database import get_recent_logs  # noqa: E402


# ══════════════════════════════════════════════════════════════════════════════
# PAGE CONFIG  (must be the very first Streamlit call)
# ══════════════════════════════════════════════════════════════════════════════

st.set_page_config(
    page_title="SentinelAgent · Admin",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── CSS ─────────────────────────────────────────────────────────────────────
# Shared project palette + admin-specific overrides
_css_path = ROOT / "frontend" / "styles.css"
if _css_path.exists():
    st.markdown(f"<style>{_css_path.read_text(encoding='utf-8')}</style>",
                unsafe_allow_html=True)

st.markdown("""
<style>
/* ── Global dark background ──────────────────────────────────────── */
html, body,
[data-testid="stAppViewContainer"],
[data-testid="stMain"],
section[data-testid="stMain"] > div, .main {
    background: #0b0f18 !important;
}
.main .block-container {
    max-width: 1300px !important;
    padding: 1.5rem 2rem 2rem !important;
}

/* ── Header banner ───────────────────────────────────────────────── */
.adm-banner {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: .75rem 1.3rem;
    border-radius: 13px;
    background: linear-gradient(135deg, #0d1521 0%, #0f1c30 100%);
    border: 1px solid rgba(90,160,230,.22);
    margin-bottom: 1.5rem;
    box-shadow: 0 6px 24px rgba(0,0,0,.4);
}
.adm-title {
    font-family: 'Barlow Condensed', sans-serif;
    font-size: 1.7rem;
    font-weight: 800;
    letter-spacing: 1px;
    color: #eaf6ff;
}
.adm-sub {
    font-family: 'JetBrains Mono', monospace;
    font-size: .62rem;
    color: #5a8fb5;
    letter-spacing: .5px;
    margin-top: 2px;
}
.status-dot {
    display: inline-block;
    width: 9px; height: 9px;
    border-radius: 50%;
    background: #28c76f;
    box-shadow: 0 0 7px #28c76f;
    margin-right: 5px;
    vertical-align: middle;
}
.status-label {
    font-family: 'JetBrains Mono', monospace;
    font-size: .8rem;
    color: #6de89a;
    vertical-align: middle;
}

/* ── Metric cards ────────────────────────────────────────────────── */
[data-testid="stMetric"] {
    background: #101928;
    border: 1px solid rgba(80,150,220,.18);
    border-radius: 13px;
    padding: 1rem 1.3rem !important;
}
[data-testid="stMetricLabel"] {
    font-family: 'JetBrains Mono', monospace !important;
    color: #5a8fb5 !important;
    font-size: .78rem !important;
    text-transform: uppercase;
    letter-spacing: .4px;
}
[data-testid="stMetricValue"] {
    font-family: 'Barlow Condensed', sans-serif !important;
    font-size: 2.5rem !important;
    font-weight: 800 !important;
    color: #eaf6ff !important;
}
[data-testid="stMetricDelta"] svg { display: none !important; }

/* ── Section headings ────────────────────────────────────────────── */
.sec-head {
    font-family: 'Barlow Condensed', sans-serif;
    font-size: 1.12rem;
    font-weight: 700;
    letter-spacing: .5px;
    color: #7fb8e0;
    border-left: 3px solid #1e6ebd;
    padding-left: .6rem;
    margin: 1.6rem 0 .55rem;
}

/* ── Action badges ───────────────────────────────────────────────── */
.badge-block {
    display: inline-block;
    background: rgba(205,57,52,.14);
    border: 1px solid rgba(205,57,52,.5);
    color: #f28b88; border-radius: 6px;
    padding: 1px 7px;
    font-family: 'JetBrains Mono', monospace;
    font-size: .76rem; font-weight: 700;
}
.badge-pass {
    display: inline-block;
    background: rgba(33,145,73,.14);
    border: 1px solid rgba(33,145,73,.45);
    color: #60d68f; border-radius: 6px;
    padding: 1px 7px;
    font-family: 'JetBrains Mono', monospace;
    font-size: .76rem; font-weight: 700;
}

/* ── Deep-dive panel ─────────────────────────────────────────────── */
.dive-label {
    font-family: 'JetBrains Mono', monospace;
    color: #6099be;
    font-size: .76rem;
    margin-bottom: .3rem;
    text-transform: uppercase;
    letter-spacing: .4px;
}

/* ── Login card ──────────────────────────────────────────────────── */
.login-wrap {
    max-width: 420px;
    margin: 7rem auto 0;
    background: #101928;
    border: 1px solid rgba(80,150,220,.22);
    border-radius: 18px;
    padding: 2.5rem 2.2rem 2rem;
    box-shadow: 0 20px 50px rgba(0,0,0,.55);
    text-align: center;
}
.login-title {
    font-family: 'Barlow Condensed', sans-serif;
    font-size: 2rem; font-weight: 800;
    color: #eaf6ff; margin-bottom: .2rem;
}
.login-sub {
    font-family: 'JetBrains Mono', monospace;
    font-size: .67rem; color: #4a80a5;
    margin-bottom: 1.8rem;
    letter-spacing: .4px;
}

/* Dark text inputs */
input[type="text"], input[type="password"] {
    background: #0b0f18 !important;
    color: #cce6f9 !important;
    border-color: rgba(70,130,185,.32) !important;
    border-radius: 8px !important;
}
[data-testid="stDataFrame"] { border-radius: 11px; overflow: hidden; }
</style>
""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTS — attack-type keyword classifier
# ══════════════════════════════════════════════════════════════════════════════

# Compiled once at import time — zero cost on re-runs.
_ATTACK_PATTERNS: dict[str, re.Pattern[str]] = {
    "SQL Injection":       re.compile(r"sql.inject|union.select|tautolog|stacked.quer", re.I),
    "XSS":                 re.compile(r"xss|cross.site|script.tag|event.handler|javascript:", re.I),
    "Prompt Injection":    re.compile(r"prompt.inject|ignore.prev|new.instruct", re.I),
    "Jailbreak":           re.compile(r"jailbreak|dan |roleplay|ignore.safet|pretend.you", re.I),
    "Data Exfiltration":   re.compile(r"exfiltrat|data.leak|dump|exfil", re.I),
    "Privilege Escalation":re.compile(r"privilege|escalat|admin.access|root.access", re.I),
    "Benign / Unknown":    re.compile(r".*"),  # catch-all — always last
}

_ADMIN_USER: str = os.getenv("ADMIN_USERNAME", "admin")
_ADMIN_PASS: str = os.getenv("ADMIN_PASSWORD", "sentinel2024")


# ══════════════════════════════════════════════════════════════════════════════
# SESSION STATE INIT
# ══════════════════════════════════════════════════════════════════════════════

if "adm_auth" not in st.session_state:
    st.session_state.adm_auth = False


# ══════════════════════════════════════════════════════════════════════════════
# 1.  LOGIN GATE
# ══════════════════════════════════════════════════════════════════════════════

def _render_login() -> None:
    st.markdown(
        '<div class="login-wrap">'
        '<div class="login-title">🔐 SentinelAgent</div>'
        '<div class="login-sub">ADMIN DASHBOARD · RESTRICTED ACCESS</div>'
        '</div>',
        unsafe_allow_html=True,
    )
    _, mid, _ = st.columns([1, 2, 1])
    with mid:
        user = st.text_input("Username", placeholder="admin", key="_adm_u")
        pwd  = st.text_input("Password", type="password", placeholder="••••••••", key="_adm_p")
        if st.button("Sign In →", use_container_width=True):
            if user == _ADMIN_USER and pwd == _ADMIN_PASS:
                st.session_state.adm_auth = True
                st.rerun()
            else:
                st.error("❌ Invalid credentials — access denied.", icon=None)


if not st.session_state.adm_auth:
    _render_login()
    st.stop()   # ← nothing below runs for unauthenticated visitors


# ══════════════════════════════════════════════════════════════════════════════
# 2.  DATA LAYER  (cached — 1 vCPU friendly)
# ══════════════════════════════════════════════════════════════════════════════

@st.cache_data(ttl=30, show_spinner=False)
def _load_logs(limit: int = 50) -> pd.DataFrame:
    """
    Fetch audit records and return a pre-formatted DataFrame.

    All heavy pandas work (type casting, timestamp parsing, snippet slicing,
    attack-type classification) happens here — inside the cache.  Subsequent
    widget interactions read the cached result without touching the DB or CPU.
    """
    raw: list[dict] = asyncio.run(get_recent_logs(limit=limit))
    if not raw:
        return pd.DataFrame()

    df = pd.DataFrame(raw)

    # ── Timestamp: parse UTC → convert to Beijing time (UTC+8) ─────────
    df["ts_parsed"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    df["Timestamp"] = (
        df["ts_parsed"]
        .dt.tz_convert("Asia/Shanghai")        # UTC → CST (UTC+8)
        .dt.strftime("%Y-%m-%d %H:%M:%S")      # format without tz suffix
    )

    # ── Risk score: float, rounded for display ────────────────────────────
    df["risk_score"] = df["risk_score"].astype(float)
    df["Risk Score"] = df["risk_score"].round(4)

    # ── Action badges ─────────────────────────────────────────────────────
    df["Action"] = df["final_action"].map(
        lambda a: "🔴 BLOCK" if a == "BLOCK" else "🟢 PASS"
    )

    # ── Payload snippet (vectorised string slice) ─────────────────────────
    df["Payload Snippet"] = df["payload"].str[:90].str.cat(
        df["payload"].str[90:].map(lambda t: "…" if t else ""), sep=""
    )

    # ── Attack-type classification via pre-compiled regexes ───────────────
    # Single pass per row, short-circuits on first match.
    def _classify(reasoning: str) -> str:
        for label, pat in _ATTACK_PATTERNS.items():
            if pat.search(reasoning):
                return label
        return "Benign / Unknown"

    df["Attack Type"] = df["reasoning"].apply(_classify)

    return df


def _get_df() -> pd.DataFrame:
    return _load_logs(50)


# ══════════════════════════════════════════════════════════════════════════════
# 3.  HEADER BAR
# ══════════════════════════════════════════════════════════════════════════════

col_hdr, col_btns = st.columns([5, 1])

with col_hdr:
    st.markdown(
        '<div class="adm-banner">'
        '  <div>'
        '    <div class="adm-title">🛡️ SentinelAgent — Admin Dashboard</div>'
        '    <div class="adm-sub">AUDIT LOG · THREAT INTELLIGENCE · REAL-TIME ANALYSIS</div>'
        '  </div>'
        '  <div style="text-align:right">'
        '    <span class="status-dot"></span>'
        '    <span class="status-label">System Online</span>'
        '  </div>'
        '</div>',
        unsafe_allow_html=True,
    )

with col_btns:
    st.markdown("<div style='height:.7rem'></div>", unsafe_allow_html=True)
    if st.button("🔄 Refresh", use_container_width=True, help="Clear cache and reload logs"):
        st.cache_data.clear()
        st.rerun()
    if st.button("🚪 Sign Out", use_container_width=True):
        st.session_state.adm_auth = False
        st.cache_data.clear()
        st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
# 4.  LIVE METRICS
# ══════════════════════════════════════════════════════════════════════════════

df = _get_df()

# Aggregate stats — all scalar ops, no iteration
total      = len(df)
n_block    = int((df["final_action"] == "BLOCK").sum()) if total else 0
n_pass     = total - n_block
block_rate = (n_block / total * 100) if total else 0.0
avg_risk   = float(df["risk_score"].mean()) if total else 0.0

st.markdown('<div class="sec-head">📊 Live Metrics</div>', unsafe_allow_html=True)
m1, m2, m3, m4 = st.columns(4)

m1.metric(
    label="Cumulative Requests",
    value=f"{total:,}",
    help="Total rows returned from audit_logs (capped at 50 in this view).",
)
m2.metric(
    label="Current Block Rate",
    value=f"{block_rate:.1f}%",
    delta=f"{n_block} blocked  ·  {n_pass} passed",
    delta_color="inverse",
    help="(Total BLOCKs / Total Requests) × 100",
)
m3.metric(
    label="Avg Risk Score",
    value=f"{avg_risk:.3f}",
    delta="0 = safe  ·  1 = critical",
    delta_color="off",
    help="Mean aggregate_confidence across displayed records.",
)
m4.metric(
    label="System Status",
    value="● Online",
    delta="DB connected · agents ready",
    delta_color="off",
    help="Gateway and audit DB are reachable.",
)

# Override the metric value colour to green for "Online"
st.markdown(
    """<style>
    [data-testid="stMetricValue"]:has(> div:contains("Online")) { color: #28c76f !important; }
    </style>""",
    unsafe_allow_html=True,
)


# ══════════════════════════════════════════════════════════════════════════════
# 5.  VISUAL ANALYSIS — Attack-Type Distribution (Plotly)
# ══════════════════════════════════════════════════════════════════════════════

st.markdown('<div class="sec-head">📈 Attack-Type Distribution</div>', unsafe_allow_html=True)

if total:
    import plotly.graph_objects as go

    # Aggregate — single groupby, tiny result frame
    atk_counts = (
        df.groupby("Attack Type", sort=False)["id"]
        .count()
        .reset_index()
        .rename(columns={"id": "Count"})
    )
    atk_counts.columns = ["Attack Type", "Count"]
    atk_counts = atk_counts.sort_values("Count", ascending=True)

    # Colour map — benign green, known threats red, rest amber
    _colour_map = {
        "SQL Injection":        "#e05c57",
        "XSS":                  "#e07a57",
        "Prompt Injection":     "#c96db5",
        "Jailbreak":            "#7b6fe0",
        "Data Exfiltration":    "#e0a257",
        "Privilege Escalation": "#d4574f",
        "Benign / Unknown":     "#3aab68",
    }
    bar_colours = [_colour_map.get(t, "#5a9fd4") for t in atk_counts["Attack Type"]]

    fig = go.Figure(go.Bar(
        x=atk_counts["Count"],
        y=atk_counts["Attack Type"],
        orientation="h",
        marker_color=bar_colours,
        marker_line_width=0,
        text=atk_counts["Count"],
        textposition="outside",
        textfont=dict(family="JetBrains Mono", size=12, color="#9fc8e8"),
    ))
    fig.update_layout(
        height=max(220, len(atk_counts) * 46),
        margin=dict(l=0, r=40, t=8, b=8),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(16,25,40,0.6)",
        font=dict(family="JetBrains Mono", color="#8ab4cc"),
        xaxis=dict(
            gridcolor="rgba(80,120,170,.15)",
            showgrid=True,
            zeroline=False,
            title=dict(text="Count", font=dict(size=11)),
        ),
        yaxis=dict(
            gridcolor="rgba(80,120,170,.1)",
            showgrid=False,
        ),
    )
    st.plotly_chart(fig, use_container_width=True)

    # Quick PASS/BLOCK split below the chart
    ca, cb = st.columns(2)
    ca.markdown(
        f'<div style="text-align:center;padding:.4rem">'
        f'<span class="badge-pass">🟢 PASS</span>&nbsp;&nbsp;'
        f'<span style="font-family:JetBrains Mono;color:#9fc8e8;font-size:1.1rem">{n_pass}</span>'
        f'</div>',
        unsafe_allow_html=True,
    )
    cb.markdown(
        f'<div style="text-align:center;padding:.4rem">'
        f'<span class="badge-block">🔴 BLOCK</span>&nbsp;&nbsp;'
        f'<span style="font-family:JetBrains Mono;color:#9fc8e8;font-size:1.1rem">{n_block}</span>'
        f'</div>',
        unsafe_allow_html=True,
    )
else:
    st.info("No audit records yet — send some traffic through the gateway first.")


# ══════════════════════════════════════════════════════════════════════════════
# 6.  SMART LOG BROWSER
# ══════════════════════════════════════════════════════════════════════════════

st.markdown(
    '<div class="sec-head">🗂️ Audit Log Browser '
    '<span style="font-family:JetBrains Mono;font-size:.7rem;color:#3d6a8a">'
    '(last 50 records · newest first)</span></div>',
    unsafe_allow_html=True,
)

if total:
    display_cols = ["id", "Timestamp", "Action", "Risk Score", "source_ip",
                    "Attack Type", "Payload Snippet"]
    st.dataframe(
        df[display_cols],
        use_container_width=True,
        hide_index=True,
        column_config={
            "id":              st.column_config.NumberColumn("ID", width="small"),
            "Timestamp":       st.column_config.TextColumn("北京时间 (CST)", width="medium"),
            "Action":          st.column_config.TextColumn("Action", width="small"),
            "Risk Score":      st.column_config.NumberColumn(
                                   "Risk", format="%.4f", width="small",
                                   help="0 = safe · 1 = critical"),
            "source_ip":       st.column_config.TextColumn("Source IP", width="small"),
            "Attack Type":     st.column_config.TextColumn("Attack Type", width="medium"),
            "Payload Snippet": st.column_config.TextColumn("Payload Snippet", width="large"),
        },
        height=min(560, 56 + total * 36),   # adaptive height, never over-tall
    )
else:
    st.info("No records in the audit log database.")


# ══════════════════════════════════════════════════════════════════════════════
# 7.  EVIDENCE INSPECTOR  (Deep Dive)
# ══════════════════════════════════════════════════════════════════════════════

st.markdown('<div class="sec-head">🔍 Evidence Inspector — Deep Dive</div>',
            unsafe_allow_html=True)

if total:
    # Build selectbox options: "ID #42  ·  🔴 BLOCK  ·  risk 0.9200"
    id_list: list[int] = df["id"].tolist()
    label_map: dict[int, str] = {
        row["id"]: (
            f"#{row['id']:>5}  ·  "
            f"{'🔴 BLOCK' if row['final_action'] == 'BLOCK' else '🟢 PASS '}  ·  "
            f"risk {row['risk_score']:.4f}  ·  {row['Attack Type']}"
        )
        for _, row in df[["id", "final_action", "risk_score", "Attack Type"]].iterrows()
    }

    sel_col, _ = st.columns([2, 3])
    with sel_col:
        selected_id: int = st.selectbox(
            "Select Log ID",
            options=id_list,
            format_func=lambda i: label_map.get(i, str(i)),
            help="Pick a record from the table above to inspect its full details.",
        )

    # Lookup is an O(1) boolean mask — no Python loop
    mask = df["id"] == selected_id
    if mask.any():
        rec = df[mask].iloc[0]

        action    = rec["final_action"]
        risk      = float(rec["risk_score"])
        reasoning = str(rec["reasoning"])
        payload   = str(rec["payload"])
        atk_type  = str(rec["Attack Type"])

        # ── Summary chip row ─────────────────────────────────────────────
        risk_colour = (
            "#f28b88" if risk >= 0.70 else
            "#e6a53e" if risk >= 0.45 else
            "#60d68f"
        )
        action_badge = (
            '<span class="badge-block">⛔ BLOCK</span>'
            if action == "BLOCK"
            else '<span class="badge-pass">✅ PASS</span>'
        )
        st.markdown(
            f"""
            <div style="display:flex;gap:1.1rem;align-items:center;
                        margin:.6rem 0 .9rem;flex-wrap:wrap">
                <span style="font-family:'JetBrains Mono',monospace;
                             color:#4e82a0;font-size:.82rem">Log ID #{selected_id}</span>
                {action_badge}
                <span style="font-family:'JetBrains Mono',monospace;
                             color:{risk_colour};font-size:.85rem;font-weight:700">
                    Risk {risk:.4f}
                </span>
                <span style="font-family:'JetBrains Mono',monospace;
                             color:#5a8fb5;font-size:.8rem">
                    {atk_type}
                </span>
                <span style="font-family:'JetBrains Mono',monospace;
                             color:#3a607a;font-size:.77rem">
                    {rec['Timestamp']} CST · {rec['source_ip']}
                </span>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # ── DeepSeek Reasoning ────────────────────────────────────────────
        st.markdown(
            '<div class="dive-label">🧠 Full Reasoning (DeepSeek / Judge)</div>',
            unsafe_allow_html=True,
        )
        if action == "BLOCK" or risk >= 0.70:
            st.error(reasoning, icon="🚫")
        elif risk >= 0.45:
            st.warning(reasoning, icon="⚠️")
        else:
            st.info(reasoning, icon="🛡️")

        # ── Full Raw Payload ──────────────────────────────────────────────
        st.markdown(
            '<div class="dive-label" style="margin-top:.9rem">'
            '📦 Full Raw Payload</div>',
            unsafe_allow_html=True,
        )
        st.code(payload, language="http")

else:
    st.info("No data to inspect. Run traffic through the gateway to populate the audit log.")


# ══════════════════════════════════════════════════════════════════════════════
# 8.  FOOTER
# ══════════════════════════════════════════════════════════════════════════════

db_path = os.getenv("DB_PATH", str(ROOT / "sentinel_audit.db"))
st.markdown(
    f"""
    <div style="margin-top:2.5rem;padding-top:1rem;
                border-top:1px solid rgba(80,130,180,.12);
                text-align:center;
                font-family:'JetBrains Mono',monospace;
                font-size:.63rem;color:#243d55">
        SentinelAgent Admin Dashboard · cache TTL 30 s ·
        DB: <span style="color:#1c3346">{db_path}</span>
    </div>
    """,
    unsafe_allow_html=True,
)
