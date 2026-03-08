"""ShieldClaw Interpretability Dashboard — Streamlit

Shows the internal reasoning behind every Claude security decision:
- Extended thinking traces (what Claude was actually "thinking")
- Risk factor breakdown per decision
- Decision timeline with risk scores
- Per-user agent history

Run:
    streamlit run dashboard_interpretability.py

Requires ShieldClaw to be running on http://127.0.0.1:8443
"""

import os
import time
from datetime import datetime, timezone

import httpx
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

SHIELDCLAW_URL = os.environ.get("SHIELDCLAW_URL", "http://127.0.0.1:8443")
SHIELDCLAW_TOKEN = os.environ.get("SHIELDCLAW_TOKEN", "dev-bypass-token")
POLL_INTERVAL = 3  # seconds between auto-refreshes

HEADERS = {"Authorization": f"Bearer {SHIELDCLAW_TOKEN}"}

STATUS_COLORS = {
    "approved": "#22c55e",
    "needs_confirmation": "#f59e0b",
    "blocked": "#ef4444",
    "unknown": "#6b7280",
}

STATUS_ICONS = {
    "approved": "✅",
    "needs_confirmation": "⏳",
    "blocked": "🚫",
    "unknown": "❓",
}

# ---------------------------------------------------------------------------
# Data fetching
# ---------------------------------------------------------------------------

@st.cache_data(ttl=POLL_INTERVAL)
def fetch_log() -> list[dict]:
    try:
        resp = httpx.get(
            f"{SHIELDCLAW_URL}/shieldclaw/backboard/log",
            headers=HEADERS,
            timeout=5.0,
        )
        resp.raise_for_status()
        return resp.json().get("log", [])
    except Exception as e:
        st.warning(f"Could not reach ShieldClaw: {e}")
        return []


@st.cache_data(ttl=POLL_INTERVAL)
def fetch_pending() -> list[dict]:
    try:
        resp = httpx.get(
            f"{SHIELDCLAW_URL}/shieldclaw/approval/pending",
            headers=HEADERS,
            timeout=5.0,
        )
        resp.raise_for_status()
        return resp.json().get("pending", [])
    except Exception:
        return []


BACKBOARD_BASE_URL = "https://app.backboard.io/api"
BACKBOARD_API_KEY = os.environ.get("BACKBOARDS_API_KEY", "")
_explain_assistant_id: str | None = None


def _get_explain_assistant() -> str:
    global _explain_assistant_id
    if _explain_assistant_id:
        return _explain_assistant_id
    headers = {"X-API-Key": BACKBOARD_API_KEY}
    # Reuse existing or create
    r = httpx.get(f"{BACKBOARD_BASE_URL}/assistants", headers=headers, timeout=10)
    if r.is_success:
        for a in r.json():
            if a.get("name") == "shieldbot-explainer":
                _explain_assistant_id = a["assistant_id"]
                return _explain_assistant_id
    r = httpx.post(
        f"{BACKBOARD_BASE_URL}/assistants",
        json={"name": "shieldbot-explainer", "model": "gemini-2.0-flash-lite-001", "system_prompt": (
            "You are a security analyst explaining AI agent security decisions. "
            "Be direct and cite specific evidence from the payload and factors."
        )},
        headers=headers, timeout=10,
    )
    r.raise_for_status()
    _explain_assistant_id = r.json()["assistant_id"]
    return _explain_assistant_id


@st.cache_data(ttl=300, show_spinner=False)
def explain_decision(action_type: str, payload_str: str, status: str, reason: str,
                     factors_str: str, risk: float, tier: str) -> str:
    """Call Backboard (same API used for evals) to explain a decision with citations."""
    try:
        headers = {"X-API-Key": BACKBOARD_API_KEY}
        assistant_id = _get_explain_assistant()

        thread_r = httpx.post(
            f"{BACKBOARD_BASE_URL}/assistants/{assistant_id}/threads",
            json={}, headers=headers, timeout=10,
        )
        thread_r.raise_for_status()
        thread_id = thread_r.json()["thread_id"]

        prompt = (
            f"A security policy engine made this decision about an AI agent action.\n"
            f"Explain WHY, citing SPECIFIC quoted text from the payload/factors that is "
            f"actually harmful. If the user explicitly requested the action, say so and "
            f"note if the decision seems overly cautious.\n\n"
            f"Action type: {action_type}\n"
            f"Payload: {payload_str}\n"
            f"Status: {status}\n"
            f"Risk score: {risk}/100\n"
            f"Trust tier: {tier}\n"
            f"Reason given: {reason}\n"
            f"Risk factors flagged: {factors_str}\n\n"
            f"Write 3-5 sentences. Quote the specific payload fields that triggered each concern."
        )

        msg_r = httpx.post(
            f"{BACKBOARD_BASE_URL}/threads/{thread_id}/messages",
            headers=headers,
            data={"content": prompt, "stream": "false", "send_to_llm": "true", "memory": "None"},
            timeout=30,
        )
        msg_r.raise_for_status()
        return (msg_r.json().get("content") or "").strip()
    except Exception as e:
        return f"Could not generate explanation: {e}"


@st.cache_data(ttl=POLL_INTERVAL)
def fetch_config() -> dict:
    try:
        resp = httpx.get(
            f"{SHIELDCLAW_URL}/shieldclaw/backboard/config",
            headers=HEADERS,
            timeout=5.0,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return {}


def set_eval_mode(mode: str):
    try:
        httpx.post(
            f"{SHIELDCLAW_URL}/shieldclaw/backboard/config",
            headers={**HEADERS, "Content-Type": "application/json"},
            json={"eval_mode": mode},
            timeout=5.0,
        )
        st.cache_data.clear()
    except Exception as e:
        st.error(f"Failed to set eval mode: {e}")


# ---------------------------------------------------------------------------
# Page setup
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="ShieldClaw — Interpretability",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    .thinking-box {
        background: #0f172a;
        border-left: 3px solid #6366f1;
        border-radius: 6px;
        padding: 14px 18px;
        font-family: 'JetBrains Mono', 'Fira Code', monospace;
        font-size: 0.82rem;
        color: #c7d2fe;
        white-space: pre-wrap;
        word-break: break-word;
        max-height: 400px;
        overflow-y: auto;
    }
    .risk-chip {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 999px;
        font-size: 0.72rem;
        font-weight: 600;
        margin: 2px 3px 2px 0;
        background: #1e293b;
        color: #94a3b8;
        border: 1px solid #334155;
    }
    .decision-card {
        border: 1px solid #1e293b;
        border-radius: 10px;
        padding: 16px;
        margin-bottom: 12px;
    }
    .metric-label { font-size: 0.75rem; color: #94a3b8; }
    .metric-value { font-size: 1.6rem; font-weight: 700; }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

with st.sidebar:
    st.title("🛡️ ShieldClaw")
    st.caption("Interpretability Dashboard")
    st.divider()

    cfg = fetch_config()
    current_mode = cfg.get("eval_mode", "fast")
    st.markdown("**Eval mode**")
    col_a, col_b = st.columns(2)
    if col_a.button("think", use_container_width=True,
                    type="primary" if current_mode == "think" else "secondary"):
        set_eval_mode("think")
        st.rerun()
    if col_b.button("fast", use_container_width=True,
                    type="primary" if current_mode == "fast" else "secondary"):
        set_eval_mode("fast")
        st.rerun()

    st.caption(
        "**think** = claude-sonnet-4-6 with extended thinking (shows reasoning)\n\n"
        "**fast** = claude-haiku-4-5 no thinking (low latency, no trace)"
    )
    st.divider()

    auto_refresh = st.toggle("Auto-refresh", value=True)
    if auto_refresh:
        st.caption(f"Refreshes every {POLL_INTERVAL}s")

    if st.button("Force refresh", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

    st.divider()
    pending = fetch_pending()
    if pending:
        st.markdown(f"**Pending approvals: {len(pending)}**")
        for p in pending:
            req = p.get("request", {})
            st.warning(
                f"`{p['approval_id'][:8]}` — {req.get('action_type', '?')} "
                f"(risk {req.get('risk_score', '?')})"
            )
    else:
        st.markdown("No pending approvals")

# ---------------------------------------------------------------------------
# Load data
# ---------------------------------------------------------------------------

log = fetch_log()

if not log:
    st.info("No decisions yet. Send a message through ShieldClaw to see interpretability data here.")
    if auto_refresh:
        time.sleep(POLL_INTERVAL)
        st.rerun()
    st.stop()

# Parse timestamps, newest first
for entry in log:
    ts = entry.get("timestamp", "")
    try:
        entry["_dt"] = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        entry["_dt"] = datetime.now(timezone.utc)

log.sort(key=lambda x: x["_dt"], reverse=True)

# ---------------------------------------------------------------------------
# Header metrics
# ---------------------------------------------------------------------------

st.title("🛡️ ShieldClaw — AI Interpretability")
st.caption(f"Live view of every Claude security decision | {len(log)} decisions in session")

total = len(log)
approved = sum(1 for e in log if e.get("status") == "approved")
blocked = sum(1 for e in log if e.get("status") == "blocked")
needs_conf = sum(1 for e in log if e.get("status") == "needs_confirmation")
has_thinking = sum(1 for e in log if e.get("reasoning"))
avg_risk = sum(e.get("risk_score", 0) for e in log) / total if total else 0

m1, m2, m3, m4, m5, m6 = st.columns(6)
m1.metric("Total decisions", total)
m2.metric("Approved", approved, delta=None)
m3.metric("Blocked", blocked)
m4.metric("Pending confirm", needs_conf)
m5.metric("Avg risk score", f"{avg_risk:.0f}/100")
m6.metric("With thinking trace", has_thinking)

st.divider()

# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------

tab_trace, tab_timeline, tab_factors, tab_users = st.tabs([
    "Thinking Traces", "Decision Timeline", "Risk Factor Analysis", "Per-User History"
])

# ── Tab 1: Thinking Traces ──────────────────────────────────────────────────
with tab_trace:
    st.subheader("Claude's Internal Reasoning")
    st.caption(
        "When eval mode is **think**, ShieldClaw uses claude-sonnet-4-6 with extended thinking. "
        "The raw thinking blocks are captured here — this is Claude reasoning through the security "
        "decision before outputting its verdict."
    )

    thinking_entries = [e for e in log if e.get("reasoning")]
    no_thinking_entries = [e for e in log if not e.get("reasoning")]

    if not thinking_entries:
        st.info(
            "No thinking traces yet. Switch eval mode to **think** in the sidebar and send "
            "a request through ShieldClaw."
        )
    else:
        st.success(f"{len(thinking_entries)} decisions have full thinking traces")

    # Show all decisions, with thinking highlighted
    for i, entry in enumerate(log[:50]):
        status = entry.get("status", "unknown")
        icon = STATUS_ICONS.get(status, "❓")
        color = STATUS_COLORS.get(status, "#6b7280")
        risk = entry.get("risk_score", 0)
        action = entry.get("action_type", "unknown")
        reason = entry.get("reason", "")
        ts = entry["_dt"].strftime("%H:%M:%S")
        thinking = entry.get("reasoning")
        factors = entry.get("factors") or []
        tier = entry.get("trust_tier", "medium")

        with st.expander(
            f"{icon} `{ts}` — **{action}** — risk {risk:.0f}/100 — {status.upper()}",
            expanded=(i == 0 and bool(thinking)),
        ):
            col_left, col_right = st.columns([2, 1])

            with col_left:
                st.markdown(f"**Decision:** {icon} `{status}`")
                st.markdown(f"**Reason:** {reason}")
                st.markdown(f"**Trust tier:** `{tier}`")

                inp = entry.get("input_summary", "")
                out = entry.get("output_summary", "")
                if inp:
                    st.markdown(f"**Request:** {inp}")
                if out:
                    st.markdown(f"**Proposed action:** {out}")

                if factors:
                    chips = "".join(f'<span class="risk-chip">{f}</span>' for f in factors)
                    st.markdown(f"**Risk factors:** {chips}", unsafe_allow_html=True)

                rules = entry.get("matched_rules") or []
                prefs = entry.get("matched_preferences") or []
                if rules:
                    st.markdown(f"**Matched rules:** `{'`, `'.join(rules)}`")
                if prefs:
                    st.markdown(f"**Matched prefs:** `{'`, `'.join(prefs)}`")

            with col_right:
                # Risk gauge
                fig = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=risk,
                    domain={"x": [0, 1], "y": [0, 1]},
                    title={"text": "Risk Score", "font": {"size": 13}},
                    gauge={
                        "axis": {"range": [0, 100], "tickwidth": 1},
                        "bar": {"color": color},
                        "steps": [
                            {"range": [0, 30], "color": "#0f2010"},
                            {"range": [30, 70], "color": "#2a1f00"},
                            {"range": [70, 100], "color": "#2a0000"},
                        ],
                        "threshold": {
                            "line": {"color": color, "width": 3},
                            "thickness": 0.75,
                            "value": risk,
                        },
                    },
                ))
                fig.update_layout(
                    height=180, margin=dict(l=10, r=10, t=30, b=10),
                    paper_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0",
                )
                st.plotly_chart(fig, width="stretch", key=f"gauge_{i}")

            if thinking:
                st.markdown("**Claude's thinking trace:**")
                st.markdown(
                    f'<div class="thinking-box">{thinking}</div>',
                    unsafe_allow_html=True,
                )
            else:
                st.markdown("**AI explanation** *(no thinking trace — fast mode)*")
                payload = entry.get("payload") or {}
                import json as _json
                payload_str = _json.dumps(payload, indent=2) if payload else "(no payload)"
                factors_str = ", ".join(factors) if factors else "none"
                with st.spinner("Generating cited explanation..."):
                    explanation = explain_decision(
                        action_type=action,
                        payload_str=payload_str,
                        status=status,
                        reason=reason,
                        factors_str=factors_str,
                        risk=risk,
                        tier=tier,
                    )
                st.markdown(
                    f'<div class="thinking-box" style="border-color:#f59e0b;color:#fde68a;">'
                    f'{explanation}</div>',
                    unsafe_allow_html=True,
                )

# ── Tab 2: Timeline ─────────────────────────────────────────────────────────
with tab_timeline:
    st.subheader("Decision Timeline")

    df = pd.DataFrame([
        {
            "time": e["_dt"],
            "action_type": e.get("action_type", "unknown"),
            "status": e.get("status", "unknown"),
            "risk_score": float(e.get("risk_score", 0)),
            "user_id": e.get("user_id", "unknown"),
            "reason": e.get("reason", ""),
            "trust_tier": e.get("trust_tier", "medium"),
            "has_thinking": bool(e.get("reasoning")),
        }
        for e in log
    ])

    # Risk score over time
    fig_risk = px.scatter(
        df,
        x="time",
        y="risk_score",
        color="status",
        symbol="has_thinking",
        hover_data=["action_type", "user_id", "reason", "trust_tier"],
        color_discrete_map=STATUS_COLORS,
        title="Risk Score per Decision (diamond = has thinking trace)",
        labels={"risk_score": "Risk Score (0-100)", "time": "Time"},
    )
    fig_risk.add_hline(y=70, line_dash="dash", line_color="#ef4444", annotation_text="Block threshold (~70)")
    fig_risk.add_hline(y=30, line_dash="dash", line_color="#f59e0b", annotation_text="Caution threshold (~30)")
    fig_risk.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(15,23,42,0.8)",
        font_color="#e2e8f0",
        height=380,
    )
    st.plotly_chart(fig_risk, width="stretch", key="timeline_risk")

    # Status distribution over time (rolling)
    col1, col2 = st.columns(2)

    with col1:
        status_counts = df["status"].value_counts().reset_index()
        status_counts.columns = ["status", "count"]
        fig_pie = px.pie(
            status_counts,
            values="count",
            names="status",
            color="status",
            color_discrete_map=STATUS_COLORS,
            title="Decision Distribution",
            hole=0.45,
        )
        fig_pie.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            font_color="#e2e8f0",
            height=300,
        )
        st.plotly_chart(fig_pie, width="stretch", key="timeline_pie")

    with col2:
        tier_counts = df["trust_tier"].value_counts().reset_index()
        tier_counts.columns = ["trust_tier", "count"]
        tier_colors = {"high": "#22c55e", "medium": "#f59e0b", "low": "#ef4444"}
        fig_tier = px.bar(
            tier_counts,
            x="trust_tier",
            y="count",
            color="trust_tier",
            color_discrete_map=tier_colors,
            title="Trust Tier Distribution",
        )
        fig_tier.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(15,23,42,0.8)",
            font_color="#e2e8f0",
            height=300,
            showlegend=False,
        )
        st.plotly_chart(fig_tier, width="stretch", key="timeline_tier")

    # Raw table
    st.markdown("**All decisions**")
    display_df = df[["time", "action_type", "status", "risk_score", "trust_tier", "user_id", "has_thinking", "reason"]].copy()
    display_df["time"] = display_df["time"].dt.strftime("%H:%M:%S")
    st.dataframe(
        display_df,
        use_container_width=True,
        column_config={
            "risk_score": st.column_config.ProgressColumn("risk_score", min_value=0, max_value=100),
            "has_thinking": st.column_config.CheckboxColumn("thinking"),
        },
        hide_index=True,
    )

# ── Tab 3: Risk Factor Analysis ─────────────────────────────────────────────
with tab_factors:
    st.subheader("Risk Factor Breakdown")
    st.caption("What factors Claude cited most often across all decisions")

    from collections import Counter

    all_factors = []
    for e in log:
        for f in (e.get("factors") or []):
            all_factors.append({
                "factor": f,
                "status": e.get("status", "unknown"),
                "risk_score": float(e.get("risk_score", 0)),
            })

    if not all_factors:
        st.info("No risk factors logged yet.")
    else:
        factor_df = pd.DataFrame(all_factors)

        # Factor frequency
        freq = factor_df["factor"].value_counts().reset_index()
        freq.columns = ["factor", "count"]
        fig_bar = px.bar(
            freq.head(20),
            x="count",
            y="factor",
            orientation="h",
            title="Top 20 Risk Factors (frequency)",
            color="count",
            color_continuous_scale="Reds",
        )
        fig_bar.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(15,23,42,0.8)",
            font_color="#e2e8f0",
            height=400,
            yaxis={"categoryorder": "total ascending"},
            coloraxis_showscale=False,
        )
        st.plotly_chart(fig_bar, width="stretch", key="factors_bar")

        # Factor vs avg risk score
        factor_risk = (
            factor_df.groupby("factor")["risk_score"]
            .agg(["mean", "count"])
            .reset_index()
            .rename(columns={"mean": "avg_risk", "count": "occurrences"})
            .sort_values("avg_risk", ascending=False)
        )
        fig_scatter = px.scatter(
            factor_risk,
            x="occurrences",
            y="avg_risk",
            text="factor",
            size="occurrences",
            color="avg_risk",
            color_continuous_scale="RdYlGn_r",
            title="Factor: Frequency vs Average Risk Score",
            labels={"avg_risk": "Avg Risk Score", "occurrences": "Times Cited"},
        )
        fig_scatter.update_traces(textposition="top center", textfont_size=10)
        fig_scatter.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(15,23,42,0.8)",
            font_color="#e2e8f0",
            height=420,
            coloraxis_showscale=False,
        )
        st.plotly_chart(fig_scatter, width="stretch", key="factors_scatter")

        # Factor → decision outcome breakdown
        st.markdown("**Factor → Decision outcome**")
        pivot = (
            factor_df.groupby(["factor", "status"])
            .size()
            .unstack(fill_value=0)
            .reset_index()
        )
        st.dataframe(pivot, use_container_width=True, hide_index=True)

# ── Tab 4: Per-User History ─────────────────────────────────────────────────
with tab_users:
    st.subheader("Per-Agent / Per-User History")

    user_ids = sorted({e.get("user_id", "unknown") for e in log})
    selected_user = st.selectbox("Select user/agent", ["(all)"] + user_ids)

    filtered = log if selected_user == "(all)" else [
        e for e in log if e.get("user_id") == selected_user
    ]

    if not filtered:
        st.info("No decisions for this user.")
    else:
        u_total = len(filtered)
        u_approved = sum(1 for e in filtered if e.get("status") == "approved")
        u_blocked = sum(1 for e in filtered if e.get("status") == "blocked")
        u_avg_risk = sum(e.get("risk_score", 0) for e in filtered) / u_total
        u_thinking = sum(1 for e in filtered if e.get("reasoning"))

        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Total", u_total)
        c2.metric("Approved", u_approved)
        c3.metric("Blocked", u_blocked)
        c4.metric("Avg risk", f"{u_avg_risk:.0f}/100")
        c5.metric("Thinking traces", u_thinking)

        # Risk over time for this user
        user_df = pd.DataFrame([
            {
                "time": e["_dt"],
                "action_type": e.get("action_type", "?"),
                "status": e.get("status", "unknown"),
                "risk_score": float(e.get("risk_score", 0)),
                "trust_tier": e.get("trust_tier", "medium"),
            }
            for e in filtered
        ])

        fig_u = px.line(
            user_df.sort_values("time"),
            x="time",
            y="risk_score",
            color="status",
            markers=True,
            color_discrete_map=STATUS_COLORS,
            title=f"Risk score over time — {selected_user}",
        )
        fig_u.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(15,23,42,0.8)",
            font_color="#e2e8f0",
            height=300,
        )
        st.plotly_chart(fig_u, width="stretch", key="user_risk")

        # Session trust tier degradation
        tier_map = {"high": 3, "medium": 2, "low": 1}
        user_df["tier_num"] = user_df["trust_tier"].map(tier_map).fillna(2)
        fig_tier = px.line(
            user_df.sort_values("time"),
            x="time",
            y="tier_num",
            title="Trust tier over session (3=high, 2=medium, 1=low)",
            markers=True,
        )
        fig_tier.update_yaxes(tickvals=[1, 2, 3], ticktext=["low", "medium", "high"])
        fig_tier.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(15,23,42,0.8)",
            font_color="#e2e8f0",
            height=240,
        )
        st.plotly_chart(fig_tier, width="stretch", key="user_tier")

        # Individual decisions with thinking
        st.markdown("**Decision history**")
        for e in filtered[:30]:
            status = e.get("status", "unknown")
            icon = STATUS_ICONS.get(status, "❓")
            ts = e["_dt"].strftime("%H:%M:%S")
            action = e.get("action_type", "?")
            risk = e.get("risk_score", 0)
            thinking = e.get("reasoning")

            with st.expander(f"{icon} `{ts}` {action} — risk {risk:.0f}"):
                st.markdown(f"**Status:** `{status}` | **Trust tier:** `{e.get('trust_tier', '?')}`")
                st.markdown(f"**Reason:** {e.get('reason', '')}")
                factors = e.get("factors") or []
                if factors:
                    chips = "".join(f'<span class="risk-chip">{f}</span>' for f in factors)
                    st.markdown(f"**Factors:** {chips}", unsafe_allow_html=True)
                if thinking:
                    st.markdown("**Thinking:**")
                    st.markdown(
                        f'<div class="thinking-box">{thinking}</div>',
                        unsafe_allow_html=True,
                    )

# ---------------------------------------------------------------------------
# Auto-refresh
# ---------------------------------------------------------------------------

if auto_refresh:
    time.sleep(POLL_INTERVAL)
    st.cache_data.clear()
    st.rerun()
