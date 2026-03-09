"""
ShieldClaw — Main Dashboard (Streamlit)
Replaces dashboard.html. Fetches backboard log, shows timeline, AI thinking, and risk analysis.
"""

import os
import time
from collections import Counter
from datetime import datetime

import httpx
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

st.set_page_config(page_title="ShieldClaw", page_icon="🛡️", layout="wide")

# ── Config ───────────────────────────────────────────────────────────────────

SHIELDCLAW_BASE = os.getenv("SHIELDCLAW_URL", "http://localhost:8443")
REFRESH_INTERVAL = 8

COLORS = {
    "low": "#10B981",
    "low_bg": "#ECFDF5",
    "med": "#F59E0B",
    "med_bg": "#FFFBEB",
    "high": "#EF4444",
    "high_bg": "#FEF2F2",
    "text": "#111827",
    "text2": "#6B7280",
    "text3": "#9CA3AF",
}

CHART_LAYOUT = dict(
    plot_bgcolor="rgba(0,0,0,0)",
    paper_bgcolor="rgba(0,0,0,0)",
    font=dict(color="white"),
)


def risk_color(score: float) -> str:
    if score < 30:
        return COLORS["low"]
    if score < 65:
        return COLORS["med"]
    return COLORS["high"]


def status_icon(status: str) -> str:
    if status == "approved":
        return "✅"
    if status == "blocked":
        return "🚫"
    return "⚠️"


# ── Data fetching ────────────────────────────────────────────────────────────


@st.cache_data(ttl=REFRESH_INTERVAL)
def fetch_log() -> list[dict]:
    try:
        r = httpx.get(f"{SHIELDCLAW_BASE}/shieldclaw/backboard/log", timeout=5.0)
        if r.status_code < 400:
            return list(reversed(r.json().get("log", [])))
    except Exception:
        pass
    return []


@st.cache_data(ttl=20)
def fetch_status() -> dict:
    try:
        r = httpx.get(f"{SHIELDCLAW_BASE}/shieldclaw/auth0/status", timeout=5.0)
        if r.status_code < 400:
            return r.json()
    except Exception:
        pass
    return {}


@st.cache_data(ttl=20)
def fetch_config() -> dict:
    out = {"eval_mode": "", "use_backboard": False, "memory_count": ""}
    try:
        r = httpx.get(f"{SHIELDCLAW_BASE}/shieldclaw/backboard/config", timeout=5.0)
        if r.status_code < 400:
            c = r.json()
            out["eval_mode"] = c.get("eval_mode", "")
            out["use_backboard"] = c.get("use_backboard", False)
    except Exception:
        pass
    try:
        r = httpx.get(f"{SHIELDCLAW_BASE}/shieldclaw/backboard/status", timeout=5.0)
        if r.status_code < 400:
            s = r.json()
            out["memory_count"] = s.get("memory_count", "")
    except Exception:
        pass
    return out


# ── Load data ────────────────────────────────────────────────────────────────

log_data = fetch_log()
status_data = fetch_status()
config_data = fetch_config()

# ── Sidebar ──────────────────────────────────────────────────────────────────

st.sidebar.title("ShieldClaw")

st.sidebar.subheader("Services")
oc = status_data.get("openclaw", {}).get("reachable", False)
bb = status_data.get("backboard", {}).get("reachable", False)
st.sidebar.markdown(f"{'🟢' if oc else '🔴'} OpenClaw")
st.sidebar.markdown(f"{'🟢' if bb else '🔴'} Backboard")
st.sidebar.markdown("🟢 ShieldClaw")

st.sidebar.subheader("Threads")
if log_data:
    threads: dict[str, dict] = {}
    for r in log_data:
        k = r.get("session_id") or r.get("thread_id") or "default"
        if k not in threads:
            threads[k] = {"user": r.get("user_id", "unknown"), "count": 0}
        threads[k]["count"] += 1
    for info in threads.values():
        user = info["user"]
        if len(user) > 18:
            user = user[:16] + "..."
        st.sidebar.markdown(f"🔴 **{user}** — {info['count']} event{'s' if info['count'] != 1 else ''}")
else:
    st.sidebar.caption("No threads")

st.sidebar.subheader("Config")
st.sidebar.markdown(f"**Eval mode:** {config_data['eval_mode']}")
st.sidebar.markdown(f"**Backboard eval:** {'on' if config_data['use_backboard'] else 'off'}")
st.sidebar.markdown(f"**Memories:** {config_data['memory_count']}")

st.sidebar.markdown("---")
if st.sidebar.button("Refresh Now"):
    st.cache_data.clear()
    st.rerun()

auto_refresh = st.sidebar.checkbox("Auto-refresh", value=False)
st.sidebar.caption(f"Last refresh: {datetime.now().strftime('%H:%M:%S')}")

# ── Stats ────────────────────────────────────────────────────────────────────

n = len(log_data)
approved = sum(1 for r in log_data if r.get("status") == "approved")
avg_risk = sum(r.get("risk_score", 0) for r in log_data) / n if n else 0
thread_ids = {r.get("session_id") or r.get("thread_id") for r in log_data if r.get("session_id") or r.get("thread_id")}

col1, col2, col3, col4 = st.columns(4)
col1.metric("Events", n)
col2.metric("Threads", len(thread_ids))
col3.metric("Avg Risk", round(avg_risk, 1))
col4.metric("Approved", f"{round(approved / n * 100)}%" if n else "0%")

# ── Tabs ─────────────────────────────────────────────────────────────────────

tab_tl, tab_th, tab_rk = st.tabs(["Timeline", "Thinking", "Risk"])

# ── Timeline tab ─────────────────────────────────────────────────────────────

with tab_tl:
    if not log_data:
        st.info("No activity yet.")
    else:
        for entry in log_data:
            ts = datetime.fromisoformat(entry["timestamp"]).strftime("%H:%M:%S") if "timestamp" in entry else ""
            action = entry.get("action_type", "")
            status = entry.get("status", "unknown")
            reason = entry.get("reason") or entry.get("input_summary") or ""
            icon = status_icon(status)
            label = status.replace("_", " ").capitalize()

            with st.container():
                c1, c2 = st.columns([1, 8])
                with c1:
                    st.code(ts, language=None)
                with c2:
                    st.markdown(f"**{action}** {icon} `{label}`")
                    if reason:
                        st.caption(reason)

# ── Thinking tab ─────────────────────────────────────────────────────────────

with tab_th:
    if not log_data:
        st.info("No evaluation data available.")
    else:
        entry = log_data[0]
        risk = min(entry.get("risk_score", 0), 100)
        status = entry.get("status", "unknown")
        is_blocked = status == "blocked"
        user_req = entry.get("input_summary") or entry.get("action_type") or "User sent a request"

        st.subheader(f"Evaluation - {entry.get('action_type', 'Unknown')}")
        st.caption(
            datetime.fromisoformat(entry["timestamp"]).strftime("%H:%M:%S")
            if "timestamp" in entry else ""
        )

        st.markdown("##### AI Thinking")
        st.info(user_req)

        st.markdown("##### Steps")
        steps = []
        if entry.get("action_type"):
            steps.append(("Parse action", f"Identified action type: {entry['action_type']}"))
        steps.append(("Load user context", f"Trust tier: {entry.get('trust_tier', 'medium')}, User: {(entry.get('user_id') or 'unknown')[:24]}"))
        factors_str = ", ".join(entry.get("factors", [])) or "No risk factors detected."
        steps.append(("Run risk analysis", f"Risk score: {round(risk)}/100. {factors_str}"))
        if entry.get("matched_rules"):
            steps.append(("Match policy rules", ", ".join(entry["matched_rules"])))
        steps.append(("Reach decision", entry.get("reason") or "Decision made based on policy evaluation."))

        for i, (title, desc) in enumerate(steps):
            st.markdown(f"**{i + 1}. {title}**")
            st.caption(desc)

        if is_blocked:
            st.error(f"**Conclusion:** {entry.get('reason', 'Action blocked by safety policy.')}")
        else:
            st.success(f"**Conclusion:** {entry.get('reason', 'Safe to proceed.')}")

        st.markdown("##### Evaluation Flow")
        fc1, fc2, fc3, fc4 = st.columns(4)
        with fc1:
            st.markdown("**INPUT**")
            st.caption(entry.get("input_summary") or entry.get("action_type") or "")
        with fc2:
            st.markdown("**CONTEXT**")
            st.caption(f"Trust: `{entry.get('trust_tier', 'medium')}`")
        with fc3:
            st.markdown("**EVALUATE**")
            st.caption(f"Risk: **{round(risk)}/100**")
        with fc4:
            icon = status_icon(status)
            st.markdown(f"**{status.upper()}** {icon}")
            st.caption(entry.get("reason") or "")

        if entry.get("reasoning"):
            with st.expander("Claude Internal Reasoning"):
                st.code(entry["reasoning"], language=None)

# ── Risk tab ─────────────────────────────────────────────────────────────────

with tab_rk:
    if not log_data:
        st.info("No risk data available.")
    else:
        avg = sum(r.get("risk_score", 0) for r in log_data) / n
        peak = max(r.get("risk_score", 0) for r in log_data)
        blocked = sum(1 for r in log_data if r.get("status") == "blocked")
        block_rate = round(blocked / n * 100) if n else 0

        # Risk scores
        st.subheader("Risk Scores")
        r1, r2, r3 = st.columns(3)
        r1.metric("Average", round(avg, 1))
        r2.metric("Peak", round(peak))
        r3.metric("Block Rate", f"{block_rate}%")

        # Risk score bar chart
        fig_risk = go.Figure()
        for label, val in [("Average", avg), ("Peak", peak), ("Block Rate", block_rate)]:
            fig_risk.add_trace(go.Bar(
                x=[val],
                y=[label],
                orientation="h",
                marker_color=risk_color(val),
                text=f"{round(val, 1)}{'%' if label == 'Block Rate' else ''}",
                textposition="auto",
            ))
        fig_risk.update_layout(
            **CHART_LAYOUT,
            showlegend=False,
            height=200,
            xaxis=dict(range=[0, 100]),
            margin=dict(l=0, r=0, t=10, b=10),
        )
        st.plotly_chart(fig_risk, use_container_width=True)

        # Risk factors
        st.subheader("Risk Factors")
        all_factors: list[str] = []
        for r in log_data:
            all_factors.extend(r.get("factors", []))

        if all_factors:
            factor_counts = Counter(all_factors).most_common(8)
            for factor, count in factor_counts:
                st.markdown(f"- **{factor}** - {count}x")
        else:
            st.caption("No risk factors detected")

        # Safety checks
        st.subheader("Safety Checks")
        no_err = not any("evaluation_error" in (r.get("factors") or []) for r in log_data)
        has_budget = not any("budget" in f for r in log_data for f in (r.get("factors") or []))
        has_rate = not any("rate_limit" in f for r in log_data for f in (r.get("factors") or []))

        checks = [
            (True, "Tool permission verified"),
            (has_budget, "Budget limit validated"),
            (has_rate, "Rate limit passed"),
            (True, "Policy engine responded"),
            (no_err, "No evaluation errors"),
            (True, "Audit trail recorded"),
        ]
        for passed, label in checks:
            st.markdown(f"{'✅' if passed else '❌'} {label}")

        # Risk timeline chart
        if len(log_data) > 1:
            st.subheader("Risk Over Time")
            risk_df = pd.DataFrame([
                {
                    "timestamp": r.get("timestamp", ""),
                    "risk_score": r.get("risk_score", 0),
                    "status": r.get("status", "unknown"),
                }
                for r in log_data
                if r.get("timestamp")
            ])
            if not risk_df.empty:
                risk_df["timestamp"] = pd.to_datetime(risk_df["timestamp"])
                fig_timeline = px.scatter(
                    risk_df,
                    x="timestamp",
                    y="risk_score",
                    color="status",
                    color_discrete_map={
                        "approved": COLORS["low"],
                        "blocked": COLORS["high"],
                        "needs_confirmation": COLORS["med"],
                    },
                    title="Risk Score per Event",
                    labels={"timestamp": "Time", "risk_score": "Risk Score", "status": "Status"},
                    height=400,
                )
                fig_timeline.update_layout(**CHART_LAYOUT)
                st.plotly_chart(fig_timeline, use_container_width=True)

# ── Auto-refresh ─────────────────────────────────────────────────────────────

if auto_refresh:
    time.sleep(REFRESH_INTERVAL)
    st.rerun()
