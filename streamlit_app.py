"""
ShieldClaw Auth0 Usage Tracker — Streamlit Dashboard
Actively probes Auth0 endpoints, tracks every call over time, and visualizes them.
"""

import os
import time
from datetime import datetime

import httpx
import pandas as pd
import plotly.express as px
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

st.set_page_config(page_title="ShieldClaw Auth0 Tracker", page_icon="🛡️", layout="wide")

SHIELDCLAW_BASE = st.sidebar.text_input("ShieldClaw URL", value="http://localhost:8443")
REFRESH_INTERVAL = st.sidebar.slider("Auto-refresh (seconds)", 3, 60, 5)

if "event_history" not in st.session_state:
    st.session_state.event_history = []

AUTH0_DOMAIN = None


# ── Helpers ──────────────────────────────────────────────────────────────────


def record_event(category: str, endpoint: str, status: str, latency_ms: float, detail: str = ""):
    """Append a tracked event to session state."""
    st.session_state.event_history.append({
        "timestamp": datetime.now(),
        "category": category,
        "endpoint": endpoint,
        "status": status,
        "latency_ms": round(latency_ms, 1),
        "detail": detail,
    })


def probe(label: str, category: str, url: str, headers: dict | None = None):
    """Hit an endpoint, record the result, return (ok, latency_ms, response_or_error)."""
    try:
        t0 = time.time()
        r = httpx.get(url, timeout=5.0, headers=headers or {})
        lat = (time.time() - t0) * 1000
        ok = r.status_code < 400
        record_event(category, label, "ok" if ok else f"http_{r.status_code}", lat, r.text[:200])
        return ok, lat, r
    except Exception as e:
        record_event(category, label, "error", 0, str(e)[:200])
        return False, 0, e


def probe_post(label: str, category: str, url: str, json_body: dict, headers: dict | None = None):
    """POST probe."""
    try:
        t0 = time.time()
        r = httpx.post(url, json=json_body, timeout=5.0, headers=headers or {})
        lat = (time.time() - t0) * 1000
        ok = r.status_code < 400
        record_event(category, label, "ok" if ok else f"http_{r.status_code}", lat, r.text[:200])
        return ok, lat, r
    except Exception as e:
        record_event(category, label, "error", 0, str(e)[:200])
        return False, 0, e


# ── Run probes ───────────────────────────────────────────────────────────────

st.title("🛡️ ShieldClaw — Auth0 Event Tracker")
st.caption("Actively probes Auth0 endpoints every refresh cycle and tracks all calls over time.")

CHART_LAYOUT = dict(
    plot_bgcolor="rgba(0,0,0,0)",
    paper_bgcolor="rgba(0,0,0,0)",
    font=dict(color="white"),
)

SCATTER_COLORS = {"ok": "#00cc96", "failed": "#ef553b"}

with st.spinner("Probing endpoints..."):
    # 1. Auth0 status
    ok, _, resp = probe("auth0/status", "Auth0 Config", f"{SHIELDCLAW_BASE}/shieldclaw/auth0/status")
    status_data = resp.json() if ok else {}
    auth0_cfg = status_data.get("auth0", {})
    AUTH0_DOMAIN = auth0_cfg.get("domain", "")

    # 2. JWKS fetch (direct Auth0 call)
    if AUTH0_DOMAIN:
        probe("JWKS", "JWKS", f"https://{AUTH0_DOMAIN}/.well-known/jwks.json")
        probe("openid-config", "JWKS", f"https://{AUTH0_DOMAIN}/.well-known/openid-configuration")

    # 3. ShieldClaw debug endpoint
    probe("debug", "ShieldClaw", f"{SHIELDCLAW_BASE}/shieldclaw/debug")

    # 4. Agent Identity
    dev_token = os.getenv("SHIELDCLAW_ADMIN_TOKEN", "")
    auth_headers = {"Authorization": f"Bearer {dev_token}"}
    probe("list-agents", "Agent Identity", f"{SHIELDCLAW_BASE}/shieldclaw/agents", headers=auth_headers)

    # 5. Auth test — with token (should succeed in dev bypass)
    probe("auth-with-token", "JWT Verification", f"{SHIELDCLAW_BASE}/shieldclaw/whoami", headers=auth_headers)

    # 6. Auth test — without token (should fail 401)
    probe("auth-no-token", "JWT Verification", f"{SHIELDCLAW_BASE}/shieldclaw/whoami")

    # 7. Token endpoint probe (Auth0 direct)
    a0_client_id = os.getenv("AUTH0_CLIENT_ID", "")
    a0_client_secret = os.getenv("AUTH0_CLIENT_SECRET", "")
    a0_audience = os.getenv("AUTH0_AUDIENCE", auth0_cfg.get("audience", ""))
    if AUTH0_DOMAIN and a0_client_id and a0_client_secret:
        probe_post(
            "token-endpoint",
            "Auth0 Token Endpoint (Client Credentials)",
            f"https://{AUTH0_DOMAIN}/oauth/token",
            json_body={
                "grant_type": "client_credentials",
                "client_id": a0_client_id,
                "client_secret": a0_client_secret,
                "audience": a0_audience,
            },
        )

    # 8-9. FGA probes — test FGA rules locally
    try:
        from fga import check_fga as _check_fga

        fga_tests = [
            ("fga:cmd git status", "get:chat", {"method": "POST", "path": "/v1/chat/completions", "body": {"command": "git status"}}),
            ("fga:POST /shieldclaw/agents", "post:shieldclaw", {"method": "POST", "path": "/shieldclaw/agents", "body": {"agent_name": "test"}}),
        ]
        for label, action_type, payload in fga_tests:
            t0 = time.time()
            result = _check_fga("dev-agent", action_type, payload)
            lat = (time.time() - t0) * 1000
            status = "ok" if result.allowed else f"denied:{result.rule_type}"
            detail = result.reason[:200]
            record_event("FGA", label, status, lat, detail)
    except ImportError:
        record_event("FGA", "fga-import", "error", 0, "Could not import fga module")

# ── Build DataFrame ──────────────────────────────────────────────────────────

df = pd.DataFrame(st.session_state.event_history)

if df.empty:
    st.warning("No events recorded yet. Waiting for first probe cycle...")
    st.stop()

df["color_status"] = df["status"].apply(lambda s: "ok" if s == "ok" else "failed")

# ── Top metrics ──────────────────────────────────────────────────────────────

total = len(df)
ok_count = len(df[df["status"] == "ok"])
fail_count = total - ok_count
categories = df["category"].nunique()
avg_latency = df[df["latency_ms"] > 0]["latency_ms"].mean()

col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Total Calls Tracked", total)
col2.metric("Successful", ok_count)
col3.metric("Failed / Errors", fail_count)
col4.metric("Categories", categories)
col5.metric("Avg Latency", f"{avg_latency:.0f} ms" if pd.notna(avg_latency) else "N/A")

# ── 1. Scatter: All Auth0 Calls Over Time ────────────────────────────────────

st.header("All Auth0-Related Calls Over Time")

fig_scatter = px.scatter(
    df,
    x="timestamp",
    y="endpoint",
    color="color_status",
    color_discrete_map=SCATTER_COLORS,
    size="latency_ms",
    size_max=20,
    hover_data=["category", "status", "latency_ms", "detail"],
    title="Every Auth0 Call — Plotted Over Time (size = latency)",
    labels={"timestamp": "Time", "endpoint": "Endpoint", "color_status": "Result"},
    height=500,
)
fig_scatter.update_layout(**CHART_LAYOUT, xaxis_title="Time", yaxis_title="Endpoint")
st.plotly_chart(fig_scatter, use_container_width=True)

# ── 2. Latency Over Time Per Category ───────────────────────────────────────

st.header("Latency Over Time by Category")

df_with_latency = df[df["latency_ms"] > 0]
if not df_with_latency.empty:
    fig_latency = px.line(
        df_with_latency,
        x="timestamp",
        y="latency_ms",
        color="category",
        markers=True,
        title="Response Latency Over Time (ms)",
        labels={"timestamp": "Time", "latency_ms": "Latency (ms)", "category": "Category"},
        height=400,
    )
    fig_latency.update_layout(**CHART_LAYOUT)
    st.plotly_chart(fig_latency, use_container_width=True)

# ── 3. Calls by Category ────────────────────────────────────────────────────

st.header("Calls by Category")

col1, col2 = st.columns(2)

with col1:
    cat_counts = df.groupby(["category", "color_status"]).size().reset_index(name="count")
    fig_bar = px.bar(
        cat_counts,
        x="category",
        y="count",
        color="color_status",
        color_discrete_map=SCATTER_COLORS,
        title="Total Calls per Auth0 Category",
        barmode="stack",
        height=400,
    )
    fig_bar.update_layout(**CHART_LAYOUT, xaxis_tickangle=-30)
    st.plotly_chart(fig_bar, use_container_width=True)

with col2:
    cat_pie = df["category"].value_counts().reset_index()
    cat_pie.columns = ["category", "count"]
    fig_pie = px.pie(
        cat_pie,
        values="count",
        names="category",
        title="Call Distribution by Category",
        height=400,
    )
    fig_pie.update_layout(paper_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
    st.plotly_chart(fig_pie, use_container_width=True)

# ── 4. Event Frequency ──────────────────────────────────────────────────────

st.header("Event Frequency Over Time")

df_freq = df.set_index("timestamp").resample("10s").size().reset_index(name="events")
fig_area = px.area(
    df_freq,
    x="timestamp",
    y="events",
    title="Auth0 Calls per 10-Second Window",
    height=300,
    color_discrete_sequence=["#636efa"],
)
fig_area.update_layout(**CHART_LAYOUT)
st.plotly_chart(fig_area, use_container_width=True)

# ── 5. FGA (Fine-Grained Authorization) ─────────────────────────────────────

fga_df = df[df["category"] == "FGA"]
if not fga_df.empty:
    st.header("FGA — Fine-Grained Authorization")
    st.caption("FGA runs on every agent request after Auth0 JWT verification. Deny rules block before OpenClaw sees the request.")

    fga_ok = len(fga_df[fga_df["status"] == "ok"])
    fga_blocked = len(fga_df[fga_df["status"] != "ok"])

    col1, col2, col3 = st.columns(3)
    col1.metric("FGA Checks", len(fga_df))
    col2.metric("Allowed", fga_ok)
    col3.metric("Blocked", fga_blocked)

    fig_fga_scatter = px.scatter(
        fga_df,
        x="timestamp",
        y="endpoint",
        color="color_status",
        color_discrete_map=SCATTER_COLORS,
        size="latency_ms",
        size_max=18,
        hover_data=["status", "latency_ms", "detail"],
        title="FGA Checks Over Time (green = allowed, red = denied)",
        height=400,
    )
    fig_fga_scatter.update_traces(marker=dict(line=dict(width=1, color="white")))
    fig_fga_scatter.update_layout(**CHART_LAYOUT)
    st.plotly_chart(fig_fga_scatter, use_container_width=True)

    fga_counts = fga_df.groupby(["endpoint", "color_status"]).size().reset_index(name="count")
    fig_fga_bar = px.bar(
        fga_counts,
        x="endpoint",
        y="count",
        color="color_status",
        color_discrete_map=SCATTER_COLORS,
        title="FGA Verdicts by Endpoint",
        barmode="group",
        height=400,
    )
    fig_fga_bar.update_layout(**CHART_LAYOUT, xaxis_tickangle=-35)
    st.plotly_chart(fig_fga_bar, use_container_width=True)

# ── 6. Failure Drill-down ───────────────────────────────────────────────────

failures = df[df["color_status"] == "failed"]
if not failures.empty:
    st.header("Failures & Errors")

    col1, col2 = st.columns(2)

    with col1:
        fail_by_ep = failures["endpoint"].value_counts().reset_index()
        fail_by_ep.columns = ["endpoint", "count"]
        fig_fail = px.bar(
            fail_by_ep,
            x="endpoint",
            y="count",
            title="Failures by Endpoint",
            color_discrete_sequence=["#ef553b"],
            height=350,
        )
        fig_fail.update_layout(**CHART_LAYOUT)
        st.plotly_chart(fig_fail, use_container_width=True)

    with col2:
        fig_fail_time = px.scatter(
            failures,
            x="timestamp",
            y="endpoint",
            color="status",
            title="Failures Over Time",
            hover_data=["detail"],
            height=350,
        )
        fig_fail_time.update_traces(marker=dict(size=12, symbol="x"))
        fig_fail_time.update_layout(**CHART_LAYOUT)
        st.plotly_chart(fig_fail_time, use_container_width=True)

# ── 7. Live Status Table ────────────────────────────────────────────────────

st.header("Latest Probe Results")

latest = df.drop_duplicates(subset="endpoint", keep="last")[
    ["endpoint", "category", "status", "latency_ms", "timestamp"]
].sort_values("category")
latest.columns = ["Endpoint", "Category", "Status", "Latency (ms)", "Last Checked"]

st.dataframe(
    latest.style.map(
        lambda v: "color: #00cc96" if v == "ok" else "color: #ef553b" if isinstance(v, str) and v != "ok" else "",
        subset=["Status"],
    ),
    use_container_width=True,
    hide_index=True,
)

# ── Raw log ──────────────────────────────────────────────────────────────────

with st.expander(f"Full Event Log ({len(df)} events)"):
    st.dataframe(df.sort_values("timestamp", ascending=False), use_container_width=True, hide_index=True)

# ── Sidebar ──────────────────────────────────────────────────────────────────

st.sidebar.markdown("---")
if AUTH0_DOMAIN:
    st.sidebar.markdown(f"**Auth0 Domain:** `{AUTH0_DOMAIN}`")
st.sidebar.markdown(f"**Events tracked:** {len(st.session_state.event_history)}")
st.sidebar.caption(f"Last refresh: {datetime.now().strftime('%H:%M:%S')}")

if st.sidebar.button("Clear History"):
    st.session_state.event_history = []
    st.rerun()

if st.sidebar.button("Refresh Now"):
    st.rerun()

time.sleep(REFRESH_INTERVAL)
st.rerun()
