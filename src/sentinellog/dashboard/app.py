"""Interactive Streamlit SOC analyst dashboard for SentinelLog."""

from collections import Counter
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

from sentinellog import __version__
from sentinellog.alerts.store import AlertStore
from sentinellog.enrich.intel import get_threat_intel_feed
from sentinellog.rules.loader import load_rules_from_dir

st.set_page_config(
    page_title="SentinelLog SOC Analyst Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


def load_data(
    db_path: Path | str,
    severity_filter: str = "All",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Fetch stored alerts and incidents from the designated database."""
    p = Path(db_path)
    if not p.is_file():
        return [], []

    store = AlertStore(p)
    sev = None if severity_filter == "All" else severity_filter.lower()
    alerts = store.get_alerts(severity=sev, limit=1000)
    incidents = store.get_incidents(limit=200)
    return alerts, incidents


# Sidebar Navigation & Controls
st.sidebar.title("🛡️ SentinelLog SOC")
st.sidebar.caption(f"Engine v{__version__} | Autonomous Detection Platform")

db_file = st.sidebar.text_input("Database Path", value="data/sentinellog.db")
sev_filter = st.sidebar.selectbox(
    "Severity Filter",
    options=["All", "Critical", "High", "Medium", "Low"],
)

rules_dir = Path("rules")
loaded_rules = load_rules_from_dir(rules_dir) if rules_dir.is_dir() else []
intel_feed = get_threat_intel_feed("data/threat_intel")

st.sidebar.markdown("---")
st.sidebar.markdown("**System Health:**")
st.sidebar.markdown(f"- 📜 Active Rules: `{len(loaded_rules)}`")
st.sidebar.markdown(f"- 🌐 Threat Intel IPs: `{len(intel_feed.exact_ips)}`")
st.sidebar.markdown(f"- 🕸️ CIDR Subnets: `{len(intel_feed.networks)}`")

alerts_data, incidents_data = load_data(db_file, severity_filter=sev_filter)

# Dashboard Main Title
st.title("🛡️ Security Operations Center (SOC) Console")

tab1, tab2, tab3, tab4 = st.tabs(
    [
        "🚨 Incident & Alert Triage",
        "🔍 Threat Hunting & Investigation",
        "🗺️ MITRE ATT&CK® Matrix",
        "📜 Detection Rules Catalog",
    ]
)

# TAB 1: INCIDENT & ALERT TRIAGE
with tab1:
    col1, col2, col3, col4 = st.columns(4)

    total_inc = len(incidents_data)
    open_inc = sum(1 for inc in incidents_data if inc.get("status") == "open")
    total_alt = len(alerts_data)
    high_crit_alt = sum(
        1 for a in alerts_data if str(a.get("severity", "")).lower() in ("high", "critical")
    )

    col1.metric("Total Incidents", total_inc)
    col2.metric(
        "Active / Open Incidents",
        open_inc,
        delta=f"{open_inc} need review",
        delta_color="inverse",
    )
    col3.metric("Total Alerts", total_alt)
    col4.metric("High / Critical Alerts", high_crit_alt)

    st.markdown("---")

    col_chart, col_incidents = st.columns([1, 2])

    with col_chart:
        st.subheader("Severity Distribution")
        if alerts_data:
            sev_counts = Counter(str(a.get("severity", "low")).upper() for a in alerts_data)
            df_sev = pd.DataFrame(
                list(sev_counts.items()), columns=["Severity", "Count"]
            ).sort_values("Count", ascending=False)
            st.bar_chart(df_sev.set_index("Severity"))
        else:
            st.info("No alert telemetry loaded.")

    with col_incidents:
        st.subheader("Correlated Security Incidents")
        if incidents_data:
            store = AlertStore(db_file)
            for inc in incidents_data[:10]:
                sev = str(inc.get("severity", "")).upper()
                title = f"[{sev}] {inc.get('id')} — {inc.get('title')}"
                with st.expander(title, expanded=(inc.get("status") == "open")):
                    st.write(f"**Primary Entity:** `{inc.get('primary_entity')}`")
                    st.write(f"**Risk Score:** `{inc.get('score')} / 100`")
                    st.write(f"**Alert Count:** `{inc.get('alert_count')}` alerts")
                    st.write(f"**Timeline:** `{inc.get('first_seen')} -> {inc.get('last_seen')}`")

                    curr_status = inc.get("status", "open")
                    new_status = st.selectbox(
                        "Update Triage Status",
                        options=["open", "investigating", "resolved", "false_positive"],
                        index=["open", "investigating", "resolved", "false_positive"].index(
                            curr_status
                        ),
                        key=f"status_{inc.get('id')}",
                    )
                    if new_status != curr_status:
                        store.update_incident_status(inc["id"], new_status)
                        st.success(f"Updated {inc['id']} to {new_status}")
                        st.rerun()
        else:
            st.info("No security incidents found in the database.")

    st.subheader("Live Alert Feed")
    if alerts_data:
        df_alerts = pd.DataFrame(
            [
                {
                    "Alert ID": a.get("id"),
                    "Rule ID": a.get("rule_id"),
                    "Rule Name": a.get("rule_name"),
                    "Severity": str(a.get("severity")).upper(),
                    "Score": a.get("score"),
                    "Status": a.get("status"),
                    "First Seen": str(a.get("first_seen"))[:19],
                }
                for a in alerts_data[:50]
            ]
        )
        st.dataframe(df_alerts, use_container_width=True)
    else:
        st.info("No alerts found matching current filters.")


# TAB 2: THREAT HUNTING & INVESTIGATION
with tab2:
    st.subheader("Entity & Log Threat Hunting")
    search_query = st.text_input(
        "Search by IP Address, Hostname, Username, or Free-Text Query",
        placeholder="e.g. 198.51.100.4, admin, srv-prod-01",
    )

    if search_query:
        q_lower = search_query.strip().lower()
        matched = []
        for a in alerts_data:
            ent_match = any(
                q_lower in str(v).lower()
                for vals in a.get("entities", {}).values()
                for v in (vals if isinstance(vals, list) else [vals])
            )
            raw_match = any(
                q_lower in str(ev.get("raw", "")).lower() for ev in a.get("evidence", [])
            )
            name_match = (
                q_lower in str(a.get("rule_name", "")).lower()
                or q_lower in str(a.get("rule_id", "")).lower()
            )

            if ent_match or raw_match or name_match:
                matched.append(a)

        st.success(f"Discovered {len(matched)} matching alert records.")
        for m in matched[:15]:
            ts_prefix = m.get("first_seen", "")[:19]
            sev = str(m.get("severity")).upper()
            m_title = f"[{sev}] {m.get('rule_id')} - {m.get('rule_name')} ({ts_prefix})"
            with st.expander(m_title):
                st.write(f"**Explanation:** {m.get('explanation')}")
                st.write(f"**Recommended Action:** {m.get('recommended_action')}")
                st.write(f"**Entities:** `{m.get('entities')}`")
                st.markdown("**Evidence Log Samples:**")
                for ev in m.get("evidence", [])[:5]:
                    st.code(f"{ev.get('file')}:{ev.get('line_number')} -> {ev.get('raw')}")
    else:
        st.info("Enter an IP, user, or keyword above to initiate threat hunting.")


# TAB 3: MITRE ATT&CK MATRIX
with tab3:
    st.subheader("MITRE ATT&CK® Tactical Framework Coverage")
    mitre_data: list[dict[str, Any]] = []
    for r in loaded_rules:
        mitre_data.append(
            {
                "Rule ID": r.id,
                "Rule Name": r.name,
                "Tactic": r.mitre.tactic,
                "Technique ID": r.mitre.technique,
                "Severity": r.severity.value.upper(),
                "Source": r.log_source,
            }
        )

    if mitre_data:
        df_mitre = pd.DataFrame(mitre_data)
        tactic_counts = df_mitre["Tactic"].value_counts().reset_index()
        tactic_counts.columns = ["MITRE Tactic", "Rule Count"]

        col_tactic_chart, col_tactic_table = st.columns([1, 1])
        with col_tactic_chart:
            st.bar_chart(tactic_counts.set_index("MITRE Tactic"))
        with col_tactic_table:
            st.dataframe(df_mitre, use_container_width=True)
    else:
        st.info("No detection rules mapped.")


# TAB 4: DETECTION RULES CATALOG
with tab4:
    st.subheader("Active Detection Rules Catalog")
    log_src_filter = st.selectbox(
        "Filter by Log Source",
        options=["All", "ssh_auth", "web_access", "windows", "any"],
    )

    filtered_rules = [
        r for r in loaded_rules if log_src_filter == "All" or r.log_source == log_src_filter
    ]

    for r in filtered_rules:
        with st.expander(f"[{r.severity.value.upper()}] {r.id}: {r.name}"):
            st.write(f"**Description:** {r.description}")
            st.write(f"**Detection Type:** `{r.type}` | **Log Source:** `{r.log_source}`")
            st.write(f"**MITRE ATT&CK:** {r.mitre.tactic} (`{r.mitre.technique}`)")
            st.write(f"**Recommended SOC Action:** {r.response.recommended_action}")
