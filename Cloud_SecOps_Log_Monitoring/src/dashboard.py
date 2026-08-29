# ============================================================
# KIROTRACE - SECURITY OPERATIONS DASHBOARD
# ============================================================
# Dashboard only presents pipeline output.
# It does NOT perform detection, correlation, severity,
# risk calculation, or incident creation.
#
# Pipeline:
#   logs -> parser.py -> detector.py -> correlator.py
#        -> incident_engine.py -> dashboard.py
# ============================================================

import json
from datetime import datetime
from pathlib import Path

import streamlit as st


# ============================================================
# CONFIGURATION
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent
OUTPUT_DIR = PROJECT_ROOT / "output"

INCIDENT_REPORT = OUTPUT_DIR / "incident_story.json"
CORRELATION_REPORT = OUTPUT_DIR / "correlation_results.json"
DETECTION_REPORT = OUTPUT_DIR / "detection_results.json"
PIPELINE_REPORT = OUTPUT_DIR / "pipeline_results.json"


st.set_page_config(
    page_title="KiroTrace Security Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# STYLE
# ============================================================

st.markdown(
    """
    <style>
        .block-container {
            padding-top: 1.5rem;
            padding-bottom: 2rem;
        }
        .critical { color: #d32f2f; font-weight: 700; }
        .high { color: #e65100; font-weight: 700; }
        .medium { color: #f9a825; font-weight: 700; }
        .low { color: #388e3c; font-weight: 700; }
    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# GENERIC HELPERS
# ============================================================

def safe_list(value):
    return value if isinstance(value, list) else []


def safe_dict(value):
    return value if isinstance(value, dict) else {}


def safe_int(value, default=0):
    if isinstance(value, bool):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def safe_float(value, default=0.0):
    if isinstance(value, bool):
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def clean_text(value, default="N/A"):
    if value is None:
        return default
    if isinstance(value, str):
        value = value.strip()
        return value if value else default
    return str(value)


def normalize_severity(value):
    return clean_text(value, "UNKNOWN").upper()


def normalize_confidence(value):
    return clean_text(value, "UNKNOWN").upper()


def format_timestamp(value):
    if value is None:
        return "N/A"
    text = str(value).strip()
    if not text:
        return "N/A"
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is not None:
            return parsed.strftime("%Y-%m-%d %H:%M:%S %Z")
        return parsed.strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return text


def first_value(record, *keys, default=None):
    if not isinstance(record, dict):
        return default
    for key in keys:
        value = record.get(key)
        if value is not None and value != "":
            return value
    return default


# ============================================================
# JSON LOADING
# ============================================================

def load_json_file(path):
    if not path.exists() or not path.is_file():
        return None

    try:
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except json.JSONDecodeError as error:
        st.error(f"Invalid JSON in `{path.name}`: {error}")
    except OSError as error:
        st.error(f"Unable to read `{path.name}`: {error}")
    return None


# ============================================================
# REPORT EXTRACTION
# ============================================================

def extract_records(report, list_keys, singular_keys=()):
    if report is None:
        return []

    if isinstance(report, list):
        return [item for item in report if isinstance(item, dict)]

    if not isinstance(report, dict):
        return []

    for key in list_keys:
        value = report.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]

    for key in singular_keys:
        value = report.get(key)
        if isinstance(value, dict):
            return [value]

    # Some reports use the record itself as the top-level object.
    record_markers = {
        "incident_id",
        "correlation_id",
        "alert_type",
        "detection_type",
    }
    if record_markers.intersection(report):
        return [report]

    return []


def extract_incidents(report):
    return extract_records(
        report,
        ("incidents", "results", "data"),
        ("incident",),
    )


def extract_correlations(report):
    return extract_records(
        report,
        ("correlations", "results", "data"),
        ("correlation",),
    )


def extract_detections(report):
    return extract_records(
        report,
        ("detections", "alerts", "results", "data"),
        ("detection", "alert", "result"),
    )


# ============================================================
# INCIDENT HELPERS
# ============================================================

def get_alert_types(incident):
    value = incident.get("alert_types")
    if isinstance(value, list):
        return [clean_text(item) for item in value]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def get_timeline(incident):
    timeline = incident.get("timeline")
    return timeline if isinstance(timeline, list) else []


def get_attack_story(incident):
    story = incident.get("attack_story")
    if isinstance(story, list):
        return story
    if isinstance(story, str) and story.strip():
        return [story]
    return []


def get_authentication_times(incident):
    return safe_dict(incident.get("authentication_times"))


# ============================================================
# TELEMETRY / EVIDENCE
# ============================================================

def get_sources(incident, correlation=None):
    correlation = correlation or {}

    for record in (incident, correlation):
        sources = record.get("telemetry_sources")
        if isinstance(sources, list) and sources:
            return sorted({clean_text(source) for source in sources})

    derived = set()
    for event in safe_list(correlation.get("related_events")):
        if isinstance(event, dict) and event.get("source"):
            derived.add(clean_text(event.get("source")))

    return sorted(derived)


def get_related_events(incident, correlation):
    incident_events = safe_list(incident.get("related_events"))
    if incident_events:
        return [event for event in incident_events if isinstance(event, dict)]

    return [
        event
        for event in safe_list(correlation.get("related_events"))
        if isinstance(event, dict)
    ]


def get_evidence_summary(incident, correlation):
    summary = incident.get("evidence_summary")
    if isinstance(summary, dict):
        return summary

    summary = correlation.get("evidence_summary")
    if isinstance(summary, dict):
        return summary

    return {}


def get_evidence_score(incident, correlation):
    summary = get_evidence_summary(incident, correlation)

    for record in (
        summary,
        incident,
        correlation,
    ):
        value = record.get("strongest_evidence_score")
        if value is not None:
            return safe_float(value)

    # Some implementations expose a single evidence_score instead.
    events = get_related_events(incident, correlation)
    scores = [safe_float(event.get("evidence_score")) for event in events]
    return max(scores, default=0.0)


# ============================================================
# CORRELATION MATCHING
# ============================================================

def find_correlation(incident, correlations):
    correlation_id = incident.get("correlation_id")
    source_ip = incident.get("source_ip")
    username = incident.get("username")

    if correlation_id:
        for correlation in correlations:
            if correlation.get("correlation_id") == correlation_id:
                return correlation

    if source_ip and username:
        for correlation in correlations:
            if (
                correlation.get("source_ip") == source_ip
                and correlation.get("username") == username
            ):
                return correlation

    if source_ip:
        for correlation in correlations:
            if correlation.get("source_ip") == source_ip:
                return correlation

    return {}


# ============================================================
# ALERT MATCHING
# ============================================================

def get_alerts(incident, detections, correlation):
    incident_id = incident.get("incident_id")
    correlation_id = incident.get("correlation_id")
    source_ip = incident.get("source_ip")
    username = incident.get("username")

    matching = []

    for alert in detections:
        alert_id = first_value(
            alert,
            "incident_id",
            "correlation_id",
        )

        if incident_id and alert_id == incident_id:
            matching.append(alert)
            continue

        if correlation_id and alert_id == correlation_id:
            matching.append(alert)
            continue

        alert_ip = alert.get("source_ip")
        alert_username = alert.get("username")

        if (
            source_ip
            and alert_ip == source_ip
            and (username is None or alert_username == username)
        ):
            matching.append(alert)

    if matching:
        return matching

    correlation_alerts = [
        alert
        for alert in safe_list(correlation.get("alerts"))
        if isinstance(alert, dict)
    ]
    if correlation_alerts:
        return correlation_alerts

    return [
        {
            "alert_type": alert_type,
            "severity": incident.get("severity"),
            "source_ip": incident.get("source_ip"),
            "username": incident.get("username"),
            "failed_attempts": incident.get("failed_attempts"),
            "successful_login": incident.get("successful_login"),
        }
        for alert_type in get_alert_types(incident)
    ]


# ============================================================
# METRICS
# ============================================================

def calculate_metrics(incidents, correlations, detections):
    metrics = {
        "total_incidents": len(incidents),
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "total_alerts": 0,
        "total_evidence": 0,
        "successful_logins": 0,
        "average_risk": 0.0,
        "highest_risk": 0.0,
    }

    risks = []

    for incident in incidents:
        severity = normalize_severity(incident.get("severity"))
        if severity == "CRITICAL":
            metrics["critical"] += 1
        elif severity == "HIGH":
            metrics["high"] += 1
        elif severity == "MEDIUM":
            metrics["medium"] += 1
        elif severity == "LOW":
            metrics["low"] += 1

        alert_count = safe_int(incident.get("alert_count"))
        if alert_count == 0:
            alert_count = len(get_alert_types(incident))
        metrics["total_alerts"] += alert_count

        evidence_count = safe_int(incident.get("related_event_count"))
        metrics["total_evidence"] += evidence_count

        if bool(incident.get("successful_login")):
            metrics["successful_logins"] += 1

        risk = safe_float(incident.get("risk_score"))
        if risk > 0:
            risks.append(risk)

    if metrics["total_alerts"] == 0:
        metrics["total_alerts"] = len(detections)

    if metrics["total_evidence"] == 0:
        seen = set()
        for correlation in correlations:
            for event in safe_list(correlation.get("related_events")):
                if isinstance(event, dict):
                    marker = (
                        event.get("timestamp"),
                        event.get("event_type"),
                        event.get("source_ip"),
                        event.get("username"),
                    )
                    if marker not in seen:
                        seen.add(marker)
                        metrics["total_evidence"] += 1

    if risks:
        metrics["average_risk"] = round(sum(risks) / len(risks), 1)
        metrics["highest_risk"] = max(risks)

    return metrics


# ============================================================
# SIDEBAR FILTERS
# ============================================================

def render_sidebar(incidents, correlations):
    st.sidebar.title("KiroTrace")
    st.sidebar.caption("Offline SecOps Log Aggregation & Threat Monitoring MVP")
    st.sidebar.divider()

    severities = sorted({normalize_severity(i.get("severity")) for i in incidents})
    selected_severities = st.sidebar.multiselect(
        "Severity",
        severities,
        default=severities,
    )

    all_sources = set()
    for incident in incidents:
        correlation = find_correlation(incident, correlations)
        all_sources.update(get_sources(incident, correlation))

    sources = sorted(all_sources)
    selected_sources = st.sidebar.multiselect(
        "Telemetry Source",
        sources,
        default=sources,
    )

    source_ips = sorted({
        clean_text(i.get("source_ip"))
        for i in incidents
        if i.get("source_ip")
    })
    selected_ips = st.sidebar.multiselect(
        "Source IP",
        source_ips,
        default=source_ips,
    )

    return selected_severities, selected_sources, selected_ips


def apply_filters(
    incidents,
    correlations,
    selected_severities,
    selected_sources,
    selected_ips,
):
    filtered = []

    for incident in incidents:
        severity = normalize_severity(incident.get("severity"))
        source_ip = clean_text(incident.get("source_ip"))
        correlation = find_correlation(incident, correlations)
        sources = set(get_sources(incident, correlation))

        if selected_severities and severity not in selected_severities:
            continue
        if selected_ips and source_ip not in selected_ips:
            continue
        if selected_sources and not sources.intersection(selected_sources):
            continue

        filtered.append(incident)

    return filtered


# ============================================================
# HEADER / OVERVIEW
# ============================================================

def render_header():
    st.title("🛡️ KiroTrace Security Dashboard")
    st.caption(
        "Security monitoring, incident correlation, evidence analysis and attack-story visualization"
    )


def render_overview(incidents, correlations, detections):
    metrics = calculate_metrics(incidents, correlations, detections)

    values = [
        ("Incidents", metrics["total_incidents"]),
        ("Critical", metrics["critical"]),
        ("High", metrics["high"]),
        ("Alerts", metrics["total_alerts"]),
        ("Evidence", metrics["total_evidence"]),
        ("Avg Risk", metrics["average_risk"]),
        ("Highest Risk", metrics["highest_risk"]),
    ]

    columns = st.columns(len(values))
    for column, (title, value) in zip(columns, values):
        with column:
            st.metric(title, value)


# ============================================================
# INCIDENT OVERVIEW TABLE
# ============================================================

def render_incident_table(incidents):
    st.subheader("Incident Overview")

    if not incidents:
        st.info("No incidents match the selected filters.")
        return

    rows = []
    for incident in incidents:
        rows.append({
            "Incident ID": clean_text(incident.get("incident_id")),
            "Type": clean_text(incident.get("incident_type")),
            "Severity": normalize_severity(incident.get("severity")),
            "Confidence": normalize_confidence(incident.get("confidence")),
            "Risk Score": safe_float(incident.get("risk_score")),
            "Source IP": clean_text(incident.get("source_ip")),
            "Username": clean_text(incident.get("username")),
            "Failed Attempts": safe_int(incident.get("failed_attempts")),
            "Evidence": safe_int(incident.get("related_event_count")),
            "Status": clean_text(incident.get("status")),
        })

    st.dataframe(rows, use_container_width=True, hide_index=True)


# ============================================================
# INCIDENT SUMMARY
# ============================================================

def render_incident_summary(incident, correlation):
    columns = st.columns(5)

    with columns[0]:
        st.metric("Incident ID", clean_text(incident.get("incident_id")))
    with columns[1]:
        st.metric("Severity", normalize_severity(incident.get("severity")))
    with columns[2]:
        st.metric("Risk Score", safe_float(incident.get("risk_score")))
    with columns[3]:
        st.metric("Confidence", normalize_confidence(incident.get("confidence")))
    with columns[4]:
        st.metric("Evidence Score", f"{get_evidence_score(incident, correlation):.0f}/100")

    telemetry_sources = get_sources(incident, correlation)

    details = {
        "Incident Type": clean_text(incident.get("incident_type")),
        "Status": clean_text(incident.get("status")),
        "Source IP": clean_text(incident.get("source_ip")),
        "Username": clean_text(incident.get("username")),
        "Failed Attempts": safe_int(incident.get("failed_attempts")),
        "Telemetry Sources": ", ".join(telemetry_sources) or "N/A",
        "Chronological Success Verified": (
            "Yes" if incident.get("chronological_success_verified") else "No"
        ),
    }

    st.dataframe(
        [{"Field": key, "Value": value} for key, value in details.items()],
        use_container_width=True,
        hide_index=True,
    )


# ============================================================
# ATTACK STORY
# ============================================================

def render_attack_story(incident):
    story = get_attack_story(incident)
    if not story:
        st.info("No attack story was generated.")
        return

    for index, item in enumerate(story, start=1):
        if isinstance(item, dict):
            timestamp = format_timestamp(item.get("timestamp"))
            phase = clean_text(item.get("attack_phase", item.get("phase")))
            description = clean_text(
                item.get("description", item.get("event", "N/A"))
            )
            st.markdown(f"**{index}. {timestamp} — {phase}**")
            st.write(description)
        else:
            st.markdown(f"**{index}.** {clean_text(item)}")


# ============================================================
# AUTHENTICATION TIMELINE
# ============================================================

def render_authentication_timeline(incident):
    auth_times = get_authentication_times(incident)

    rows = [
        {
            "Authentication Event": "First Failed Authentication",
            "Timestamp": format_timestamp(auth_times.get("first_failed")),
        },
        {
            "Authentication Event": "Last Failed Authentication",
            "Timestamp": format_timestamp(auth_times.get("last_failed")),
        },
        {
            "Authentication Event": "Successful Login",
            "Timestamp": format_timestamp(auth_times.get("successful_login")),
        },
    ]

    st.dataframe(rows, use_container_width=True, hide_index=True)

    if incident.get("chronological_success_verified"):
        st.success("Chronological successful authentication was verified by the incident engine.")
    elif incident.get("successful_login"):
        st.warning(
            "A successful login exists, but chronological success verification is not confirmed."
        )


# ============================================================
# EVIDENCE
# ============================================================

def render_evidence(incident, correlation):
    evidence = get_related_events(incident, correlation)
    summary = get_evidence_summary(incident, correlation)

    values = [
        ("Related Events", safe_int(summary.get("related_events", len(evidence)))),
        ("Firewall Events", safe_int(summary.get("firewall_events"))),
        ("CloudTrail Events", safe_int(summary.get("cloudtrail_events"))),
        ("SSH Events", safe_int(summary.get("ssh_events"))),
        ("Strongest Score", f"{get_evidence_score(incident, correlation):.0f}/100"),
    ]

    columns = st.columns(len(values))
    for column, (title, value) in zip(columns, values):
        with column:
            st.metric(title, value)

    if not evidence:
        st.info("No detailed correlated evidence was found.")
        return

    rows = []
    for event in evidence:
        distance = event.get("time_difference_seconds")
        distance_text = "N/A" if distance is None else f"{safe_float(distance):.0f}s"

        rows.append({
            "Timestamp": format_timestamp(event.get("timestamp")),
            "Source": clean_text(event.get("source")),
            "Event Type": clean_text(event.get("event_type")),
            "Source IP": clean_text(event.get("source_ip")),
            "Username": clean_text(event.get("username")),
            "Phase": clean_text(event.get("phase", event.get("attack_phase"))),
            "Username Match": clean_text(event.get("username_match")),
            "Anchor": clean_text(event.get("anchor_type")),
            "Distance": distance_text,
            "Evidence Score": safe_float(event.get("evidence_score")),
        })

    st.dataframe(rows, use_container_width=True, hide_index=True)

    st.markdown("### Correlation Reasons")
    for index, event in enumerate(evidence, start=1):
        score = safe_float(event.get("evidence_score"))
        st.markdown(f"**Evidence {index} — Score: {score:.0f}/100**")
        st.write(clean_text(event.get("correlation_reason")))


# ============================================================
# ALERTS
# ============================================================

def render_alerts(incident, detections, correlation):
    alerts = get_alerts(incident, detections, correlation)
    if not alerts:
        st.info("No detector alerts attached to this incident.")
        return

    rows = []
    for alert in alerts:
        rows.append({
            "Alert Type": clean_text(alert.get("alert_type", alert.get("type"))),
            "Severity": normalize_severity(
                alert.get("severity", incident.get("severity"))
            ),
            "Source IP": clean_text(
                alert.get("source_ip", incident.get("source_ip"))
            ),
            "Username": clean_text(
                alert.get("username", incident.get("username"))
            ),
            "Failed Attempts": safe_int(
                alert.get("failed_attempts", incident.get("failed_attempts"))
            ),
            "First Failed": format_timestamp(
                alert.get("first_failed_timestamp", alert.get("first_failed"))
            ),
            "Last Failed": format_timestamp(
                alert.get("last_failed_timestamp", alert.get("last_failed"))
            ),
            "Successful Login": "Yes" if alert.get("successful_login") else "No",
        })

    st.dataframe(rows, use_container_width=True, hide_index=True)


# ============================================================
# INCIDENT TIMELINE
# ============================================================

def render_timeline(incident):
    timeline = get_timeline(incident)
    if not timeline:
        st.info("No incident timeline available.")
        return

    rows = []
    for item in timeline:
        if not isinstance(item, dict):
            rows.append({
                "Timestamp": "N/A",
                "Source": "N/A",
                "Event": clean_text(item),
                "Phase": "N/A",
                "Source IP": "N/A",
                "Username": "N/A",
                "Evidence Score": 0,
            })
            continue

        rows.append({
            "Timestamp": format_timestamp(item.get("timestamp")),
            "Source": clean_text(item.get("source")),
            "Event": clean_text(
                item.get(
                    "event",
                    item.get("event_type", item.get("description", "N/A")),
                )
            ),
            "Phase": clean_text(
                item.get("phase", item.get("attack_phase", "N/A"))
            ),
            "Source IP": clean_text(item.get("source_ip")),
            "Username": clean_text(item.get("username")),
            "Evidence Score": safe_float(item.get("evidence_score")),
        })

    st.dataframe(rows, use_container_width=True, hide_index=True)


# ============================================================
# INCIDENT INVESTIGATION
# ============================================================

def render_incident_details(incidents, correlations, detections):
    st.subheader("Incident Investigation")

    if not incidents:
        st.info("No incident available.")
        return

    labels = [
        (
            f"{clean_text(i.get('incident_id'))} | "
            f"{normalize_severity(i.get('severity'))} | "
            f"{clean_text(i.get('source_ip'))}"
        )
        for i in incidents
    ]

    selected_label = st.selectbox(
        "Select Incident",
        labels,
        key="incident_selector",
    )
    incident = incidents[labels.index(selected_label)]
    correlation = find_correlation(incident, correlations)

    render_incident_summary(incident, correlation)

    tabs = st.tabs([
        "Attack Story",
        "Authentication Timeline",
        "Evidence",
        "Alerts",
        "Timeline",
    ])

    with tabs[0]:
        render_attack_story(incident)
    with tabs[1]:
        render_authentication_timeline(incident)
    with tabs[2]:
        render_evidence(incident, correlation)
    with tabs[3]:
        render_alerts(incident, detections, correlation)
    with tabs[4]:
        render_timeline(incident)


# ============================================================
# RAW DATA
# ============================================================

def render_raw_data(incidents, correlations):
    if not incidents:
        return

    st.subheader("Raw Data Inspection")

    labels = [clean_text(i.get("incident_id")) for i in incidents]
    selected = st.selectbox(
        "Select Incident for Raw Data",
        range(len(incidents)),
        format_func=lambda index: labels[index],
        key="raw_incident_selector",
    )

    incident = incidents[selected]
    correlation = find_correlation(incident, correlations)

    with st.expander("Raw Incident Data"):
        st.json(incident)

    with st.expander("Raw Correlation Data"):
        if correlation:
            st.json(correlation)
        else:
            st.info("No matching correlation record.")


# ============================================================
# PIPELINE FILE STATUS
# ============================================================

def render_file_status(
    incident_report,
    correlation_report,
    detection_report,
    pipeline_report,
):
    with st.expander("Pipeline Output Files"):
        files = [
            ("incident_story.json", incident_report, INCIDENT_REPORT),
            ("correlation_results.json", correlation_report, CORRELATION_REPORT),
            ("detection_results.json", detection_report, DETECTION_REPORT),
            ("pipeline_results.json", pipeline_report, PIPELINE_REPORT),
        ]

        rows = [
            {
                "File": name,
                "Status": "Available" if report is not None else "Missing",
                "Path": str(path),
            }
            for name, report, path in files
        ]

        st.dataframe(rows, use_container_width=True, hide_index=True)


# ============================================================
# PIPELINE SUMMARY
# ============================================================

def render_pipeline_summary(pipeline_report):
    if pipeline_report is None:
        return

    with st.expander("Pipeline Summary"):
        if isinstance(pipeline_report, dict):
            st.json(pipeline_report)
        else:
            st.write(pipeline_report)


# ============================================================
# MAIN
# ============================================================

def main():
    render_header()

    incident_report = load_json_file(INCIDENT_REPORT)
    correlation_report = load_json_file(CORRELATION_REPORT)
    detection_report = load_json_file(DETECTION_REPORT)
    pipeline_report = load_json_file(PIPELINE_REPORT)

    incidents = extract_incidents(incident_report)
    correlations = extract_correlations(correlation_report)
    detections = extract_detections(detection_report)

    render_file_status(
        incident_report,
        correlation_report,
        detection_report,
        pipeline_report,
    )

    render_pipeline_summary(pipeline_report)

    if incident_report is None:
        st.error("KiroTrace incident output was not found.")
        st.markdown(
            f"Expected file: `{INCIDENT_REPORT}`\n\n"
            "Run the KiroTrace pipeline first, then refresh this dashboard."
        )
        return

    if not incidents:
        st.warning(
            "incident_story.json exists, but no incident records could be extracted. "
            "Check the JSON structure produced by incident_engine.py."
        )
        return

    selected_severities, selected_sources, selected_ips = render_sidebar(
        incidents,
        correlations,
    )

    filtered_incidents = apply_filters(
        incidents,
        correlations,
        selected_severities,
        selected_sources,
        selected_ips,
    )

    st.divider()
    render_overview(filtered_incidents, correlations, detections)

    st.divider()
    render_incident_table(filtered_incidents)

    st.divider()
    render_incident_details(
        filtered_incidents,
        correlations,
        detections,
    )

    st.divider()
    render_raw_data(filtered_incidents, correlations)


if __name__ == "__main__":
    main()
