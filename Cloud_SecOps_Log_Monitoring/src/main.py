import json
from pathlib import Path
from datetime import datetime, timezone

from parser import (
    parse_all_logs,
    build_parser_summary,
)

from detector import (
    detect_failed_ssh_attempts,
    is_ssh_authentication_event,
)

from correlator import (
    correlate_events,
)

from incident_engine import (
    generate_incidents,
    build_incident_summary,
)


# ============================================================
# KIROTRACE - MAIN PIPELINE
# VERSION 2.0
# ============================================================
#
# RESPONSIBILITY
#
# main.py is ONLY the pipeline orchestrator.
#
# It does NOT implement:
#   - parsing logic
#   - detection logic
#   - correlation logic
#   - incident severity logic
#   - confidence logic
#   - risk scoring logic
#
# Pipeline:
#
#     RAW LOGS
#         ↓
#     PARSER
#         ↓
#     UNIFIED EVENTS
#         ↓
#     SSH DETECTOR
#         ↓
#     CORRELATOR
#         ↓
#     INCIDENT ENGINE
#         ↓
#     FINAL INCIDENTS
#         ↓
#     JSON OUTPUT
#
# Supported sources:
#     Linux SSH
#     Firewall
#     CloudTrail
#
# ============================================================


# ============================================================
# PROJECT PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent

OUTPUT_DIR = PROJECT_ROOT / "output"

DETECTION_RESULTS_FILE = (
    OUTPUT_DIR / "detection_results.json"
)

CORRELATION_RESULTS_FILE = (
    OUTPUT_DIR / "correlation_results.json"
)

INCIDENT_STORY_FILE = (
    OUTPUT_DIR / "incident_story.json"
)

PIPELINE_RESULTS_FILE = (
    OUTPUT_DIR / "pipeline_results.json"
)


# ============================================================
# DETECTION / CORRELATION CONFIGURATION
# ============================================================

FAILED_ATTEMPT_THRESHOLD = 5

DETECTION_WINDOW_MINUTES = 5

CORRELATION_FIREWALL_WINDOW_MINUTES = 30

CORRELATION_CLOUDTRAIL_WINDOW_MINUTES = 30


# ============================================================
# OUTPUT HELPERS
# ============================================================

def ensure_output_directory():
    """
    Create output directory if it does not exist.
    """

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )


def get_utc_timestamp():
    """
    Return current UTC timestamp.
    """

    return datetime.now(
        timezone.utc
    ).isoformat()


def save_json(file_path, data):
    """
    Save data as formatted JSON.

    Returns:
        True  -> success
        False -> failure
    """

    try:

        with open(
            file_path,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                data,
                file,
                indent=4,
                ensure_ascii=False
            )

        return True

    except (
        OSError,
        TypeError,
        ValueError
    ) as error:

        print(
            f"[ERROR] Could not write "
            f"{file_path}: {error}"
        )

        return False


# ============================================================
# SSH EVENT EXTRACTION
# ============================================================

def get_ssh_events(events):
    """
    Extract SSH authentication events.

    Uses detector.py's own SSH validation function
    so main.py does not maintain a duplicate definition.
    """

    if not isinstance(
        events,
        list
    ):
        return []

    ssh_events = []

    for event in events:

        if not isinstance(
            event,
            dict
        ):
            continue

        if is_ssh_authentication_event(
            event
        ):

            ssh_events.append(
                event
            )

    return ssh_events


# ============================================================
# ALERT SUMMARY
# ============================================================

def build_alert_summary(alerts):
    """
    Build Day 3 detection summary.
    """

    summary = {

        "total_alerts": 0,

        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,

        "brute_force_alerts": 0,
        "compromise_alerts": 0,
    }

    if not isinstance(
        alerts,
        list
    ):
        return summary

    for alert in alerts:

        if not isinstance(
            alert,
            dict
        ):
            continue

        summary[
            "total_alerts"
        ] += 1

        severity = str(
            alert.get(
                "severity",
                ""
            )
        ).upper()

        if severity == "CRITICAL":

            summary[
                "critical"
            ] += 1

        elif severity == "HIGH":

            summary[
                "high"
            ] += 1

        elif severity == "MEDIUM":

            summary[
                "medium"
            ] += 1

        elif severity == "LOW":

            summary[
                "low"
            ] += 1

        alert_type = str(
            alert.get(
                "alert_type",
                ""
            )
        ).lower()

        if "brute force" in alert_type:

            summary[
                "brute_force_alerts"
            ] += 1

        if "compromise" in alert_type:

            summary[
                "compromise_alerts"
            ] += 1

    return summary


# ============================================================
# CORRELATION SUMMARY
# ============================================================

def build_correlation_summary(correlations):
    """
    Build summary for raw correlation packages.

    This is intentionally separate from final incident
    severity/risk calculations.
    """

    summary = {

        "total_correlations": 0,

        "correlated": 0,

        "no_external_evidence": 0,

        "firewall_correlations": 0,

        "cloudtrail_correlations": 0,

        "ssh_correlations": 0,

        "total_related_events": 0,
    }

    if not isinstance(
        correlations,
        list
    ):
        return summary

    for correlation in correlations:

        if not isinstance(
            correlation,
            dict
        ):
            continue

        summary[
            "total_correlations"
        ] += 1

        status = str(
            correlation.get(
                "correlation_status",
                ""
            )
        ).upper()

        if status == "CORRELATED":

            summary[
                "correlated"
            ] += 1

        elif status == "NO_EXTERNAL_EVIDENCE":

            summary[
                "no_external_evidence"
            ] += 1

        related_events = correlation.get(
            "related_events",
            []
        )

        if isinstance(
            related_events,
            list
        ):

            summary[
                "total_related_events"
            ] += len(
                related_events
            )

        sources = correlation.get(
            "telemetry_sources",
            []
        )

        if not isinstance(
            sources,
            list
        ):
            sources = []

        normalized_sources = {
            str(source).strip().lower()
            for source in sources
            if source is not None
        }

        if "firewall" in normalized_sources:

            summary[
                "firewall_correlations"
            ] += 1

        if (
            "cloudtrail"
            in normalized_sources
        ):

            summary[
                "cloudtrail_correlations"
            ] += 1

        if (
            "linux ssh"
            in normalized_sources
            or
            "ssh"
            in normalized_sources
        ):

            summary[
                "ssh_correlations"
            ] += 1

    return summary


# ============================================================
# PIPELINE HEALTH
# ============================================================

def build_pipeline_health(
    parsed_events,
    ssh_events,
    alerts,
    correlations,
    incidents
):
    """
    Build overall pipeline health information.
    """

    parsed_count = (
        len(parsed_events)
        if isinstance(parsed_events, list)
        else 0
    )

    ssh_count = (
        len(ssh_events)
        if isinstance(ssh_events, list)
        else 0
    )

    alert_count = (
        len(alerts)
        if isinstance(alerts, list)
        else 0
    )

    correlation_count = (
        len(correlations)
        if isinstance(correlations, list)
        else 0
    )

    incident_count = (
        len(incidents)
        if isinstance(incidents, list)
        else 0
    )

    if parsed_count == 0:

        status = "NO_DATA"

    elif ssh_count == 0:

        status = "NO_SSH_EVENTS"

    elif alert_count == 0:

        status = "NO_ALERTS"

    elif correlation_count == 0:

        status = "NO_CORRELATIONS"

    else:

        status = "HEALTHY"

    return {

        "status":
            status,

        "parsed_events":
            parsed_count,

        "ssh_events":
            ssh_count,

        "alerts_generated":
            alert_count,

        "correlations_generated":
            correlation_count,

        "incidents_generated":
            incident_count,
    }


# ============================================================
# PRINT HEADER
# ============================================================

def print_header():

    print()

    print("=" * 80)

    print(
        "KIROTRACE - SECOPS LOG AGGREGATION "
        "& THREAT MONITORING"
    )

    print("=" * 80)

    print(
        "Offline Security Monitoring MVP"
    )

    print()

    print(
        "Pipeline:"
    )

    print(
        "Parser -> Detection -> Correlation "
        "-> Incident Engine -> JSON"
    )

    print("=" * 80)


# ============================================================
# PRINT PARSER SUMMARY
# ============================================================

def print_parser_summary(
    parsed_data,
    parser_summary
):

    if not isinstance(
        parsed_data,
        dict
    ):
        return

    cloudtrail_events = parsed_data.get(
        "cloudtrail",
        []
    )

    linux_events = parsed_data.get(
        "linux",
        []
    )

    firewall_events = parsed_data.get(
        "firewall",
        []
    )

    all_events = parsed_data.get(
        "all_events",
        []
    )

    print()

    print("-" * 80)

    print("PARSER SUMMARY")

    print("-" * 80)

    print(
        f"CloudTrail Events : "
        f"{len(cloudtrail_events)}"
    )

    print(
        f"Linux SSH Events  : "
        f"{len(linux_events)}"
    )

    print(
        f"Firewall Events   : "
        f"{len(firewall_events)}"
    )

    print(
        f"Total Events      : "
        f"{len(all_events)}"
    )

    print()

    print("Sources:")

    for source, count in sorted(
        parser_summary.get(
            "sources",
            {}
        ).items()
    ):

        print(
            f"  {source}: {count}"
        )

    print()

    print("Event Types:")

    for event_type, count in sorted(
        parser_summary.get(
            "event_types",
            {}
        ).items()
    ):

        print(
            f"  {event_type}: {count}"
        )


# ============================================================
# PRINT ALERTS
# ============================================================

def print_alerts(alerts):

    print()

    print("=" * 80)

    print("DAY 3 DETECTION RESULTS")

    print("=" * 80)

    if not alerts:

        print(
            "No suspicious SSH activity detected."
        )

        return

    for index, alert in enumerate(
        alerts,
        start=1
    ):

        print()

        print("-" * 80)

        print(
            f"ALERT #{index}"
        )

        print("-" * 80)

        print(
            f"Alert ID        : "
            f"{alert.get('alert_id')}"
        )

        print(
            f"Alert Type      : "
            f"{alert.get('alert_type')}"
        )

        print(
            f"Detection Stage : "
            f"{alert.get('detection_stage')}"
        )

        print(
            f"Source IP       : "
            f"{alert.get('source_ip')}"
        )

        print(
            f"Username        : "
            f"{alert.get('username')}"
        )

        print(
            f"Failed Attempts : "
            f"{alert.get('failed_attempts')}"
        )

        if alert.get(
            "threshold"
        ) is not None:

            print(
                f"Threshold       : "
                f"{alert.get('threshold')}"
            )

        print(
            f"Severity        : "
            f"{alert.get('severity')}"
        )

        print(
            f"Confidence      : "
            f"{alert.get('confidence')}"
        )

        print(
            f"Status          : "
            f"{alert.get('status')}"
        )

        print(
            f"First Failed    : "
            f"{alert.get('first_failed_timestamp')}"
        )

        print(
            f"Last Failed     : "
            f"{alert.get('last_failed_timestamp')}"
        )

        if alert.get(
            "successful_login_timestamp"
        ):

            print(
                f"Successful Login: "
                f"{alert.get('successful_login_timestamp')}"
            )

            print(
                f"Time Difference : "
                f"{alert.get('time_difference_seconds')} "
                f"seconds"
            )

        print()

        print(
            f"Description     : "
            f"{alert.get('description')}"
        )


# ============================================================
# PRINT CORRELATIONS
# ============================================================

def print_correlations(correlations):

    print()

    print("=" * 80)

    print("DAY 4 CORRELATION RESULTS")

    print("=" * 80)

    if not correlations:

        print(
            "No cross-source correlations generated."
        )

        return

    for index, correlation in enumerate(
        correlations,
        start=1
    ):

        if not isinstance(
            correlation,
            dict
        ):
            continue

        print()

        print("-" * 80)

        print(
            f"CORRELATION #{index}"
        )

        print("-" * 80)

        print(
            f"Source IP        : "
            f"{correlation.get('source_ip')}"
        )

        print(
            f"Username         : "
            f"{correlation.get('username')}"
        )

        print(
            f"Status           : "
            f"{correlation.get('correlation_status')}"
        )

        print(
            f"Telemetry Sources: "
            f"{correlation.get('telemetry_sources', [])}"
        )

        print(
            f"Related Events   : "
            f"{len(correlation.get('related_events', []))}"
        )

        print(
            f"Excluded Events  : "
            f"{correlation.get('excluded_event_counts', {})}"
        )

        print(
            f"Authentication   : "
            f"{correlation.get('authentication_times', {})}"
        )


# ============================================================
# PRINT INCIDENTS
# ============================================================

def print_incidents(incidents):

    print()

    print("=" * 80)

    print("FINAL SECURITY INCIDENTS")

    print("=" * 80)

    if not incidents:

        print(
            "No final incidents generated."
        )

        return

    for index, incident in enumerate(
        incidents,
        start=1
    ):

        if not isinstance(
            incident,
            dict
        ):
            continue

        print()

        print("-" * 80)

        print(
            f"INCIDENT #{index}"
        )

        print("-" * 80)

        print(
            f"Incident ID      : "
            f"{incident.get('incident_id')}"
        )

        print(
            f"Incident Type    : "
            f"{incident.get('incident_type')}"
        )

        print(
            f"Severity         : "
            f"{incident.get('severity')}"
        )

        print(
            f"Confidence       : "
            f"{incident.get('confidence')}"
        )

        print(
            f"Risk Score       : "
            f"{incident.get('risk_score')}/100"
        )

        print(
            f"Status           : "
            f"{incident.get('status')}"
        )

        print(
            f"Source IP        : "
            f"{incident.get('source_ip')}"
        )

        print(
            f"Username         : "
            f"{incident.get('username')}"
        )

        print(
            f"Failed Attempts  : "
            f"{incident.get('failed_attempts')}"
        )

        print(
            f"Chrono Verified  : "
            f"{incident.get('chronological_success_verified')}"
        )

        print(
            f"Telemetry Sources: "
            f"{incident.get('telemetry_sources')}"
        )

        print(
            f"Domain Families  : "
            f"{incident.get('domain_families')}"
        )

        print(
            f"Related Events   : "
            f"{incident.get('related_event_count')}"
        )

        print()

        print(
            "ATTACK STORY:"
        )

        print(
            incident.get(
                "attack_story",
                "N/A"
            )
        )


# ============================================================
# BUILD DETECTION OUTPUT
# ============================================================

def build_detection_output(
    ssh_events,
    alerts
):

    return {

        "project":
            "KiroTrace",

        "generated_at":
            get_utc_timestamp(),

        "stage":
            "Day 3",

        "detection_engine": {

            "name":
                "SSH Detection Engine",

            "day_3a":
                "SSH Brute Force Detection",

            "day_3b":
                "Possible Account Compromise Detection",
        },

        "configuration": {

            "failed_attempt_threshold":
                FAILED_ATTEMPT_THRESHOLD,

            "detection_window_minutes":
                DETECTION_WINDOW_MINUTES,
        },

        "input": {

            "ssh_events":
                len(ssh_events),
        },

        "summary":
            build_alert_summary(
                alerts
            ),

        "alerts":
            alerts,
    }


# ============================================================
# BUILD CORRELATION OUTPUT
# ============================================================

def build_correlation_output(
    correlations
):

    return {

        "project":
            "KiroTrace",

        "generated_at":
            get_utc_timestamp(),

        "stage":
            "Day 4",

        "correlation_engine": {

            "name":
                "Cross Source Correlation Engine",

            "firewall_window_minutes":
                CORRELATION_FIREWALL_WINDOW_MINUTES,

            "cloudtrail_window_minutes":
                CORRELATION_CLOUDTRAIL_WINDOW_MINUTES,

            "sources":
                [
                    "Linux SSH",
                    "Firewall",
                    "CloudTrail",
                ],
        },

        "summary":
            build_correlation_summary(
                correlations
            ),

        "correlations":
            correlations,
    }


# ============================================================
# BUILD INCIDENT OUTPUT
# ============================================================

def build_incident_output(
    incidents
):

    return {

        "project":
            "KiroTrace",

        "generated_at":
            get_utc_timestamp(),

        "stage":
            "Final Incident Engine",

        "summary":
            build_incident_summary(
                incidents
            ),

        "incidents":
            incidents,
    }


# ============================================================
# BUILD COMPLETE PIPELINE OUTPUT
# ============================================================

def build_pipeline_output(
    parsed_data,
    parser_summary,
    ssh_events,
    alerts,
    correlations,
    incidents
):

    return {

        "project":
            "KiroTrace",

        "generated_at":
            get_utc_timestamp(),

        "pipeline": [

            "raw_logs",

            "parser",

            "parsed_events",

            "ssh_detection",

            "day_3_brute_force",

            "day_3_account_compromise",

            "day_4_cross_source_correlation",

            "incident_engine",

            "final_incidents",
        ],

        "configuration": {

            "failed_attempt_threshold":
                FAILED_ATTEMPT_THRESHOLD,

            "detection_window_minutes":
                DETECTION_WINDOW_MINUTES,

            "firewall_correlation_window_minutes":
                CORRELATION_FIREWALL_WINDOW_MINUTES,

            "cloudtrail_correlation_window_minutes":
                CORRELATION_CLOUDTRAIL_WINDOW_MINUTES,
        },

        "parser":
            parser_summary,

        "detection":
            build_alert_summary(
                alerts
            ),

        "correlation":
            build_correlation_summary(
                correlations
            ),

        "incident":
            build_incident_summary(
                incidents
            ),

        "pipeline_health":
            build_pipeline_health(

                parsed_data.get(
                    "all_events",
                    []
                ),

                ssh_events,

                alerts,

                correlations,

                incidents
            ),

        "alerts":
            alerts,

        "correlations":
            correlations,

        "incidents":
            incidents,
    }


# ============================================================
# MAIN PIPELINE
# ============================================================

def run_pipeline():

    print_header()

    ensure_output_directory()

    # ========================================================
    # STEP 1 - PARSER
    # ========================================================

    print()

    print(
        "[1/7] Parsing security logs..."
    )

    parsed_data = parse_all_logs()

    if not isinstance(
        parsed_data,
        dict
    ):

        print(
            "[ERROR] Parser returned invalid data."
        )

        return False

    all_events = parsed_data.get(
        "all_events",
        []
    )

    if not isinstance(
        all_events,
        list
    ):

        print(
            "[ERROR] Parser did not return "
            "a valid all_events list."
        )

        return False

    print(
        f"Parsed events: {len(all_events)}"
    )

    # ========================================================
    # STEP 2 - PARSER SUMMARY
    # ========================================================

    print()

    print(
        "[2/7] Building parser summary..."
    )

    parser_summary = build_parser_summary(
        all_events
    )

    if not isinstance(
        parser_summary,
        dict
    ):

        print(
            "[ERROR] Parser summary is invalid."
        )

        return False

    print_parser_summary(
        parsed_data,
        parser_summary
    )

    # ========================================================
    # STEP 3 - SSH EVENTS
    # ========================================================

    print()

    print(
        "[3/7] Extracting SSH authentication events..."
    )

    ssh_events = get_ssh_events(
        all_events
    )

    print(
        f"SSH authentication events: "
        f"{len(ssh_events)}"
    )

    # ========================================================
    # STEP 4 - DAY 3 DETECTION
    # ========================================================

    print()

    print(
        "[4/7] Running Day 3 SSH detection..."
    )

    print()

    print(
        "Detection configuration:"
    )

    print(
        f"  Failed threshold: "
        f"{FAILED_ATTEMPT_THRESHOLD}"
    )

    print(
        f"  Detection window: "
        f"{DETECTION_WINDOW_MINUTES} minutes"
    )

    alerts = detect_failed_ssh_attempts(

        ssh_events,

        threshold=(
            FAILED_ATTEMPT_THRESHOLD
        ),

        detection_window_minutes=(
            DETECTION_WINDOW_MINUTES
        ),

        correlation_window_minutes=(
            DETECTION_WINDOW_MINUTES
        )
    )

    if not isinstance(
        alerts,
        list
    ):

        print(
            "[ERROR] Detection engine "
            "returned invalid data."
        )

        return False

    print_alerts(
        alerts
    )

    # ========================================================
    # STEP 5 - DAY 4 CORRELATION
    # ========================================================

    print()

    print(
        "[5/7] Running Day 4 cross-source correlation..."
    )

    print()

    print(
        "Correlation configuration:"
    )

    print(
        f"  Firewall window   : "
        f"{CORRELATION_FIREWALL_WINDOW_MINUTES} minutes"
    )

    print(
        f"  CloudTrail window : "
        f"{CORRELATION_CLOUDTRAIL_WINDOW_MINUTES} minutes"
    )

    correlations = correlate_events(

        alerts=alerts,

        normalized_events=all_events,

        firewall_window_minutes=(
            CORRELATION_FIREWALL_WINDOW_MINUTES
        ),

        cloudtrail_window_minutes=(
            CORRELATION_CLOUDTRAIL_WINDOW_MINUTES
        )
    )

    if not isinstance(
        correlations,
        list
    ):

        print(
            "[ERROR] Correlation engine "
            "returned invalid data."
        )

        return False

    print(
        f"Correlations generated: "
        f"{len(correlations)}"
    )

    print_correlations(
        correlations
    )

    # ========================================================
    # STEP 6 - INCIDENT ENGINE
    # ========================================================

    print()

    print(
        "[6/7] Building final security incidents..."
    )

    incidents = generate_incidents(
        correlations
    )

    if not isinstance(
        incidents,
        list
    ):

        print(
            "[ERROR] Incident engine "
            "returned invalid data."
        )

        return False

    print(
        f"Final incidents generated: "
        f"{len(incidents)}"
    )

    print_incidents(
        incidents
    )

    # ========================================================
    # STEP 7 - SAVE OUTPUTS
    # ========================================================

    print()

    print(
        "[7/7] Saving KiroTrace results..."
    )

    detection_output = (
        build_detection_output(
            ssh_events,
            alerts
        )
    )

    correlation_output = (
        build_correlation_output(
            correlations
        )
    )

    incident_output = (
        build_incident_output(
            incidents
        )
    )

    pipeline_output = (
        build_pipeline_output(

            parsed_data,

            parser_summary,

            ssh_events,

            alerts,

            correlations,

            incidents
        )
    )

    detection_saved = save_json(
        DETECTION_RESULTS_FILE,
        detection_output
    )

    correlation_saved = save_json(
        CORRELATION_RESULTS_FILE,
        correlation_output
    )

    incident_saved = save_json(
        INCIDENT_STORY_FILE,
        incident_output
    )

    pipeline_saved = save_json(
        PIPELINE_RESULTS_FILE,
        pipeline_output
    )

    if detection_saved:

        print(
            f"[OK] Detection results: "
            f"{DETECTION_RESULTS_FILE}"
        )

    if correlation_saved:

        print(
            f"[OK] Correlation results: "
            f"{CORRELATION_RESULTS_FILE}"
        )

    if incident_saved:

        print(
            f"[OK] Incident story: "
            f"{INCIDENT_STORY_FILE}"
        )

    if pipeline_saved:

        print(
            f"[OK] Pipeline results: "
            f"{PIPELINE_RESULTS_FILE}"
        )

    # ========================================================
    # FINAL SUMMARY
    # ========================================================

    alert_summary = (
        build_alert_summary(
            alerts
        )
    )

    correlation_summary = (
        build_correlation_summary(
            correlations
        )
    )

    incident_summary = (
        build_incident_summary(
            incidents
        )
    )

    print()

    print("=" * 80)

    print(
        "KIROTRACE PIPELINE COMPLETE"
    )

    print("=" * 80)

    print()

    print(
        f"Total parsed events : "
        f"{len(all_events)}"
    )

    print(
        f"SSH events          : "
        f"{len(ssh_events)}"
    )

    print(
        f"Detection alerts    : "
        f"{alert_summary['total_alerts']}"
    )

    print(
        f"Brute force alerts  : "
        f"{alert_summary['brute_force_alerts']}"
    )

    print(
        f"Compromise alerts   : "
        f"{alert_summary['compromise_alerts']}"
    )

    print(
        f"Correlations        : "
        f"{correlation_summary['total_correlations']}"
    )

    print(
        f"Incidents           : "
        f"{incident_summary['incident_count']}"
    )

    print(
        f"Critical incidents  : "
        f"{incident_summary['critical_count']}"
    )

    print(
        f"High incidents      : "
        f"{incident_summary['high_count']}"
    )

    print(
        f"Medium incidents    : "
        f"{incident_summary['medium_count']}"
    )

    print(
        f"Low incidents       : "
        f"{incident_summary['low_count']}"
    )

    print(
        f"Average risk        : "
        f"{incident_summary['average_risk_score']}"
    )

    print(
        f"Highest risk        : "
        f"{incident_summary['highest_risk_score']}/100"
    )

    print()

    if incidents:

        print(
            "Security status     : "
            "FINAL SECURITY INCIDENTS GENERATED"
        )

    elif correlations:

        print(
            "Security status     : "
            "CROSS-SOURCE ACTIVITY CORRELATED"
        )

    elif alerts:

        print(
            "Security status     : "
            "SUSPICIOUS SSH ACTIVITY DETECTED"
        )

    else:

        print(
            "Security status     : "
            "NO SUSPICIOUS ACTIVITY DETECTED"
        )

    print()

    print(
        f"Detection output    : "
        f"{DETECTION_RESULTS_FILE}"
    )

    print(
        f"Correlation output  : "
        f"{CORRELATION_RESULTS_FILE}"
    )

    print(
        f"Incident output     : "
        f"{INCIDENT_STORY_FILE}"
    )

    print(
        f"Pipeline output     : "
        f"{PIPELINE_RESULTS_FILE}"
    )

    print()

    return (
        detection_saved
        and correlation_saved
        and incident_saved
        and pipeline_saved
    )


# ============================================================
# ENTRY POINT
# ============================================================

def main():

    try:

        success = run_pipeline()

        if not success:

            return 1

        return 0

    except KeyboardInterrupt:

        print()

        print(
            "[WARNING] Pipeline interrupted."
        )

        return 1

    except Exception as error:

        print()

        print(
            "[FATAL ERROR] "
            f"{type(error).__name__}: "
            f"{error}"
        )

        return 1


# ============================================================
# EXECUTION
# ============================================================

if __name__ == "__main__":

    raise SystemExit(
        main()
    )