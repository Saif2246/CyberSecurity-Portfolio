from datetime import datetime, timezone
import hashlib


# ============================================================
# KIROTRACE - INCIDENT ENGINE
# VERSION 2.0
# ============================================================
#
# Responsibility:
#   Convert correlation packages into final security incidents.
#
# Pipeline:
#
#   parser
#       ↓
#   normalizer
#       ↓
#   detector
#       ↓
#   correlator
#       ↓
#   incident_engine
#       ↓
#   final incident
#
# Day 5 responsibilities:
#
#   - Deterministic incident identity
#   - Incident classification
#   - Evidence-backed severity
#   - Evidence-backed confidence
#   - Calibrated risk scoring
#   - GRC-safe attack-story language
#   - Final attack phases
#   - Final timeline
#   - Primary evidence
#   - Supporting evidence
#   - Excluded evidence
#   - Evidence-to-event traceability
#   - Auditability chain
#   - Incident deduplication
#   - Safe malformed-input handling
#
# The engine remains compatible with the existing correlation
# package structure and does not require mandatory schema changes
# from correlator.py.
#
# ============================================================


# ============================================================
# CONFIGURATION
# ============================================================

INCIDENT_ENGINE_VERSION = "2.0"
INCIDENT_SCHEMA_VERSION = "2.0"

MAX_RISK_SCORE = 100


# ============================================================
# CONTROLLED TAXONOMY
# ============================================================

SOURCE_DOMAIN_MAP = {
    "linux ssh": "SSH",
    "ssh": "SSH",
    "linux": "SSH",
    "firewall": "Firewall",
    "cloudtrail": "CloudTrail",
}


SEVERITY_RANK = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


CONFIDENCE_RANK = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
}


# ============================================================
# ATTACK PHASE TAXONOMY
# ============================================================

ATTACK_PHASE_RANK = {
    "INITIAL_ACCESS": 1,
    "BRUTE_FORCE": 2,
    "AUTHENTICATION_SUCCESS": 3,
    "POST_AUTHENTICATION": 4,
    "POST_COMPROMISE_ACTIVITY": 5,
    "CLOUD_ACTIVITY": 6,
    "NETWORK_ACTIVITY": 7,
    "UNKNOWN": 99,
}


# ============================================================
# GENERIC HELPERS
# ============================================================

def clean_value(value):
    if value is None:
        return None

    if isinstance(value, str):
        value = value.strip()

        if not value:
            return None

    return value


def normalize_text(value):
    value = clean_value(value)

    if value is None:
        return None

    return str(value).strip().lower()


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


def clamp(value, minimum=0, maximum=100):
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return minimum

    numeric = max(minimum, min(numeric, maximum))

    if numeric.is_integer():
        return int(numeric)

    return round(numeric, 1)


def unique_preserve_order(values):
    result = []
    seen = set()

    for value in values:
        normalized = normalize_text(value)

        if normalized is None:
            continue

        if normalized in seen:
            continue

        seen.add(normalized)
        result.append(value)

    return result


# ============================================================
# TIMESTAMP HELPERS
# ============================================================

def parse_timestamp(timestamp):
    timestamp = clean_value(timestamp)

    if timestamp is None:
        return None

    if isinstance(timestamp, datetime):

        if timestamp.tzinfo is None:
            return timestamp.replace(
                tzinfo=timezone.utc
            )

        return timestamp.astimezone(timezone.utc)

    if not isinstance(timestamp, str):
        return None

    timestamp = timestamp.strip()

    try:
        iso_timestamp = timestamp

        if iso_timestamp.endswith("Z"):
            iso_timestamp = (
                iso_timestamp[:-1] + "+00:00"
            )

        parsed = datetime.fromisoformat(
            iso_timestamp
        )

        if parsed.tzinfo is None:
            parsed = parsed.replace(
                tzinfo=timezone.utc
            )
        else:
            parsed = parsed.astimezone(
                timezone.utc
            )

        return parsed

    except (TypeError, ValueError):
        pass

    formats = (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y/%m/%d %H:%M:%S",
        "%Y/%m/%d %H:%M",
    )

    for fmt in formats:

        try:
            parsed = datetime.strptime(
                timestamp,
                fmt
            )

            return parsed.replace(
                tzinfo=timezone.utc
            )

        except ValueError:
            continue

    return None


def normalize_timestamp(timestamp):
    parsed = parse_timestamp(timestamp)

    if parsed is None:
        return None

    return parsed.isoformat()


# ============================================================
# INCIDENT ID
# ============================================================

def build_incident_id(correlation):
    """
    Generate deterministic incident ID.

    Priority:
        correlation_id + incident identity

    Fallback:
        incident identity only
    """

    if not isinstance(correlation, dict):
        return None

    correlation_id = clean_value(
        correlation.get("correlation_id")
    )

    source_ip = normalize_text(
        correlation.get(
            "source_ip",
            "unknown-ip"
        )
    ) or "unknown-ip"

    username = normalize_text(
        correlation.get(
            "username",
            "unknown-user"
        )
    ) or "unknown-user"

    auth_times = correlation.get(
        "authentication_times",
        {}
    )

    if isinstance(auth_times, dict):

        first_failed = (
            normalize_timestamp(
                auth_times.get(
                    "first_failed"
                )
            )
            or ""
        )

        last_failed = (
            normalize_timestamp(
                auth_times.get(
                    "last_failed"
                )
            )
            or ""
        )

        successful_login = (
            normalize_timestamp(
                auth_times.get(
                    "successful_login"
                )
            )
            or ""
        )

    else:
        first_failed = ""
        last_failed = ""
        successful_login = ""

    if correlation_id:

        raw = (
            f"{correlation_id}|"
            f"{source_ip}|"
            f"{username}|"
            f"{first_failed}|"
            f"{last_failed}|"
            f"{successful_login}"
        )

    else:

        raw = (
            f"{source_ip}|"
            f"{username}|"
            f"{first_failed}|"
            f"{last_failed}|"
            f"{successful_login}"
        )

    digest = hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()

    return (
        "INC-"
        + digest[:16].upper()
    )


# ============================================================
# ALERT HELPERS
# ============================================================

def get_alerts(correlation):
    if not isinstance(correlation, dict):
        return []

    alerts = correlation.get(
        "alerts",
        []
    )

    if not isinstance(alerts, list):
        return []

    return [
        alert
        for alert in alerts
        if isinstance(alert, dict)
    ]


def get_alert_types(correlation):
    alert_types = []

    for alert in get_alerts(correlation):

        alert_type = clean_value(
            alert.get("alert_type")
        )

        if alert_type:
            alert_types.append(
                str(alert_type)
            )

    return unique_preserve_order(
        alert_types
    )


def get_max_failed_attempts(correlation):
    maximum = 0

    for alert in get_alerts(correlation):

        attempts = safe_int(
            alert.get(
                "failed_attempts",
                0
            )
        )

        maximum = max(
            maximum,
            attempts
        )

    return maximum


def get_highest_alert_severity(correlation):
    highest = "LOW"

    for alert in get_alerts(correlation):

        severity = clean_value(
            alert.get("severity")
        )

        if not severity:
            continue

        severity = str(
            severity
        ).upper()

        if (
            SEVERITY_RANK.get(
                severity,
                0
            )
            >
            SEVERITY_RANK.get(
                highest,
                0
            )
        ):
            highest = severity

    return highest


# ============================================================
# AUTHENTICATION / CHRONOLOGY
# ============================================================

def get_authentication_times(correlation):
    default = {
        "first_failed": None,
        "last_failed": None,
        "successful_login": None,
    }

    if not isinstance(correlation, dict):
        return default

    auth_times = correlation.get(
        "authentication_times",
        {}
    )

    if not isinstance(
        auth_times,
        dict
    ):
        return default

    return {
        "first_failed":
            normalize_timestamp(
                auth_times.get(
                    "first_failed"
                )
            ),

        "last_failed":
            normalize_timestamp(
                auth_times.get(
                    "last_failed"
                )
            ),

        "successful_login":
            normalize_timestamp(
                auth_times.get(
                    "successful_login"
                )
            ),
    }


def has_authentication_evidence(correlation):
    auth_times = get_authentication_times(
        correlation
    )

    return any(
        value is not None
        for value in auth_times.values()
    )


def has_successful_login_timestamp(correlation):
    auth_times = get_authentication_times(
        correlation
    )

    return (
        parse_timestamp(
            auth_times.get(
                "successful_login"
            )
        )
        is not None
    )


def is_valid_chronological_success(correlation):
    """
    Strict chronology:

        successful_login > last_failed

    Fallback:

        successful_login > first_failed
    """

    auth_times = get_authentication_times(
        correlation
    )

    successful_login = parse_timestamp(
        auth_times.get(
            "successful_login"
        )
    )

    if successful_login is None:
        return False

    last_failed = parse_timestamp(
        auth_times.get(
            "last_failed"
        )
    )

    first_failed = parse_timestamp(
        auth_times.get(
            "first_failed"
        )
    )

    if last_failed is not None:
        return successful_login > last_failed

    if first_failed is not None:
        return successful_login > first_failed

    return False


# ============================================================
# RELATED EVENTS
# ============================================================

def get_related_events(correlation):
    if not isinstance(correlation, dict):
        return []

    events = correlation.get(
        "related_events",
        []
    )

    if not isinstance(events, list):
        return []

    return [
        event
        for event in events
        if isinstance(event, dict)
    ]


# ============================================================
# EXCLUDED EVENTS
# ============================================================

def get_excluded_events(correlation):
    """
    Supports the correlation package's excluded-event
    structures without requiring one exact schema.

    Accepted:
        excluded_events: [...]
        excluded_evidence: [...]
    """

    if not isinstance(correlation, dict):
        return []

    candidates = correlation.get(
        "excluded_events"
    )

    if candidates is None:
        candidates = correlation.get(
            "excluded_evidence",
            []
        )

    if not isinstance(candidates, list):
        return []

    return [
        event
        for event in candidates
        if isinstance(event, dict)
    ]


# ============================================================
# SOURCE / DOMAIN
# ============================================================

def normalize_source(source):
    source = normalize_text(source)

    if source is None:
        return None

    if source in SOURCE_DOMAIN_MAP:
        return SOURCE_DOMAIN_MAP[source]

    if "cloudtrail" in source:
        return "CloudTrail"

    if "firewall" in source:
        return "Firewall"

    if source in {
        "ssh",
        "linux",
        "linux ssh",
    }:
        return "SSH"

    return None


def get_related_sources(correlation):
    sources = []

    for event in get_related_events(
        correlation
    ):

        source = normalize_source(
            event.get("source")
        )

        if source:
            sources.append(source)

    return sorted(
        unique_preserve_order(
            sources
        ),
        key=lambda value:
            normalize_text(value) or ""
    )


def get_actual_telemetry_domains(correlation):
    return set(
        get_related_sources(
            correlation
        )
    )


def get_domain_families(correlation):
    families = set(
        get_actual_telemetry_domains(
            correlation
        )
    )

    if has_authentication_evidence(
        correlation
    ):
        families.add("SSH")

    for alert in get_alerts(
        correlation
    ):

        alert_type = normalize_text(
            alert.get(
                "alert_type"
            )
        )

        if (
            alert_type
            and "ssh" in alert_type
        ):
            families.add("SSH")

    return families


# ============================================================
# EVIDENCE HELPERS
# ============================================================

def get_strongest_evidence_score(correlation):
    if not isinstance(correlation, dict):
        return 0

    strongest = safe_float(
        correlation.get(
            "strongest_evidence_score",
            0
        )
    )

    for event in get_related_events(
        correlation
    ):

        score = safe_float(
            event.get(
                "evidence_score",
                0
            )
        )

        strongest = max(
            strongest,
            score
        )

    return clamp(
        strongest
    )


def count_exact_username_matches(correlation):
    count = 0

    for event in get_related_events(
        correlation
    ):

        match = normalize_text(
            event.get(
                "username_match"
            )
        )

        if match == "exact":
            count += 1

    return count


def count_username_mismatches(correlation):
    count = 0

    for event in get_related_events(
        correlation
    ):

        match = normalize_text(
            event.get(
                "username_match"
            )
        )

        if match in {
            "mismatch",
            "mismatched",
            "different",
        }:
            count += 1

    return count


def count_missing_username_matches(correlation):
    count = 0

    for event in get_related_events(
        correlation
    ):

        match = normalize_text(
            event.get(
                "username_match"
            )
        )

        if match in {
            "missing",
            "unknown",
            "none",
        }:
            count += 1

    return count


def get_evidence_score_distribution(correlation):
    scores = []

    for event in get_related_events(
        correlation
    ):

        score = safe_float(
            event.get(
                "evidence_score",
                0
            )
        )

        if score > 0:
            scores.append(
                clamp(score)
            )

    if not scores:
        return {
            "count": 0,
            "minimum": 0,
            "maximum": 0,
            "average": 0,
        }

    return {
        "count": len(scores),
        "minimum": min(scores),
        "maximum": max(scores),
        "average": round(
            sum(scores) / len(scores),
            1
        ),
    }


# ============================================================
# EVENT COUNTS
# ============================================================

def count_related_events_by_domain(correlation):
    counts = {
        "SSH": 0,
        "Firewall": 0,
        "CloudTrail": 0,
    }

    for event in get_related_events(
        correlation
    ):

        domain = normalize_source(
            event.get(
                "source"
            )
        )

        if domain in counts:
            counts[domain] += 1

    return counts


def get_effective_ssh_event_count(correlation):
    raw_ssh_events = count_related_events_by_domain(
        correlation
    )["SSH"]

    if raw_ssh_events > 0:
        return raw_ssh_events

    if has_authentication_evidence(
        correlation
    ):
        return 1

    return 0


# ============================================================
# INCIDENT SEVERITY
# ============================================================

def calculate_incident_severity(correlation):
    if not isinstance(correlation, dict):
        return "LOW"

    chronological_success = (
        is_valid_chronological_success(
            correlation
        )
    )

    actual_domains = (
        get_actual_telemetry_domains(
            correlation
        )
    )

    domain_count = len(
        actual_domains
    )

    strongest_score = (
        get_strongest_evidence_score(
            correlation
        )
    )

    failed_attempts = (
        get_max_failed_attempts(
            correlation
        )
    )

    exact_matches = (
        count_exact_username_matches(
            correlation
        )
    )

    if (
        chronological_success
        and strongest_score >= 80
        and domain_count >= 2
        and exact_matches >= 1
    ):
        return "CRITICAL"

    if (
        chronological_success
        and strongest_score >= 80
    ):
        return "HIGH"

    if (
        chronological_success
        and domain_count >= 2
        and strongest_score >= 60
    ):
        return "HIGH"

    if (
        failed_attempts >= 5
        and strongest_score >= 60
    ):
        return "HIGH"

    if (
        domain_count >= 2
        and strongest_score >= 70
    ):
        return "HIGH"

    if chronological_success:
        return "MEDIUM"

    if domain_count >= 2:
        return "MEDIUM"

    if failed_attempts >= 3:
        return "MEDIUM"

    return "LOW"


# ============================================================
# INCIDENT CONFIDENCE
# ============================================================

def calculate_incident_confidence(correlation):
    if not isinstance(correlation, dict):
        return "LOW"

    score = 0

    strongest_evidence = (
        get_strongest_evidence_score(
            correlation
        )
    )

    related_events = (
        get_related_events(
            correlation
        )
    )

    exact_matches = (
        count_exact_username_matches(
            correlation
        )
    )

    chronological_success = (
        is_valid_chronological_success(
            correlation
        )
    )

    actual_domain_count = len(
        get_actual_telemetry_domains(
            correlation
        )
    )

    username_mismatches = (
        count_username_mismatches(
            correlation
        )
    )

    if strongest_evidence >= 90:
        score += 35

    elif strongest_evidence >= 80:
        score += 30

    elif strongest_evidence >= 60:
        score += 25

    elif strongest_evidence >= 40:
        score += 15

    elif strongest_evidence > 0:
        score += 5

    if len(related_events) >= 4:
        score += 15

    elif len(related_events) >= 2:
        score += 10

    elif len(related_events) >= 1:
        score += 5

    if exact_matches >= 2:
        score += 20

    elif exact_matches == 1:
        score += 15

    if chronological_success:
        score += 15

    if actual_domain_count >= 3:
        score += 10

    elif actual_domain_count >= 2:
        score += 5

    if username_mismatches >= 2:
        score -= 10

    elif username_mismatches == 1:
        score -= 5

    score = clamp(score)

    if score >= 80:
        return "HIGH"

    if score >= 50:
        return "MEDIUM"

    return "LOW"


# ============================================================
# RISK SCORE
# ============================================================

def calculate_risk_score(
    correlation,
    severity,
    confidence
):
    severity_points = {
        "CRITICAL": 30,
        "HIGH": 24,
        "MEDIUM": 16,
        "LOW": 8,
    }

    confidence_points = {
        "HIGH": 20,
        "MEDIUM": 12,
        "LOW": 5,
    }

    score = (
        severity_points.get(
            severity,
            8
        )
        +
        confidence_points.get(
            confidence,
            5
        )
    )

    chronological_success = (
        is_valid_chronological_success(
            correlation
        )
    )

    failed_attempts = (
        get_max_failed_attempts(
            correlation
        )
    )

    strongest_evidence = (
        get_strongest_evidence_score(
            correlation
        )
    )

    exact_matches = (
        count_exact_username_matches(
            correlation
        )
    )

    actual_domains = (
        get_actual_telemetry_domains(
            correlation
        )
    )

    username_mismatches = (
        count_username_mismatches(
            correlation
        )
    )

    if chronological_success:
        score += 15

    if len(actual_domains) >= 3:
        score += 12

    elif len(actual_domains) >= 2:
        score += 7

    if failed_attempts >= 10:
        score += 8

    elif failed_attempts >= 5:
        score += 5

    elif failed_attempts >= 3:
        score += 3

    if strongest_evidence >= 90:
        score += 8

    elif strongest_evidence >= 80:
        score += 6

    elif strongest_evidence >= 60:
        score += 4

    elif strongest_evidence >= 40:
        score += 2

    if exact_matches >= 2:
        score += 6

    elif exact_matches == 1:
        score += 3

    if username_mismatches >= 2:
        score -= 8

    elif username_mismatches == 1:
        score -= 4

    return clamp(
        score,
        minimum=0,
        maximum=MAX_RISK_SCORE
    )


# ============================================================
# INCIDENT STATUS
# ============================================================

def determine_incident_status(correlation):
    if not isinstance(correlation, dict):
        return "REVIEW"

    chronological_success = (
        is_valid_chronological_success(
            correlation
        )
    )

    related_events = (
        get_related_events(
            correlation
        )
    )

    actual_domain_count = len(
        get_actual_telemetry_domains(
            correlation
        )
    )

    strongest_score = (
        get_strongest_evidence_score(
            correlation
        )
    )

    if chronological_success:
        return "INVESTIGATE"

    if (
        actual_domain_count >= 2
        and strongest_score >= 50
    ):
        return "INVESTIGATE"

    if len(related_events) >= 2:
        return "INVESTIGATE"

    if len(related_events) == 1:
        return "SUSPICIOUS"

    if has_authentication_evidence(
        correlation
    ):
        return "DETECTED"

    return "DETECTED"


# ============================================================
# INCIDENT TYPE
# ============================================================

def determine_incident_type(
    correlation,
    chronological_success,
    domains
):
    alert_types = get_alert_types(
        correlation
    )

    if chronological_success:
        return "Potential Account Compromise"

    for alert_type in alert_types:

        normalized = normalize_text(
            alert_type
        )

        if normalized is None:
            continue

        if "brute force" in normalized:
            return "SSH Brute Force"

        if "cloud" in normalized:
            return "Suspicious Cloud Activity"

    valid_domains = sorted(
        [
            domain
            for domain in domains
            if domain
        ]
    )

    if len(valid_domains) >= 2:
        return (
            f"{' + '.join(valid_domains)} "
            f"Suspicious Activity"
        )

    if len(valid_domains) == 1:
        return (
            f"{valid_domains[0]} "
            f"Suspicious Activity"
        )

    return "Suspicious Activity"


# ============================================================
# ATTACK PHASE NORMALIZATION
# ============================================================

def normalize_attack_phase(
    phase,
    event=None
):
    normalized = normalize_text(
        phase
    )

    if normalized:

        phase_map = {
            "initial_access":
                "INITIAL_ACCESS",

            "initial-access":
                "INITIAL_ACCESS",

            "brute_force":
                "BRUTE_FORCE",

            "brute-force":
                "BRUTE_FORCE",

            "authentication":
                "INITIAL_ACCESS",

            "post_failure":
                "AUTHENTICATION_SUCCESS",

            "post-failure":
                "AUTHENTICATION_SUCCESS",

            "successful_login":
                "AUTHENTICATION_SUCCESS",

            "post_success":
                "POST_COMPROMISE_ACTIVITY",

            "post-success":
                "POST_COMPROMISE_ACTIVITY",

            "post_authentication":
                "POST_AUTHENTICATION",

            "post-auth":
                "POST_AUTHENTICATION",

            "cloud_activity":
                "CLOUD_ACTIVITY",

            "network_activity":
                "NETWORK_ACTIVITY",
        }

        if normalized in phase_map:
            return phase_map[normalized]

        upper_phase = str(
            phase
        ).strip().upper()

        if upper_phase in ATTACK_PHASE_RANK:
            return upper_phase

    if isinstance(event, dict):

        event_type = normalize_text(
            event.get(
                "event_type"
            )
            or event.get(
                "event"
            )
            or event.get(
                "action"
            )
        )

        source = normalize_source(
            event.get(
                "source"
            )
        )

        action = normalize_text(
            event.get(
                "action"
            )
        )

        if event_type:

            if (
                "brute" in event_type
                or "failed" in event_type
            ):
                return "BRUTE_FORCE"

            if (
                "success" in event_type
                or "login" in event_type
            ):
                return "AUTHENTICATION_SUCCESS"

        if action:

            if "fail" in action:
                return "BRUTE_FORCE"

            if "success" in action:
                return "AUTHENTICATION_SUCCESS"

        if source == "CloudTrail":
            return "CLOUD_ACTIVITY"

        if source == "Firewall":
            return "NETWORK_ACTIVITY"

    return "UNKNOWN"


# ============================================================
# ATTACK PHASE CONSTRUCTION
# ============================================================

def build_attack_phases(correlation):
    """
    Build final incident-level attack phases from:

        1. authentication chronology
        2. detector alerts
        3. correlated telemetry
        4. event phase metadata

    No external MITRE mapping is introduced.
    """

    phases = []

    def add_phase(
        phase,
        source=None,
        timestamp=None,
        evidence_count=0,
        reason=None
    ):
        phase = normalize_attack_phase(
            phase
        )

        if phase == "UNKNOWN":
            return

        phases.append({
            "phase": phase,
            "source": source,
            "timestamp": normalize_timestamp(
                timestamp
            ),
            "evidence_count":
                evidence_count,
            "reason": reason,
        })

    auth_times = get_authentication_times(
        correlation
    )

    failed_attempts = (
        get_max_failed_attempts(
            correlation
        )
    )

    if failed_attempts > 0:

        add_phase(
            "BRUTE_FORCE",
            source="Linux SSH",
            timestamp=auth_times.get(
                "first_failed"
            ),
            evidence_count=failed_attempts,
            reason=(
                "Multiple failed SSH authentication "
                "attempts were observed."
            )
        )

    if is_valid_chronological_success(
        correlation
    ):

        add_phase(
            "AUTHENTICATION_SUCCESS",
            source="Linux SSH",
            timestamp=auth_times.get(
                "successful_login"
            ),
            evidence_count=1,
            reason=(
                "Successful authentication occurred "
                "after the failed authentication sequence."
            )
        )

    elif has_successful_login_timestamp(
        correlation
    ):

        add_phase(
            "AUTHENTICATION_SUCCESS",
            source="Linux SSH",
            timestamp=auth_times.get(
                "successful_login"
            ),
            evidence_count=1,
            reason=(
                "A successful login was observed, but "
                "strict chronology was not established."
            )
        )

    for event in get_related_events(
        correlation
    ):

        phase = normalize_attack_phase(
            event.get(
                "phase"
            )
            or event.get(
                "attack_phase"
            ),
            event
        )

        source = (
            normalize_source(
                event.get(
                    "source"
                )
            )
            or clean_value(
                event.get(
                    "source"
                )
            )
        )

        timestamp = event.get(
            "timestamp"
        )

        if phase == "BRUTE_FORCE":
            reason = (
                "Correlated telemetry supports "
                "authentication attack activity."
            )

        elif phase == "AUTHENTICATION_SUCCESS":
            reason = (
                "Telemetry is associated with "
                "successful authentication."
            )

        elif phase == "CLOUD_ACTIVITY":
            reason = (
                "CloudTrail activity was correlated "
                "with the incident."
            )

        elif phase == "NETWORK_ACTIVITY":
            reason = (
                "Firewall/network telemetry was "
                "correlated with the incident."
            )

        elif phase == "POST_COMPROMISE_ACTIVITY":
            reason = (
                "Post-authentication activity was "
                "correlated with the incident."
            )

        else:
            reason = (
                "Correlated telemetry contributed "
                "to the incident timeline."
            )

        add_phase(
            phase,
            source=source,
            timestamp=timestamp,
            evidence_count=1,
            reason=reason
        )

    # --------------------------------------------------------
    # Merge phases by phase type
    # --------------------------------------------------------

    merged = {}

    for item in phases:

        phase = item["phase"]

        if phase not in merged:

            merged[phase] = {
                "phase": phase,
                "sources": [],
                "first_observed": item[
                    "timestamp"
                ],
                "last_observed": item[
                    "timestamp"
                ],
                "evidence_count": 0,
                "reasons": [],
            }

        target = merged[phase]

        source = item.get(
            "source"
        )

        if source:
            target["sources"].append(
                source
            )

        timestamp = parse_timestamp(
            item.get(
                "timestamp"
            )
        )

        first_timestamp = parse_timestamp(
            target.get(
                "first_observed"
            )
        )

        last_timestamp = parse_timestamp(
            target.get(
                "last_observed"
            )
        )

        if (
            timestamp is not None
            and (
                first_timestamp is None
                or timestamp < first_timestamp
            )
        ):
            target["first_observed"] = (
                timestamp.isoformat()
            )

        if (
            timestamp is not None
            and (
                last_timestamp is None
                or timestamp > last_timestamp
            )
        ):
            target["last_observed"] = (
                timestamp.isoformat()
            )

        target["evidence_count"] += safe_int(
            item.get(
                "evidence_count",
                1
            ),
            default=1
        )

        reason = clean_value(
            item.get(
                "reason"
            )
        )

        if reason:
            target["reasons"].append(
                reason
            )

    result = list(
        merged.values()
    )

    for item in result:

        item["sources"] = sorted(
            unique_preserve_order(
                item["sources"]
            )
        )

        item["reasons"] = (
            unique_preserve_order(
                item["reasons"]
            )
        )

    result.sort(
        key=lambda item:
            (
                ATTACK_PHASE_RANK.get(
                    item["phase"],
                    99
                ),
                parse_timestamp(
                    item.get(
                        "first_observed"
                    )
                )
                or datetime.max.replace(
                    tzinfo=timezone.utc
                ),
            )
    )

    return result


# ============================================================
# GENERATED AUTHENTICATION EVENTS
# ============================================================

def build_generated_auth_events(
    authentication_times,
    source_ip,
    username
):
    events = []

    first_failed = (
        authentication_times.get(
            "first_failed"
        )
    )

    last_failed = (
        authentication_times.get(
            "last_failed"
        )
    )

    successful_login = (
        authentication_times.get(
            "successful_login"
        )
    )

    if first_failed:

        events.append({
            "timestamp": first_failed,
            "event": (
                "Authentication failure "
                "sequence started"
            ),
            "event_type": "ssh_failed",
            "source": "Linux SSH",
            "phase": "BRUTE_FORCE",
            "evidence_score": None,
            "username_match": (
                "EXACT"
                if username
                else None
            ),
            "anchor_type": "FIRST_FAILED",
            "source_ip": source_ip,
            "username": username,
            "action": "failed",
            "generated": True,
            "trace_type": "authentication_anchor",
        })

    if (
        last_failed
        and last_failed != first_failed
    ):

        events.append({
            "timestamp": last_failed,
            "event": (
                "Last failed authentication "
                "observed"
            ),
            "event_type": "ssh_failed",
            "source": "Linux SSH",
            "phase": "BRUTE_FORCE",
            "evidence_score": None,
            "username_match": (
                "EXACT"
                if username
                else None
            ),
            "anchor_type": "LAST_FAILED",
            "source_ip": source_ip,
            "username": username,
            "action": "failed",
            "generated": True,
            "trace_type": "authentication_anchor",
        })

    if successful_login:

        events.append({
            "timestamp": successful_login,
            "event": "Successful login observed",
            "event_type": "ssh_success",
            "source": "Linux SSH",
            "phase": "AUTHENTICATION_SUCCESS",
            "evidence_score": None,
            "username_match": (
                "EXACT"
                if username
                else None
            ),
            "anchor_type": "SUCCESSFUL_LOGIN",
            "source_ip": source_ip,
            "username": username,
            "action": "success",
            "generated": True,
            "trace_type": "authentication_anchor",
        })

    return events


# ============================================================
# EVENT TRACEABILITY
# ============================================================

def build_event_reference(
    event,
    index=None
):
    """
    Preserve traceability back to the correlated event.

    Uses existing identifiers when available and otherwise
    creates a deterministic reference from event content.
    """

    if not isinstance(event, dict):
        return None

    existing_id = clean_value(
        event.get(
            "event_id"
        )
    )

    source = (
        normalize_source(
            event.get(
                "source"
            )
        )
        or clean_value(
            event.get(
                "source"
            )
        )
        or "UNKNOWN"
    )

    timestamp = (
        normalize_timestamp(
            event.get(
                "timestamp"
            )
        )
    )

    source_ip = (
        clean_value(
            event.get(
                "source_ip"
            )
        )
        or "unknown"
    )

    username = (
        clean_value(
            event.get(
                "username"
            )
        )
        or "unknown"
    )

    event_type = (
        clean_value(
            event.get(
                "event_type"
            )
        )
        or clean_value(
            event.get(
                "event"
            )
        )
        or clean_value(
            event.get(
                "action"
            )
        )
        or "unknown"
    )

    if existing_id:

        event_id = str(
            existing_id
        )

    else:

        raw = (
            f"{source}|"
            f"{timestamp or ''}|"
            f"{source_ip}|"
            f"{username}|"
            f"{event_type}|"
            f"{index if index is not None else ''}"
        )

        event_id = (
            "EVT-"
            +
            hashlib.sha256(
                raw.encode(
                    "utf-8"
                )
            ).hexdigest()[:16].upper()
        )

    original_log_reference = (
        clean_value(
            event.get(
                "original_log_reference"
            )
        )
        or clean_value(
            event.get(
                "log_reference"
            )
        )
        or clean_value(
            event.get(
                "log_id"
            )
        )
        or clean_value(
            event.get(
                "source_file"
            )
        )
        or clean_value(
            event.get(
                "file"
            )
        )
    )

    return {
        "event_id": event_id,
        "source": source,
        "timestamp": timestamp,
        "source_ip": source_ip,
        "username": username,
        "event_type": str(
            event_type
        ),
        "original_log_reference":
            original_log_reference,
    }


# ============================================================
# EVIDENCE CLASSIFICATION
# ============================================================

def calculate_evidence_priority(event):
    """
    Evidence priority is independent from incident risk.

    Primary evidence:
        strong evidence directly supporting the incident.

    Supporting evidence:
        useful contextual evidence.
    """

    if not isinstance(event, dict):
        return "SUPPORTING"

    score = safe_float(
        event.get(
            "evidence_score",
            0
        )
    )

    username_match = normalize_text(
        event.get(
            "username_match"
        )
    )

    phase = normalize_attack_phase(
        event.get(
            "phase"
        )
        or event.get(
            "attack_phase"
        ),
        event
    )

    anchor = normalize_text(
        event.get(
            "anchor_type"
        )
    )

    if score >= 80:
        return "PRIMARY"

    if (
        username_match == "exact"
        and score >= 60
    ):
        return "PRIMARY"

    if (
        phase in {
            "AUTHENTICATION_SUCCESS",
            "BRUTE_FORCE",
        }
        and anchor in {
            "successful_login",
            "first_failed",
            "last_failed",
        }
        and score >= 50
    ):
        return "PRIMARY"

    return "SUPPORTING"


def build_evidence_item(
    event,
    index=None,
    classification=None
):
    if not isinstance(event, dict):
        return None

    event_reference = build_event_reference(
        event,
        index=index
    )

    if event_reference is None:
        return None

    evidence_score = event.get(
        "evidence_score"
    )

    if evidence_score is not None:
        evidence_score = clamp(
            evidence_score
        )

    phase = normalize_attack_phase(
        event.get(
            "phase"
        )
        or event.get(
            "attack_phase"
        ),
        event
    )

    correlation_reason = (
        clean_value(
            event.get(
                "correlation_reason"
            )
        )
        or clean_value(
            event.get(
                "reason"
            )
        )
    )

    return {
        "evidence_id": (
            "EVD-"
            +
            hashlib.sha256(
                (
                    f"{event_reference['event_id']}|"
                    f"{classification or 'SUPPORTING'}"
                ).encode("utf-8")
            ).hexdigest()[:16].upper()
        ),
        "classification": (
            classification
            or calculate_evidence_priority(
                event
            )
        ),
        "event_id":
            event_reference["event_id"],
        "source":
            event_reference["source"],
        "timestamp":
            event_reference["timestamp"],
        "source_ip":
            event_reference["source_ip"],
        "username":
            event_reference["username"],
        "event_type":
            event_reference["event_type"],
        "phase": phase,
        "evidence_score":
            evidence_score,
        "username_match":
            event.get(
                "username_match"
            ),
        "anchor_type":
            event.get(
                "anchor_type"
            ),
        "correlation_reason":
            correlation_reason,
        "original_log_reference":
            event_reference[
                "original_log_reference"
            ],
    }


def build_evidence_collections(correlation):
    """
    Build explicit:

        primary_evidence
        supporting_evidence
        excluded_evidence
    """

    primary = []
    supporting = []
    excluded = []

    related_events = (
        get_related_events(
            correlation
        )
    )

    for index, event in enumerate(
        related_events,
        start=1
    ):

        classification = (
            calculate_evidence_priority(
                event
            )
        )

        evidence = build_evidence_item(
            event,
            index=index,
            classification=classification
        )

        if evidence is None:
            continue

        if classification == "PRIMARY":
            primary.append(
                evidence
            )

        else:
            supporting.append(
                evidence
            )

    excluded_events = (
        get_excluded_events(
            correlation
        )
    )

    for index, event in enumerate(
        excluded_events,
        start=1
    ):

        evidence = build_evidence_item(
            event,
            index=index,
            classification="EXCLUDED"
        )

        if evidence is None:
            continue

        evidence["exclusion_reason"] = (
            clean_value(
                event.get(
                    "exclusion_reason"
                )
            )
            or clean_value(
                event.get(
                    "correlation_reason"
                )
            )
            or "Event was excluded by correlation logic."
        )

        excluded.append(
            evidence
        )

    return {
        "primary_evidence": primary,
        "supporting_evidence": supporting,
        "excluded_evidence": excluded,
    }


# ============================================================
# TIMELINE DEDUPLICATION
# ============================================================

def timeline_event_key(event):
    if not isinstance(event, dict):
        return None

    anchor = normalize_text(
        event.get(
            "anchor_type"
        )
    )

    timestamp = normalize_timestamp(
        event.get(
            "timestamp"
        )
    )

    source = normalize_text(
        event.get(
            "source"
        )
    ) or "unknown"

    event_type = normalize_text(
        event.get("event")
        or event.get("event_type")
        or event.get("action")
    ) or "unknown"

    source_ip = normalize_text(
        event.get(
            "source_ip"
        )
    ) or "unknown"

    username = normalize_text(
        event.get(
            "username"
        )
    ) or "unknown"

    generated = bool(
        event.get(
            "generated",
            False
        )
    )

    event_id = clean_value(
        event.get(
            "event_id"
        )
    )

    if event_id:
        return (
            "event-id|"
            f"{event_id}"
        )

    if generated and anchor in {
        "first_failed",
        "last_failed",
        "successful_login",
    }:
        return (
            "generated|"
            f"{anchor}|"
            f"{timestamp}|"
            f"{source_ip}|"
            f"{username}"
        )

    return (
        "raw|"
        f"{timestamp}|"
        f"{source}|"
        f"{event_type}|"
        f"{source_ip}|"
        f"{username}"
    )


# ============================================================
# INCIDENT TIMELINE
# ============================================================

def build_incident_timeline(correlation):
    if not isinstance(correlation, dict):
        return []

    timeline = []

    auth_times = (
        get_authentication_times(
            correlation
        )
    )

    source_ip = clean_value(
        correlation.get(
            "source_ip"
        )
    )

    username = clean_value(
        correlation.get(
            "username"
        )
    )

    for index, event in enumerate(
        get_related_events(
            correlation
        ),
        start=1
    ):

        timestamp = normalize_timestamp(
            event.get(
                "timestamp"
            )
        )

        if timestamp is None:
            continue

        event_type = (
            clean_value(
                event.get(
                    "event_type"
                )
            )
            or
            clean_value(
                event.get(
                    "event"
                )
            )
            or
            clean_value(
                event.get(
                    "action"
                )
            )
            or
            "Telemetry event"
        )

        source = (
            clean_value(
                event.get(
                    "source"
                )
            )
            or
            "Unknown"
        )

        event_id = (
            clean_value(
                event.get(
                    "event_id"
                )
            )
        )

        if event_id is None:
            event_id = build_event_reference(
                event,
                index=index
            )["event_id"]

        timeline.append({
            "event_id": event_id,
            "timestamp": timestamp,
            "event": str(event_type),
            "source": str(source),
            "source_ip": (
                event.get(
                    "source_ip"
                )
                or source_ip
            ),
            "username": (
                event.get(
                    "username"
                )
                or username
            ),
            "phase": (
                normalize_attack_phase(
                    event.get(
                        "phase"
                    )
                    or event.get(
                        "attack_phase"
                    ),
                    event
                )
            ),
            "evidence_score":
                event.get(
                    "evidence_score"
                ),
            "username_match":
                event.get(
                    "username_match"
                ),
            "anchor_type":
                event.get(
                    "anchor_type"
                ),
            "generated": False,
            "original_log_reference": (
                clean_value(
                    event.get(
                        "original_log_reference"
                    )
                )
                or clean_value(
                    event.get(
                        "log_reference"
                    )
                )
                or clean_value(
                    event.get(
                        "log_id"
                    )
                )
                or clean_value(
                    event.get(
                        "source_file"
                    )
                )
            ),
        })

    generated_events = (
        build_generated_auth_events(
            auth_times,
            source_ip,
            username
        )
    )

    timeline.extend(
        generated_events
    )

    unique_timeline = []
    seen = set()

    for item in timeline:

        key = timeline_event_key(
            item
        )

        if key is None:
            continue

        if key in seen:
            continue

        seen.add(key)

        unique_timeline.append(
            item
        )

    unique_timeline.sort(
        key=lambda item:
            parse_timestamp(
                item.get(
                    "timestamp"
                )
            )
            or
            datetime.min.replace(
                tzinfo=timezone.utc
            )
    )

    return unique_timeline


# ============================================================
# EVIDENCE SUMMARY
# ============================================================

def build_evidence_summary(correlation):
    related_events = (
        get_related_events(
            correlation
        )
    )

    counts = (
        count_related_events_by_domain(
            correlation
        )
    )

    actual_sources = (
        get_related_sources(
            correlation
        )
    )

    domain_families = (
        get_domain_families(
            correlation
        )
    )

    evidence_collections = (
        build_evidence_collections(
            correlation
        )
    )

    return {

        "related_events":
            len(related_events),

        "firewall_events":
            counts["Firewall"],

        "cloudtrail_events":
            counts["CloudTrail"],

        "related_ssh_events":
            counts["SSH"],

        "authentication_evidence":
            has_authentication_evidence(
                correlation
            ),

        "effective_ssh_evidence":
            get_effective_ssh_event_count(
                correlation
            ),

        "exact_username_matches":
            count_exact_username_matches(
                correlation
            ),

        "username_mismatches":
            count_username_mismatches(
                correlation
            ),

        "missing_username_matches":
            count_missing_username_matches(
                correlation
            ),

        "strongest_evidence_score":
            get_strongest_evidence_score(
                correlation
            ),

        "evidence_score_distribution":
            get_evidence_score_distribution(
                correlation
            ),

        "telemetry_sources":
            actual_sources,

        "domain_families":
            sorted(domain_families),

        "primary_evidence_count":
            len(
                evidence_collections[
                    "primary_evidence"
                ]
            ),

        "supporting_evidence_count":
            len(
                evidence_collections[
                    "supporting_evidence"
                ]
            ),

        "excluded_evidence_count":
            len(
                evidence_collections[
                    "excluded_evidence"
                ]
            ),
    }


# ============================================================
# AUDITABILITY
# ============================================================

def build_auditability(
    incident_id,
    correlation,
    evidence_collections,
    timeline
):
    """
    Explicit Day 5 auditability chain:

        Incident
            ↓
        Correlation Package
            ↓
        Evidence
            ↓
        Original Event
            ↓
        Original Log reference

    The engine preserves references when the upstream modules
    provide them and does not invent original-log contents.
    """

    correlation_id = (
        clean_value(
            correlation.get(
                "correlation_id"
            )
        )
    )

    evidence_links = []

    for collection_name in (
        "primary_evidence",
        "supporting_evidence",
        "excluded_evidence",
    ):

        for evidence in (
            evidence_collections[
                collection_name
            ]
        ):

            evidence_links.append({
                "evidence_id":
                    evidence.get(
                        "evidence_id"
                    ),

                "classification":
                    collection_name,

                "event_id":
                    evidence.get(
                        "event_id"
                    ),

                "original_log_reference":
                    evidence.get(
                        "original_log_reference"
                    ),

                "source":
                    evidence.get(
                        "source"
                    ),

                "timestamp":
                    evidence.get(
                        "timestamp"
                    ),
            })

    timeline_links = []

    for event in timeline:

        timeline_links.append({
            "event_id":
                event.get(
                    "event_id"
                ),

            "timestamp":
                event.get(
                    "timestamp"
                ),

            "source":
                event.get(
                    "source"
                ),

            "original_log_reference":
                event.get(
                    "original_log_reference"
                ),
        })

    return {
        "incident_id":
            incident_id,

        "correlation_id":
            correlation_id,

        "trace_chain": [
            "INCIDENT",
            "CORRELATION_PACKAGE",
            "EVIDENCE",
            "ORIGINAL_EVENT",
            "ORIGINAL_LOG",
        ],
        "correlation_reference": {
            "correlation_id":
                correlation_id,

            "correlation_version":
                clean_value(
                    correlation.get(
                        "correlation_version"
                    )
                ),

            "correlation_created_at":
                correlation.get(
                    "correlation_created_at"
                ),

            "correlation_identity":
                correlation.get(
                    "correlation_identity"
                ),
        },

        "evidence_references":
            evidence_links,

        "timeline_event_references":
            timeline_links,

        "original_log_references_available":
            any(
                item.get(
                    "original_log_reference"
                )
                for item in evidence_links
            ),

        "auditability_status": (
            "TRACEABLE"
            if correlation_id
            and evidence_links
            else "PARTIALLY_TRACEABLE"
        ),
    }


# ============================================================
# ATTACK STORY
# ============================================================

def build_attack_story(
    correlation,
    severity
):
    if not isinstance(correlation, dict):
        return (
            "Insufficient evidence to construct "
            "an attack story."
        )

    source_ip = (
        clean_value(
            correlation.get(
                "source_ip"
            )
        )
        or "unknown source"
    )

    username = (
        clean_value(
            correlation.get(
                "username"
            )
        )
        or "unknown user"
    )

    failed_attempts = (
        get_max_failed_attempts(
            correlation
        )
    )

    has_success = (
        has_successful_login_timestamp(
            correlation
        )
    )

    chronological_success = (
        is_valid_chronological_success(
            correlation
        )
    )

    domains = sorted(
        get_domain_families(
            correlation
        )
    )

    strongest_score = (
        get_strongest_evidence_score(
            correlation
        )
    )

    exact_matches = (
        count_exact_username_matches(
            correlation
        )
    )

    username_mismatches = (
        count_username_mismatches(
            correlation
        )
    )

    parts = []

    if failed_attempts > 0:

        parts.append(
            f"{failed_attempts} failed authentication "
            f"attempts were observed from {source_ip} "
            f"against username {username}."
        )

    else:

        parts.append(
            f"Suspicious authentication activity was "
            f"observed from {source_ip} involving "
            f"username {username}."
        )

    if has_success:

        if chronological_success:

            parts.append(
                "A successful login was observed after "
                "the failed authentication sequence. "
                "This temporal relationship is consistent "
                "with potential account compromise, but "
                "does not independently prove compromise."
            )

        else:

            parts.append(
                "A successful login was observed, but "
                "strict chronology did not establish that "
                "it occurred after the failed "
                "authentication sequence."
            )

    if len(domains) >= 2:

        domain_list = ", ".join(
            domains
        )

        parts.append(
            f"Evidence was correlated across the "
            f"{domain_list} security domains."
        )

    elif len(domains) == 1:

        parts.append(
            f"Evidence was observed within the "
            f"{domains[0]} security domain."
        )

    if exact_matches > 0:

        parts.append(
            f"{exact_matches} correlated event(s) "
            f"contained an exact username match."
        )

    if username_mismatches > 0:

        parts.append(
            f"{username_mismatches} correlated event(s) "
            f"contained a username mismatch; these "
            f"events reduce attribution confidence."
        )

    if strongest_score > 0:

        parts.append(
            f"The strongest correlated evidence scored "
            f"{int(strongest_score)}/100."
        )

    if severity == "CRITICAL":

        parts.append(
            "The incident is classified as CRITICAL "
            "priority and requires immediate investigation."
        )

    elif severity == "HIGH":

        parts.append(
            "The incident is classified as HIGH priority "
            "and warrants investigation."
        )

    elif severity == "MEDIUM":

        parts.append(
            "The incident is classified as MEDIUM priority "
            "and requires analyst review."
        )

    else:

        parts.append(
            "The available evidence is suspicious but "
            "does not independently prove compromise."
        )

    return " ".join(parts)


# ============================================================
# INCIDENT DEDUPLICATION
# ============================================================

def deduplicate_incidents(incidents):
    if not isinstance(
        incidents,
        list
    ):
        return []

    unique = []
    seen = set()

    for incident in incidents:

        if not isinstance(
            incident,
            dict
        ):
            continue

        incident_id = clean_value(
            incident.get(
                "incident_id"
            )
        )

        if incident_id is None:

            source_ip = normalize_text(
                incident.get(
                    "source_ip",
                    "unknown"
                )
            ) or "unknown"

            username = normalize_text(
                incident.get(
                    "username",
                    "unknown"
                )
            ) or "unknown"

            auth_times = incident.get(
                "authentication_times",
                {}
            )

            if isinstance(
                auth_times,
                dict
            ):

                first_failed = (
                    normalize_timestamp(
                        auth_times.get(
                            "first_failed"
                        )
                    )
                    or ""
                )

                last_failed = (
                    normalize_timestamp(
                        auth_times.get(
                            "last_failed"
                        )
                    )
                    or ""
                )

                successful_login = (
                    normalize_timestamp(
                        auth_times.get(
                            "successful_login"
                        )
                    )
                    or ""
                )

            else:
                first_failed = ""
                last_failed = ""
                successful_login = ""

            raw = (
                f"{source_ip}|"
                f"{username}|"
                f"{first_failed}|"
                f"{last_failed}|"
                f"{successful_login}"
            )

            incident_id = (
                "INC-"
                +
                hashlib.sha256(
                    raw.encode(
                        "utf-8"
                    )
                ).hexdigest()[:16].upper()
            )

        if incident_id in seen:
            continue

        seen.add(
            incident_id
        )

        unique.append(
            incident
        )

    return unique


# ============================================================
# INCIDENT SORTING
# ============================================================

def sort_incidents(incidents):
    if not isinstance(
        incidents,
        list
    ):
        return []

    def sort_key(incident):

        if not isinstance(
            incident,
            dict
        ):
            return (
                0,
                0,
                0,
                0
            )

        severity = (
            normalize_text(
                incident.get(
                    "severity",
                    ""
                )
            )
            or ""
        ).upper()

        confidence = (
            normalize_text(
                incident.get(
                    "confidence",
                    ""
                )
            )
            or ""
        ).upper()

        severity_value = (
            SEVERITY_RANK.get(
                severity,
                0
            )
        )

        confidence_value = (
            CONFIDENCE_RANK.get(
                confidence,
                0
            )
        )

        risk = safe_float(
            incident.get(
                "risk_score",
                0
            )
        )

        chronological_success = (
            1
            if incident.get(
                "chronological_success_verified"
            )
            else 0
        )

        return (
            severity_value,
            risk,
            chronological_success,
            confidence_value,
        )

    return sorted(
        incidents,
        key=sort_key,
        reverse=True
    )


# ============================================================
# BUILD ONE INCIDENT
# ============================================================

def build_incident(correlation):
    if not isinstance(correlation, dict):
        return None

    source_ip = (
        clean_value(
            correlation.get(
                "source_ip"
            )
        )
        or "unknown"
    )

    username = (
        clean_value(
            correlation.get(
                "username"
            )
        )
        or "unknown"
    )

    severity = calculate_incident_severity(
        correlation
    )

    confidence = calculate_incident_confidence(
        correlation
    )

    risk_score = calculate_risk_score(
        correlation,
        severity,
        confidence
    )

    status = determine_incident_status(
        correlation
    )

    incident_id = build_incident_id(
        correlation
    )

    auth_times = get_authentication_times(
        correlation
    )

    alert_types = get_alert_types(
        correlation
    )

    telemetry_sources = get_related_sources(
        correlation
    )

    related_events = get_related_events(
        correlation
    )

    alerts = get_alerts(
        correlation
    )

    chronological_success = (
        is_valid_chronological_success(
            correlation
        )
    )

    domains = get_domain_families(
        correlation
    )

    incident_type = determine_incident_type(
        correlation,
        chronological_success,
        domains
    )

    timeline = build_incident_timeline(
        correlation
    )

    evidence_summary = build_evidence_summary(
        correlation
    )

    evidence_collections = (
        build_evidence_collections(
            correlation
        )
    )

    attack_phases = build_attack_phases(
        correlation
    )

    auditability = build_auditability(
        incident_id,
        correlation,
        evidence_collections,
        timeline
    )

    return {

        # ----------------------------------------------------
        # Identity / schema
        # ----------------------------------------------------

        "schema_version":
            INCIDENT_SCHEMA_VERSION,

        "engine_version":
            INCIDENT_ENGINE_VERSION,

        "incident_id":
            incident_id,

        "correlation_id":
            clean_value(
                correlation.get(
                    "correlation_id"
                )
            ),
    
        "correlation_version":
            clean_value(
                correlation.get(
                    "correlation_version"
                )
            ),

        "correlation_created_at":
            correlation.get(
                "correlation_created_at"
            ),

        "correlation_identity":
            correlation.get(
                "correlation_identity"
            ),
        # ----------------------------------------------------
        # Classification
        # ----------------------------------------------------

        "incident_type":
            incident_type,

        "severity":
            severity,

        "confidence":
            confidence,

        "risk_score":
            risk_score,

        "status":
            status,

        # ----------------------------------------------------
        # Identity
        # ----------------------------------------------------

        "source_ip":
            source_ip,

        "username":
            username,

        # ----------------------------------------------------
        # Authentication
        # ----------------------------------------------------

        "failed_attempts":
            get_max_failed_attempts(
                correlation
            ),

        "successful_login":
            has_successful_login_timestamp(
                correlation
            ),

        "chronological_success_verified":
            chronological_success,

        "authentication_times":
            auth_times,

        # ----------------------------------------------------
        # Alerts
        # ----------------------------------------------------

        "alert_types":
            alert_types,

        "alert_count":
            len(alerts),

        # ----------------------------------------------------
        # Telemetry / domains
        # ----------------------------------------------------

        "telemetry_sources":
            telemetry_sources,

        "domain_families":
            sorted(domains),

        "related_event_count":
            len(related_events),

        # ----------------------------------------------------
        # Day 5 - Attack phases
        # ----------------------------------------------------

        "attack_phases":
            attack_phases,

        # ----------------------------------------------------
        # Day 5 - Evidence
        # ----------------------------------------------------

        "evidence_summary":
            evidence_summary,

        "primary_evidence":
            evidence_collections[
                "primary_evidence"
            ],

        "supporting_evidence":
            evidence_collections[
                "supporting_evidence"
            ],

        "excluded_evidence":
            evidence_collections[
                "excluded_evidence"
            ],

        # ----------------------------------------------------
        # Day 5 - Narrative
        # ----------------------------------------------------

        "attack_story":
            build_attack_story(
                correlation,
                severity
            ),

        # ----------------------------------------------------
        # Day 5 - Final timeline
        # ----------------------------------------------------

        "timeline":
            timeline,

        # ----------------------------------------------------
        # Day 5 - Auditability
        # ----------------------------------------------------

        "auditability":
            auditability,
    }


# ============================================================
# PUBLIC API
# ============================================================

def build_incidents(correlations):
    if not isinstance(
        correlations,
        list
    ):
        return []

    incidents = []

    for correlation in correlations:

        incident = build_incident(
            correlation
        )

        if incident is not None:
            incidents.append(
                incident
            )

    incidents = deduplicate_incidents(
        incidents
    )

    return sort_incidents(
        incidents
    )


def generate_incidents(correlations):
    return build_incidents(
        correlations
    )


# ============================================================
# INCIDENT SUMMARY
# ============================================================

def build_incident_summary(incidents):
    if not isinstance(
        incidents,
        list
    ):
        incidents = []

    summary = {

        "incident_count": 0,

        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,

        "investigation_count": 0,
        "suspicious_count": 0,
        "detected_count": 0,

        "potential_compromise_incidents": 0,

        "cloudtrail_incidents": 0,
        "firewall_incidents": 0,
        "ssh_incidents": 0,

        "primary_evidence_count": 0,
        "supporting_evidence_count": 0,
        "excluded_evidence_count": 0,

        "average_risk_score": 0,
        "highest_risk_score": 0,
        "lowest_risk_score": 0,
    }

    risk_scores = []

    for incident in incidents:

        if not isinstance(
            incident,
            dict
        ):
            continue

        summary[
            "incident_count"
        ] += 1

        severity = (
            normalize_text(
                incident.get(
                    "severity",
                    ""
                )
            )
            or ""
        )

        if severity == "critical":

            summary[
                "critical_count"
            ] += 1

        elif severity == "high":

            summary[
                "high_count"
            ] += 1

        elif severity == "medium":

            summary[
                "medium_count"
            ] += 1

        elif severity == "low":

            summary[
                "low_count"
            ] += 1

        status = (
            normalize_text(
                incident.get(
                    "status",
                    ""
                )
            )
            or ""
        )

        if status == "investigate":

            summary[
                "investigation_count"
            ] += 1

        elif status == "suspicious":

            summary[
                "suspicious_count"
            ] += 1

        elif status == "detected":

            summary[
                "detected_count"
            ] += 1

        if incident.get(
            "chronological_success_verified"
        ):

            summary[
                "potential_compromise_incidents"
            ] += 1

        domains = {
            normalize_text(
                domain
            )
            for domain in incident.get(
                "domain_families",
                []
            )
        }

        if "cloudtrail" in domains:

            summary[
                "cloudtrail_incidents"
            ] += 1

        if "firewall" in domains:

            summary[
                "firewall_incidents"
            ] += 1

        if "ssh" in domains:

            summary[
                "ssh_incidents"
            ] += 1

        summary[
            "primary_evidence_count"
        ] += len(
            incident.get(
                "primary_evidence",
                []
            )
        )

        summary[
            "supporting_evidence_count"
        ] += len(
            incident.get(
                "supporting_evidence",
                []
            )
        )

        summary[
            "excluded_evidence_count"
        ] += len(
            incident.get(
                "excluded_evidence",
                []
            )
        )

        risk = safe_float(
            incident.get(
                "risk_score",
                0
            )
        )

        risk_scores.append(
            risk
        )

    if risk_scores:

        summary[
            "average_risk_score"
        ] = round(
            sum(risk_scores)
            /
            len(risk_scores),
            1
        )

        summary[
            "highest_risk_score"
        ] = max(
            risk_scores
        )

        summary[
            "lowest_risk_score"
        ] = min(
            risk_scores
        )

    return summary


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    print("\n" + "=" * 75)

    print(
        "KIROTRACE INCIDENT ENGINE TEST (V2.0)"
    )

    print("=" * 75)

    test_correlations = [

 {
    "schema_version": "1.1",
    "engine_version": "1.1",

    "correlation_id":
        "CORR-C94D9B2999CA85EA",

    "correlation_version":
        "1.0",

    "correlation_created_at":
        "2026-08-14T10:05:33+00:00",

    "correlation_identity":
        {
            "identity_type":
                "SOURCE_IP_USERNAME_AUTH_TIMELINE",

            "source_ip":
                "203.0.113.50",

            "username":
                "admin",
        },

    "source_ip":
        "203.0.113.50",

    "username":
        "admin",

            "alerts": [

                {
                    "alert_type":
                        "Possible Account Compromise",

                    "source_ip":
                        "203.0.113.50",

                    "username":
                        "admin",

                    "failed_attempts":
                        5,

                    "successful_login":
                        True,

                    "first_failed_timestamp":
                        "2026-08-14T10:05:33Z",

                    "last_failed_timestamp":
                        "2026-08-14T10:05:53Z",

                    "successful_login_timestamp":
                        "2026-08-14T10:06:02Z",

                    "severity":
                        "CRITICAL",
                },

                {
                    "alert_type":
                        "Possible SSH Brute Force",

                    "source_ip":
                        "203.0.113.50",

                    "username":
                        "admin",

                    "failed_attempts":
                        5,

                    "severity":
                        "HIGH",
                },
            ],

            "authentication_times": {

                "first_failed":
                    "2026-08-14T10:05:33+00:00",

                "last_failed":
                    "2026-08-14T10:05:53+00:00",

                "successful_login":
                    "2026-08-14T10:06:02+00:00",
            },

            "related_events": [

                {
                    "event_id":
                        "EVT-SSH-001",

                    "timestamp":
                        "2026-08-14T10:05:33Z",

                    "source":
                        "Linux SSH",

                    "event_type":
                        "ssh_failed",

                    "source_ip":
                        "203.0.113.50",

                    "username":
                        "admin",

                    "username_match":
                        "EXACT",

                    "phase":
                        "BRUTE_FORCE",

                    "anchor_type":
                        "FIRST_FAILED",

                    "time_difference_seconds":
                        0,

                    "evidence_score":
                        85,

                    "correlation_reason":
                        "SSH authentication failure is the primary authentication evidence.",

                    "original_log_reference":
                        "auth.log:line-101",
                },

                {
                    "event_id":
                        "EVT-FW-001",

                    "timestamp":
                        "2026-08-14T10:10:05Z",

                    "source":
                        "Firewall",

                    "event_type":
                        "FirewallNetworkEvent",

                    "source_ip":
                        "203.0.113.50",

                    "username_match":
                        "MISSING",

                    "phase":
                        "POST_SUCCESS",

                    "anchor_type":
                        "SUCCESSFUL_LOGIN",

                    "time_difference_seconds":
                        243.0,

                    "evidence_score":
                        70,

                    "correlation_reason":
                        "Firewall telemetry occurred after successful authentication.",

                    "original_log_reference":
                        "firewall.log:line-450",
                },

                {
                    "event_id":
                        "EVT-CT-001",

                    "timestamp":
                        "2026-08-14T10:18:00Z",

                    "source":
                        "CloudTrail",

                    "event_type":
                        "DescribeInstances",

                    "source_ip":
                        "203.0.113.50",

                    "username_match":
                        "MISSING",

                    "phase":
                        "POST_SUCCESS",

                    "anchor_type":
                        "SUCCESSFUL_LOGIN",

                    "time_difference_seconds":
                        718.0,

                    "evidence_score":
                        75,

                    "correlation_reason":
                        "CloudTrail telemetry occurred after successful authentication.",

                    "original_log_reference":
                        "cloudtrail.json:event-3001",
                },

                {
                    "event_id":
                        "EVT-CT-002",

                    "timestamp":
                        "2026-08-14T10:25:01Z",

                    "source":
                        "CloudTrail",

                    "event_type":
                        "AuthorizeSecurityGroupIngress",

                    "source_ip":
                        "203.0.113.50",

                    "username":
                        "admin",

                    "username_match":
                        "EXACT",

                    "phase":
                        "POST_SUCCESS",

                    "anchor_type":
                        "SUCCESSFUL_LOGIN",

                    "time_difference_seconds":
                        1139.0,

                    "evidence_score":
                        90,

                    "correlation_reason":
                        "CloudTrail telemetry occurred after successful authentication and exactly matched the username.",

                    "original_log_reference":
                        "cloudtrail.json:event-3010",
                },
            ],

            "excluded_events": [

                {
                    "event_id":
                        "EVT-FW-999",

                    "timestamp":
                        "2026-08-14T15:00:00Z",

                    "source":
                        "Firewall",

                    "event_type":
                        "FirewallNetworkEvent",

                    "source_ip":
                        "198.51.100.20",

                    "username_match":
                        "MISMATCH",

                    "evidence_score":
                        10,

                    "exclusion_reason":
                        "SOURCE_IP_MISMATCH",

                    "original_log_reference":
                        "firewall.log:line-999",
                }
            ],

            "strongest_evidence_score":
                90,
        }
    ]

    # --------------------------------------------------------
    # Generate incidents
    # --------------------------------------------------------

    incidents = generate_incidents(
        test_correlations
    )

    summary = build_incident_summary(
        incidents
    )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    print("\nINCIDENT SUMMARY")
    print("-" * 75)

    for key, value in summary.items():

        print(
            f"{key}: {value}"
        )

    # --------------------------------------------------------
    # Incident details
    # --------------------------------------------------------

    for index, incident in enumerate(
        incidents,
        start=1
    ):

        print("\n" + "=" * 75)

        print(
            f"INCIDENT #{index}"
        )

        print("-" * 75)

        print(
            f"Incident ID       : "
            f"{incident['incident_id']}"
        )

        print(
            f"Incident Type     : "
            f"{incident['incident_type']}"
        )

        print(
            f"Severity          : "
            f"{incident['severity']}"
        )

        print(
            f"Confidence        : "
            f"{incident['confidence']}"
        )

        print(
            f"Risk Score        : "
            f"{incident['risk_score']}"
        )

        print(
            f"Status            : "
            f"{incident['status']}"
        )

        print(
            f"Chrono Verified   : "
            f"{incident['chronological_success_verified']}"
        )

        print(
            f"Failed Attempts   : "
            f"{incident['failed_attempts']}"
        )

        print(
            f"Alert Types       : "
            f"{incident['alert_types']}"
        )

        print(
            f"Telemetry Sources : "
            f"{incident['telemetry_sources']}"
        )

        print(
            f"Domain Families   : "
            f"{incident['domain_families']}"
        )

        print(
            f"Related Events    : "
            f"{incident['related_event_count']}"
        )

        # ----------------------------------------------------
        # Attack phases
        # ----------------------------------------------------

        print("\nATTACK PHASES:")

        for phase in incident[
            "attack_phases"
        ]:

            print(
                f"  {phase['phase']} | "
                f"sources={phase['sources']} | "
                f"first={phase['first_observed']} | "
                f"last={phase['last_observed']} | "
                f"evidence={phase['evidence_count']}"
            )

        # ----------------------------------------------------
        # Evidence
        # ----------------------------------------------------

        print("\nPRIMARY EVIDENCE:")

        for evidence in incident[
            "primary_evidence"
        ]:

            print(
                f"  {evidence['evidence_id']} | "
                f"event={evidence['event_id']} | "
                f"source={evidence['source']} | "
                f"score={evidence['evidence_score']} | "
                f"log={evidence['original_log_reference']}"
            )

        print("\nSUPPORTING EVIDENCE:")

        for evidence in incident[
            "supporting_evidence"
        ]:

            print(
                f"  {evidence['evidence_id']} | "
                f"event={evidence['event_id']} | "
                f"source={evidence['source']} | "
                f"score={evidence['evidence_score']} | "
                f"log={evidence['original_log_reference']}"
            )

        print("\nEXCLUDED EVIDENCE:")

        for evidence in incident[
            "excluded_evidence"
        ]:

            print(
                f"  {evidence['evidence_id']} | "
                f"event={evidence['event_id']} | "
                f"reason={evidence['exclusion_reason']} | "
                f"log={evidence['original_log_reference']}"
            )

        # ----------------------------------------------------
        # Evidence summary
        # ----------------------------------------------------

        print("\nEVIDENCE SUMMARY:")

        for key, value in incident[
            "evidence_summary"
        ].items():

            print(
                f"  {key}: {value}"
            )

        # ----------------------------------------------------
        # Attack story
        # ----------------------------------------------------

        print("\nATTACK STORY:")

        print(
            incident["attack_story"]
        )

        # ----------------------------------------------------
        # Timeline
        # ----------------------------------------------------

        print("\nTIMELINE:")

        for item in incident[
            "timeline"
        ]:

            print(
                f"  {item['timestamp']} | "
                f"{item['source']} | "
                f"{item['event']} | "
                f"phase={item['phase']} | "
                f"source_ip="
                f"{item.get('source_ip', 'none')} | "
                f"event_id="
                f"{item.get('event_id', 'none')}"
            )

        # ----------------------------------------------------
        # Auditability
        # ----------------------------------------------------

        print("\nAUDITABILITY:")

        auditability = incident[
            "auditability"
        ]

        print(
            f"  Status: "
            f"{auditability['auditability_status']}"
        )

        print(
            f"  Correlation ID: "
            f"{auditability['correlation_id']}"
        )

        print(
            f"  Original log references available: "
            f"{auditability['original_log_references_available']}"
        )

        print(
            f"  Trace chain: "
            f"{' -> '.join(auditability['trace_chain'])}"
        )

    print("\n" + "=" * 75)

    print(
        "INCIDENT ENGINE TEST COMPLETE"
    )

    print("=" * 75)