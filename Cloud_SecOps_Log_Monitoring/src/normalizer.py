from datetime import datetime, timezone
import json

# ============================================================
# KIROTRACE - NORMALIZER + DAY 4 SECOPS INTELLIGENCE
# ============================================================
#
# Pipeline:
#
#   Parser Events
#       |
#       v
#   Validation
#       |
#       v
#   Timestamp Normalization
#       |
#       v
#   Value Normalization
#       |
#       v
#   Unified Event Schema
#       |
#       v
#   Deduplication
#       |
#       v
#   Chronological Sorting
#       |
#       v
#   Day 4 Correlation
#       |
#       v
#   Attack Story
#       |
#       v
#   Evidence Chain
#       |
#       v
#   Risk Scoring
#       |
#       v
#   Incident Severity
#       |
#       v
#   Unified Incident JSON
#
# ============================================================


# ============================================================
# CONFIGURATION
# ============================================================

DEFAULT_LOG_YEAR = 2026
DEFAULT_LOG_MONTH = 8
DEFAULT_LOG_DAY = 14
DEFAULT_INCIDENT_CORRELATION_WINDOW_MINUTES = 10


# ============================================================
# RISK CONFIGURATION
# ============================================================

RISK_BRUTE_FORCE = 40
RISK_ACCOUNT_COMPROMISE = 70
RISK_FIREWALL_DENY = 10
RISK_FIREWALL_ALLOW = 5
RISK_CLOUD_SUCCESS = 10
RISK_CLOUD_SECURITY_CHANGE = 25
RISK_SUCCESSFUL_LOGIN = 20
RISK_CROSS_SOURCE = 20
RISK_MULTIPLE_CLOUD_EVENTS = 10
RISK_EVIDENCE_COUNT_BONUS = 5


# ============================================================
# INCIDENT SEVERITY
# ============================================================

SEVERITY_CRITICAL_THRESHOLD = 80
SEVERITY_HIGH_THRESHOLD = 50
SEVERITY_MEDIUM_THRESHOLD = 25


# ============================================================
# CLOUD SECURITY EVENTS
# ============================================================

CLOUD_SECURITY_KEYWORDS = (
    "authorizesecuritygroup",
    "revokesecuritygroup",
    "putbucketpolicy",
    "deletebucketpolicy",
    "putrolepolicy",
    "attachrolepolicy",
    "detachrolepolicy",
    "createrole",
    "deleterole",
    "updateassumerolepolicy",
    "createaccesskey",
)


# ============================================================
# GENERIC HELPERS
# ============================================================

def clean_value(value):
    """
    Clean simple values. Empty strings become None.
    Non-string values are preserved.
    """
    if value is None:
        return None

    if isinstance(value, str):
        value = value.strip()
        if not value:
            return None

    return value


def normalize_status(status):
    """
    Normalize status values.
    """
    status = clean_value(status)
    if status is None:
        return None

    if isinstance(status, str):
        return status.lower()

    return status


def normalize_action(action):
    """
    Normalize action to lowercase.
    """
    action = clean_value(action)
    if action is None:
        return None

    if isinstance(action, str):
        return action.lower()

    return action


def normalize_protocol(protocol):
    """
    Normalize protocol to uppercase.
    """
    protocol = clean_value(protocol)
    if protocol is None:
        return None

    if isinstance(protocol, str):
        return protocol.upper()

    return protocol


def normalize_username(username):
    """
    Normalize username for correlation.
    """
    username = clean_value(username)
    if username is None:
        return None

    if isinstance(username, str):
        return username.lower()

    return username


def normalize_ip(source_ip):
    """
    Normalize IP representation.
    IP validation remains parser responsibility.
    """
    source_ip = clean_value(source_ip)
    if source_ip is None:
        return None

    return str(source_ip)


def normalize_event_source(source):
    """
    Normalize event source while preserving useful source information.
    """
    source = clean_value(source)
    if source is None:
        return None

    if isinstance(source, str):
        return source.strip()

    return source


def normalize_event_type(event_type):
    """
    Normalize event type while preserving readable representation.
    """
    event_type = clean_value(event_type)
    if event_type is None:
        return None

    if isinstance(event_type, str):
        return event_type.strip()

    return event_type


# ============================================================
# TIMESTAMP NORMALIZATION
# ============================================================

def normalize_timestamp(timestamp):
    """
    Convert supported timestamps into UTC ISO 8601.

    Supported:
        2026-08-14T10:15:22Z
        2026-08-14T10:15:22+00:00
        2026-08-14T10:15:22
        2026-08-14T10:15:22.123Z
        2026-08-14 10:15:22
        2026-08-14 10:15:22.123
        Aug 14 10:05:33
        Aug 14 10:05:33.123
        10:10:05
        10:10:05.123

    Important:
    Syslog and time-only timestamps are assigned the
    configured DEFAULT_LOG_YEAR / MONTH / DAY.
    All naive timestamps are treated as UTC because this
    offline MVP does not have source timezone metadata.
    """
    timestamp = clean_value(timestamp)

    if timestamp is None:
        return None

    if not isinstance(timestamp, str):
        return None

    timestamp = timestamp.strip()

    # --------------------------------------------------------
    # ISO 8601
    # --------------------------------------------------------
    try:
        iso_timestamp = timestamp

        if iso_timestamp.endswith("Z"):
            iso_timestamp = (
                iso_timestamp[:-1] + "+00:00"
            )

        parsed_time = datetime.fromisoformat(
            iso_timestamp
        )

        if parsed_time.tzinfo is None:
            parsed_time = parsed_time.replace(
                tzinfo=timezone.utc
            )
        else:
            parsed_time = parsed_time.astimezone(
                timezone.utc
            )

        return parsed_time.isoformat()

    except (TypeError, ValueError):
        pass

    # --------------------------------------------------------
    # Standard datetime with microseconds
    # --------------------------------------------------------
    standard_datetime_formats = (
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
    )

    for date_format in standard_datetime_formats:
        try:
            parsed_time = datetime.strptime(
                timestamp, date_format
            )
            parsed_time = parsed_time.replace(
                tzinfo=timezone.utc
            )
            return parsed_time.isoformat()
        except (TypeError, ValueError):
            continue

    # --------------------------------------------------------
    # Linux syslog timestamp
    #
    # Explicitly prepend the configured year.
    #
    # This avoids Python's deprecated behavior of parsing
    # month/day without an explicit year.
    # --------------------------------------------------------
    syslog_formats = (
        "%Y %b %d %H:%M:%S.%f",
        "%Y %b %d %H:%M:%S",
    )

    for date_format in syslog_formats:
        try:
            parsed_time = datetime.strptime(
                f"{DEFAULT_LOG_YEAR} {timestamp}",
                date_format
            )
            parsed_time = parsed_time.replace(
                tzinfo=timezone.utc
            )
            return parsed_time.isoformat()
        except (TypeError, ValueError):
            continue

    # --------------------------------------------------------
    # Time-only firewall timestamp
    #
    # Explicitly construct the full date.
    # --------------------------------------------------------
    time_formats = (
        "%H:%M:%S.%f",
        "%H:%M:%S",
    )

    for time_format in time_formats:
        try:
            parsed_time = datetime.strptime(
                timestamp, time_format
            )
            parsed_time = parsed_time.replace(
                year=DEFAULT_LOG_YEAR,
                month=DEFAULT_LOG_MONTH,
                day=DEFAULT_LOG_DAY,
                tzinfo=timezone.utc
            )
            return parsed_time.isoformat()
        except (TypeError, ValueError):
            continue

    return None


def parse_normalized_timestamp(timestamp):
    """
    Convert normalized timestamp into timezone-aware datetime.
    """
    if timestamp is None:
        return None

    try:
        parsed = datetime.fromisoformat(
            timestamp
        )

        if parsed.tzinfo is None:
            parsed = parsed.replace(
                tzinfo=timezone.utc
            )

        return parsed.astimezone(
            timezone.utc
        )

    except (TypeError, ValueError):
        return None


def is_valid_timestamp(timestamp):
    """
    Check timestamp validity.
    """
    return (
        normalize_timestamp(timestamp) is not None
    )


# ============================================================
# EVENT VALIDATION
# ============================================================

def validate_event(event):
    """
    Validate minimum parser event requirements.

    Required:
        timestamp
        event_source
        event_name
    """
    if not isinstance(event, dict):
        return False

    required_fields = (
        "timestamp",
        "event_source",
        "event_name",
    )

    for field in required_fields:
        if not clean_value(
            event.get(field)
        ):
            return False

    if not is_valid_timestamp(
        event.get("timestamp")
    ):
        return False

    return True


# ============================================================
# SINGLE EVENT NORMALIZATION
# ============================================================

def normalize_event(event):
    """
    Convert parser event into unified KiroTrace schema.
    """
    if not validate_event(event):
        return None

    normalized_timestamp = normalize_timestamp(
        event.get("timestamp")
    )

    normalized_event = {
        # ----------------------------------------------------
        # Temporal
        # ----------------------------------------------------
        "timestamp": normalized_timestamp,

        # ----------------------------------------------------
        # Source
        # ----------------------------------------------------
        "source": normalize_event_source(
            event.get("event_source")
        ),
        "event_type": normalize_event_type(
            event.get("event_name")
        ),

        # ----------------------------------------------------
        # Identity
        # ----------------------------------------------------
        "username": normalize_username(
            event.get("username")
        ),
        "source_ip": normalize_ip(
            event.get("source_ip")
        ),

        # ----------------------------------------------------
        # Network
        # ----------------------------------------------------
        "destination_ip": normalize_ip(
            event.get("destination_ip")
        ),
        "destination_port": clean_value(
            event.get("destination_port")
        ),
        "protocol": normalize_protocol(
            event.get("protocol")
        ),

        # ----------------------------------------------------
        # Activity
        # ----------------------------------------------------
        "action": normalize_action(
            event.get("action")
        ),
        "status": normalize_status(
            event.get("status")
        ),
    }

    # ========================================================
    # OPTIONAL / SOURCE-SPECIFIC FIELDS
    # ========================================================
    optional_fields = (
        # CloudTrail
        "event_id",
        "aws_region",
        "user_type",
        "user_arn",
        "error_code",
        "error_message",
        "read_only",
        "event_category",
        "management_event",

        # Linux SSH
        "authentication_method",
        "invalid_user",
        "log_year",

        # Forensics
        "line_number",
        "raw_log",
    )

    for field in optional_fields:
        value = clean_value(
            event.get(field)
        )
        if value is not None:
            normalized_event[field] = value

    return normalized_event


# ============================================================
# EVENT FINGERPRINT
# ============================================================

def event_key(event):
    """
    Generate stable event fingerprint.

    CloudTrail: source + event_id
    Other events: timestamp + source + event details
    """
    if not isinstance(event, dict):
        return None

    event_id = clean_value(
        event.get("event_id")
    )

    if event_id:
        return (
            "cloudtrail",
            event.get("source"),
            str(event_id),
        )

    return (
        "event",
        event.get("timestamp"),
        event.get("source"),
        event.get("event_type"),
        event.get("username"),
        event.get("source_ip"),
        event.get("destination_ip"),
        event.get("destination_port"),
        event.get("protocol"),
        event.get("action"),
        event.get("status"),
    )


# ============================================================
# DEDUPLICATION
# ============================================================

def deduplicate_events(events):
    """
    Remove duplicate normalized events.
    """
    if not isinstance(events, list):
        return []

    unique_events = []
    seen = set()

    for event in events:
        if not isinstance(event, dict):
            continue

        key = event_key(event)

        if key is None:
            continue

        if key in seen:
            continue

        seen.add(key)
        unique_events.append(event)

    return unique_events


# ============================================================
# CHRONOLOGICAL SORTING
# ============================================================

def sort_events(events):
    """
    Sort events oldest -> newest.
    """
    if not isinstance(events, list):
        return []

    maximum_time = datetime.max.replace(
        tzinfo=timezone.utc
    )

    def sort_key(event):
        parsed_time = parse_normalized_timestamp(
            event.get("timestamp")
        )
        if parsed_time is None:
            return maximum_time
        return parsed_time

    return sorted(
        events,
        key=sort_key
    )


# ============================================================
# NORMALIZE MULTIPLE EVENTS
# ============================================================

def normalize_events(events):
    """
    Complete normalization pipeline.
    """
    if not isinstance(events, list):
        return []

    normalized_events = []

    for event in events:
        normalized_event = normalize_event(
            event
        )

        if normalized_event is None:
            continue

        normalized_events.append(
            normalized_event
        )

    normalized_events = deduplicate_events(
        normalized_events
    )

    normalized_events = sort_events(
        normalized_events
    )

    return normalized_events


# ============================================================
# EVENT STATISTICS
# ============================================================

def get_event_statistics(events):
    """
    Generate event statistics.
    """
    if not isinstance(events, list):
        return {
            "total_events": 0,
            "sources": {},
            "event_types": {},
            "statuses": {},
            "actions": {},
        }

    sources = {}
    event_types = {}
    statuses = {}
    actions = {}

    for event in events:
        if not isinstance(event, dict):
            continue

        source = event.get("source")
        if source:
            sources[source] = (
                sources.get(source, 0) + 1
            )

        event_type = event.get(
            "event_type"
        )
        if event_type:
            event_types[event_type] = (
                event_types.get(
                    event_type, 0
                ) + 1
            )

        status = event.get("status")
        if status:
            statuses[status] = (
                statuses.get(status, 0) + 1
            )

        action = event.get("action")
        if action:
            actions[action] = (
                actions.get(action, 0) + 1
            )

    return {
        "total_events": len(events),
        "sources": sources,
        "event_types": event_types,
        "statuses": statuses,
        "actions": actions,
    }


# ============================================================
# NORMALIZATION REPORT
# ============================================================

def build_normalization_report(
    input_events,
    normalized_events
):
    """
    Generate normalization statistics.
    """
    input_count = (
        len(input_events)
        if isinstance(input_events, list)
        else 0
    )
    output_count = (
        len(normalized_events)
        if isinstance(normalized_events, list)
        else 0
    )

    return {
        "input_events": input_count,
        "normalized_events": output_count,
        "discarded_events": max(
            input_count - output_count, 0
        ),
        "statistics": get_event_statistics(
            normalized_events
        ),
    }


# ============================================================
# DAY 4 - SOURCE CLASSIFICATION
# ============================================================

def is_ssh_event(event):
    if not isinstance(event, dict):
        return False
    source = str(
        event.get("source", "")
    ).lower()
    event_type = str(
        event.get("event_type", "")
    ).lower()
    return (
        "ssh" in source or
        "ssh" in event_type
    )

def is_firewall_event(event):
    if not isinstance(event, dict):
        return False
    source = str(
        event.get("source", "")
    ).lower()
    event_type = str(
        event.get("event_type", "")
    ).lower()
    return (
        "firewall" in source or
        "firewall" in event_type
    )

def is_cloudtrail_event(event):
    if not isinstance(event, dict):
        return False
    source = str(
        event.get("source", "")
    ).lower()
    event_type = str(
        event.get("event_type", "")
    ).lower()
    return (
        "cloudtrail" in source or
        source.endswith(".amazonaws.com") or
        "cloudtrail" in event_type
    )

def get_event_source_category(event):
    if is_ssh_event(event):
        return "SSH"
    if is_firewall_event(event):
        return "FIREWALL"
    if is_cloudtrail_event(event):
        return "CLOUDTRAIL"
    return "OTHER"


# ============================================================
# DAY 4 - CORRELATION IDENTITY
# ============================================================

def get_correlation_identity(event):
    """
    Determine strongest available correlation identity.
    Priority:
    1. Source IP
    2. Username
    """
    if not isinstance(event, dict):
        return None

    source_ip = normalize_ip(
        event.get("source_ip")
    )
    username = normalize_username(
        event.get("username")
    )

    if source_ip is not None:
        return (
            "IP",
            source_ip,
        )

    if username is not None:
        return (
            "USER",
            username,
        )

    return None


# ============================================================
# DAY 4 - TIME WINDOW
# ============================================================

def events_within_window(
    first_event,
    second_event,
    window_seconds
):
    if not isinstance(first_event, dict):
        return False
    if not isinstance(second_event, dict):
        return False

    first_time = parse_normalized_timestamp(
        first_event.get("timestamp")
    )
    second_time = parse_normalized_timestamp(
        second_event.get("timestamp")
    )

    if first_time is None or second_time is None:
        return False

    difference = abs(
        (
            second_time - first_time
        ).total_seconds()
    )

    return difference <= window_seconds


# ============================================================
# DAY 4 - CORRELATION MATCH
# ============================================================

def events_share_identity(
    anchor_event,
    candidate_event
):
    if not isinstance(anchor_event, dict):
        return False
    if not isinstance(candidate_event, dict):
        return False

    anchor_ip = normalize_ip(
        anchor_event.get("source_ip")
    )
    candidate_ip = normalize_ip(
        candidate_event.get("source_ip")
    )
    anchor_username = normalize_username(
        anchor_event.get("username")
    )
    candidate_username = normalize_username(
        candidate_event.get("username")
    )

    # Both IPs available -> IP authoritative.
    if (
        anchor_ip is not None and
        candidate_ip is not None
    ):
        return anchor_ip == candidate_ip

    # If IP is unavailable on either side,
    # username fallback is allowed.
    if (
        anchor_username is not None and
        candidate_username is not None
    ):
        return (
            anchor_username == candidate_username
        )

    return False


# ============================================================
# DAY 4 - SOURCE RELATIONSHIP
# ============================================================

def is_cross_source_pair(
    anchor_event,
    candidate_event
):
    anchor_source = get_event_source_category(
        anchor_event
    )
    candidate_source = get_event_source_category(
        candidate_event
    )
    return anchor_source != candidate_source


# ============================================================
# DAY 4 - CROSS SOURCE CORRELATION
# ============================================================

def find_related_events(
    anchor_event,
    events,
    correlation_window_minutes=(
        DEFAULT_INCIDENT_CORRELATION_WINDOW_MINUTES
    )
):
    if not isinstance(anchor_event, dict):
        return []
    if not isinstance(events, list):
        return []

    try:
        correlation_window_seconds = (
            float(
                correlation_window_minutes
            ) * 60
        )
    except (TypeError, ValueError):
        return []

    if correlation_window_seconds <= 0:
        return []

    related_events = []

    for event in events:
        if not isinstance(event, dict):
            continue

        if event is anchor_event:
            continue

        if not events_within_window(
            anchor_event,
            event,
            correlation_window_seconds
        ):
            continue

        if not events_share_identity(
            anchor_event,
            event
        ):
            continue

        related_events.append(event)

    return sort_events(
        related_events
    )


# ============================================================
# DAY 4 - SUSPICIOUS EVENT DETECTION
# ============================================================

def is_suspicious_event(event):
    if not isinstance(event, dict):
        return False

    event_type = str(
        event.get(
            "event_type", ""
        )
    ).lower()

    status = normalize_status(
        event.get("status")
    )

    action = normalize_action(
        event.get("action")
    )

    # SSH failed authentication
    if is_ssh_event(event):
        if status == "failed":
            return True

    # SSH successful login
    if is_ssh_event(event):
        if status == "success":
            return True

    # Firewall deny
    if is_firewall_event(event):
        if (
            status == "deny" or
            action == "deny"
        ):
            return True

    # Cloud security-sensitive operations
    for keyword in CLOUD_SECURITY_KEYWORDS:
        if keyword in event_type:
            return True

    return False


# ============================================================
# DAY 4 - EVIDENCE DESCRIPTION
# ============================================================

def describe_evidence(event):
    source = get_event_source_category(
        event
    )
    event_type = event.get(
        "event_type"
    )
    source_ip = event.get(
        "source_ip"
    )
    username = event.get(
        "username"
    )
    status = event.get(
        "status"
    )
    action = event.get(
        "action"
    )

    if source == "SSH":
        return (
            f"SSH event: {event_type}; "
            f"source_ip={source_ip}; "
            f"username={username}; "
            f"status={status}"
        )

    if source == "FIREWALL":
        return (
            f"Firewall event: {event_type}; "
            f"source_ip={source_ip}; "
            f"destination_ip="
            f"{event.get('destination_ip')}; "
            f"destination_port="
            f"{event.get('destination_port')}; "
            f"action={action}; "
            f"status={status}"
        )

    if source == "CLOUDTRAIL":
        return (
            f"CloudTrail event: {event_type}; "
            f"username={username}; "
            f"source_ip={source_ip}; "
            f"status={status}"
        )

    return (
        f"Event: {event_type}; "
        f"source_ip={source_ip}; "
        f"username={username}"
    )


# ============================================================
# DAY 4 - EVENT RISK
# ============================================================

def calculate_event_risk(event):
    if not isinstance(event, dict):
        return 0

    source = get_event_source_category(
        event
    )
    status = normalize_status(
        event.get("status")
    )
    action = normalize_action(
        event.get("action")
    )
    event_type = str(
        event.get(
            "event_type", ""
        )
    ).lower()

    score = 0

    # --------------------------------------------------------
    # SSH
    # --------------------------------------------------------
    if source == "SSH":
        if status == "failed":
            score += 8
        elif status == "success":
            score += RISK_SUCCESSFUL_LOGIN

    # --------------------------------------------------------
    # Firewall
    # --------------------------------------------------------
    elif source == "FIREWALL":
        if (
            status == "deny" or
            action == "deny"
        ):
            score += RISK_FIREWALL_DENY
        elif (
            status == "allow" or
            action == "allow"
        ):
            score += RISK_FIREWALL_ALLOW

    # --------------------------------------------------------
    # CloudTrail
    # --------------------------------------------------------
    elif source == "CLOUDTRAIL":
        if status == "success":
            score += RISK_CLOUD_SUCCESS
        for keyword in CLOUD_SECURITY_KEYWORDS:
            if keyword in event_type:
                score += RISK_CLOUD_SECURITY_CHANGE
                break

    return score


# ============================================================
# DAY 4 - DETECTOR ALERT RISK
# ============================================================

def calculate_alert_risk(alert):
    if not isinstance(alert, dict):
        return 0

    alert_type = str(
        alert.get(
            "alert_type", ""
        )
    ).lower()

    score = 0

    if "brute force" in alert_type:
        score += RISK_BRUTE_FORCE

    if "account compromise" in alert_type:
        score += RISK_ACCOUNT_COMPROMISE

    return score


# ============================================================
# DAY 4 - INCIDENT SEVERITY
# ============================================================

def calculate_incident_severity(
    risk_score
):
    try:
        risk_score = int(
            risk_score
        )
    except (TypeError, ValueError):
        return "LOW"

    if risk_score >= SEVERITY_CRITICAL_THRESHOLD:
        return "CRITICAL"
    if risk_score >= SEVERITY_HIGH_THRESHOLD:
        return "HIGH"
    if risk_score >= SEVERITY_MEDIUM_THRESHOLD:
        return "MEDIUM"

    return "LOW"


# ============================================================
# DAY 4 - INCIDENT TYPE
# ============================================================

def determine_incident_type(
    evidence_events,
    detection_alerts
):
    if not isinstance(evidence_events, list):
        evidence_events = []
    if not isinstance(detection_alerts, list):
        detection_alerts = []

    alert_types = []
    for alert in detection_alerts:
        if not isinstance(alert, dict):
            continue
        alert_type = str(
            alert.get(
                "alert_type", ""
            )
        ).lower()
        alert_types.append(
            alert_type
        )

    if any(
        "account compromise" in alert_type
        for alert_type in alert_types
    ):
        return "Possible Account Compromise"

    if any(
        "brute force" in alert_type
        for alert_type in alert_types
    ):
        return "SSH Brute Force Activity"

    has_ssh = any(
        is_ssh_event(event)
        for event in evidence_events
    )
    has_firewall = any(
        is_firewall_event(event)
        for event in evidence_events
    )
    has_cloudtrail = any(
        is_cloudtrail_event(event)
        for event in evidence_events
    )

    if (
        has_ssh and
        has_firewall and
        has_cloudtrail
    ):
        return "Cross-Source Suspicious Activity"

    if has_ssh and has_firewall:
        return "SSH + Firewall Suspicious Activity"

    if has_ssh and has_cloudtrail:
        return "SSH + Cloud Suspicious Activity"

    if has_firewall and has_cloudtrail:
        return "Network + Cloud Suspicious Activity"

    if has_cloudtrail:
        return "Suspicious Cloud Activity"

    if has_firewall:
        return "Suspicious Network Activity"

    if has_ssh:
        return "Suspicious SSH Activity"

    return "Suspicious Activity"


# ============================================================
# DAY 4 - ATTACK STORY
# ============================================================

def build_attack_story(
    evidence_events,
    detection_alerts
):
    if not evidence_events:
        return (
            "No sufficient evidence available "
            "to construct an attack story."
        )

    sources = []
    for event in evidence_events:
        source = get_event_source_category(
            event
        )
        if source not in sources:
            sources.append(source)

    sources_text = ", ".join(
        sources
    )
    first_event = evidence_events[0]
    last_event = evidence_events[-1]
    first_time = first_event.get(
        "timestamp"
    )
    last_time = last_event.get(
        "timestamp"
    )

    story = (
        f"Suspicious activity was observed "
        f"across {sources_text}. "
        f"The correlated evidence begins at "
        f"{first_time} and continues through "
        f"{last_time}."
    )

    if (
        "SSH" in sources and
        "FIREWALL" in sources
    ):
        story += (
            " SSH authentication activity was "
            "correlated with firewall activity "
            "from the same source identity."
        )

    if (
        "SSH" in sources and
        "CLOUDTRAIL" in sources
    ):
        story += (
            " SSH activity was correlated with "
            "cloud control-plane activity."
        )

    if (
        "FIREWALL" in sources and
        "CLOUDTRAIL" in sources
    ):
        story += (
            " Firewall activity was correlated "
            "with cloud control-plane activity."
        )

    if len(sources) >= 3:
        story += (
            " The presence of SSH, firewall, "
            "and CloudTrail evidence forms a "
            "cross-source attack story requiring "
            "investigation."
        )

    successful_ssh = any(
        is_ssh_event(event) and
        normalize_status(
            event.get("status")
        ) == "success"
        for event in evidence_events
    )

    failed_ssh_count = sum(
        1 for event in evidence_events
        if (
            is_ssh_event(event) and
            normalize_status(
                event.get("status")
            ) == "failed"
        )
    )

    if (
        failed_ssh_count > 0 and
        successful_ssh
    ):
        story += (
            f" {failed_ssh_count} failed SSH "
            "authentication attempt(s) were "
            "followed by a successful login, "
            "which may indicate account compromise."
        )

    if detection_alerts:
        alert_names = []
        for alert in detection_alerts:
            if not isinstance(alert, dict):
                continue
            alert_type = clean_value(
                alert.get(
                    "alert_type"
                )
            )
            if (
                alert_type and
                alert_type not in alert_names
            ):
                alert_names.append(
                    alert_type
                )
        if alert_names:
            story += (
                " Day 3 detection logic also "
                "reported: " + ", ".join(alert_names) + "."
            )

    return story


# ============================================================
# DAY 4 - EVIDENCE CHAIN
# ============================================================

def build_evidence_chain(
    evidence_events
):
    evidence_chain = []
    for index, event in enumerate(
        sort_events(evidence_events),
        start=1
    ):
        evidence_chain.append({
            "sequence": index,
            "timestamp": event.get(
                "timestamp"
            ),
            "source": get_event_source_category(
                event
            ),
            "event_type": event.get(
                "event_type"
            ),
            "source_ip": event.get(
                "source_ip"
            ),
            "username": event.get(
                "username"
            ),
            "status": event.get(
                "status"
            ),
            "action": event.get(
                "action"
            ),
            "description": describe_evidence(
                event
            ),
            "event": event,
        })
    return evidence_chain


# ============================================================
# DAY 4 - INCIDENT ID
# ============================================================

def generate_incident_id(
    evidence_events
):
    if not evidence_events:
        return "INC-EMPTY"

    raw_parts = []
    for event in sort_events(
        evidence_events
    ):
        raw_parts.append(
            "|".join(
                [
                    str(
                        event.get(
                            "timestamp", ""
                        )
                    ),
                    str(
                        event.get(
                            "source", ""
                        )
                    ),
                    str(
                        event.get(
                            "event_type", ""
                        )
                    ),
                    str(
                        event.get(
                            "source_ip", ""
                        )
                    ),
                    str(
                        event.get(
                            "username", ""
                        )
                    ),
                    str(
                        event.get(
                            "status", ""
                        )
                    ),
                ]
            )
        )

    raw = "||".join(
        raw_parts
    )

    digest = 0
    for character in raw:
        digest = (
            (
                digest * 31
            ) + ord(character)
        ) & 0xFFFFFFFF

    return f"INC-{digest:08X}"


# ============================================================
# DAY 4 - CONFIDENCE
# ============================================================

def calculate_incident_confidence(
    evidence_events,
    detection_alerts
):
    evidence_count = len(
        evidence_events
    )
    source_categories = set(
        get_event_source_category(event)
        for event in evidence_events
    )

    if evidence_count <= 1:
        if detection_alerts:
            return "DETECTED"
        return "SINGLE_EVENT"

    if (
        len(source_categories) >= 2 or
        len(detection_alerts) >= 2
    ):
        return "HIGH"

    return "CORRELATED"


# ============================================================
# DAY 4 - ALERT DEDUPLICATION
# ============================================================

def deduplicate_alerts(
    alerts
):
    if not isinstance(alerts, list):
        return []

    unique_alerts = []
    seen = set()

    for alert in alerts:
        if not isinstance(alert, dict):
            continue

        alert_id = clean_value(
            alert.get("alert_id")
        )

        if alert_id:
            key = (
                "alert_id",
                str(alert_id),
            )
        else:
            key = (
                "alert",
                clean_value(
                    alert.get(
                        "alert_type"
                    )
                ),
                normalize_ip(
                    alert.get(
                        "source_ip"
                    )
                ),
                normalize_username(
                    alert.get(
                        "username"
                    )
                ),
                alert.get(
                    "timestamp"
                ),
            )

        if key in seen:
            continue

        seen.add(key)
        unique_alerts.append(alert)

    return unique_alerts


# ============================================================
# DAY 4 - ALERT MATCHING
# ============================================================

def alert_matches_event(
    alert,
    event,
    correlation_window_minutes
):
    if not isinstance(alert, dict):
        return False
    if not isinstance(event, dict):
        return False

    alert_ip = normalize_ip(
        alert.get("source_ip")
    )
    event_ip = normalize_ip(
        event.get("source_ip")
    )
    alert_username = normalize_username(
        alert.get("username")
    )
    event_username = normalize_username(
        event.get("username")
    )

    identity_match = False
    if (
        alert_ip is not None and
        event_ip is not None
    ):
        identity_match = (
            alert_ip == event_ip
        )
    elif (
        alert_username is not None and
        event_username is not None
    ):
        identity_match = (
            alert_username == event_username
        )

    if not identity_match:
        return False

    alert_timestamp = alert.get(
        "timestamp"
    )
    event_timestamp = event.get(
        "timestamp"
    )

    if not alert_timestamp:
        return True

    alert_time = parse_normalized_timestamp(
        alert_timestamp
    )
    event_time = parse_normalized_timestamp(
        event_timestamp
    )

    if (
        alert_time is None or
        event_time is None
    ):
        return True

    try:
        difference = abs(
            (
                alert_time - event_time
            ).total_seconds()
        )
        window_seconds = (
            float(
                correlation_window_minutes
            ) * 60
        )
        if window_seconds <= 0:
            return False
        return difference <= window_seconds
    except (
        TypeError,
        ValueError,
    ):
        return False


# ============================================================
# DAY 4 - INCIDENT EVIDENCE IDENTITY
# ============================================================

def incident_evidence_key(
    evidence_events
):
    if not isinstance(
        evidence_events, list
    ):
        return ()

    keys = []
    for event in sort_events(
        evidence_events
    ):
        key = event_key(event)
        if key is not None:
            keys.append(key)
    return tuple(keys)


# ============================================================
# DAY 4 - UNIFIED INCIDENT
# ============================================================

def build_unified_incident(
    evidence_events,
    detection_alerts=None
):
    if not isinstance(
        evidence_events, list
    ):
        evidence_events = []
    if not isinstance(
        detection_alerts, list
    ):
        detection_alerts = []

    evidence_events = deduplicate_events(
        evidence_events
    )
    evidence_events = sort_events(
        evidence_events
    )
    detection_alerts = deduplicate_alerts(
        detection_alerts
    )

    # --------------------------------------------------------
    # Raw event risk
    # --------------------------------------------------------
    event_risk = sum(
        calculate_event_risk(event)
        for event in evidence_events
    )

    # --------------------------------------------------------
    # Detector risk
    # --------------------------------------------------------
    alert_risk = sum(
        calculate_alert_risk(alert)
        for alert in detection_alerts
    )

    # --------------------------------------------------------
    # Source diversity
    # --------------------------------------------------------
    source_categories = []
    for event in evidence_events:
        source = get_event_source_category(
            event
        )
        if source not in source_categories:
            source_categories.append(
                source
            )

    cross_source_bonus = 0
    if len(source_categories) >= 2:
        cross_source_bonus = (
            RISK_CROSS_SOURCE
        )

    # --------------------------------------------------------
    # Multiple CloudTrail events
    # --------------------------------------------------------
    cloud_events = [
        event for event in evidence_events
        if is_cloudtrail_event(event)
    ]
    cloud_bonus = 0
    if len(cloud_events) >= 2:
        cloud_bonus = (
            RISK_MULTIPLE_CLOUD_EVENTS
        )

    # --------------------------------------------------------
    # Evidence count bonus
    # --------------------------------------------------------
    evidence_bonus = 0
    if len(evidence_events) >= 3:
        evidence_bonus = (
            RISK_EVIDENCE_COUNT_BONUS
        )

    # --------------------------------------------------------
    # Final risk
    #
    # IMPORTANT:
    #
    # Event and detector risk are raw supporting
    # indicators. They are not allowed to simply
    # stack indefinitely and force the score to 100.
    #
    # The final score uses the strongest risk signal
    # plus contextual bonuses.
    # --------------------------------------------------------
    strongest_signal = max(
        event_risk, alert_risk
    )
    contextual_bonus = (
        cross_source_bonus +
        cloud_bonus +
        evidence_bonus
    )
    risk_score = (
        strongest_signal +
        contextual_bonus
    )
    risk_score = min(
        max(risk_score, 0), 100
    )

    severity = calculate_incident_severity(
        risk_score
    )
    incident_type = determine_incident_type(
        evidence_events,
        detection_alerts
    )
    evidence_chain = build_evidence_chain(
        evidence_events
    )
    confidence = calculate_incident_confidence(
        evidence_events,
        detection_alerts
    )

    return {
        # ====================================================
        # IDENTITY
        # ====================================================
        "incident_id": generate_incident_id(
            evidence_events
        ),
        "incident_type": incident_type,

        # ====================================================
        # CLASSIFICATION
        # ====================================================
        "severity": severity,
        "status": "OPEN",
        "confidence": confidence,

        # ====================================================
        # RISK
        # ====================================================
        "risk": {
            "score": risk_score,
            "event_risk": event_risk,
            "detection_risk": alert_risk,
            "strongest_signal": strongest_signal,
            "cross_source_bonus": cross_source_bonus,
            "cloud_activity_bonus": cloud_bonus,
            "evidence_count_bonus": evidence_bonus,
            "evidence_count": len(
                evidence_events
            ),
            "source_count": len(
                source_categories
            ),
        },

        # ====================================================
        # TIMELINE
        # ====================================================
        "timeline": {
            "start": (
                evidence_events[0].get(
                    "timestamp"
                ) if evidence_events else None
            ),
            "end": (
                evidence_events[-1].get(
                    "timestamp"
                ) if evidence_events else None
            ),
        },

        # ====================================================
        # SOURCES
        # ====================================================
        "sources": source_categories,

        # ====================================================
        # ATTACK STORY
        # ====================================================
        "attack_story": build_attack_story(
            evidence_events,
            detection_alerts
        ),

        # ====================================================
        # EVIDENCE CHAIN
        # ====================================================
        "evidence_chain": evidence_chain,

        # ====================================================
        # RELATED EVENTS
        # ====================================================
        "related_events": evidence_events,

        # ====================================================
        # DAY 3 DETECTIONS
        # ====================================================
        "detection_alerts": detection_alerts,
    }


# ============================================================
# DAY 4 - INCIDENT ENGINE
# ============================================================

def build_incidents(
    events,
    detection_alerts=None,
    correlation_window_minutes=(
        DEFAULT_INCIDENT_CORRELATION_WINDOW_MINUTES
    )
):
    if not isinstance(
        events, list
    ):
        return []
    if not isinstance(
        detection_alerts, list
    ):
        detection_alerts = []

    try:
        correlation_window_minutes = float(
            correlation_window_minutes
        )
    except (
        TypeError, ValueError
    ):
        return []

    if correlation_window_minutes <= 0:
        return []

    normalized_events = sort_events(
        deduplicate_events(events)
    )

    suspicious_events = [
        event for event in normalized_events
        if is_suspicious_event(event)
    ]

    incidents = []

    # ========================================================
    # BUILD INCIDENT CANDIDATES
    # ========================================================
    for anchor_event in suspicious_events:
        related_events = find_related_events(
            anchor_event=anchor_event,
            events=normalized_events,
            correlation_window_minutes=(
                correlation_window_minutes
            )
        )

        evidence_events = [
            anchor_event
        ]
        evidence_events.extend(
            related_events
        )
        evidence_events = deduplicate_events(
            evidence_events
        )
        evidence_events = sort_events(
            evidence_events
        )

        if not evidence_events:
            continue

        # ====================================================
        # MATCH DAY 3 ALERTS
        # ====================================================
        matched_alerts = []
        for alert in detection_alerts:
            if not isinstance(
                alert, dict
            ):
                continue

            alert_matched = any(
                alert_matches_event(
                    alert,
                    evidence_event,
                    correlation_window_minutes
                )
                for evidence_event in evidence_events
            )

            if alert_matched:
                matched_alerts.append(
                    alert
                )

        matched_alerts = deduplicate_alerts(
            matched_alerts
        )

        # ====================================================
        # BUILD INCIDENT
        # ====================================================
        incident = build_unified_incident(
            evidence_events=evidence_events,
            detection_alerts=matched_alerts
        )
        incidents.append(
            incident
        )

    # ========================================================
    # INCIDENT DEDUPLICATION
    # ========================================================
    unique_incidents = []
    seen = set()

    for incident in incidents:
        if not isinstance(
            incident, dict
        ):
            continue

        evidence_events = incident.get(
            "related_events", []
        )
        identity = incident_evidence_key(
            evidence_events
        )

        if not identity:
            continue

        if identity in seen:
            continue

        seen.add(identity)
        unique_incidents.append(
            incident
        )

    # ========================================================
    # SEVERITY SORT
    # ========================================================
    severity_priority = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
    }

    unique_incidents.sort(
        key=lambda incident: (
            severity_priority.get(
                incident.get(
                    "severity"
                ), 0
            ),
            incident.get(
                "risk", {}
            ).get(
                "score", 0
            ),
            len(
                incident.get(
                    "evidence_chain", []
                )
            )
        ),
        reverse=True
    )

    return unique_incidents


# ============================================================
# DAY 4 - JSON EXPORT
# ============================================================

def incidents_to_json(
    incidents, indent=2
):
    if not isinstance(
        incidents, list
    ):
        incidents = []
    return json.dumps(
        incidents,
        indent=indent,
        ensure_ascii=False
    )


# ============================================================
# TIMESTAMP TEST DATA
# ============================================================

TEST_TIMESTAMP_VALUES = [
    "2026-08-14T10:05:33Z",
    "2026-08-14T10:05:33+00:00",
    "2026-08-14T10:05:33.123Z",
    "2026-08-14 10:05:33",
    "Aug 14 10:05:33",
    "10:05:33",
    "10:05:33.123",
]


# ============================================================
# TEST DATA
# ============================================================

TEST_EVENTS = [
    {
        "timestamp": "2026-08-14T10:05:33Z",
        "event_name": "SSHAuthentication",
        "event_source": "Linux SSH",
        "username": "admin",
        "source_ip": "203.0.113.50",
        "action": "LOGIN",
        "status": "FAILED",
    },
    {
        "timestamp": "2026-08-14T10:05:38Z",
        "event_name": "SSHAuthentication",
        "event_source": "Linux SSH",
        "username": "admin",
        "source_ip": "203.0.113.50",
        "action": "LOGIN",
        "status": "FAILED",
    },
    {
        "timestamp": "2026-08-14T10:05:43Z",
        "event_name": "SSHAuthentication",
        "event_source": "Linux SSH",
        "username": "admin",
        "source_ip": "203.0.113.50",
        "action": "LOGIN",
        "status": "FAILED",
    },
    {
        "timestamp": "2026-08-14T10:06:02Z",
        "event_name": "SSHAuthentication",
        "event_source": "Linux SSH",
        "username": "admin",
        "source_ip": "203.0.113.50",
        "action": "LOGIN",
        "status": "SUCCESS",
    },
    {
        "timestamp": "2026-08-14T10:07:05Z",
        "event_name": "FirewallNetworkEvent",
        "event_source": "Firewall",
        "source_ip": "203.0.113.50",
        "destination_ip": "10.0.0.10",
        "destination_port": 22,
        "protocol": "tcp",
        "action": "DENY",
        "status": "DENY",
    },
    {
        "timestamp": "2026-08-14T10:09:01Z",
        "event_name": "AuthorizeSecurityGroupIngress",
        "event_source": "ec2.amazonaws.com",
        "username": "admin",
        "source_ip": "203.0.113.50",
        "action": "AuthorizeSecurityGroupIngress",
        "status": "SUCCESS",
        "event_id": "example-event-001",
        "aws_region": "us-east-1",
    },
    {
        "timestamp": "2026-08-14T10:10:01Z",
        "event_name": "PutBucketPolicy",
        "event_source": "s3.amazonaws.com",
        "username": "admin",
        "source_ip": "203.0.113.50",
        "action": "PutBucketPolicy",
        "status": "SUCCESS",
        "event_id": "example-event-002",
        "aws_region": "us-east-1",
    },
    {
        "timestamp": "INVALID_TIMESTAMP",
        "event_name": "InvalidEvent",
        "event_source": "Linux SSH",
        "source_ip": "203.0.113.50",
    },
]


# ============================================================
# TEST DAY 3 DETECTOR ALERTS
# ============================================================

TEST_DETECTION_ALERTS = [
    {
        "alert_id": "SSH-BRUTE-TEST-1",
        "alert_type": "Possible SSH Brute Force",
        "source_ip": "203.0.113.50",
        "username": "admin",
        "failed_attempts": 3,
        "severity": "HIGH",
        "confidence": "HIGH",
        "status": "SUSPICIOUS",
    },
    {
        "alert_id": "SSH-COMPROMISE-TEST-1",
        "alert_type": "Possible Account Compromise",
        "source_ip": "203.0.113.50",
        "username": "admin",
        "failed_attempts": 3,
        "successful_login": True,
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "status": "SUSPICIOUS",
    },
]


# ============================================================
# DIRECT TEST
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 75)
    print(
        "KIROTRACE NORMALIZER + DAY 4 "
        "SECOPS INTELLIGENCE"
    )
    print("=" * 75)

    # ========================================================
    # TIMESTAMP CONFIGURATION
    # ========================================================
    print()
    print("-" * 75)
    print("TIMESTAMP CONFIGURATION")
    print("-" * 75)

    print(
        f"Default Log Date: "
        f"{DEFAULT_LOG_YEAR:04d}-"
        f"{DEFAULT_LOG_MONTH:02d}-"
        f"{DEFAULT_LOG_DAY:02d}"
    )

    # ========================================================
    # TIMESTAMP TEST
    # ========================================================
    print()
    print("-" * 75)
    print("TIMESTAMP NORMALIZATION TEST")
    print("-" * 75)

    for timestamp in TEST_TIMESTAMP_VALUES:
        normalized = normalize_timestamp(
            timestamp
        )
        print(
            f"{timestamp:<35} -> "
            f"{normalized}"
        )

    # ========================================================
    # NORMALIZATION
    # ========================================================
    print()
    print("-" * 75)
    print("NORMALIZATION")
    print("-" * 75)

    normalized_events = normalize_events(
        TEST_EVENTS
    )
    normalization_report = (
        build_normalization_report(
            TEST_EVENTS,
            normalized_events
        )
    )

    print(
        f"Input Events      : "
        f"{normalization_report['input_events']}"
    )
    print(
        f"Normalized Events : "
        f"{normalization_report['normalized_events']}"
    )
    print(
        f"Discarded Events  : "
        f"{normalization_report['discarded_events']}"
    )

    # ========================================================
    # NORMALIZED EVENTS
    # ========================================================
    print()
    print("-" * 75)
    print("NORMALIZED EVENTS")
    print("-" * 75)

    for index, event in enumerate(
        normalized_events,
        start=1
    ):
        print(
            f"[{index}] "
            f"{event.get('timestamp')} | "
            f"{event.get('source')} | "
            f"{event.get('event_type')} | "
            f"{event.get('source_ip')} | "
            f"{event.get('username')} | "
            f"{event.get('action')} | "
            f"{event.get('status')}"
        )

    # ========================================================
    # STATISTICS
    # ========================================================
    statistics = get_event_statistics(
        normalized_events
    )

    print()
    print("-" * 75)
    print("EVENT STATISTICS")
    print("-" * 75)

    print(
        f"Total Events: "
        f"{statistics['total_events']}"
    )
    print(
        f"Sources: "
        f"{statistics['sources']}"
    )
    print(
        f"Event Types: "
        f"{statistics['event_types']}"
    )
    print(
        f"Statuses: "
        f"{statistics['statuses']}"
    )
    print(
        f"Actions: "
        f"{statistics['actions']}"
    )

    # ========================================================
    # DAY 4 INCIDENT ENGINE
    # ========================================================
    print()
    print("-" * 75)
    print(
        "DAY 4 — INCIDENT / ATTACK STORY ENGINE"
    )
    print("-" * 75)

    incidents = build_incidents(
        events=normalized_events,
        detection_alerts=TEST_DETECTION_ALERTS,
        correlation_window_minutes=10
    )

    print(
        f"Incidents Generated: "
        f"{len(incidents)}"
    )

    # ========================================================
    # INCIDENT SUMMARY
    # ========================================================
    for index, incident in enumerate(
        incidents,
        start=1
    ):
        print()
        print("=" * 75)
        print(
            f"INCIDENT #{index}"
        )
        print(
            f"Incident ID: "
            f"{incident.get('incident_id')}"
        )
        print(
            f"Type: "
            f"{incident.get('incident_type')}"
        )
        print(
            f"Severity: "
            f"{incident.get('severity')}"
        )
        print(
            f"Confidence: "
            f"{incident.get('confidence')}"
        )
        print(
            f"Risk Score: "
            f"{incident.get('risk', {}).get('score')}"
        )
        print(
            f"Sources: "
            f"{incident.get('sources')}"
        )
        print(
            f"Evidence Count: "
            f"{len(incident.get('evidence_chain', []))}"
        )
        print(
            f"Detection Alerts: "
            f"{len(incident.get('detection_alerts', []))}"
        )

        print()
        print("Timeline:")
        print(
            f"  Start: "
            f"{incident.get('timeline', {}).get('start')}"
        )
        print(
            f"  End: "
            f"{incident.get('timeline', {}).get('end')}"
        )

        print()
        print("Attack Story:")
        print(
            incident.get(
                "attack_story"
            )
        )

        print()
        print("Evidence Chain:")
        for evidence in incident.get(
            "evidence_chain", []
        ):
            print(
                f"  "
                f"{evidence.get('sequence')}. "
                f"{evidence.get('timestamp')} | "
                f"{evidence.get('source')} | "
                f"{evidence.get('event_type')} | "
                f"{evidence.get('source_ip')} | "
                f"{evidence.get('username')} | "
                f"{evidence.get('status')}"
            )

    # ========================================================
    # UNIFIED JSON
    # ========================================================
    print()
    print("-" * 75)
    print("UNIFIED INCIDENT JSON")
    print("-" * 75)

    print(
        incidents_to_json(
            incidents
        )
    )

    # ========================================================
    # COMPLETE
    # ========================================================
    print()
    print("=" * 75)
    print(
        "DAY 4 NORMALIZER + SECOPS "
        "INTELLIGENCE TEST COMPLETE"
    )
    print("=" * 75)