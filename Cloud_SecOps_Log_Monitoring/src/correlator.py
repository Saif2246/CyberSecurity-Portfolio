from datetime import datetime, timezone
import hashlib
import json


# ============================================================
# KIROTRACE - CROSS-SOURCE CORRELATOR
# ============================================================
#
# Responsibility:
#   Correlate detector alerts with normalized telemetry.
#
# DOES:
#   - Cross-source correlation
#   - Identity matching
#   - Temporal correlation
#   - Authentication timeline analysis
#   - Evidence extraction
#   - Evidence quality scoring
#   - Event deduplication
#   - Excluded-event classification
#   - Attack-phase classification
#   - Deterministic correlation identity
#   - Correlation-level auditability
#
# DOES NOT:
#   - Calculate final incident risk
#   - Assign final incident severity
#   - Declare compromise
#   - Build final incident object
#
# Those responsibilities belong to:
#   incident_engine.py
#
# Supported telemetry:
#   - Linux SSH
#   - Firewall
#   - AWS CloudTrail
#
# IMPORTANT:
#   Linux SSH is the authentication source represented by
#   detector alerts.
#
#   Firewall and CloudTrail are external telemetry sources
#   correlated against those detector alerts.
#
# IMPORTANT:
#   Correlation indicates related activity.
#   It does NOT prove malicious intent or compromise.
#
# ============================================================


# ============================================================
# CONFIGURATION
# ============================================================

DEFAULT_FIREWALL_WINDOW_MINUTES = 30
DEFAULT_CLOUDTRAIL_WINDOW_MINUTES = 30

# Linux syslog does not contain a year.
# This MVP assumes 2026.
DEFAULT_SYSLOG_YEAR = 2026

# Event exactly at the configured window limit is included.
INCLUDE_WINDOW_BOUNDARY = True

# Stable schema/version identifier for correlation packages.
CORRELATION_VERSION = "1.0"

# Correlation ID prefix.
CORRELATION_ID_PREFIX = "CORR"


# ============================================================
# CONSTANTS
# ============================================================

CLOUDTRAIL_SOURCES = {
    "ec2.amazonaws.com",
    "s3.amazonaws.com",
    "iam.amazonaws.com",
    "signin.amazonaws.com",
    "cloudtrail.amazonaws.com",
    "cloudtrail",
    "aws cloudtrail",
    "aws cloudtrail service",
}

FIREWALL_SOURCES = {
    "firewall",
    "firewallnetworkevent",
    "firewall network",
}

SSH_SOURCES = {
    "linux ssh",
    "ssh",
    "linux-ssh",
    "linux_ssh",
}

# External telemetry sources that can be correlated
# against detector-generated SSH authentication alerts.
SUPPORTED_EXTERNAL_SOURCES = {
    "Firewall",
    "CloudTrail",
}

# All telemetry families understood by the correlator.
ALL_SUPPORTED_SOURCES = {
    "Linux SSH",
    "Firewall",
    "CloudTrail",
}


# ============================================================
# GENERIC HELPERS
# ============================================================

def clean_value(value):
    """Return cleaned value or None."""

    if value is None:
        return None

    if isinstance(value, str):
        value = value.strip()

        if not value:
            return None

    return value


def normalize_text(value):
    """Normalize arbitrary text for reliable comparison."""

    value = clean_value(value)

    if value is None:
        return None

    return str(value).strip().lower()


def normalize_username(username):
    """Normalize username."""

    return normalize_text(username)


def normalize_ip(source_ip):
    """Normalize source IP."""

    source_ip = clean_value(source_ip)

    if source_ip is None:
        return None

    return str(source_ip).strip()


def is_number(value):
    """Return True for int/float excluding bool."""

    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
    )


def safe_positive_minutes(value):
    """
    Validate a positive correlation window.

    Returns:
        float if valid
        None otherwise
    """

    if not is_number(value):
        return None

    if value <= 0:
        return None

    return float(value)


def safe_non_negative_seconds(value):
    """Validate non-negative numeric seconds."""

    if not is_number(value):
        return None

    if value < 0:
        return None

    return float(value)


# ============================================================
# SOURCE NORMALIZATION
# ============================================================

def normalize_source(source):
    """
    Convert raw source into logical source family.

    Examples:
        ec2.amazonaws.com -> CloudTrail
        iam.amazonaws.com -> CloudTrail
        firewall          -> Firewall
        ssh               -> Linux SSH
    """

    normalized = normalize_text(source)

    if normalized is None:
        return None

    if normalized in CLOUDTRAIL_SOURCES:
        return "CloudTrail"

    if normalized in FIREWALL_SOURCES:
        return "Firewall"

    if normalized in SSH_SOURCES:
        return "Linux SSH"

    # Preserve unknown source.
    return clean_value(source)


def is_cloudtrail_source(source):
    return normalize_source(source) == "CloudTrail"


def is_firewall_source(source):
    return normalize_source(source) == "Firewall"


def is_ssh_source(source):
    return normalize_source(source) == "Linux SSH"


# ============================================================
# TIMESTAMP PARSING
# ============================================================

def parse_timestamp(timestamp):
    """
    Convert supported timestamp formats into
    timezone-aware UTC datetime.

    Supported:
        ISO 8601
        ISO 8601 with Z
        ISO 8601 with timezone offset
        YYYY-MM-DD HH:MM:SS
        Linux syslog: Aug 14 10:05:33

    Naive timestamps are treated as UTC for this MVP.
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
                iso_timestamp[:-1]
                + "+00:00"
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

    # --------------------------------------------------------
    # Standard datetime
    # --------------------------------------------------------

    try:
        parsed = datetime.strptime(
            timestamp,
            "%Y-%m-%d %H:%M:%S",
        )

        return parsed.replace(
            tzinfo=timezone.utc
        )

    except (TypeError, ValueError):
        pass

    # --------------------------------------------------------
    # Linux syslog
    # --------------------------------------------------------

    try:
        parsed = datetime.strptime(
            timestamp,
            "%b %d %H:%M:%S",
        )

        parsed = parsed.replace(
            year=DEFAULT_SYSLOG_YEAR,
            tzinfo=timezone.utc,
        )

        return parsed

    except (TypeError, ValueError):
        pass

    return None


# ============================================================
# EVENT IDENTITY
# ============================================================

def build_event_fingerprint(event):
    """
    Build a stable identity for a telemetry event.

    event_id is preferred because CloudTrail provides
    a stable event identity.

    IMPORTANT:
    The same fingerprint function is used for raw events
    and evidence objects so deduplication remains consistent.
    """

    if not isinstance(event, dict):
        return None

    event_id = clean_value(
        event.get("event_id")
    )

    source = normalize_source(
        event.get("source")
    )

    # --------------------------------------------------------
    # Strong identity
    # --------------------------------------------------------

    if event_id is not None:
        return (
            "event_id",
            source,
            str(event_id),
        )

    # --------------------------------------------------------
    # Fallback identity
    # --------------------------------------------------------

    return (
        "event",
        clean_value(
            event.get("timestamp")
        ),
        source,
        normalize_text(
            event.get("event_type")
        ),
        normalize_ip(
            event.get("source_ip")
        ),
        normalize_username(
            event.get("username")
        ),
        normalize_ip(
            event.get("destination_ip")
        ),
        clean_value(
            event.get("destination_port")
        ),
        normalize_text(
            event.get("protocol")
        ),
        normalize_text(
            event.get("action")
        ),
        normalize_text(
            event.get("status")
        ),
    )


def event_key(event):
    """Generate stable raw telemetry event identity."""

    return build_event_fingerprint(event)


def evidence_key(evidence):
    """
    Generate stable evidence identity.

    Uses exactly the same identity logic as raw telemetry.
    This prevents correlated events from being incorrectly
    classified again as excluded events.
    """

    return build_event_fingerprint(evidence)


def alert_key(alert):
    """Generate stable detector alert identity."""

    if not isinstance(alert, dict):
        return None

    return (
        normalize_text(
            alert.get("alert_type")
        ),
        normalize_ip(
            alert.get("source_ip")
        ),
        normalize_username(
            alert.get("username")
        ),
        clean_value(
            alert.get(
                "first_failed_timestamp"
            )
        ),
        clean_value(
            alert.get(
                "last_failed_timestamp"
            )
        ),
        clean_value(
            alert.get(
                "successful_login_timestamp"
            )
        ),
    )


# ============================================================
# CORRELATION IDENTITY
# ============================================================

def build_correlation_fingerprint(
    source_ip,
    username,
    authentication_times,
    alerts,
):
    """
    Build deterministic correlation identity material.

    The fingerprint intentionally uses stable identity and
    authentication information rather than generated timestamps.

    This means the same logical detector-alert group produces
    the same correlation identity across repeated executions.
    """

    if not isinstance(authentication_times, dict):
        authentication_times = {}

    alert_fingerprints = []

    if isinstance(alerts, list):
        for alert in alerts:

            key = alert_key(alert)

            if key is not None:
                alert_fingerprints.append(
                    repr(key)
                )

    alert_fingerprints.sort()

    identity_material = {
        "version": CORRELATION_VERSION,
        "source_ip": normalize_ip(source_ip),
        "username": normalize_username(username),
        "first_failed": (
            authentication_times.get(
                "first_failed"
            ).isoformat()
            if authentication_times.get(
                "first_failed"
            ) is not None
            else None
        ),
        "last_failed": (
            authentication_times.get(
                "last_failed"
            ).isoformat()
            if authentication_times.get(
                "last_failed"
            ) is not None
            else None
        ),
        "successful_login": (
            authentication_times.get(
                "successful_login"
            ).isoformat()
            if authentication_times.get(
                "successful_login"
            ) is not None
            else None
        ),
        "alerts": alert_fingerprints,
    }

    return json.dumps(
        identity_material,
        sort_keys=True,
        separators=(",", ":"),
    )


def generate_correlation_id(
    source_ip,
    username,
    authentication_times,
    alerts,
):
    """
    Generate deterministic SHA-256 correlation ID.

    Format:

        CORR-<16 hex characters>

    The ID is intentionally deterministic so repeated executions
    do not create different correlation identities for the same
    detector-alert group.
    """

    fingerprint = build_correlation_fingerprint(
        source_ip=source_ip,
        username=username,
        authentication_times=authentication_times,
        alerts=alerts,
    )

    digest = hashlib.sha256(
        fingerprint.encode("utf-8")
    ).hexdigest()

    return (
        f"{CORRELATION_ID_PREFIX}-"
        f"{digest[:16]}"
    )


def build_correlation_identity(
    correlation_id,
    source_ip,
    username,
    authentication_times,
):
    """
    Build audit-friendly correlation identity metadata.
    """

    return {
        "correlation_id": correlation_id,
        "correlation_version": CORRELATION_VERSION,
        "identity_type": "SOURCE_IP_USERNAME_AUTH_TIMELINE",
        "source_ip": normalize_ip(
            source_ip
        ),
        "username": normalize_username(
            username
        ),
        "first_failed_timestamp": (
            authentication_times.get(
                "first_failed"
            ).isoformat()
            if authentication_times.get(
                "first_failed"
            ) is not None
            else None
        ),
        "last_failed_timestamp": (
            authentication_times.get(
                "last_failed"
            ).isoformat()
            if authentication_times.get(
                "last_failed"
            ) is not None
            else None
        ),
        "successful_login_timestamp": (
            authentication_times.get(
                "successful_login"
            ).isoformat()
            if authentication_times.get(
                "successful_login"
            ) is not None
            else None
        ),
    }


# ============================================================
# DEDUPLICATION
# ============================================================

def deduplicate_alerts(alerts):
    """Remove duplicate detector alerts."""

    if not isinstance(alerts, list):
        return []

    unique = []
    seen = set()

    for alert in alerts:

        if not isinstance(alert, dict):
            continue

        key = alert_key(alert)

        if key is None:
            continue

        if key in seen:
            continue

        seen.add(key)
        unique.append(alert)

    return unique


def deduplicate_events(events):
    """Remove duplicate raw telemetry events."""

    if not isinstance(events, list):
        return []

    unique = []
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
        unique.append(event)

    return unique


def deduplicate_evidence(events):
    """Remove duplicate evidence objects."""

    if not isinstance(events, list):
        return []

    unique = []
    seen = set()

    for evidence in events:

        if not isinstance(evidence, dict):
            continue

        key = evidence_key(evidence)

        if key is None:
            continue

        if key in seen:
            continue

        seen.add(key)
        unique.append(evidence)

    return unique


# ============================================================
# IDENTITY MATCHING
# ============================================================

def source_ips_match(alert_ip, event_ip):
    """
    Source IP is the primary correlation identity.

    Missing IP never matches.
    """

    alert_ip = normalize_ip(alert_ip)
    event_ip = normalize_ip(event_ip)

    if alert_ip is None or event_ip is None:
        return False

    return alert_ip == event_ip


def username_match_type(
    alert_username,
    event_username,
):
    """
    Return:

        EXACT
        MISMATCH
        MISSING
    """

    alert_username = normalize_username(
        alert_username
    )

    event_username = normalize_username(
        event_username
    )

    if (
        alert_username is not None
        and event_username is not None
    ):

        if alert_username == event_username:
            return "EXACT"

        return "MISMATCH"

    return "MISSING"


# ============================================================
# AUTHENTICATION TIMELINE
# ============================================================

def get_authentication_times(alerts):
    """
    Extract complete SSH authentication timeline.

    Returns:

        first_failed
        last_failed
        successful_login
    """

    failed_times = []
    successful_times = []

    if not isinstance(alerts, list):
        return {
            "first_failed": None,
            "last_failed": None,
            "successful_login": None,
        }

    for alert in alerts:

        if not isinstance(alert, dict):
            continue

        for field in (
            "first_failed_timestamp",
            "last_failed_timestamp",
        ):

            parsed = parse_timestamp(
                alert.get(field)
            )

            if parsed is not None:
                failed_times.append(parsed)

        successful = parse_timestamp(
            alert.get(
                "successful_login_timestamp"
            )
        )

        if successful is not None:
            successful_times.append(
                successful
            )

    first_failed = (
        min(failed_times)
        if failed_times
        else None
    )

    last_failed = (
        max(failed_times)
        if failed_times
        else None
    )

    successful_login = (
        min(successful_times)
        if successful_times
        else None
    )

    return {
        "first_failed": first_failed,
        "last_failed": last_failed,
        "successful_login": successful_login,
    }


# ============================================================
# TEMPORAL ANCHORS
# ============================================================

def get_correlation_anchors(
    authentication_times,
):
    """
    Build temporal anchors.

    Anchors:
        FIRST_FAILED_AUTH
        LAST_FAILED_AUTH
        SUCCESSFUL_LOGIN
    """

    if not isinstance(
        authentication_times,
        dict,
    ):
        return []

    anchors = []

    first_failed = authentication_times.get(
        "first_failed"
    )

    last_failed = authentication_times.get(
        "last_failed"
    )

    successful_login = authentication_times.get(
        "successful_login"
    )

    if first_failed is not None:
        anchors.append(
            (
                "FIRST_FAILED_AUTH",
                first_failed,
            )
        )

    if (
        last_failed is not None
        and last_failed != first_failed
    ):
        anchors.append(
            (
                "LAST_FAILED_AUTH",
                last_failed,
            )
        )

    if successful_login is not None:
        anchors.append(
            (
                "SUCCESSFUL_LOGIN",
                successful_login,
            )
        )

    return anchors


# ============================================================
# ATTACK PHASE
# ============================================================

def determine_attack_phase(
    event_time,
    authentication_times,
):
    """
    Classify external telemetry relative to
    SSH authentication sequence.

    Possible values:

        PRE_AUTH
        POST_FAILURE
        POST_SUCCESS
        UNKNOWN

    Rules:

        event < first_failed
            -> PRE_AUTH

        first_failed <= event < successful_login
            -> POST_FAILURE

        event >= successful_login
            -> POST_SUCCESS
    """

    if event_time is None:
        return "UNKNOWN"

    if not isinstance(
        authentication_times,
        dict,
    ):
        return "UNKNOWN"

    first_failed = authentication_times.get(
        "first_failed"
    )

    successful_login = authentication_times.get(
        "successful_login"
    )

    if first_failed is None:
        return "UNKNOWN"

    if successful_login is not None:

        if event_time >= successful_login:
            return "POST_SUCCESS"

        if event_time >= first_failed:
            return "POST_FAILURE"

        return "PRE_AUTH"

    if event_time < first_failed:
        return "PRE_AUTH"

    return "POST_FAILURE"


# ============================================================
# TEMPORAL CORRELATION
# ============================================================

def is_within_temporal_window(
    event_time,
    anchor_time,
    window_seconds,
):
    """
    Check whether event occurred within absolute
    temporal distance of an anchor.
    """

    if event_time is None:
        return False

    if anchor_time is None:
        return False

    window_seconds = safe_non_negative_seconds(
        window_seconds
    )

    if window_seconds is None:
        return False

    elapsed = abs(
        (
            event_time
            - anchor_time
        ).total_seconds()
    )

    if INCLUDE_WINDOW_BOUNDARY:
        return elapsed <= window_seconds

    return elapsed < window_seconds


def find_best_temporal_anchor(
    event_time,
    authentication_times,
    window_seconds,
):
    """
    Select the closest valid authentication anchor.

    Supports:

        PRE_AUTH
        POST_FAILURE
        POST_SUCCESS

    Tie-breaking preference:

        SUCCESSFUL_LOGIN
        LAST_FAILED_AUTH
        FIRST_FAILED_AUTH
    """

    if event_time is None:
        return None

    window_seconds = safe_non_negative_seconds(
        window_seconds
    )

    if window_seconds is None:
        return None

    candidates = []

    anchors = get_correlation_anchors(
        authentication_times
    )

    anchor_priority = {
        "SUCCESSFUL_LOGIN": 0,
        "LAST_FAILED_AUTH": 1,
        "FIRST_FAILED_AUTH": 2,
    }

    for anchor_type, anchor_time in anchors:

        if not is_within_temporal_window(
            event_time,
            anchor_time,
            window_seconds,
        ):
            continue

        elapsed = abs(
            (
                event_time
                - anchor_time
            ).total_seconds()
        )

        candidates.append(
            {
                "anchor_type": anchor_type,
                "anchor_time": anchor_time,
                "elapsed_seconds": elapsed,
                "event_before_anchor": (
                    event_time < anchor_time
                ),
            }
        )

    if not candidates:
        return None

    candidates.sort(
        key=lambda item: (
            item["elapsed_seconds"],
            anchor_priority.get(
                item["anchor_type"],
                99,
            ),
        )
    )

    return candidates[0]


# ============================================================
# EVIDENCE SCORING
# ============================================================

def calculate_event_evidence_score(
    source,
    username_match,
    elapsed_seconds,
    attack_phase,
):
    """
    Calculate evidence quality.

    This is NOT:

        - maliciousness probability
        - incident severity
        - compromise probability

    Maximum:

        Source       = 30
        Username     = 30
        Temporal     = 20
        Phase        = 20

        Total        = 100
    """

    score = 0

    # --------------------------------------------------------
    # Source reliability
    # --------------------------------------------------------

    if source == "CloudTrail":
        score += 30

    elif source == "Firewall":
        score += 20

    # --------------------------------------------------------
    # Identity strength
    # --------------------------------------------------------

    if username_match == "EXACT":
        score += 30

    elif username_match == "MISSING":
        score += 10

    # MISMATCH contributes zero.

    # --------------------------------------------------------
    # Temporal proximity
    # --------------------------------------------------------

    if is_number(elapsed_seconds):

        if elapsed_seconds <= 300:
            score += 20

        elif elapsed_seconds <= 900:
            score += 15

        elif elapsed_seconds <= 1800:
            score += 10

    # --------------------------------------------------------
    # Attack phase
    # --------------------------------------------------------

    if attack_phase == "POST_SUCCESS":
        score += 20

    elif attack_phase == "POST_FAILURE":
        score += 15

    elif attack_phase == "PRE_AUTH":
        score += 5

    return min(
        max(score, 0),
        100,
    )


# ============================================================
# CORRELATION REASON
# ============================================================

def build_correlation_reason(
    source,
    username_match,
    anchor_type,
    elapsed_seconds,
    attack_phase,
):
    """Build human-readable audit explanation."""

    elapsed_seconds = int(
        round(elapsed_seconds)
    )

    anchor_descriptions = {
        "SUCCESSFUL_LOGIN":
            "the successful SSH login",

        "LAST_FAILED_AUTH":
            "the last failed SSH authentication",

        "FIRST_FAILED_AUTH":
            "the first failed SSH authentication",
    }

    anchor_description = (
        anchor_descriptions.get(
            anchor_type,
            "the SSH authentication activity",
        )
    )

    reason = (
        f"{source} telemetry is temporally related "
        f"to {anchor_description} by "
        f"{elapsed_seconds} seconds and uses the "
        f"same source IP."
    )

    if username_match == "EXACT":

        reason += (
            " The telemetry username exactly "
            "matched the SSH username."
        )

    elif username_match == "MISSING":

        reason += (
            " The telemetry did not provide a "
            "comparable username."
        )

    if attack_phase == "POST_SUCCESS":

        reason += (
            " The activity occurred after "
            "successful authentication."
        )

    elif attack_phase == "POST_FAILURE":

        reason += (
            " The activity occurred during or "
            "after the failed-authentication sequence."
        )

    elif attack_phase == "PRE_AUTH":

        reason += (
            " The activity occurred before "
            "the failed-authentication sequence."
        )

    return reason


# ============================================================
# EVIDENCE BUILDER
# ============================================================

def build_evidence_event(
    event,
    reference_time,
    anchor_type,
    correlation_type,
    correlation_reason,
    username_match,
    attack_phase,
    correlation_id,
):
    """Convert normalized telemetry into evidence."""

    if not isinstance(event, dict):
        return None

    if reference_time is None:
        return None

    event_time = parse_timestamp(
        event.get("timestamp")
    )

    if event_time is None:
        return None

    time_difference = abs(
        (
            event_time
            - reference_time
        ).total_seconds()
    )

    source = normalize_source(
        event.get("source")
    )

    evidence_score = (
        calculate_event_evidence_score(
            source=source,
            username_match=username_match,
            elapsed_seconds=time_difference,
            attack_phase=attack_phase,
        )
    )

    return {
        # ----------------------------------------------------
        # Correlation identity
        # ----------------------------------------------------

        "correlation_id": correlation_id,

        # ----------------------------------------------------
        # Original event identity
        # ----------------------------------------------------

        "timestamp": event.get(
            "timestamp"
        ),

        "source": source,

        "raw_source": event.get(
            "source"
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

        "destination_ip": event.get(
            "destination_ip"
        ),

        "destination_port": event.get(
            "destination_port"
        ),

        "protocol": event.get(
            "protocol"
        ),

        "action": event.get(
            "action"
        ),

        "status": event.get(
            "status"
        ),

        "event_id": event.get(
            "event_id"
        ),

        # ----------------------------------------------------
        # Correlation metadata
        # ----------------------------------------------------

        "correlation_type": (
            correlation_type
        ),

        "correlation_reason": (
            correlation_reason
        ),

        "anchor_type": anchor_type,

        "anchor_timestamp": (
            reference_time.isoformat()
        ),

        "attack_phase": attack_phase,

        "username_match": (
            username_match
        ),

        "time_difference_seconds": (
            int(round(time_difference))
        ),

        # ----------------------------------------------------
        # Evidence quality
        # ----------------------------------------------------

        "evidence_score": (
            evidence_score
        ),
    }


# ============================================================
# CORRELATE SINGLE EVENT
# ============================================================

def correlate_event(
    event,
    source_ip,
    username,
    authentication_times,
    firewall_window_seconds,
    cloudtrail_window_seconds,
    correlation_id,
):
    """
    Determine whether one normalized event
    belongs to the suspicious activity sequence.

    IMPORTANT:

    Linux SSH events are intentionally NOT correlated here.

    They are already represented by the detector alerts.
    The correlator is responsible for connecting those
    authentication alerts with external telemetry such as:

        Firewall
        CloudTrail
    """

    if not isinstance(event, dict):
        return None

    # --------------------------------------------------------
    # Source
    # --------------------------------------------------------

    event_source = normalize_source(
        event.get("source")
    )

    if event_source not in SUPPORTED_EXTERNAL_SOURCES:
        return None

    # --------------------------------------------------------
    # Primary identity: source IP
    # --------------------------------------------------------

    if not source_ips_match(
        source_ip,
        event.get("source_ip"),
    ):
        return None

    # --------------------------------------------------------
    # Secondary identity: username
    # --------------------------------------------------------

    username_match = username_match_type(
        username,
        event.get("username"),
    )

    # Explicit mismatch means different identity.
    if username_match == "MISMATCH":
        return None

    # --------------------------------------------------------
    # Timestamp
    # --------------------------------------------------------

    event_time = parse_timestamp(
        event.get("timestamp")
    )

    if event_time is None:
        return None

    # --------------------------------------------------------
    # Source-specific window
    # --------------------------------------------------------

    if event_source == "Firewall":

        window_seconds = (
            firewall_window_seconds
        )

        correlation_type = (
            "Firewall Correlation"
        )

    elif event_source == "CloudTrail":

        window_seconds = (
            cloudtrail_window_seconds
        )

        correlation_type = (
            "CloudTrail Correlation"
        )

    else:
        return None

    # --------------------------------------------------------
    # Temporal anchor
    # --------------------------------------------------------

    anchor = find_best_temporal_anchor(
        event_time=event_time,
        authentication_times=authentication_times,
        window_seconds=window_seconds,
    )

    if anchor is None:
        return None

    # --------------------------------------------------------
    # Attack phase
    # --------------------------------------------------------

    attack_phase = determine_attack_phase(
        event_time=event_time,
        authentication_times=authentication_times,
    )

    # --------------------------------------------------------
    # Explanation
    # --------------------------------------------------------

    reason = build_correlation_reason(
        source=event_source,
        username_match=username_match,
        anchor_type=anchor["anchor_type"],
        elapsed_seconds=anchor["elapsed_seconds"],
        attack_phase=attack_phase,
    )

    # --------------------------------------------------------
    # Evidence
    # --------------------------------------------------------

    return build_evidence_event(
        event=event,
        reference_time=anchor["anchor_time"],
        anchor_type=anchor["anchor_type"],
        correlation_type=correlation_type,
        correlation_reason=reason,
        username_match=username_match,
        attack_phase=attack_phase,
        correlation_id=correlation_id,
    )


# ============================================================
# EVIDENCE SUMMARY
# ============================================================

def calculate_evidence_summary(
    related_events,
):
    """Summarize evidence quality."""

    if not isinstance(
        related_events,
        list,
    ):
        related_events = []

    exact_matches = 0
    missing_matches = 0

    post_success_events = 0
    post_failure_events = 0
    pre_auth_events = 0

    scores = []

    sources = set()

    for event in related_events:

        if not isinstance(event, dict):
            continue

        match_type = event.get(
            "username_match"
        )

        if match_type == "EXACT":
            exact_matches += 1

        elif match_type == "MISSING":
            missing_matches += 1

        phase = event.get(
            "attack_phase"
        )

        if phase == "POST_SUCCESS":
            post_success_events += 1

        elif phase == "POST_FAILURE":
            post_failure_events += 1

        elif phase == "PRE_AUTH":
            pre_auth_events += 1

        score = event.get(
            "evidence_score"
        )

        if is_number(score):

            scores.append(
                max(
                    0,
                    min(
                        float(score),
                        100,
                    ),
                )
            )

        source = normalize_source(
            event.get("source")
        )

        # Only external correlated sources belong
        # in this source summary.
        if (
            source in
            SUPPORTED_EXTERNAL_SOURCES
        ):
            sources.add(source)

    average_score = (
        round(
            sum(scores)
            / len(scores),
            1,
        )
        if scores
        else 0
    )

    strongest_score = (
        max(scores)
        if scores
        else 0
    )

    if (
        isinstance(
            strongest_score,
            float,
        )
        and strongest_score.is_integer()
    ):
        strongest_score = int(
            strongest_score
        )

    return {
        "exact_username_matches": (
            exact_matches
        ),

        "missing_username_matches": (
            missing_matches
        ),

        "average_evidence_score": (
            average_score
        ),

        "strongest_evidence_score": (
            strongest_score
        ),

        "total_related_events": (
            len(related_events)
        ),

        "post_success_events": (
            post_success_events
        ),

        "post_failure_events": (
            post_failure_events
        ),

        "pre_auth_events": (
            pre_auth_events
        ),

        "external_sources": (
            sorted(sources)
        ),
    }


# ============================================================
# EXCLUDED EVENT ANALYSIS
# ============================================================

def classify_excluded_event(
    event,
    source_ip,
    username,
    authentication_times,
    firewall_window_seconds,
    cloudtrail_window_seconds,
):
    """
    Explain why an event was not correlated.

    Important distinction:

        Linux SSH events are not "unsupported".
        They are internal authentication telemetry already
        represented by detector alerts.

        Unknown telemetry sources are genuinely unsupported.
    """

    if not isinstance(event, dict):
        return "INVALID_EVENT"

    # --------------------------------------------------------
    # Source
    # --------------------------------------------------------

    event_source = normalize_source(
        event.get("source")
    )

    # --------------------------------------------------------
    # Linux SSH
    # --------------------------------------------------------

    if event_source == "Linux SSH":
        return "INTERNAL_AUTH_EVENT"

    # --------------------------------------------------------
    # External source validation
    # --------------------------------------------------------

    if event_source not in SUPPORTED_EXTERNAL_SOURCES:
        return "UNSUPPORTED_SOURCE"

    # --------------------------------------------------------
    # IP
    # --------------------------------------------------------

    event_ip = normalize_ip(
        event.get("source_ip")
    )

    if event_ip is None:
        return "MISSING_SOURCE_IP"

    if not source_ips_match(
        source_ip,
        event_ip,
    ):
        return "SOURCE_IP_MISMATCH"

    # --------------------------------------------------------
    # Username
    # --------------------------------------------------------

    username_match = username_match_type(
        username,
        event.get("username"),
    )

    if username_match == "MISMATCH":
        return "USERNAME_MISMATCH"

    # --------------------------------------------------------
    # Timestamp
    # --------------------------------------------------------

    event_time = parse_timestamp(
        event.get("timestamp")
    )

    if event_time is None:
        return "INVALID_TIMESTAMP"

    # --------------------------------------------------------
    # Source-specific window
    # --------------------------------------------------------

    if event_source == "Firewall":

        window_seconds = (
            firewall_window_seconds
        )

        window_reason = (
            "OUTSIDE_FIREWALL_WINDOW"
        )

    elif event_source == "CloudTrail":

        window_seconds = (
            cloudtrail_window_seconds
        )

        window_reason = (
            "OUTSIDE_CLOUDTRAIL_WINDOW"
        )

    else:
        return "UNSUPPORTED_SOURCE"

    # --------------------------------------------------------
    # Authentication anchors
    # --------------------------------------------------------

    anchors = get_correlation_anchors(
        authentication_times
    )

    if not anchors:
        return "NO_CORRELATION_ANCHOR"

    # --------------------------------------------------------
    # Defensive consistency check
    # --------------------------------------------------------

    anchor = find_best_temporal_anchor(
        event_time=event_time,
        authentication_times=authentication_times,
        window_seconds=window_seconds,
    )

    if anchor is not None:
        return "NOT_CORRELATED"

    # --------------------------------------------------------
    # Before authentication
    # --------------------------------------------------------

    first_failed = authentication_times.get(
        "first_failed"
    )

    if (
        first_failed is not None
        and event_time < first_failed
    ):

        difference = (
            first_failed
            - event_time
        ).total_seconds()

        if difference > window_seconds:
            return "BEFORE_CORRELATION_ANCHOR"

    # --------------------------------------------------------
    # Otherwise outside source-specific window
    # --------------------------------------------------------

    return window_reason


# ============================================================
# ALERT GROUPING
# ============================================================

def group_alerts(alerts):
    """
    Group alerts by source IP + normalized username.

    This prevents unrelated identities from being
    merged into the same correlation package.
    """

    groups = {}

    if not isinstance(alerts, list):
        return groups

    for alert in alerts:

        if not isinstance(alert, dict):
            continue

        source_ip = normalize_ip(
            alert.get("source_ip")
        )

        if source_ip is None:
            continue

        username = normalize_username(
            alert.get("username")
        )

        key = (
            source_ip,
            username,
        )

        groups.setdefault(
            key,
            [],
        ).append(alert)

    return groups


# ============================================================
# CORRELATE ALERT GROUP
# ============================================================

def correlate_alert_group(
    group_alerts,
    normalized_events,
    firewall_window_minutes,
    cloudtrail_window_minutes,
):
    """Correlate one detector-alert group."""

    # --------------------------------------------------------
    # Validate windows
    # --------------------------------------------------------

    firewall_window_minutes = (
        safe_positive_minutes(
            firewall_window_minutes
        )
    )

    cloudtrail_window_minutes = (
        safe_positive_minutes(
            cloudtrail_window_minutes
        )
    )

    if (
        firewall_window_minutes is None
        or cloudtrail_window_minutes is None
    ):
        return None

    # --------------------------------------------------------
    # Deduplicate alerts
    # --------------------------------------------------------

    unique_alerts = deduplicate_alerts(
        group_alerts
    )

    if not unique_alerts:
        return None

    # --------------------------------------------------------
    # Identity
    # --------------------------------------------------------

    source_ip = normalize_ip(
        unique_alerts[0].get(
            "source_ip"
        )
    )

    username = normalize_username(
        unique_alerts[0].get(
            "username"
        )
    )

    if source_ip is None:
        return None

    # --------------------------------------------------------
    # Authentication timeline
    # --------------------------------------------------------

    authentication_times = (
        get_authentication_times(
            unique_alerts
        )
    )

    if (
        authentication_times[
            "first_failed"
        ] is None
    ):
        return None

    # --------------------------------------------------------
    # Deterministic correlation ID
    # --------------------------------------------------------

    correlation_id = generate_correlation_id(
        source_ip=source_ip,
        username=username,
        authentication_times=authentication_times,
        alerts=unique_alerts,
    )

    correlation_identity = (
        build_correlation_identity(
            correlation_id=correlation_id,
            source_ip=source_ip,
            username=username,
            authentication_times=authentication_times,
        )
    )

    # --------------------------------------------------------
    # Correlation creation metadata
    # --------------------------------------------------------

    correlation_created_at = (
        datetime.now(
            timezone.utc
        ).isoformat()
    )

    # --------------------------------------------------------
    # Window conversion
    # --------------------------------------------------------

    firewall_window_seconds = (
        firewall_window_minutes * 60
    )

    cloudtrail_window_seconds = (
        cloudtrail_window_minutes * 60
    )

    # --------------------------------------------------------
    # Deduplicate telemetry
    # --------------------------------------------------------

    unique_events = deduplicate_events(
        normalized_events
    )

    # --------------------------------------------------------
    # Correlate external events
    #
    # Linux SSH is intentionally NOT included here.
    # The detector alerts already represent SSH
    # authentication activity.
    # --------------------------------------------------------

    related_events = []

    for event in unique_events:

        evidence = correlate_event(
            event=event,
            source_ip=source_ip,
            username=username,
            authentication_times=(
                authentication_times
            ),
            firewall_window_seconds=(
                firewall_window_seconds
            ),
            cloudtrail_window_seconds=(
                cloudtrail_window_seconds
            ),
            correlation_id=correlation_id,
        )

        if evidence is not None:
            related_events.append(
                evidence
            )

    # --------------------------------------------------------
    # Deduplicate evidence
    # --------------------------------------------------------

    related_events = deduplicate_evidence(
        related_events
    )

    # --------------------------------------------------------
    # Chronological ordering
    # --------------------------------------------------------

    related_events.sort(
        key=lambda event: (
            parse_timestamp(
                event.get("timestamp")
            )
            or datetime.max.replace(
                tzinfo=timezone.utc
            )
        )
    )

    # --------------------------------------------------------
    # Telemetry sources
    #
    # Linux SSH is NOT an external correlated source.
    # --------------------------------------------------------

    telemetry_sources = set()

    for event in related_events:

        source = normalize_source(
            event.get("source")
        )

        if (
            source in
            SUPPORTED_EXTERNAL_SOURCES
        ):
            telemetry_sources.add(
                source
            )

    # --------------------------------------------------------
    # Evidence summary
    # --------------------------------------------------------

    evidence_summary = (
        calculate_evidence_summary(
            related_events
        )
    )

    # --------------------------------------------------------
    # Correlated event keys
    # --------------------------------------------------------

    correlated_keys = set()

    for event in related_events:

        key = evidence_key(event)

        if key is not None:
            correlated_keys.add(key)

    # --------------------------------------------------------
    # Excluded events
    # --------------------------------------------------------

    excluded_event_counts = {}

    for event in unique_events:

        raw_key = event_key(event)

        if raw_key is None:
            continue

        # Already-correlated event.
        if raw_key in correlated_keys:
            continue

        reason = classify_excluded_event(
            event=event,
            source_ip=source_ip,
            username=username,
            authentication_times=(
                authentication_times
            ),
            firewall_window_seconds=(
                firewall_window_seconds
            ),
            cloudtrail_window_seconds=(
                cloudtrail_window_seconds
            ),
        )

        excluded_event_counts[
            reason
        ] = (
            excluded_event_counts.get(
                reason,
                0,
            )
            + 1
        )

    # --------------------------------------------------------
    # Authentication timeline output
    # --------------------------------------------------------

    timeline = {
        key: (
            value.isoformat()
            if value is not None
            else None
        )
        for key, value
        in authentication_times.items()
    }

    # --------------------------------------------------------
    # Correlation package
    # --------------------------------------------------------

    return {
        # ====================================================
        # CORRELATION IDENTITY
        # ====================================================

        "correlation_id": (
            correlation_id
        ),

        "correlation_version": (
            CORRELATION_VERSION
        ),

        "correlation_created_at": (
            correlation_created_at
        ),

        "correlation_identity": (
            correlation_identity
        ),

        # ====================================================
        # PRIMARY IDENTITY
        # ====================================================

        "source_ip": source_ip,

        "username": username,

        # ====================================================
        # DETECTOR ALERTS
        # ====================================================

        "alerts": unique_alerts,

        # ====================================================
        # AUTHENTICATION TIMELINE
        # ====================================================

        "authentication_times": timeline,

        # ====================================================
        # CORRELATED EVIDENCE
        # ====================================================

        "related_events": related_events,

        # ONLY externally correlated telemetry.
        "telemetry_sources": sorted(
            telemetry_sources
        ),

        # ====================================================
        # EVIDENCE QUALITY
        # ====================================================

        "evidence_summary": (
            evidence_summary
        ),

        # ====================================================
        # EXCLUDED TELEMETRY
        # ====================================================

        "excluded_event_counts": (
            excluded_event_counts
        ),

        # ====================================================
        # CORRELATION CONFIGURATION
        # ====================================================

        "firewall_window_minutes": (
            firewall_window_minutes
        ),

        "cloudtrail_window_minutes": (
            cloudtrail_window_minutes
        ),

        # ====================================================
        # FINAL CORRELATION STATE
        # ====================================================

        "correlation_status": (
            "CORRELATED"
            if related_events
            else "NO_EXTERNAL_EVIDENCE"
        ),
    }


# ============================================================
# MAIN CORRELATION API
# ============================================================

def correlate_events(
    alerts,
    normalized_events,
    firewall_window_minutes=(
        DEFAULT_FIREWALL_WINDOW_MINUTES
    ),
    cloudtrail_window_minutes=(
        DEFAULT_CLOUDTRAIL_WINDOW_MINUTES
    ),
):
    """
    Main cross-source correlation API.

    Returns:
        List of correlation packages.
    """

    # --------------------------------------------------------
    # Input validation
    # --------------------------------------------------------

    if not isinstance(
        alerts,
        list,
    ):
        return []

    if not isinstance(
        normalized_events,
        list,
    ):
        return []

    if not alerts:
        return []

    # --------------------------------------------------------
    # Validate windows
    # --------------------------------------------------------

    firewall_window_minutes = (
        safe_positive_minutes(
            firewall_window_minutes
        )
    )

    cloudtrail_window_minutes = (
        safe_positive_minutes(
            cloudtrail_window_minutes
        )
    )

    if (
        firewall_window_minutes is None
        or cloudtrail_window_minutes is None
    ):
        return []

    # --------------------------------------------------------
    # Group alerts
    # --------------------------------------------------------

    groups = group_alerts(
        alerts
    )

    correlations = []

    # --------------------------------------------------------
    # Correlate each identity group
    # --------------------------------------------------------

    for group in groups.values():

        result = correlate_alert_group(
            group_alerts=group,
            normalized_events=normalized_events,
            firewall_window_minutes=(
                firewall_window_minutes
            ),
            cloudtrail_window_minutes=(
                cloudtrail_window_minutes
            ),
        )

        if result is None:
            continue

        # ----------------------------------------------------
        # Require at least one external source.
        # ----------------------------------------------------

        external_sources = {
            source
            for source
            in result[
                "telemetry_sources"
            ]
            if source in SUPPORTED_EXTERNAL_SOURCES
        }

        if not external_sources:
            continue

        correlations.append(
            result
        )

    return correlations


# ============================================================
# TEST HELPERS
# ============================================================

def print_correlation_result(
    correlations,
):
    """Pretty-print correlation results."""

    print()

    if not correlations:

        print(
            "No correlated evidence found."
        )

        return

    for index, correlation in enumerate(
        correlations,
        start=1,
    ):

        print()
        print(
            f"CORRELATION #{index}"
        )

        print(
            "-" * 70
        )

        print(
            f"Correlation ID : "
            f"{correlation['correlation_id']}"
        )

        print(
            f"Version        : "
            f"{correlation['correlation_version']}"
        )

        print(
            f"Created At     : "
            f"{correlation['correlation_created_at']}"
        )

        print(
            f"Source IP      : "
            f"{correlation['source_ip']}"
        )

        print(
            f"Username       : "
            f"{correlation['username']}"
        )

        print(
            f"Sources        : "
            f"{', '.join(correlation['telemetry_sources'])}"
        )

        print(
            f"Status         : "
            f"{correlation['correlation_status']}"
        )

        print()

        print(
            "Correlation Identity:"
        )

        for key, value in (
            correlation[
                "correlation_identity"
            ].items()
        ):

            print(
                f"  {key}: {value}"
            )

        print()

        print(
            "Authentication Timeline:"
        )

        for key, value in (
            correlation[
                "authentication_times"
            ].items()
        ):

            print(
                f"  {key}: {value}"
            )

        print()

        print(
            "Evidence Summary:"
        )

        for key, value in (
            correlation[
                "evidence_summary"
            ].items()
        ):

            print(
                f"  {key}: {value}"
            )

        print()

        print(
            "RELATED EVENTS:"
        )

        if not correlation[
            "related_events"
        ]:

            print(
                "  None"
            )

        else:

            for event in (
                correlation[
                    "related_events"
                ]
            ):

                print(
                    f"  {event['timestamp']} | "
                    f"{event['source']} | "
                    f"{event['event_type']} | "
                    f"phase={event['attack_phase']} | "
                    f"anchor={event['anchor_type']} | "
                    f"username_match="
                    f"{event['username_match']} | "
                    f"distance="
                    f"{event['time_difference_seconds']}s | "
                    f"score="
                    f"{event['evidence_score']}"
                )

                print(
                    f"    Correlation ID: "
                    f"{event['correlation_id']}"
                )

                print(
                    f"    Reason: "
                    f"{event['correlation_reason']}"
                )

        print()

        print(
            "EXCLUDED EVENTS:"
        )

        if not correlation[
            "excluded_event_counts"
        ]:

            print(
                "  None"
            )

        else:

            for reason, count in sorted(
                correlation[
                    "excluded_event_counts"
                ].items()
            ):

                print(
                    f"  {reason}: {count}"
                )


# ============================================================
# DIRECT TEST
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 70)
    print(
        "KIROTRACE CROSS-SOURCE CORRELATOR TEST"
    )
    print("=" * 70)

    # ========================================================
    # TEST ALERTS
    # ========================================================

    test_alerts = [

        {
            "alert_type":
                "Possible SSH Brute Force",

            "source_ip":
                "203.0.113.50",

            "username":
                "admin",

            "failed_attempts":
                5,

            "first_failed_timestamp":
                "2026-08-14T10:05:33Z",

            "last_failed_timestamp":
                "2026-08-14T10:05:53Z",

            "severity":
                "HIGH",
        },

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

            "time_difference_seconds":
                9,

            "severity":
                "CRITICAL",
        },
    ]

    # ========================================================
    # TEST TELEMETRY
    # ========================================================

    test_events = [

        # ----------------------------------------------------
        # PRE-AUTH FIREWALL EVENT
        # ----------------------------------------------------

        {
            "timestamp":
                "2026-08-14T10:04:00Z",

            "source":
                "Firewall",

            "event_type":
                "FirewallNetworkEvent",

            "source_ip":
                "203.0.113.50",

            "destination_ip":
                "10.0.0.10",

            "destination_port":
                22,

            "protocol":
                "TCP",

            "action":
                "DENY",

            "status":
                "deny",
        },

        # ----------------------------------------------------
        # POST-FAILURE FIREWALL EVENT
        # ----------------------------------------------------

        {
            "timestamp":
                "2026-08-14T10:10:05Z",

            "source":
                "Firewall",

            "event_type":
                "FirewallNetworkEvent",

            "source_ip":
                "203.0.113.50",

            "destination_ip":
                "10.0.0.10",

            "destination_port":
                22,

            "protocol":
                "TCP",

            "action":
                "DENY",

            "status":
                "deny",
        },

        # ----------------------------------------------------
        # POST-SUCCESS CLOUDTRAIL
        # ----------------------------------------------------

        {
            "timestamp":
                "2026-08-14T10:25:01Z",

            "source":
                "ec2.amazonaws.com",

            "event_type":
                "AuthorizeSecurityGroupIngress",

            "source_ip":
                "203.0.113.50",

            "username":
                "admin",

            "action":
                "AuthorizeSecurityGroupIngress",

            "status":
                "success",

            "event_id":
                "aws-event-001",
        },

        # ----------------------------------------------------
        # WRONG IP
        # ----------------------------------------------------

        {
            "timestamp":
                "2026-08-14T10:20:00Z",

            "source":
                "Firewall",

            "event_type":
                "FirewallNetworkEvent",

            "source_ip":
                "198.51.100.20",

            "destination_ip":
                "10.0.0.20",

            "destination_port":
                443,

            "protocol":
                "TCP",

            "action":
                "ALLOW",

            "status":
                "allow",
        },

        # ----------------------------------------------------
        # WRONG USERNAME
        # ----------------------------------------------------

        {
            "timestamp":
                "2026-08-14T10:15:00Z",

            "source":
                "s3.amazonaws.com",

            "event_type":
                "PutBucketPolicy",

            "source_ip":
                "203.0.113.50",

            "username":
                "different_user",

            "action":
                "PutBucketPolicy",

            "status":
                "success",

            "event_id":
                "aws-event-002",
        },

        # ----------------------------------------------------
        # OUTSIDE WINDOW
        # ----------------------------------------------------

        {
            "timestamp":
                "2026-08-14T11:00:00Z",

            "source":
                "iam.amazonaws.com",

            "event_type":
                "CreateUser",

            "source_ip":
                "203.0.113.50",

            "username":
                "admin",

            "action":
                "CreateUser",

            "status":
                "success",

            "event_id":
                "aws-event-003",
        },

        # ----------------------------------------------------
        # CLOUDTRAIL WITHOUT USERNAME
        # ----------------------------------------------------

        {
            "timestamp":
                "2026-08-14T10:18:00Z",

            "source":
                "cloudtrail.amazonaws.com",

            "event_type":
                "DescribeInstances",

            "source_ip":
                "203.0.113.50",

            "action":
                "DescribeInstances",

            "status":
                "success",

            "event_id":
                "aws-event-004",
        },

        # ----------------------------------------------------
        # DUPLICATE CLOUDTRAIL EVENT
        # ----------------------------------------------------

        {
            "timestamp":
                "2026-08-14T10:18:00Z",

            "source":
                "cloudtrail.amazonaws.com",

            "event_type":
                "DescribeInstances",

            "source_ip":
                "203.0.113.50",

            "action":
                "DescribeInstances",

            "status":
                "success",

            "event_id":
                "aws-event-004",
        },
    ]

    # ========================================================
    # RUN CORRELATION
    # ========================================================

    correlations = correlate_events(
        alerts=test_alerts,
        normalized_events=test_events,
        firewall_window_minutes=30,
        cloudtrail_window_minutes=30,
    )

    # ========================================================
    # PRINT RESULT
    # ========================================================

    print_correlation_result(
        correlations
    )

    print()
    print("=" * 70)
    print(
        "CORRELATOR TEST COMPLETE"
    )
    print("=" * 70)