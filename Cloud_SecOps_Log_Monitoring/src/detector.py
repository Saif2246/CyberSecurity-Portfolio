from datetime import datetime, timezone
import hashlib
import ipaddress


# ============================================================
# KIROTRACE - SSH DETECTION ENGINE
# ============================================================
#
# RESPONSIBILITY
#
# DAY 3A
#   Same Source IP
#   + Same Username
#   + Failed SSH threshold
#   + Detection time window
#
#   -> Possible SSH Brute Force
#
#
# DAY 3B
#   Qualifying brute-force window
#   + Successful SSH login
#   + Same Source IP
#   + Same Username
#   + Success AFTER failed activity
#   + Correlation window
#
#   -> Possible Account Compromise
#
#
# IMPORTANT
#
# Cross-domain correlation with Firewall / CloudTrail
# belongs to correlator.py.
#
# detector.py MUST NOT perform Day 4 correlation.
#
# Detection identifies suspicious patterns.
# It does NOT prove malicious intent or compromise.
#
# ============================================================


# ============================================================
# CONFIGURATION
# ============================================================

DEFAULT_FAILED_ATTEMPT_THRESHOLD = 5

DEFAULT_DETECTION_WINDOW_MINUTES = 5

DEFAULT_CORRELATION_WINDOW_MINUTES = 5


# ============================================================
# SEVERITY
# ============================================================

BRUTE_FORCE_SEVERITY = "HIGH"

COMPROMISE_SEVERITY = "CRITICAL"

DETECTION_CONFIDENCE = "HIGH"

DETECTION_STATUS = "SUSPICIOUS"


# ============================================================
# SECURITY DOMAIN
# ============================================================

SSH_SOURCE = "linux ssh"


# ============================================================
# TIMESTAMP PARSER
# ============================================================

def parse_timestamp(timestamp):
    """
    Convert supported timestamp values into timezone-aware UTC.

    Supported examples:

        2026-08-14T10:05:33Z
        2026-08-14T10:05:33+00:00
        2026-08-14T10:05:33
        2026-08-14 10:05:33

    Returns:
        timezone-aware datetime in UTC
        or None if invalid
    """

    if timestamp is None:
        return None

    if isinstance(timestamp, datetime):

        parsed_time = timestamp

        if parsed_time.tzinfo is None:
            return parsed_time.replace(
                tzinfo=timezone.utc
            )

        return parsed_time.astimezone(
            timezone.utc
        )

    if not isinstance(timestamp, str):
        return None

    timestamp = timestamp.strip()

    if not timestamp:
        return None

    try:

        if timestamp.endswith("Z"):
            timestamp = (
                timestamp[:-1]
                + "+00:00"
            )

        parsed_time = datetime.fromisoformat(
            timestamp
        )

        if parsed_time.tzinfo is None:

            parsed_time = parsed_time.replace(
                tzinfo=timezone.utc
            )

        else:

            parsed_time = parsed_time.astimezone(
                timezone.utc
            )

        return parsed_time

    except (
        TypeError,
        ValueError,
        AttributeError
    ):
        return None


# ============================================================
# NORMALIZATION
# ============================================================

def normalize_text(value):
    """
    Normalize arbitrary text into lowercase stripped text.
    """

    if value is None:
        return None

    value = str(value).strip()

    if not value:
        return None

    return value.lower()


def normalize_ip(source_ip):
    """
    Validate and normalize IPv4 / IPv6.

    Returns canonical IP string or None.
    """

    if source_ip is None:
        return None

    source_ip = str(source_ip).strip()

    if not source_ip:
        return None

    try:

        return str(
            ipaddress.ip_address(
                source_ip
            )
        )

    except ValueError:
        return None


def normalize_username(username):
    """
    Normalize username.
    """

    return normalize_text(
        username
    )


def safe_int(value, default=0):
    """
    Safely convert value to integer.
    """

    if isinstance(value, bool):
        return default

    try:
        return int(value)

    except (
        TypeError,
        ValueError
    ):
        return default


def safe_float(value, default=0.0):
    """
    Safely convert value to float.
    """

    if isinstance(value, bool):
        return default

    try:
        return float(value)

    except (
        TypeError,
        ValueError
    ):
        return default


# ============================================================
# EVENT TYPE
# ============================================================

def get_event_type(event):
    """
    Extract normalized event type.

    Supports:
        event_type
        event_name
    """

    if not isinstance(event, dict):
        return None

    return (
        normalize_text(
            event.get("event_type")
        )
        or
        normalize_text(
            event.get("event_name")
        )
    )


# ============================================================
# EVENT SOURCE
# ============================================================

def get_event_source(event):
    """
    Extract normalized event source.

    Supports:
        event_source
        source
    """

    if not isinstance(event, dict):
        return None

    return (
        normalize_text(
            event.get("event_source")
        )
        or
        normalize_text(
            event.get("source")
        )
    )


# ============================================================
# SSH EVENT VALIDATION
# ============================================================

def is_ssh_authentication_event(event):
    """
    Determine whether an event represents SSH authentication.
    """

    if not isinstance(event, dict):
        return False

    event_type = get_event_type(event)

    event_source = get_event_source(event)

    # Normalized:
    # SSHAuthentication -> ssauthentication
    #
    # event_type comparison therefore works
    # after normalize_text().

    if event_type == "sshauthentication":
        return True

    if event_source == SSH_SOURCE:
        return True

    return False


def is_failed_ssh_event(event):
    """
    Determine whether event is a failed SSH authentication.
    """

    if not is_ssh_authentication_event(event):
        return False

    return (
        normalize_text(
            event.get("status")
        )
        == "failed"
    )


def is_successful_ssh_event(event):
    """
    Determine whether event is a successful SSH authentication.
    """

    if not is_ssh_authentication_event(event):
        return False

    return (
        normalize_text(
            event.get("status")
        )
        == "success"
    )


# ============================================================
# EVENT IDENTITY
# ============================================================

def get_event_identity(event):
    """
    SSH correlation identity:

        source_ip + username

    Both fields are required.
    """

    if not isinstance(event, dict):
        return None

    source_ip = normalize_ip(
        event.get("source_ip")
    )

    username = normalize_username(
        event.get("username")
    )

    if source_ip is None:
        return None

    if username is None:
        return None

    return (
        source_ip,
        username
    )


# ============================================================
# ALERT ID
# ============================================================

def generate_alert_id(
    prefix,
    source_ip,
    username,
    attack_window_number
):
    """
    Generate deterministic alert ID.
    """

    identity = (
        f"{prefix}|"
        f"{source_ip}|"
        f"{username}|"
        f"{attack_window_number}"
    )

    digest = hashlib.sha256(
        identity.encode("utf-8")
    ).hexdigest()[:12]

    return (
        f"{prefix}-"
        f"{digest}-"
        f"{attack_window_number}"
    )


# ============================================================
# GROUP SSH EVENTS
# ============================================================

def group_ssh_events(events):
    """
    Group SSH authentication events by:

        source_ip + username

    Returns:

        {
            (source_ip, username): {
                "failed": [...],
                "successful": [...]
            }
        }
    """

    groups = {}

    if not isinstance(events, list):
        return groups

    for event in events:

        if not is_ssh_authentication_event(
            event
        ):
            continue

        identity = get_event_identity(
            event
        )

        if identity is None:
            continue

        groups.setdefault(
            identity,
            {
                "failed": [],
                "successful": []
            }
        )

        if is_failed_ssh_event(event):

            groups[
                identity
            ]["failed"].append(event)

        elif is_successful_ssh_event(event):

            groups[
                identity
            ]["successful"].append(event)

    return groups


# ============================================================
# TIMESTAMPED EVENTS
# ============================================================

def get_timestamped_events(events):
    """
    Return valid timestamped events sorted chronologically.

    Output:

        [
            (datetime, event),
            ...
        ]
    """

    timestamped_events = []

    if not isinstance(events, list):
        return timestamped_events

    for event in events:

        if not isinstance(event, dict):
            continue

        event_time = parse_timestamp(
            event.get("timestamp")
        )

        if event_time is None:
            continue

        timestamped_events.append(
            (
                event_time,
                event
            )
        )

    timestamped_events.sort(
        key=lambda item: item[0]
    )

    return timestamped_events


# ============================================================
# DAY 3A
# FIND THRESHOLD WINDOWS
# ============================================================

def find_threshold_windows(
    failed_events,
    threshold,
    detection_window_seconds
):
    """
    Find non-overlapping qualifying brute-force windows.

    A window qualifies when:

        failed attempts >= threshold

    within:

        detection_window_seconds

    The first event of each candidate window becomes
    the anchor timestamp.

    Once a qualifying burst is found, its events are
    consumed so that the same attack burst does not
    repeatedly generate overlapping alerts.
    """

    if not failed_events:
        return []

    threshold = safe_int(
        threshold,
        default=0
    )

    detection_window_seconds = safe_float(
        detection_window_seconds,
        default=0.0
    )

    if threshold <= 0:
        return []

    if detection_window_seconds <= 0:
        return []

    windows = []

    index = 0

    event_count = len(
        failed_events
    )

    while index < event_count:

        window_start_time = (
            failed_events[index][0]
        )

        window_events = []

        current_index = index

        while current_index < event_count:

            current_time = (
                failed_events[
                    current_index
                ][0]
            )

            elapsed_seconds = (
                current_time
                - window_start_time
            ).total_seconds()

            if (
                elapsed_seconds
                <= detection_window_seconds
            ):

                window_events.append(
                    failed_events[
                        current_index
                    ]
                )

                current_index += 1

            else:
                break

        if len(window_events) >= threshold:

            windows.append(
                window_events
            )

            # Consume this burst.
            index = current_index

        else:

            # Move anchor forward by one event.
            index += 1

    return windows


# ============================================================
# DAY 3B
# FIND CORRELATED SSH SUCCESS
# ============================================================

def find_correlated_success(
    qualifying_failed_events,
    successful_events,
    correlation_window_seconds
):
    """
    Find a successful SSH login occurring:

        AFTER the final failed attempt

    and:

        WITHIN the correlation window.

    Returns:
        correlation dictionary
        or None
    """

    if not qualifying_failed_events:
        return None

    if not successful_events:
        return None

    correlation_window_seconds = safe_float(
        correlation_window_seconds,
        default=0.0
    )

    if correlation_window_seconds <= 0:
        return None

    last_failed_time = (
        qualifying_failed_events[-1][0]
    )

    last_failed_event = (
        qualifying_failed_events[-1][1]
    )

    for (
        success_time,
        success_event
    ) in successful_events:

        time_difference = (
            success_time
            - last_failed_time
        ).total_seconds()

        # Success must happen AFTER
        # the failed activity.
        if time_difference <= 0:
            continue

        if (
            time_difference
            <= correlation_window_seconds
        ):

            return {
                "success_time":
                    success_time,

                "success_event":
                    success_event,

                "last_failed_time":
                    last_failed_time,

                "last_failed_event":
                    last_failed_event,

                "time_difference_seconds":
                    int(
                        time_difference
                    )
            }

    return None


# ============================================================
# DAY 3A
# BUILD BRUTE FORCE ALERT
# ============================================================

def build_brute_force_alert(
    source_ip,
    username,
    qualifying_events,
    threshold,
    detection_window_minutes,
    attack_window_number
):
    """
    Build Day 3A brute-force alert.
    """

    if not qualifying_events:
        return None

    first_failed_time = (
        qualifying_events[0][0]
    )

    last_failed_time = (
        qualifying_events[-1][0]
    )

    first_failed_event = (
        qualifying_events[0][1]
    )

    last_failed_event = (
        qualifying_events[-1][1]
    )

    actual_window_seconds = (
        last_failed_time
        - first_failed_time
    ).total_seconds()

    failed_attempts = len(
        qualifying_events
    )

    return {

        "alert_id":
            generate_alert_id(
                "SSH-BRUTE",
                source_ip,
                username,
                attack_window_number
            ),

        "alert_type":
            "Possible SSH Brute Force",

        "detection_stage":
            "Day 3A",

        "source_ip":
            source_ip,

        "username":
            username,

        "failed_attempts":
            failed_attempts,

        "threshold":
            threshold,

        "threshold_exceeded":
            failed_attempts >= threshold,

        "attack_window_number":
            attack_window_number,

        "first_failed_timestamp":
            first_failed_event.get(
                "timestamp"
            ),

        "last_failed_timestamp":
            last_failed_event.get(
                "timestamp"
            ),

        "detection_window_minutes":
            detection_window_minutes,

        "actual_attack_window_seconds":
            int(
                actual_window_seconds
            ),

        "severity":
            BRUTE_FORCE_SEVERITY,

        "confidence":
            DETECTION_CONFIDENCE,

        "status":
            DETECTION_STATUS,

        "evidence_count":
            failed_attempts,

        "description":
            (
                "Multiple failed SSH authentication "
                "attempts from the same source IP and "
                "username reached or exceeded the "
                "configured threshold within the "
                "detection window."
            )
    }


# ============================================================
# DAY 3B
# BUILD COMPROMISE ALERT
# ============================================================

def build_compromise_alert(
    source_ip,
    username,
    qualifying_failed_events,
    correlation,
    correlation_window_minutes,
    attack_window_number
):
    """
    Build Day 3B possible account compromise alert.
    """

    if not qualifying_failed_events:
        return None

    if not correlation:
        return None

    first_failed_event = (
        qualifying_failed_events[0][1]
    )

    last_failed_event = (
        qualifying_failed_events[-1][1]
    )

    success_event = (
        correlation.get(
            "success_event"
        )
    )

    if not isinstance(
        success_event,
        dict
    ):
        return None

    return {

        "alert_id":
            generate_alert_id(
                "SSH-COMPROMISE",
                source_ip,
                username,
                attack_window_number
            ),

        "alert_type":
            "Possible Account Compromise",

        "detection_stage":
            "Day 3B",

        "source_ip":
            source_ip,

        "username":
            username,

        "failed_attempts":
            len(
                qualifying_failed_events
            ),

        "successful_login":
            True,

        "attack_window_number":
            attack_window_number,

        "first_failed_timestamp":
            first_failed_event.get(
                "timestamp"
            ),

        "last_failed_timestamp":
            last_failed_event.get(
                "timestamp"
            ),

        "successful_login_timestamp":
            success_event.get(
                "timestamp"
            ),

        "time_difference_seconds":
            correlation.get(
                "time_difference_seconds",
                0
            ),

        "correlation_window_minutes":
            correlation_window_minutes,

        "severity":
            COMPROMISE_SEVERITY,

        "confidence":
            DETECTION_CONFIDENCE,

        "status":
            DETECTION_STATUS,

        "evidence_count":
            len(
                qualifying_failed_events
            ) + 1,

        "description":
            (
                "A successful SSH login occurred shortly "
                "after multiple failed authentication "
                "attempts from the same source IP and "
                "username. This pattern may indicate "
                "successful credential use following "
                "suspicious authentication activity; "
                "additional evidence is required to "
                "confirm compromise."
            )
    }


# ============================================================
# ALERT DEDUPLICATION
# ============================================================

def deduplicate_alerts(alerts):
    """
    Remove duplicate detector alerts.

    Day 4 evidence-based deduplication has intentionally
    been removed because Day 4 belongs to correlator.py.
    """

    if not isinstance(alerts, list):
        return []

    unique_alerts = []

    seen_alerts = set()

    for alert in alerts:

        if not isinstance(alert, dict):
            continue

        alert_key = (
            normalize_text(
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
                "first_failed_timestamp"
            ),

            alert.get(
                "last_failed_timestamp"
            ),

            alert.get(
                "successful_login_timestamp"
            ),

            alert.get(
                "attack_window_number"
            )
        )

        if alert_key in seen_alerts:
            continue

        seen_alerts.add(
            alert_key
        )

        unique_alerts.append(
            alert
        )

    return unique_alerts


# ============================================================
# SEVERITY SORTING
# ============================================================

def sort_alerts(alerts):
    """
    Sort alerts by severity and timestamp.
    """

    if not isinstance(alerts, list):
        return []

    severity_priority = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "INFO": 0
    }

    def sort_key(alert):

        severity = normalize_text(
            alert.get(
                "severity"
            )
        )

        timestamp = (
            alert.get(
                "successful_login_timestamp"
            )
            or
            alert.get(
                "last_failed_timestamp"
            )
            or
            ""
        )

        return (
            severity_priority.get(
                str(
                    severity or ""
                ).upper(),
                0
            ),
            timestamp,
            str(
                alert.get(
                    "source_ip",
                    ""
                )
            ),
            str(
                alert.get(
                    "username",
                    ""
                )
            )
        )

    return sorted(
        alerts,
        key=sort_key,
        reverse=True
    )


# ============================================================
# DETECTION ENGINE
# ============================================================

def detect_failed_ssh_attempts(
    events,
    threshold=DEFAULT_FAILED_ATTEMPT_THRESHOLD,
    detection_window_minutes=(
        DEFAULT_DETECTION_WINDOW_MINUTES
    ),
    correlation_window_minutes=(
        DEFAULT_CORRELATION_WINDOW_MINUTES
    )
):
    """
    Main KiroTrace SSH detection engine.

    RESPONSIBILITY:

        Day 3A:
            SSH brute-force detection.

        Day 3B:
            SSH brute-force followed by
            successful SSH login.

    NOT RESPONSIBLE FOR:

        Firewall correlation
        CloudTrail correlation
        Cross-domain correlation
        Incident aggregation

    Those responsibilities belong to:

        correlator.py
        incident_engine.py

    Returns:
        List of detector alerts.
    """

    if not isinstance(events, list):
        return []

    # ========================================================
    # CONFIGURATION VALIDATION
    # ========================================================

    threshold = safe_int(
        threshold,
        default=0
    )

    detection_window_minutes = safe_float(
        detection_window_minutes,
        default=0.0
    )

    correlation_window_minutes = safe_float(
        correlation_window_minutes,
        default=0.0
    )

    if threshold <= 0:
        return []

    if detection_window_minutes <= 0:
        return []

    if correlation_window_minutes <= 0:
        return []

    detection_window_seconds = (
        detection_window_minutes * 60
    )

    correlation_window_seconds = (
        correlation_window_minutes * 60
    )

    # ========================================================
    # GROUP SSH EVENTS
    # ========================================================

    ssh_groups = group_ssh_events(
        events
    )

    alerts = []

    # ========================================================
    # PROCESS EACH SSH IDENTITY
    # ========================================================

    for (
        source_ip,
        username
    ), group in ssh_groups.items():

        # ====================================================
        # FAILED EVENTS
        # ====================================================

        failed_events = get_timestamped_events(
            group.get(
                "failed",
                []
            )
        )

        if not failed_events:
            continue

        # ====================================================
        # SUCCESS EVENTS
        # ====================================================

        successful_events = get_timestamped_events(
            group.get(
                "successful",
                []
            )
        )

        # ====================================================
        # DAY 3A
        # ====================================================

        qualifying_windows = find_threshold_windows(
            failed_events=failed_events,
            threshold=threshold,
            detection_window_seconds=(
                detection_window_seconds
            )
        )

        if not qualifying_windows:
            continue

        # ====================================================
        # PROCESS EACH ATTACK WINDOW
        # ====================================================

        for (
            window_number,
            qualifying_failed_events
        ) in enumerate(
            qualifying_windows,
            start=1
        ):

            # =================================================
            # DAY 3A
            # =================================================

            brute_force_alert = (
                build_brute_force_alert(
                    source_ip=source_ip,
                    username=username,
                    qualifying_events=(
                        qualifying_failed_events
                    ),
                    threshold=threshold,
                    detection_window_minutes=(
                        detection_window_minutes
                    ),
                    attack_window_number=(
                        window_number
                    )
                )
            )

            if brute_force_alert is None:
                continue

            alerts.append(
                brute_force_alert
            )

            # =================================================
            # DAY 3B
            # =================================================

            if successful_events:

                correlation = (
                    find_correlated_success(
                        qualifying_failed_events=(
                            qualifying_failed_events
                        ),
                        successful_events=(
                            successful_events
                        ),
                        correlation_window_seconds=(
                            correlation_window_seconds
                        )
                    )
                )

                if correlation is not None:

                    compromise_alert = (
                        build_compromise_alert(
                            source_ip=source_ip,
                            username=username,
                            qualifying_failed_events=(
                                qualifying_failed_events
                            ),
                            correlation=correlation,
                            correlation_window_minutes=(
                                correlation_window_minutes
                            ),
                            attack_window_number=(
                                window_number
                            )
                        )
                    )

                    if compromise_alert is not None:

                        alerts.append(
                            compromise_alert
                        )

    # ========================================================
    # FINAL PROCESSING
    # ========================================================

    alerts = deduplicate_alerts(
        alerts
    )

    alerts = sort_alerts(
        alerts
    )

    return alerts


# ============================================================
# DIRECT TEST
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 75)
    print(
        "KIROTRACE SSH DETECTION ENGINE"
    )
    print("=" * 75)

    # ========================================================
    # TEST DATA
    # ========================================================

    test_events = [

        {
            "timestamp":
                "2026-08-14T10:05:33+00:00",

            "event_name":
                "SSHAuthentication",

            "event_source":
                "Linux SSH",

            "source_ip":
                "203.0.113.50",

            "username":
                "admin",

            "status":
                "failed"
        },

        {
            "timestamp":
                "2026-08-14T10:05:38+00:00",

            "event_name":
                "SSHAuthentication",

            "event_source":
                "Linux SSH",

            "source_ip":
                "203.0.113.50",

            "username":
                "admin",

            "status":
                "failed"
        },

        {
            "timestamp":
                "2026-08-14T10:05:43+00:00",

            "event_name":
                "SSHAuthentication",

            "event_source":
                "Linux SSH",

            "source_ip":
                "203.0.113.50",

            "username":
                "admin",

            "status":
                "failed"
        },

        {
            "timestamp":
                "2026-08-14T10:05:48+00:00",

            "event_name":
                "SSHAuthentication",

            "event_source":
                "Linux SSH",

            "source_ip":
                "203.0.113.50",

            "username":
                "admin",

            "status":
                "failed"
        },

        {
            "timestamp":
                "2026-08-14T10:05:53+00:00",

            "event_name":
                "SSHAuthentication",

            "event_source":
                "Linux SSH",

            "source_ip":
                "203.0.113.50",

            "username":
                "admin",

            "status":
                "failed"
        },

        # Success AFTER the failed burst.
        {
            "timestamp":
                "2026-08-14T10:06:02+00:00",

            "event_name":
                "SSHAuthentication",

            "event_source":
                "Linux SSH",

            "source_ip":
                "203.0.113.50",

            "username":
                "admin",

            "status":
                "success"
        },

        # These events are intentionally present to demonstrate
        # that detector.py ignores cross-domain telemetry.
        #
        # correlator.py is responsible for these.
        {
            "timestamp":
                "2026-08-14T10:05:55+00:00",

            "event_name":
                "FirewallNetworkEvent",

            "event_source":
                "Firewall",

            "source_ip":
                "203.0.113.50",

            "status":
                "deny",

            "action":
                "deny",

            "destination_ip":
                "10.0.0.10",

            "destination_port":
                22,

            "protocol":
                "TCP"
        },

        {
            "timestamp":
                "2026-08-14T10:07:00+00:00",

            "event_name":
                "ConsoleLogin",

            "event_source":
                "CloudTrail",

            "source_ip":
                "203.0.113.50",

            "username":
                "admin",

            "status":
                "success",

            "service_source":
                "signin.amazonaws.com",

            "aws_region":
                "us-east-1"
        }
    ]

    # ========================================================
    # RUN DETECTOR
    # ========================================================

    results = detect_failed_ssh_attempts(
        test_events,
        threshold=5,
        detection_window_minutes=5,
        correlation_window_minutes=5
    )

    # ========================================================
    # DISPLAY
    # ========================================================

    print()
    print(
        f"Total Detector Alerts: "
        f"{len(results)}"
    )
    print()

    for index, alert in enumerate(
        results,
        start=1
    ):

        print("-" * 75)

        print(
            f"Alert #{index}"
        )

        print(
            f"Alert ID: "
            f"{alert.get('alert_id')}"
        )

        print(
            f"Alert Type: "
            f"{alert.get('alert_type')}"
        )

        print(
            f"Detection Stage: "
            f"{alert.get('detection_stage')}"
        )

        print(
            f"Source IP: "
            f"{alert.get('source_ip')}"
        )

        print(
            f"Username: "
            f"{alert.get('username')}"
        )

        print(
            f"Failed Attempts: "
            f"{alert.get('failed_attempts')}"
        )

        print(
            f"Severity: "
            f"{alert.get('severity')}"
        )

        print(
            f"Confidence: "
            f"{alert.get('confidence')}"
        )

        print(
            f"Status: "
            f"{alert.get('status')}"
        )

        print(
            f"First Failed: "
            f"{alert.get('first_failed_timestamp')}"
        )

        print(
            f"Last Failed: "
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
                f"Time Difference: "
                f"{alert.get('time_difference_seconds')} "
                f"seconds"
            )

        print()

        print(
            f"Description: "
            f"{alert.get('description')}"
        )

    print()
    print("=" * 75)
    print(
        "DETECTOR TEST COMPLETE"
    )
    print("=" * 75)