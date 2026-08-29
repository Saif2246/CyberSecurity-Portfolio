import json
import re
import ipaddress
import hashlib

from pathlib import Path
from datetime import datetime, timezone


# ============================================================
# KIROTRACE - LOG PARSER
# ============================================================
#
# Responsibility:
#
#   Raw logs
#       |
#       v
#   Structured events
#       |
#       v
#   Normalization
#       |
#       v
#   Validation
#       |
#       v
#   Enrichment
#       |
#       v
#   Deduplication
#       |
#       v
#   Chronological sorting
#       |
#       v
#   Correlation-ready metadata
#
# Parser does NOT perform:
#
#   - attack-story generation
#   - threshold detection
#   - temporal correlation decisions
#   - incident creation
#   - incident severity decisions
#   - risk scoring
#
# Those remain in:
#
#   detector.py
#   correlator.py
#   incident_engine.py
#
# ============================================================


# ============================================================
# PROJECT PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"

CLOUDTRAIL_FILE = DATA_DIR / "cloudtrail_sample.json"
LINUX_LOG_FILE = DATA_DIR / "linux_auth_sample.log"
FIREWALL_LOG_FILE = DATA_DIR / "firewall_sample.log"


# ============================================================
# CONFIGURATION
# ============================================================

SAMPLE_LOG_YEAR = 2026


SUPPORTED_PROTOCOLS = {
    "TCP",
    "UDP",
    "ICMP",
    "GRE",
    "ESP",
    "AH",
}


HIGH_RISK_PORTS = {
    21,      # FTP
    22,      # SSH
    23,      # Telnet
    25,      # SMTP
    3389,    # RDP
    445,     # SMB
    1433,    # MSSQL
    3306,    # MySQL
    5432,    # PostgreSQL
    6379,    # Redis
    9200,    # Elasticsearch
}


COMMON_PORT_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    3306: "MYSQL",
    3389: "RDP",
    5432: "POSTGRESQL",
    6379: "REDIS",
    9200: "ELASTICSEARCH",
}


# ============================================================
# GENERIC HELPERS
# ============================================================

def clean_value(value):
    """
    Normalize a basic value.

    Strings:
        - surrounding whitespace removed
        - empty strings become None

    Non-string values are preserved.
    """

    if value is None:
        return None

    if isinstance(value, str):
        value = value.strip()

        if not value:
            return None

    return value


def clean_ip(value):
    """
    Validate IPv4 or IPv6 address.

    Returns:
        normalized IP string
        None if invalid
    """

    value = clean_value(value)

    if value is None:
        return None

    if isinstance(value, bool):
        return None

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def clean_port(value):
    """
    Validate network port.

    Valid range:
        1 - 65535
    """

    if value is None:
        return None

    if isinstance(value, bool):
        return None

    try:
        port = int(value)
    except (TypeError, ValueError):
        return None

    if 1 <= port <= 65535:
        return port

    return None


def normalize_status(status):
    """
    Normalize status to lowercase.
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

    Unknown protocols are preserved.
    """

    protocol = clean_value(protocol)

    if protocol is None:
        return None

    if isinstance(protocol, str):
        return protocol.upper()

    return protocol


def normalize_event_source(source):
    """
    Normalize event source.
    """

    source = clean_value(source)

    if source is None:
        return None

    return str(source).strip()


def normalize_username(username):
    """
    Normalize username for consistent comparison.

    Identity fields such as principal_id and user_arn
    remain separate.
    """

    username = clean_value(username)

    if username is None:
        return None

    return str(username).strip()


def normalize_identity_value(value):
    """
    Normalize identity value for correlation.

    This does not modify the original identity field.
    """

    value = clean_value(value)

    if value is None:
        return None

    return str(value).strip().lower()


# ============================================================
# TIMESTAMP HELPERS
# ============================================================

def normalize_timestamp(timestamp):
    """
    Normalize timestamp to UTC ISO format.

    Supported examples:

        2026-08-14T10:10:05Z
        2026-08-14T10:10:05+00:00
        2026-08-14 10:10:05

    Naive timestamps are interpreted as UTC.
    """

    timestamp = clean_value(timestamp)

    if timestamp is None:
        return None

    if not isinstance(timestamp, str):
        return None

    value = timestamp.strip()

    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"

        parsed = datetime.fromisoformat(value)

        if parsed.tzinfo is None:
            parsed = parsed.replace(
                tzinfo=timezone.utc
            )
        else:
            parsed = parsed.astimezone(
                timezone.utc
            )

        return parsed.isoformat()

    except (ValueError, TypeError):
        return None


def parse_timestamp(timestamp):
    """
    Convert timestamp into timezone-aware datetime.
    """

    normalized = normalize_timestamp(timestamp)

    if normalized is None:
        return None

    try:
        return datetime.fromisoformat(normalized)

    except (ValueError, TypeError):
        return None


def get_temporal_metadata(timestamp):
    """
    Generate temporal metadata.

    Parser does not perform temporal correlation.
    """

    parsed = parse_timestamp(timestamp)

    if parsed is None:
        return {
            "event_date": None,
            "event_hour": None,
            "event_minute": None,
            "epoch_seconds": None,
        }

    return {
        "event_date": parsed.date().isoformat(),
        "event_hour": parsed.hour,
        "event_minute": parsed.minute,
        "epoch_seconds": int(parsed.timestamp()),
    }


# ============================================================
# ID GENERATION
# ============================================================

def generate_event_id(event):
    """
    Generate deterministic event ID.

    If source already provides event_id,
    preserve it.

    Otherwise generate SHA-256 fingerprint.

    IMPORTANT:
    line_number is intentionally NOT part of the
    fingerprint because it represents log provenance,
    not event identity.
    """

    if not isinstance(event, dict):
        return None

    existing_id = clean_value(
        event.get("event_id")
    )

    if existing_id:
        return str(existing_id)

    identity_fields = [
        event.get("timestamp"),
        event.get("event_name"),
        event.get("event_source"),
        event.get("source_ip"),
        event.get("destination_ip"),
        event.get("destination_port"),
        event.get("source_port"),
        event.get("protocol"),
        event.get("username"),
        event.get("principal_id"),
        event.get("user_arn"),
        event.get("account_id"),
        event.get("action"),
        event.get("status"),
        event.get("service_source"),
        event.get("request_id"),
    ]

    raw_identifier = "|".join(
        "" if value is None else str(value)
        for value in identity_fields
    )

    return hashlib.sha256(
        raw_identifier.encode("utf-8")
    ).hexdigest()[:20]


# ============================================================
# SOURCE CLASSIFICATION
# ============================================================

def classify_source(event_source):
    """
    Classify parser source.

    CloudTrail -> cloud
    Linux SSH  -> authentication
    Firewall   -> network
    """

    source = normalize_event_source(
        event_source
    )

    if not source:
        return "unknown"

    source_lower = source.lower()

    if "cloudtrail" in source_lower:
        return "cloud"

    if "linux" in source_lower:
        return "authentication"

    if "ssh" in source_lower:
        return "authentication"

    if "firewall" in source_lower:
        return "network"

    return "unknown"


# ============================================================
# ACTOR / IDENTITY
# ============================================================

def extract_actor_identity(event):
    """
    Determine useful actor identity.

    Priority:

        username
        principal_id
        user_arn
        account_id
        source_ip
    """

    if not isinstance(event, dict):
        return None

    return (
        clean_value(event.get("username"))
        or clean_value(event.get("principal_id"))
        or clean_value(event.get("user_arn"))
        or clean_value(event.get("account_id"))
        or clean_value(event.get("source_ip"))
    )


# ============================================================
# CORRELATION METADATA
# ============================================================

def build_correlation_key(event):
    """
    Build stable primary grouping key.

    IMPORTANT:
    This is only a grouping aid.

    It does NOT decide whether
    two events belong to the same attack.
    """

    if not isinstance(event, dict):
        return None

    source_ip = clean_ip(
        event.get("source_ip")
    )

    username = normalize_identity_value(
        event.get("username")
    )

    principal_id = normalize_identity_value(
        event.get("principal_id")
    )

    account_id = normalize_identity_value(
        event.get("account_id")
    )

    if source_ip and username:
        return (
            f"ip:{source_ip}"
            f"|user:{username}"
        )

    if source_ip and principal_id:
        return (
            f"ip:{source_ip}"
            f"|principal:{principal_id}"
        )

    if source_ip and account_id:
        return (
            f"ip:{source_ip}"
            f"|account:{account_id}"
        )

    if source_ip:
        return f"ip:{source_ip}"

    if username:
        return f"user:{username}"

    if principal_id:
        return f"principal:{principal_id}"

    if account_id:
        return f"account:{account_id}"

    actor = extract_actor_identity(event)

    if actor:
        return (
            f"actor:"
            f"{normalize_identity_value(actor)}"
        )

    return None


def build_correlation_dimensions(event):
    """
    Build multiple independent correlation dimensions.

    These are intentionally separate from the final
    correlation decision.

    A future correlator can decide which dimensions
    are relevant for a particular detection rule.
    """

    if not isinstance(event, dict):
        return {}

    dimensions = {}

    source_ip = clean_ip(
        event.get("source_ip")
    )

    destination_ip = clean_ip(
        event.get("destination_ip")
    )

    username = normalize_identity_value(
        event.get("username")
    )

    principal_id = normalize_identity_value(
        event.get("principal_id")
    )

    account_id = normalize_identity_value(
        event.get("account_id")
    )

    user_arn = normalize_identity_value(
        event.get("user_arn")
    )

    service_source = normalize_identity_value(
        event.get("service_source")
    )

    destination_port = clean_port(
        event.get("destination_port")
    )

    if source_ip:
        dimensions["source_ip"] = source_ip

    if destination_ip:
        dimensions["destination_ip"] = destination_ip

    if username:
        dimensions["username"] = username

    if principal_id:
        dimensions["principal_id"] = principal_id

    if account_id:
        dimensions["account_id"] = account_id

    if user_arn:
        dimensions["user_arn"] = user_arn

    if service_source:
        dimensions["service_source"] = service_source

    if destination_port is not None:
        dimensions["destination_port"] = destination_port

    return dimensions


# ============================================================
# NETWORK HELPERS
# ============================================================

def classify_destination_port(port):
    """
    Classify common network service ports.
    """

    port = clean_port(port)

    if port is None:
        return None

    return COMMON_PORT_SERVICES.get(
        port,
        "UNKNOWN"
    )


def is_high_risk_port(port):
    """
    Determine whether port is high-risk.
    """

    port = clean_port(port)

    if port is None:
        return False

    return port in HIGH_RISK_PORTS


def normalize_network_fields(event):
    """
    Normalize common network fields.
    """

    if not isinstance(event, dict):
        return event

    if "source_ip" in event:
        event["source_ip"] = clean_ip(
            event.get("source_ip")
        )

    if "destination_ip" in event:
        event["destination_ip"] = clean_ip(
            event.get("destination_ip")
        )

    if "destination_port" in event:
        event["destination_port"] = clean_port(
            event.get("destination_port")
        )

    if "source_port" in event:
        event["source_port"] = clean_port(
            event.get("source_port")
        )

    if "protocol" in event:
        event["protocol"] = normalize_protocol(
            event.get("protocol")
        )

    return event


# ============================================================
# UNIFIED EVENT BUILDER
# ============================================================

def build_event(
    timestamp,
    event_name,
    event_source,
    source_ip=None,
    username=None,
    action=None,
    status=None,
    **extra_fields
):
    """
    Build unified parser-level event.
    """

    normalized_timestamp = normalize_timestamp(
        timestamp
    )

    normalized_source = normalize_event_source(
        event_source
    )

    normalized_event_name = clean_value(
        event_name
    )

    event = {
        "timestamp": normalized_timestamp,
        "event_name": normalized_event_name,
        "event_type": normalized_event_name,
        "event_source": normalized_source,
        "source": normalized_source,
        "source_ip": clean_ip(source_ip),
        "username": normalize_username(username),
        "action": normalize_action(action),
        "status": normalize_status(status),
    }

    for key, value in extra_fields.items():

        if value is not None:
            event[key] = value

    normalize_network_fields(event)

    event["source_category"] = classify_source(
        event["event_source"]
    )

    event["actor"] = extract_actor_identity(
        event
    )

    event.update(
        get_temporal_metadata(
            normalized_timestamp
        )
    )

    event["correlation_key"] = (
        build_correlation_key(event)
    )

    event["correlation_dimensions"] = (
        build_correlation_dimensions(event)
    )

    destination_port = clean_port(
        event.get("destination_port")
    )

    if destination_port is not None:

        event["destination_port"] = destination_port

        event["destination_service"] = (
            classify_destination_port(
                destination_port
            )
        )

        event["high_risk_port"] = (
            is_high_risk_port(
                destination_port
            )
        )

    else:

        event["destination_service"] = None
        event["high_risk_port"] = False

    event["event_id"] = generate_event_id(
        event
    )

    return event


# ============================================================
# VALIDATION
# ============================================================

def is_valid_event(event):
    """
    Validate minimum event structure.
    """

    if not isinstance(event, dict):
        return False

    required_fields = (
        "timestamp",
        "event_name",
        "event_source",
    )

    for field in required_fields:

        if not clean_value(
            event.get(field)
        ):
            return False

    if parse_timestamp(
        event.get("timestamp")
    ) is None:
        return False

    return True


def validate_day4_fields(event):
    """
    Validate Day 4 metadata.

    correlation_key may legitimately be None.
    actor may legitimately be None.
    """

    if not isinstance(event, dict):
        return False

    if not clean_value(
        event.get("event_id")
    ):
        return False

    if parse_timestamp(
        event.get("timestamp")
    ) is None:
        return False

    if not clean_value(
        event.get("source_category")
    ):
        return False

    if not isinstance(
        event.get("correlation_dimensions"),
        dict
    ):
        return False

    return True


# ============================================================
# EVENT DEDUPLICATION
# ============================================================

def event_key(event):
    """
    Generate stable deduplication key.

    event_id is preferred.

    If no event_id exists, use meaningful
    event fields as fallback.
    """

    if not isinstance(event, dict):
        return None

    event_id = clean_value(
        event.get("event_id")
    )

    if event_id:
        return (
            "event_id",
            event_id,
        )

    return (
        "event",
        event.get("timestamp"),
        event.get("event_name"),
        event.get("event_source"),
        event.get("source_ip"),
        event.get("destination_ip"),
        event.get("destination_port"),
        event.get("source_port"),
        event.get("protocol"),
        event.get("username"),
        event.get("principal_id"),
        event.get("user_arn"),
        event.get("account_id"),
        event.get("action"),
        event.get("status"),
        event.get("service_source"),
        event.get("request_id"),
    )


def deduplicate_events(events):
    """
    Remove duplicate events while preserving order.
    """

    if not isinstance(events, list):
        return []

    unique_events = []
    seen = set()

    for event in events:

        if not isinstance(event, dict):
            continue

        key = event_key(event)

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
    Sort events chronologically.

    Invalid timestamps are placed at the end.
    """

    if not isinstance(events, list):
        return []

    def sort_key(event):

        parsed = parse_timestamp(
            event.get("timestamp")
        )

        if parsed is None:

            return (
                1,
                datetime.max.replace(
                    tzinfo=timezone.utc
                ),
                event.get(
                    "event_id",
                    ""
                ),
            )

        return (
            0,
            parsed,
            event.get(
                "event_id",
                ""
            ),
        )

    return sorted(
        events,
        key=sort_key
    )


# ============================================================
# CLOUDTRAIL HELPERS
# ============================================================

def extract_cloudtrail_records(data):
    """
    Extract CloudTrail records.

    Supports:

        {"Records": [...]}

    and:

        [...]
    """

    if isinstance(data, list):
        return data

    if isinstance(data, dict):

        records = data.get("Records")

        if isinstance(records, list):
            return records

    return []


def get_cloudtrail_username(user_identity):
    """
    Extract actual CloudTrail username.

    Only userName is treated as username.

    Other identity values remain in
    dedicated fields.
    """

    if not isinstance(
        user_identity,
        dict
    ):
        return None

    return clean_value(
        user_identity.get("userName")
    )


# ============================================================
# CLOUDTRAIL PARSER
# ============================================================

def parse_cloudtrail_logs(file_path):
    """
    Parse CloudTrail JSON events.
    """

    parsed_events = []

    try:

        with open(
            file_path,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(file)

    except FileNotFoundError:

        print(
            "[ERROR] CloudTrail file "
            f"not found: {file_path}"
        )

        return []

    except json.JSONDecodeError as error:

        print(
            "[ERROR] Invalid CloudTrail "
            f"JSON: {error}"
        )

        return []

    except OSError as error:

        print(
            "[ERROR] Could not read "
            f"CloudTrail file: {error}"
        )

        return []

    records = extract_cloudtrail_records(data)

    if not records:

        print(
            "[WARNING] No CloudTrail "
            "records found."
        )

        return []

    for record in records:

        if not isinstance(
            record,
            dict
        ):
            continue

        event_time = clean_value(
            record.get("eventTime")
        )

        event_name = clean_value(
            record.get("eventName")
        )

        service_source = clean_value(
            record.get("eventSource")
        )

        if not event_time:
            continue

        if not event_name:
            continue

        if not service_source:
            continue

        user_identity = record.get(
            "userIdentity"
        )

        if not isinstance(
            user_identity,
            dict
        ):
            user_identity = {}

        username = get_cloudtrail_username(
            user_identity
        )

        error_code = clean_value(
            record.get("errorCode")
        )

        error_message = clean_value(
            record.get("errorMessage")
        )

        status = (
            "failed"
            if error_code
            else "success"
        )

        source_ip = clean_ip(
            record.get("sourceIPAddress")
        )

        event_id = clean_value(
            record.get("eventID")
        )

        parsed_event = build_event(
            timestamp=event_time,
            event_name=event_name,
            event_source="CloudTrail",
            source_ip=source_ip,
            username=username,
            action=event_name,
            status=status,

            event_id=event_id,

            service_source=service_source,

            aws_region=clean_value(
                record.get("awsRegion")
            ),

            user_type=clean_value(
                user_identity.get("type")
            ),

            user_arn=clean_value(
                user_identity.get("arn")
            ),

            principal_id=clean_value(
                user_identity.get("principalId")
            ),

            account_id=clean_value(
                user_identity.get("accountId")
            ),

            error_code=error_code,

            error_message=error_message,

            read_only=record.get(
                "readOnly"
            ),

            event_category=clean_value(
                record.get("eventCategory")
            ),

            management_event=record.get(
                "managementEvent"
            ),

            event_version=clean_value(
                record.get("eventVersion")
            ),

            recipient_account_id=clean_value(
                record.get("recipientAccountId")
            ),

            request_id=clean_value(
                record.get("requestID")
            ),

            event_type_cloudtrail=clean_value(
                record.get("eventType")
            ),

            raw_event=record,
        )

        if is_valid_event(
            parsed_event
        ):
            parsed_events.append(
                parsed_event
            )

    return deduplicate_events(
        parsed_events
    )


# ============================================================
# LINUX SSH PATTERNS
# ============================================================

LINUX_INVALID_USER_PATTERN = re.compile(
    r"(?P<timestamp>"
    r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
    r")"
    r".*?"
    r"Failed\s+"
    r"(?:password|publickey)"
    r"\s+for\s+invalid\s+user\s+"
    r"(?P<username>\S+)"
    r"\s+from\s+"
    r"(?P<source_ip>\S+)",
    re.IGNORECASE
)


LINUX_SSH_PATTERN = re.compile(
    r"(?P<timestamp>"
    r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
    r")"
    r".*?"
    r"(?P<action>Accepted|Failed)"
    r"\s+"
    r"(?P<method>password|publickey)"
    r"\s+for\s+"
    r"(?P<username>\S+)"
    r"\s+from\s+"
    r"(?P<source_ip>\S+)",
    re.IGNORECASE
)


# ============================================================
# LINUX TIMESTAMP
# ============================================================

def normalize_linux_timestamp(timestamp):
    """
    Normalize Linux syslog timestamp.
    """

    timestamp = clean_value(timestamp)

    if not timestamp:
        return None

    try:

        parsed = datetime.strptime(
            f"{SAMPLE_LOG_YEAR} {timestamp}",
            "%Y %b %d %H:%M:%S"
        )

        parsed = parsed.replace(
            tzinfo=timezone.utc
        )

        return parsed.isoformat()

    except (ValueError, TypeError):

        return None


# ============================================================
# LINUX SSH PARSER
# ============================================================

def parse_linux_auth_logs(file_path):
    """
    Parse Linux SSH authentication logs.
    """

    parsed_events = []

    try:

        with open(
            file_path,
            "r",
            encoding="utf-8"
        ) as file:

            for line_number, raw_line in enumerate(
                file,
                start=1
            ):

                line = raw_line.strip()

                if not line:
                    continue

                match = (
                    LINUX_INVALID_USER_PATTERN.search(
                        line
                    )
                )

                invalid_user = False

                if match:

                    invalid_user = True

                else:

                    match = (
                        LINUX_SSH_PATTERN.search(
                            line
                        )
                    )

                if not match:
                    continue

                data = match.groupdict()

                username = clean_value(
                    data.get("username")
                )

                source_ip = clean_ip(
                    data.get("source_ip")
                )

                if not username:
                    continue

                if not source_ip:
                    continue

                if invalid_user:

                    status = "failed"
                    method = "password"

                else:

                    action_value = (
                        data.get("action")
                        or ""
                    ).lower()

                    method = (
                        data.get("method")
                        or "unknown"
                    ).lower()

                    status = (
                        "success"
                        if action_value == "accepted"
                        else "failed"
                    )

                timestamp = (
                    normalize_linux_timestamp(
                        data.get("timestamp")
                    )
                )

                if timestamp is None:
                    continue

                parsed_event = build_event(
                    timestamp=timestamp,

                    event_name="SSHAuthentication",

                    event_source="Linux SSH",

                    source_ip=source_ip,

                    username=username,

                    action="login",

                    status=status,

                    authentication_method=method,

                    invalid_user=invalid_user,

                    log_year=SAMPLE_LOG_YEAR,

                    line_number=line_number,

                    raw_log=line,
                )

                if is_valid_event(
                    parsed_event
                ):

                    parsed_events.append(
                        parsed_event
                    )

    except FileNotFoundError:

        print(
            "[ERROR] Linux authentication "
            "file not found: "
            f"{file_path}"
        )

        return []

    except OSError as error:

        print(
            "[ERROR] Could not read Linux "
            f"authentication file: {error}"
        )

        return []

    return deduplicate_events(
        parsed_events
    )


# ============================================================
# FIREWALL PARSER
# ============================================================

# The previous implementation was too strict here.
#
# It assumed:
#
#     TIMESTAMP FIREWALL ACTION PROTOCOL
#
# with the timestamp represented by a single non-space token.
#
# The improved implementation separates timestamp extraction
# from FIREWALL/action/protocol extraction.
#
# This allows:
#
#     2026-08-14T10:00:00Z FIREWALL DENY TCP
#
#     2026-08-14 10:00:00 FIREWALL DENY TCP
#
#     2026-08-14T10:00:00+00:00 FIREWALL TCP DENY
#
# and lines where ACTION/PROTO are supplied through
# KEY=VALUE fields.
# ============================================================


FIREWALL_TIMESTAMP_PATTERN = re.compile(
    r"^(?P<timestamp>"
    r"\d{4}-\d{2}-\d{2}"
    r"(?:T|\s+)"
    r"\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:\d{2})?"
    r")"
    r"\s+",
    re.IGNORECASE
)


FIREWALL_MARKER_PATTERN = re.compile(
    r"(?:^|\s|\[)"
    r"FIREWALL"
    r"(?:\]|\s|$)",
    re.IGNORECASE
)


FIREWALL_ACTION_PATTERN = re.compile(
    r"\b(?P<action>ALLOW|DENY)\b",
    re.IGNORECASE
)


FIREWALL_PROTOCOL_PATTERN = re.compile(
    r"\b(?P<protocol>"
    r"TCP|UDP|ICMP|GRE|ESP|AH"
    r")\b",
    re.IGNORECASE
)


FIREWALL_FIELD_PATTERN = re.compile(
    r"(?P<key>"
    r"SRC|DST|DPORT|SPORT|PROTO|PROTOCOL|"
    r"ACTION|USER|USERNAME|"
    r"IN|OUT|INTERFACE"
    r")"
    r"="
    r"(?P<value>"
    r"\"[^\"]*\""
    r"|'[^']*'"
    r"|\S+"
    r")",
    re.IGNORECASE
)


def strip_quotes(value):
    """
    Remove surrounding quotes.
    """

    value = clean_value(value)

    if value is None:
        return None

    if len(value) >= 2:

        if (
            value.startswith('"')
            and value.endswith('"')
        ):
            return value[1:-1]

        if (
            value.startswith("'")
            and value.endswith("'")
        ):
            return value[1:-1]

    return value


def parse_firewall_key_values(line):
    """
    Extract firewall KEY=VALUE fields.
    """

    fields = {}

    for match in FIREWALL_FIELD_PATTERN.finditer(
        line
    ):

        key = (
            match.group("key")
            .strip()
            .upper()
        )

        value = strip_quotes(
            match.group("value")
        )

        fields[key] = value

    return fields


def extract_firewall_header(line):
    """
    Extract firewall header metadata.

    Returns:

        {
            "timestamp": ...,
            "action": ...,
            "protocol": ...
        }

    The function deliberately does not require
    action or protocol to exist in the header because
    they may be provided as KEY=VALUE fields.
    """

    if not isinstance(line, str):
        return None

    line = line.strip()

    if not line:
        return None

    timestamp_match = (
        FIREWALL_TIMESTAMP_PATTERN.match(
            line
        )
    )

    if not timestamp_match:
        return None

    timestamp = normalize_timestamp(
        timestamp_match.group("timestamp")
    )

    if timestamp is None:
        return None

    remainder = line[
        timestamp_match.end():
    ].strip()

    # --------------------------------------------------------
    # FIREWALL marker
    # --------------------------------------------------------

    if not FIREWALL_MARKER_PATTERN.search(
        remainder
    ):
        return None

    # --------------------------------------------------------
    # Remove the FIREWALL marker for header analysis.
    # --------------------------------------------------------

    header_text = re.sub(
        r"\bFIREWALL\b",
        " ",
        remainder,
        count=1,
        flags=re.IGNORECASE
    )

    # --------------------------------------------------------
    # Remove KEY=VALUE fields from header analysis.
    #
    # This prevents values such as:
    #
    #     ACTION=DENY
    #
    # from being incorrectly interpreted as the
    # positional header action.
    # --------------------------------------------------------

    header_text = FIREWALL_FIELD_PATTERN.sub(
        " ",
        header_text
    )

    action_match = (
        FIREWALL_ACTION_PATTERN.search(
            header_text
        )
    )

    protocol_match = (
        FIREWALL_PROTOCOL_PATTERN.search(
            header_text
        )
    )

    action = (
        normalize_action(
            action_match.group("action")
        )
        if action_match
        else None
    )

    protocol = (
        normalize_protocol(
            protocol_match.group("protocol")
        )
        if protocol_match
        else None
    )

    return {
        "timestamp": timestamp,
        "action": action,
        "protocol": protocol,
    }


def parse_firewall_logs(file_path):
    """
    Parse firewall network events.

    Supported examples:

        2026-08-14T10:00:00Z FIREWALL DENY TCP
        SRC=203.0.113.50 DST=10.0.0.10
        DPORT=22 ACTION=DENY

        2026-08-14T10:00:00Z FIREWALL ALLOW TCP
        SRC=192.168.1.10 DST=10.0.0.10 DPORT=443

        2026-08-14 10:00:00 FIREWALL TCP DENY
        SRC=203.0.113.50 DST=10.0.0.10 DPORT=22

    Parser is tolerant of:

        - ISO timestamps
        - timestamps containing spaces
        - field order
        - extra fields
        - optional ACTION
        - optional PROTO
        - quoted values
        - header action/protocol
        - KEY=VALUE action/protocol
    """

    parsed_events = []

    try:

        with open(
            file_path,
            "r",
            encoding="utf-8"
        ) as file:

            for line_number, raw_line in enumerate(
                file,
                start=1
            ):

                line = raw_line.strip()

                if not line:
                    continue

                # ------------------------------------------------
                # Header
                # ------------------------------------------------

                header = (
                    extract_firewall_header(
                        line
                    )
                )

                if header is None:
                    continue

                timestamp = header.get(
                    "timestamp"
                )

                header_action = normalize_action(
                    header.get("action")
                )

                header_protocol = normalize_protocol(
                    header.get("protocol")
                )

                # ------------------------------------------------
                # KEY=VALUE fields
                # ------------------------------------------------

                fields = parse_firewall_key_values(
                    line
                )

                source_ip = clean_ip(
                    fields.get("SRC")
                )

                destination_ip = clean_ip(
                    fields.get("DST")
                )

                destination_port = clean_port(
                    fields.get("DPORT")
                )

                source_port = clean_port(
                    fields.get("SPORT")
                )

                field_protocol = normalize_protocol(
                    fields.get("PROTO")
                    or fields.get("PROTOCOL")
                )

                protocol = (
                    field_protocol
                    or header_protocol
                )

                field_action = normalize_action(
                    fields.get("ACTION")
                )

                action = (
                    field_action
                    or header_action
                )

                username = (
                    fields.get("USERNAME")
                    or fields.get("USER")
                )

                username = normalize_username(
                    username
                )

                # ------------------------------------------------
                # Required network fields
                # ------------------------------------------------

                if source_ip is None:
                    continue

                if destination_ip is None:
                    continue

                if destination_port is None:
                    continue

                if protocol is None:
                    continue

                if protocol not in SUPPORTED_PROTOCOLS:
                    continue

                if action is None:
                    continue

                # ------------------------------------------------
                # Build event
                # ------------------------------------------------

                parsed_event = build_event(
                    timestamp=timestamp,

                    event_name=(
                        "FirewallNetworkEvent"
                    ),

                    event_source="Firewall",

                    source_ip=source_ip,

                    username=username,

                    action=action,

                    status=action,

                    destination_ip=destination_ip,

                    destination_port=destination_port,

                    source_port=source_port,

                    protocol=protocol,

                    line_number=line_number,

                    firewall_interface=(
                        fields.get(
                            "INTERFACE"
                        )
                    ),

                    direction_in=(
                        fields.get(
                            "IN"
                        )
                    ),

                    direction_out=(
                        fields.get(
                            "OUT"
                        )
                    ),

                    raw_log=line,
                )

                if is_valid_event(
                    parsed_event
                ):

                    parsed_events.append(
                        parsed_event
                    )

    except FileNotFoundError:

        print(
            "[ERROR] Firewall file "
            "not found: "
            f"{file_path}"
        )

        return []

    except OSError as error:

        print(
            "[ERROR] Could not read firewall "
            f"file: {error}"
        )

        return []

    return deduplicate_events(
        parsed_events
    )


# ============================================================
# DAY 4 ENRICHMENT
# ============================================================

def enrich_event_for_correlation(event):
    """
    Refresh Day 4 metadata.

    Does not perform correlation.
    Does not make attack decisions.
    """

    if not isinstance(event, dict):
        return None

    event = dict(event)

    # --------------------------------------------------------
    # Base fields
    # --------------------------------------------------------

    event["timestamp"] = normalize_timestamp(
        event.get("timestamp")
    )

    event["event_source"] = (
        normalize_event_source(
            event.get("event_source")
        )
    )

    event["event_name"] = clean_value(
        event.get("event_name")
    )

    event["event_type"] = (
        event["event_name"]
    )

    event["source"] = (
        event["event_source"]
    )

    event["username"] = normalize_username(
        event.get("username")
    )

    event["action"] = normalize_action(
        event.get("action")
    )

    event["status"] = normalize_status(
        event.get("status")
    )

    # --------------------------------------------------------
    # Network
    # --------------------------------------------------------

    normalize_network_fields(
        event
    )

    # --------------------------------------------------------
    # Day 4 metadata
    # --------------------------------------------------------

    event["source_category"] = (
        classify_source(
            event.get("event_source")
        )
    )

    event["actor"] = (
        extract_actor_identity(
            event
        )
    )

    event.update(
        get_temporal_metadata(
            event.get("timestamp")
        )
    )

    event["correlation_key"] = (
        build_correlation_key(
            event
        )
    )

    event["correlation_dimensions"] = (
        build_correlation_dimensions(
            event
        )
    )

    # --------------------------------------------------------
    # Network metadata
    # --------------------------------------------------------

    destination_port = clean_port(
        event.get(
            "destination_port"
        )
    )

    if destination_port is not None:

        event["destination_port"] = (
            destination_port
        )

        event["destination_service"] = (
            classify_destination_port(
                destination_port
            )
        )

        event["high_risk_port"] = (
            is_high_risk_port(
                destination_port
            )
        )

    else:

        event["destination_port"] = None

        event["destination_service"] = None

        event["high_risk_port"] = False

    # --------------------------------------------------------
    # Stable event ID
    # --------------------------------------------------------

    event["event_id"] = (
        generate_event_id(
            event
        )
    )

    return event


def enrich_events_for_correlation(events):
    """
    Enrich every parsed event.
    """

    if not isinstance(events, list):
        return []

    enriched = []

    for event in events:

        enriched_event = (
            enrich_event_for_correlation(
                event
            )
        )

        if enriched_event is not None:
            enriched.append(
                enriched_event
            )

    return enriched


# ============================================================
# PARSE ALL LOGS
# ============================================================

def parse_all_logs():
    """
    Parse all supported sources.

    Pipeline:

        CloudTrail
             +
        Linux SSH
             +
        Firewall
             |
             v
        Enrichment
             |
             v
        Deduplication
             |
             v
        Chronological sorting
    """

    cloudtrail_events = (
        parse_cloudtrail_logs(
            CLOUDTRAIL_FILE
        )
    )

    linux_events = (
        parse_linux_auth_logs(
            LINUX_LOG_FILE
        )
    )

    firewall_events = (
        parse_firewall_logs(
            FIREWALL_LOG_FILE
        )
    )

    all_events = (
        cloudtrail_events
        + linux_events
        + firewall_events
    )

    all_events = (
        enrich_events_for_correlation(
            all_events
        )
    )

    all_events = deduplicate_events(
        all_events
    )

    all_events = sort_events(
        all_events
    )

    return {
        "cloudtrail": cloudtrail_events,
        "linux": linux_events,
        "firewall": firewall_events,
        "all_events": all_events,
    }


# ============================================================
# SUMMARY HELPERS
# ============================================================

def build_source_summary(events):

    summary = {}

    if not isinstance(events, list):
        return summary

    for event in events:

        source = (
            event.get("event_source")
            or "Unknown"
        )

        summary[source] = (
            summary.get(source, 0)
            + 1
        )

    return summary


def build_source_category_summary(events):

    summary = {}

    if not isinstance(events, list):
        return summary

    for event in events:

        category = (
            event.get("source_category")
            or "unknown"
        )

        summary[category] = (
            summary.get(category, 0)
            + 1
        )

    return summary


def build_status_summary(events):

    summary = {}

    if not isinstance(events, list):
        return summary

    for event in events:

        status = (
            event.get("status")
            or "unknown"
        )

        summary[status] = (
            summary.get(status, 0)
            + 1
        )

    return summary


def build_event_type_summary(events):

    summary = {}

    if not isinstance(events, list):
        return summary

    for event in events:

        event_type = (
            event.get("event_type")
            or event.get("event_name")
            or "Unknown"
        )

        summary[event_type] = (
            summary.get(event_type, 0)
            + 1
        )

    return summary


def build_correlation_key_summary(events):

    summary = {}

    if not isinstance(events, list):
        return summary

    for event in events:

        key = event.get(
            "correlation_key"
        )

        if not key:
            continue

        summary[key] = (
            summary.get(key, 0)
            + 1
        )

    return summary


def build_actor_summary(events):

    summary = {}

    if not isinstance(events, list):
        return summary

    for event in events:

        actor = event.get(
            "actor"
        )

        if not actor:
            continue

        actor = str(actor)

        summary[actor] = (
            summary.get(actor, 0)
            + 1
        )

    return summary


def build_high_risk_network_summary(events):

    summary = {}

    if not isinstance(events, list):
        return summary

    for event in events:

        if not event.get(
            "high_risk_port",
            False
        ):
            continue

        port = event.get(
            "destination_port"
        )

        service = event.get(
            "destination_service"
        )

        key = (
            f"{service}:{port}"
        )

        summary[key] = (
            summary.get(key, 0)
            + 1
        )

    return summary


def build_protocol_summary(events):

    summary = {}

    if not isinstance(events, list):
        return summary

    for event in events:

        protocol = event.get(
            "protocol"
        )

        if not protocol:
            continue

        summary[protocol] = (
            summary.get(protocol, 0)
            + 1
        )

    return summary


# ============================================================
# DAY 4 HEALTH
# ============================================================

def build_day4_health_summary(events):

    if not isinstance(events, list):
        events = []

    total = len(events)

    event_ids = 0
    correlation_keys = 0
    correlation_dimensions = 0
    timestamps = 0
    actors = 0
    categories = 0

    for event in events:

        if event.get("event_id"):
            event_ids += 1

        if event.get("correlation_key"):
            correlation_keys += 1

        if isinstance(
            event.get("correlation_dimensions"),
            dict
        ):
            correlation_dimensions += 1

        if parse_timestamp(
            event.get("timestamp")
        ):
            timestamps += 1

        if event.get("actor"):
            actors += 1

        if event.get("source_category"):
            categories += 1

    return {

        "total_events":
            total,

        "events_with_event_id":
            event_ids,

        "events_with_correlation_key":
            correlation_keys,

        "events_with_correlation_dimensions":
            correlation_dimensions,

        "events_with_timestamp":
            timestamps,

        "events_with_actor":
            actors,

        "events_with_source_category":
            categories,

        "correlation_ready": (
            event_ids == total
            and timestamps == total
            and categories == total
            and correlation_dimensions == total
        )
        if total > 0
        else True,
    }


# ============================================================
# PARSER SUMMARY
# ============================================================

def build_parser_summary(events):

    if not isinstance(events, list):
        events = []

    return {

        "total_events":
            len(events),

        "sources":
            build_source_summary(
                events
            ),

        "source_categories":
            build_source_category_summary(
                events
            ),

        "event_types":
            build_event_type_summary(
                events
            ),

        "statuses":
            build_status_summary(
                events
            ),

        "actors":
            build_actor_summary(
                events
            ),

        "correlation_keys":
            build_correlation_key_summary(
                events
            ),

        "protocols":
            build_protocol_summary(
                events
            ),

        "high_risk_network_events":
            build_high_risk_network_summary(
                events
            ),

        "day4_health":
            build_day4_health_summary(
                events
            ),
    }


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 70)
    print("KIROTRACE LOG PARSER")
    print("DAY 4 CORRELATION-READY VERSION")
    print("=" * 70)

    # ========================================================
    # PARSE
    # ========================================================

    parsed_data = parse_all_logs()

    cloudtrail_events = (
        parsed_data["cloudtrail"]
    )

    linux_events = (
        parsed_data["linux"]
    )

    firewall_events = (
        parsed_data["firewall"]
    )

    all_events = (
        parsed_data["all_events"]
    )

    # ========================================================
    # COUNTS
    # ========================================================

    print()

    print(
        "CloudTrail Events : "
        f"{len(cloudtrail_events)}"
    )

    print(
        "Linux SSH Events  : "
        f"{len(linux_events)}"
    )

    print(
        "Firewall Events   : "
        f"{len(firewall_events)}"
    )

    print(
        "Total Events      : "
        f"{len(all_events)}"
    )

    # ========================================================
    # PARSED EVENTS
    # ========================================================

    print()
    print("-" * 70)
    print("PARSED EVENTS")
    print("-" * 70)

    for index, event in enumerate(
        all_events,
        start=1
    ):

        print(
            f"[{index}] "
            f"{event.get('timestamp')} | "
            f"{event.get('event_source')} | "
            f"{event.get('event_name')} | "
            f"{event.get('source_ip')} | "
            f"{event.get('username')} | "
            f"{event.get('status')} | "
            f"ID={event.get('event_id')}"
        )

    # ========================================================
    # CORRELATION METADATA
    # ========================================================

    print()
    print("-" * 70)
    print("DAY 4 CORRELATION METADATA")
    print("-" * 70)

    for index, event in enumerate(
        all_events,
        start=1
    ):

        print()
        print(
            f"Event #{index}"
        )

        print(
            "  Event ID        : "
            f"{event.get('event_id')}"
        )

        print(
            "  Event Type      : "
            f"{event.get('event_type')}"
        )

        print(
            "  Source          : "
            f"{event.get('source')}"
        )

        print(
            "  Category        : "
            f"{event.get('source_category')}"
        )

        print(
            "  Actor           : "
            f"{event.get('actor')}"
        )

        print(
            "  Username        : "
            f"{event.get('username')}"
        )

        print(
            "  Correlation Key : "
            f"{event.get('correlation_key')}"
        )

        print(
            "  Correlation Dims: "
            f"{event.get('correlation_dimensions')}"
        )

        print(
            "  Event Date      : "
            f"{event.get('event_date')}"
        )

        print(
            "  Event Hour      : "
            f"{event.get('event_hour')}"
        )

        print(
            "  Event Minute    : "
            f"{event.get('event_minute')}"
        )

        print(
            "  Epoch Seconds   : "
            f"{event.get('epoch_seconds')}"
        )

        if event.get(
            "destination_port"
        ) is not None:

            print(
                "  Destination     : "
                f"{event.get('destination_ip')}:"
                f"{event.get('destination_port')}"
            )

            print(
                "  Service         : "
                f"{event.get('destination_service')}"
            )

            print(
                "  High Risk Port  : "
                f"{event.get('high_risk_port')}"
            )

    # ========================================================
    # CLOUDTRAIL SERVICES
    # ========================================================

    if cloudtrail_events:

        print()
        print("-" * 70)
        print("CLOUDTRAIL SERVICES")
        print("-" * 70)

        for event in cloudtrail_events:

            print(
                f"{event.get('event_name')} "
                f"-> "
                f"{event.get('service_source')}"
            )

    # ========================================================
    # SUMMARY
    # ========================================================

    summary = build_parser_summary(
        all_events
    )

    # ========================================================
    # SOURCE SUMMARY
    # ========================================================

    print()
    print("-" * 70)
    print("SOURCE SUMMARY")
    print("-" * 70)

    for source, count in sorted(
        summary["sources"].items()
    ):

        print(
            f"{source}: {count}"
        )

    # ========================================================
    # CATEGORY SUMMARY
    # ========================================================

    print()
    print("-" * 70)
    print("SOURCE CATEGORY SUMMARY")
    print("-" * 70)

    for category, count in sorted(
        summary["source_categories"].items()
    ):

        print(
            f"{category}: {count}"
        )

    # ========================================================
    # EVENT TYPE SUMMARY
    # ========================================================

    print()
    print("-" * 70)
    print("EVENT TYPE SUMMARY")
    print("-" * 70)

    for event_type, count in sorted(
        summary["event_types"].items()
    ):

        print(
            f"{event_type}: {count}"
        )

    # ========================================================
    # STATUS SUMMARY
    # ========================================================

    print()
    print("-" * 70)
    print("STATUS SUMMARY")
    print("-" * 70)

    for status, count in sorted(
        summary["statuses"].items()
    ):

        print(
            f"{status}: {count}"
        )

    # ========================================================
    # PROTOCOL SUMMARY
    # ========================================================

    print()
    print("-" * 70)
    print("PROTOCOL SUMMARY")
    print("-" * 70)

    for protocol, count in sorted(
        summary["protocols"].items()
    ):

        print(
            f"{protocol}: {count}"
        )

    # ========================================================
    # CORRELATION KEYS
    # ========================================================

    print()
    print("-" * 70)
    print("CORRELATION KEY SUMMARY")
    print("-" * 70)

    for key, count in sorted(
        summary["correlation_keys"].items()
    ):

        print(
            f"{key}: {count}"
        )

    # ========================================================
    # ACTORS
    # ========================================================

    print()
    print("-" * 70)
    print("ACTOR SUMMARY")
    print("-" * 70)

    for actor, count in sorted(
        summary["actors"].items()
    ):

        print(
            f"{actor}: {count}"
        )

    # ========================================================
    # HIGH-RISK NETWORK
    # ========================================================

    print()
    print("-" * 70)
    print("HIGH-RISK NETWORK SUMMARY")
    print("-" * 70)

    high_risk = summary[
        "high_risk_network_events"
    ]

    if high_risk:

        for service, count in sorted(
            high_risk.items()
        ):

            print(
                f"{service}: {count}"
            )

    else:

        print(
            "No high-risk network events."
        )

    # ========================================================
    # DAY 4 HEALTH
    # ========================================================

    health = summary[
        "day4_health"
    ]

    print()
    print("-" * 70)
    print("DAY 4 CORRELATION HEALTH")
    print("-" * 70)

    print(
        "Total Events                : "
        f"{health['total_events']}"
    )

    print(
        "Events with Event ID        : "
        f"{health['events_with_event_id']}"
    )

    print(
        "Events with Correlation Key : "
        f"{health['events_with_correlation_key']}"
    )

    print(
        "Events with Correlation Dims: "
        f"{health['events_with_correlation_dimensions']}"
    )

    print(
        "Events with Timestamp       : "
        f"{health['events_with_timestamp']}"
    )

    print(
        "Events with Actor           : "
        f"{health['events_with_actor']}"
    )

    print(
        "Events with Source Category : "
        f"{health['events_with_source_category']}"
    )

    print(
        "Correlation Ready           : "
        f"{health['correlation_ready']}"
    )

    # ========================================================
    # VALIDATION
    # ========================================================

    invalid_count = sum(
        1
        for event in all_events
        if not is_valid_event(event)
    )

    day4_invalid_count = sum(
        1
        for event in all_events
        if not validate_day4_fields(event)
    )

    print()
    print("-" * 70)
    print("VALIDATION")
    print("-" * 70)

    print(
        "Invalid Base Events  : "
        f"{invalid_count}"
    )

    print(
        "Invalid Day 4 Events : "
        f"{day4_invalid_count}"
    )

    # ========================================================
    # PARSER HEALTH
    # ========================================================

    print()
    print("-" * 70)
    print("PARSER HEALTH")
    print("-" * 70)

    if (
        invalid_count == 0
        and day4_invalid_count == 0
        and health["correlation_ready"]
    ):

        print(
            "Status : HEALTHY"
        )

    else:

        print(
            "Status : WARNING"
        )

    # ========================================================
    # COMPLETE
    # ========================================================

    print()
    print("=" * 70)
    print("PARSER COMPLETE")
    print("=" * 70)