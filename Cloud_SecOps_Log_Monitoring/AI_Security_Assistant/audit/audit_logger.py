"""
KiroTrace - Audit Logger

Append-only audit logging for the AI Security Assistant.

Responsibilities:
    - Record assistant requests and execution decisions.
    - Record controlled tool execution results.
    - Preserve policy and execution metadata.
    - Use JSON Lines (JSONL) for simple local audit storage.
    - Fail safely without exposing secrets in audit records.

Security principles:
    - No arbitrary command execution.
    - No shell execution.
    - No passwords or obvious secrets should be logged.
    - Audit records are structured and machine-readable.
    - Logging failures must not crash the security assistant.
"""

from __future__ import annotations

import json
import re
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


# ============================================================
# CONFIGURATION
# ============================================================

DEFAULT_AUDIT_DIRECTORY = (
    Path(__file__).resolve().parent
)

DEFAULT_AUDIT_FILE = (
    DEFAULT_AUDIT_DIRECTORY / "audit.log.jsonl"
)

AUDIT_SCHEMA_VERSION = "1.1"

_MAX_STRING_LENGTH = 2000


# ============================================================
# INTERNAL LOCK
# ============================================================

_AUDIT_LOCK = threading.Lock()


# ============================================================
# AUDIT EVENT
# ============================================================

@dataclass(frozen=True)
class AuditEvent:
    """
    Structured audit event.

    The event intentionally stores security-relevant metadata
    instead of arbitrary application state.
    """

    timestamp: str
    event_type: str
    success: bool
    status: str
    request_id: str = ""
    question: str = ""
    tool: str = ""
    command: str = ""

    policy_category: str = ""
    execution_mode: str = "none"

    reason: str = ""
    error: str = ""

    return_code: Optional[int] = None
    duration_ms: int = 0

    schema_version: str = AUDIT_SCHEMA_VERSION


# ============================================================
# SANITIZATION
# ============================================================

_SECRET_PATTERNS = (
    re.compile(
        r"(?i)(password|passwd|pwd)\s*=\s*[^\s]+"
    ),
    re.compile(
        r"(?i)(api[_-]?key|token|secret)\s*=\s*[^\s]+"
    ),
    re.compile(
        r"(?i)(authorization)\s*:\s*[^\s]+"
    ),
)


def _sanitize_string(
    value: Any,
    *,
    max_length: int = _MAX_STRING_LENGTH,
) -> str:
    """
    Convert a value to a bounded string and redact
    obvious credential/token patterns.
    """

    if value is None:
        return ""

    text = str(value).strip()

    if len(text) > max_length:
        text = text[:max_length] + "...[TRUNCATED]"

    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(
            lambda match: (
                match.group(0).split(
                    "=" if "=" in match.group(0) else ":",
                    1,
                )[0]
                + "=<REDACTED>"
                if "=" in match.group(0)
                else (
                    match.group(0).split(
                        ":",
                        1,
                    )[0]
                    + ": <REDACTED>"
                )
            ),
            text,
        )

    return text


def _sanitize_return_code(
    value: Any,
) -> Optional[int]:
    """
    Normalize a process return code.
    """

    if value is None:
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _sanitize_duration(
    value: Any,
) -> int:
    """
    Normalize execution duration.
    """

    try:
        duration = int(value)
    except (TypeError, ValueError):
        return 0

    return max(0, duration)


# ============================================================
# EVENT CREATION
# ============================================================

def create_audit_event(
    *,
    event_type: str,
    success: bool,
    status: str,
    request_id: str = "",
    question: str = "",
    tool: str = "",
    command: str = "",
    policy_category: str = "",
    execution_mode: str = "none",
    reason: str = "",
    error: str = "",
    return_code: Optional[int] = None,
    duration_ms: int = 0,
) -> AuditEvent:
    """
    Create a sanitized structured audit event.
    """

    return AuditEvent(
        timestamp=datetime.now(
            timezone.utc
        ).isoformat(),

        event_type=_sanitize_string(
            event_type,
            max_length=100,
        ),

        success=bool(success),

        status=_sanitize_string(
            status,
            max_length=100,
        ),
        request_id=_sanitize_string(
           request_id,
           max_length=100,
       ),
        question=_sanitize_string(
            question
        ),

        tool=_sanitize_string(
            tool,
            max_length=100,
        ),

        command=_sanitize_string(
            command
        ),

        policy_category=_sanitize_string(
            policy_category,
            max_length=100,
        ),

        execution_mode=_sanitize_string(
            execution_mode,
            max_length=100,
        ),

        reason=_sanitize_string(
            reason
        ),

        error=_sanitize_string(
            error
        ),

        return_code=_sanitize_return_code(
            return_code
        ),

        duration_ms=_sanitize_duration(
            duration_ms
        ),
    )


# ============================================================
# SERIALIZATION
# ============================================================

def audit_event_to_dict(
    event: AuditEvent,
) -> dict[str, Any]:
    """
    Convert an AuditEvent into a JSON-safe dictionary.
    """

    return asdict(event)


def audit_event_to_json(
    event: AuditEvent,
) -> str:
    """
    Serialize an audit event as compact JSON.
    """

    return json.dumps(
        audit_event_to_dict(event),
        ensure_ascii=False,
        separators=(",", ":"),
    )


# ============================================================
# FILE INITIALIZATION
# ============================================================

def ensure_audit_directory(
    audit_file: Path | str = DEFAULT_AUDIT_FILE,
) -> Path:
    """
    Ensure the audit-log parent directory exists.
    """

    path = Path(audit_file).resolve()

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    return path


# ============================================================
# WRITE AUDIT EVENT
# ============================================================

def write_audit_event(
    event: AuditEvent,
    audit_file: Path | str = DEFAULT_AUDIT_FILE,
) -> bool:
    """
    Append one audit event to the JSONL audit file.

    Returns:
        True  -> event written successfully
        False -> logging failed

    Logging failure is deliberately isolated from the main
    security-assistant execution path.
    """

    try:
        path = ensure_audit_directory(
            audit_file
        )

        line = audit_event_to_json(event)

        with _AUDIT_LOCK:
            with path.open(
                "a",
                encoding="utf-8",
            ) as handle:
                handle.write(
                    line + "\n"
                )

        return True

    except (
        OSError,
        TypeError,
        ValueError,
    ):
        return False


# ============================================================
# CONVENIENCE LOGGER
# ============================================================

def log_audit_event(
    *,
    event_type: str,
    success: bool,
    status: str,
    request_id: str = "",
    question: str = "",
    tool: str = "",
    command: str = "",
    policy_category: str = "",
    execution_mode: str = "none",
    reason: str = "",
    error: str = "",
    return_code: Optional[int] = None,
    duration_ms: int = 0,
    audit_file: Path | str = DEFAULT_AUDIT_FILE,
) -> bool:
    """
    Create and immediately persist an audit event.
    """

    event = create_audit_event(
        event_type=event_type,
        success=success,
        status=status,
        request_id=request_id,
        question=question,
        tool=tool,
        command=command,
        policy_category=policy_category,
        execution_mode=execution_mode,
        reason=reason,
        error=error,
        return_code=return_code,
        duration_ms=duration_ms,
    )

    return write_audit_event(
        event,
        audit_file=audit_file,
    )


# ============================================================
# ORCHESTRATOR RESULT LOGGER
# ============================================================

def log_tool_orchestration_result(
    result: Any,
    *,
    audit_file: Path | str = DEFAULT_AUDIT_FILE,
) -> bool:
    """
    Log a ToolOrchestrationResult without creating a hard
    dependency on tool_orchestrator.py.

    Attribute-based access keeps the audit layer decoupled
    from the execution layer.
    """

    return log_audit_event(
        event_type="TOOL_ORCHESTRATION",
        success=bool(
            getattr(result, "success", False)
        ),
        status=_sanitize_string(
            getattr(result, "status", "")
        ),
        request_id=_sanitize_string(
           getattr(result, "request_id", "")
       ),
        question=_sanitize_string(
            getattr(result, "question", "")
        ),
        tool=_sanitize_string(
            getattr(result, "tool", "")
        ),
        command=_sanitize_string(
            getattr(result, "command", "")
        ),
        policy_category=_sanitize_string(
            getattr(result, "policy_category", "")
        ),
        execution_mode=_sanitize_string(
            getattr(
                result,
                "execution_mode",
                "none",
            )
        ),
        reason=_sanitize_string(
            getattr(result, "reason", "")
        ),
        error=_sanitize_string(
            getattr(result, "error", "")
        ),
        return_code=getattr(
            result,
            "return_code",
            None,
        ),
        duration_ms=getattr(
            result,
            "duration_ms",
            0,
        ),
        audit_file=audit_file,
    )


# ============================================================
# READ AUDIT EVENTS
# ============================================================

def read_audit_events(
    audit_file: Path | str = DEFAULT_AUDIT_FILE,
) -> list[dict[str, Any]]:
    """
    Read valid JSONL audit events.

    Invalid lines are ignored instead of breaking the entire
    audit-reading operation.
    """

    path = Path(audit_file).resolve()

    if not path.exists():
        return []

    events: list[dict[str, Any]] = []

    try:
        with path.open(
            "r",
            encoding="utf-8",
        ) as handle:

            for line in handle:
                line = line.strip()

                if not line:
                    continue

                try:
                    parsed = json.loads(line)

                except json.JSONDecodeError:
                    continue

                if isinstance(
                    parsed,
                    dict,
                ):
                    events.append(parsed)

    except OSError:
        return []

    return events


# ============================================================
# SELF TEST
# ============================================================

def run_self_test() -> bool:
    """
    Validate audit-event creation, sanitization,
    persistence, reading, and orchestration logging.
    """

    import tempfile

    with tempfile.TemporaryDirectory() as temp_dir:

        audit_file = (
            Path(temp_dir)
            / "audit.log.jsonl"
        )

        # ----------------------------------------------------
        # TEST 1: EVENT CREATION
        # ----------------------------------------------------

        event = create_audit_event(
            event_type="TEST",
            success=True,
            status="EXECUTED",
            question="Who am I?",
            tool="whoami",
            command="whoami",
            policy_category="SYSTEM_INFORMATION",
            execution_mode="normal",
            reason="Safe controlled tool.",
            return_code=0,
            duration_ms=12,
        )

        assert event.success is True
        assert event.status == "EXECUTED"
        assert event.tool == "whoami"
        assert event.command == "whoami"
        assert event.return_code == 0
        assert event.duration_ms == 12
        assert event.schema_version == "1.1"

        # ----------------------------------------------------
        # TEST 2: SANITIZATION
        # ----------------------------------------------------

        sanitized = create_audit_event(
            event_type="TEST",
            success=False,
            status="REJECTED",
            question=(
                "password=SuperSecret123 "
                "token=ABC123"
            ),
        )

        assert "SuperSecret123" not in (
            sanitized.question
        )

        assert "ABC123" not in (
            sanitized.question
        )

        assert "<REDACTED>" in (
            sanitized.question
        )

        # ----------------------------------------------------
        # TEST 3: WRITE
        # ----------------------------------------------------

        assert write_audit_event(
            event,
            audit_file=audit_file,
        )

        assert audit_file.exists()

        # ----------------------------------------------------
        # TEST 4: READ
        # ----------------------------------------------------

        events = read_audit_events(
            audit_file
        )

        assert len(events) == 1
        assert events[0]["tool"] == "whoami"
        assert events[0]["status"] == "EXECUTED"

        # ----------------------------------------------------
        # TEST 5: CONVENIENCE LOGGER
        # ----------------------------------------------------

        assert log_audit_event(
            event_type="POLICY_DECISION",
            success=False,
            status="REJECTED",
            question="Run dangerous command",
            tool="",
            command="",
            policy_category="DENIED",
            execution_mode="none",
            reason="Command not authorized.",
            audit_file=audit_file,
        )

        events = read_audit_events(
            audit_file
        )

        assert len(events) == 2
        assert (
            events[1]["event_type"]
            == "POLICY_DECISION"
        )

        # ----------------------------------------------------
        # TEST 6: ORCHESTRATION RESULT ADAPTER
        # ----------------------------------------------------

        class FakeResult:
            success = True
            status = "SANDBOX_EXECUTED"
            request_id = "test-request-001"
            question = "What is my hostname?"
            tool = "hostname"
            command = "hostname"
            policy_category = "SYSTEM_INFORMATION"
            execution_mode = "sandbox"
            reason = "Authorized."
            error = ""
            return_code = 0
            duration_ms = 8

        assert log_tool_orchestration_result(
            FakeResult(),
            audit_file=audit_file,
        )

        events = read_audit_events(
            audit_file
        )

        assert len(events) == 3
        assert (
            events[2]["event_type"]
            == "TOOL_ORCHESTRATION"
        )
        assert (
            events[2]["execution_mode"]
            == "sandbox"
        )
        assert (
            events[2]["request_id"]
            == "test-request-001"
        )
    print(
        "[OK] Audit logger self-test passed."
    )

    return True


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    run_self_test()