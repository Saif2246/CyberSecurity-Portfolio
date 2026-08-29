"""
KiroTrace - Security Tool Service

Service layer connecting natural-language security tool intent
to the controlled tool orchestration pipeline.

Architecture:

    AI / User Request
          |
          v
    Tool Intent
          |
          v
    Tool Orchestrator
          |
          v
    Tool Runner
          |
          v
    Policy Controller
          |
          v
    Structured Tool Result

IMPORTANT:
    - This module never executes shell commands directly.
    - This module never uses shell=True.
    - This module never constructs arbitrary shell commands.
    - This module never bypasses the tool orchestrator.
    - Argument-requiring tools are denied by the service layer.
    - Only deterministic argument-free intents may reach
      the controlled orchestration layer.
    - Failures fail closed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


# ============================================================
# IMPORTS
# ============================================================

try:
    from .tool_intent import (
        ToolIntent,
        detect_tool_intent,
        is_argument_free_tool_intent,
    )

    from .tool_orchestrator import (
        ToolOrchestrationResult,
        orchestrate_tool_request,
    )

except ImportError:
    from tool_intent import (
        ToolIntent,
        detect_tool_intent,
        is_argument_free_tool_intent,
    )

    from tool_orchestrator import (
        ToolOrchestrationResult,
        orchestrate_tool_request,
    )
# ============================================================
# AUDIT LOGGER
# ============================================================

try:
    from ..audit.audit_logger import (
         log_audit_event,
        log_tool_orchestration_result,
    )
except ImportError:
    from audit.audit_logger import (
        log_audit_event,
        log_tool_orchestration_result,
    )

# ============================================================
# SERVICE STATUS
# ============================================================

SUCCESS = "SUCCESS"
DENIED = "DENIED"
INVALID = "INVALID"
NO_TOOL = "NO_TOOL"
FAILED = "FAILED"
REJECTED = "REJECTED"


# ============================================================
# SERVICE RESULT
# ============================================================

@dataclass(frozen=True)
class ToolServiceResult:
    """
    Stable service-level result.

    The AI/RAG layer consumes this contract instead of depending
    directly on lower-level policy or execution objects.
    """

    success: bool
    status: str
    request_id: str
    intent: str
    tool: str
    command: str
    reason: str
    output: str
    error: str
    return_code: int | None
    duration_ms: int
    policy_category: str


# ============================================================
# HELPERS
# ============================================================

def _safe_text(
    value: Any,
) -> str:
    """
    Convert an arbitrary value into normalized text.
    """

    if value is None:
        return ""

    return str(value).strip()


def _intent_name(
    intent: Any,
) -> str:
    """
    Extract a stable intent name.

    ToolIntent currently exposes the tool name through
    the `tool` field, so that is preferred.
    """

    if intent is None:
        return ""

    tool = getattr(
        intent,
        "tool",
        None,
    )

    if tool:
        return _safe_text(
            tool
        ).lower()

    value = getattr(
        intent,
        "name",
        None,
    )

    if value:
        return _safe_text(
            value
        ).lower()

    value = getattr(
        intent,
        "value",
        None,
    )

    if value:
        return _safe_text(
            value
        ).lower()

    return _safe_text(
        intent
    ).lower()


def _failure_result(
    *,
    status: str,
    request_id: str = "",
    intent: str = "",
    tool: str = "",
    command: str = "",
    reason: str = "",
    error: str = "",
) -> ToolServiceResult:
    """
    Create a deterministic failed service result.
    """

    return ToolServiceResult(
        success=False,
        status=status,
        request_id=request_id,
        intent=intent,
        tool=tool,
        command=command,
        reason=reason,
        output="",
        error=error,
        return_code=None,
        duration_ms=0,
        policy_category=status,
    )


# ============================================================
# ORCHESTRATION RESULT MAPPING
# ============================================================

def _map_orchestration_result(
    *,
    request_id: str,
    intent_name: str,
    result: ToolOrchestrationResult,
) -> ToolServiceResult:
    """
    Convert the orchestration result into the stable service
    result contract.

    The orchestration layer remains authoritative for actual
    execution and policy decisions.
    """

    success = bool(
        getattr(
            result,
            "success",
            False,
        )
    )

    tool = _safe_text(
        getattr(
            result,
            "tool",
            "",
        )
    )

    command = _safe_text(
        getattr(
            result,
            "command",
            "",
        )
    )

    reason = _safe_text(
        getattr(
            result,
            "reason",
            "",
        )
    )

    output = _safe_text(
        getattr(
            result,
            "output",
            getattr(
                result,
                "stdout",
                "",
            ),
        )
    )

    error = _safe_text(
        getattr(
            result,
            "error",
            getattr(
                result,
                "stderr",
                "",
            ),
        )
    )

    return_code = getattr(
        result,
        "return_code",
        None,
    )

    duration_ms = int(
        getattr(
            result,
            "duration_ms",
            0,
        )
        or 0
    )

    policy_category = _safe_text(
        getattr(
            result,
            "policy_category",
            "",
        )
    )

    raw_status = _safe_text(
        getattr(
            result,
            "status",
            "",
        )
    ).upper()

    # --------------------------------------------------------
    # STATUS MAPPING
    # --------------------------------------------------------

    if success:
        status = SUCCESS

    elif raw_status in {
        DENIED,
        INVALID,
        NO_TOOL,
        REJECTED,
    }:
        status = raw_status

    elif policy_category.upper() in {
        DENIED,
        INVALID,
        REJECTED,
    }:
        status = policy_category.upper()

    else:
        status = FAILED

    return ToolServiceResult(
        success=success,
        status=status,
        request_id=request_id,
        intent=intent_name,
        tool=tool,
        command=command,
        reason=reason,
        output=output,
        error=error,
        return_code=return_code,
        duration_ms=duration_ms,
        policy_category=policy_category,
    )


# ============================================================
# TOOL REQUEST SERVICE
# ============================================================

def execute_tool_request(
    request: str,
    timeout_seconds: int = 15,
    request_id: str = "",
) -> ToolServiceResult:
    """
    Process a natural-language security tool request.

    Pipeline:

        Request
          |
          v
        Intent detection
          |
          v
        Argument-free safety gate
          |
          v
        Tool orchestrator
          |
          v
        Tool runner
          |
          v
        Policy-controlled execution
          |
          v
        Structured service result

    The request itself is NEVER treated as a shell command.
    """

    # --------------------------------------------------------
    # INPUT VALIDATION
    # --------------------------------------------------------

    if not isinstance(
        request,
        str,
    ):
        return _failure_result(
            status=INVALID,
            request_id=request_id,
            reason=(
                "Tool request must be provided as text."
            ),
            error=(
                "Tool request must be provided as text."
            ),
        )

    request = request.strip()

    if not request:
        return _failure_result(
            status=INVALID,
            reason="Tool request cannot be empty.",
            error="Tool request cannot be empty.",
        )

    if not isinstance(
        timeout_seconds,
        int,
    ):
        return _failure_result(
            status=INVALID,
            request_id=request_id,
            reason="Timeout must be an integer.",
            error="Timeout must be an integer.",
        )

    if timeout_seconds <= 0:
        return _failure_result(
            status=INVALID,
            request_id=request_id,
            reason="Timeout must be greater than zero.",
            error="Timeout must be greater than zero.",
        )

    # --------------------------------------------------------
    # DETERMINISTIC INTENT DETECTION
    # --------------------------------------------------------

    try:
        intent: ToolIntent | None = (
            detect_tool_intent(
                request
            )
        )

    except Exception as exc:
        return _failure_result(
            status=DENIED,
            request_id=request_id,
            reason=(
                "Tool intent detection failed closed."
            ),
            error=str(exc),
        )

    # --------------------------------------------------------
    # NO APPROVED TOOL INTENT
    # --------------------------------------------------------

    if intent is None:
        return _failure_result(
            status=NO_TOOL,
            request_id=request_id,
            reason=(
                "The request does not clearly map to an "
                "approved security tool intent."
            ),
        )

    intent_name = _intent_name(
        intent
    )

    tool_name = _safe_text(
        getattr(
            intent,
            "tool",
            "",
        )
    ).lower()

    command_name = _safe_text(
        getattr(
            intent,
            "command",
            "",
        )
    ).lower()
    # --------------------------------------------------------
    # ARGUMENT-FREE SAFETY GATE
    # --------------------------------------------------------

    try:
        argument_free = (
            is_argument_free_tool_intent(
                intent
            )
        )

    except Exception as exc:
        return _failure_result(
            status=DENIED,
            request_id=request_id,
            intent=intent_name,
            tool=tool_name,
            command=command_name,
            reason=(
                "Tool intent safety validation "
                "failed closed."
            ),
            error=str(exc),
        )

    if not argument_free:
        reason = (
            "This tool intent requires explicit "
            "arguments or a target and cannot be "
            "automatically executed by the service."
        )

        try:
            log_audit_event(
                event_type="TOOL_ORCHESTRATION",
                success=False,
                status=DENIED,
                request_id=request_id,
                question=request,
                tool=tool_name,
                command="",
                policy_category=DENIED,
                execution_mode="none",
                reason=reason,
                error="",
                return_code=None,
                duration_ms=0,
            )

        except Exception:
            # Audit logging failure must never
            # break the security assistant.
            pass

        return _failure_result(
            status=DENIED,
            request_id=request_id,
            intent=intent_name,
            tool=tool_name,
            command="",
            reason=reason,
        )
    # --------------------------------------------------------
    # CONTROLLED ORCHESTRATION
    # --------------------------------------------------------

    try:
        orchestration_result = (
            orchestrate_tool_request(
                question=request,
                timeout_seconds=timeout_seconds,
                request_id=request_id,
            )
        )

    except Exception as exc:
        return _failure_result(
            status=DENIED,
            request_id=request_id,
            intent=intent_name,
            tool=tool_name,
            command=command_name,
            reason=(
                "Tool orchestration failed closed."
            ),
            error=str(exc),
        )
    # --------------------------------------------------------
    # AUDIT LOGGING
    # --------------------------------------------------------

    try:
        log_tool_orchestration_result(
            orchestration_result
        )

    except Exception:
        # Audit logging failure must never break
        # the security assistant execution path.
        pass
    
    # --------------------------------------------------------
    # FINAL SERVICE RESULT
    # --------------------------------------------------------

    return _map_orchestration_result(
        request_id=request_id,
        intent_name=intent_name,
        result=orchestration_result,
    )


# ============================================================
# SERIALIZATION
# ============================================================

def result_to_dict(
    result: ToolServiceResult,
) -> dict[str, Any]:
    """
    Convert a ToolServiceResult into a JSON-safe dictionary.
    """

    return {
        "success": result.success,
        "status": result.status,
        "request_id": result.request_id,
        "intent": result.intent,
        "tool": result.tool,
        "command": result.command,
        "reason": result.reason,
        "output": result.output,
        "error": result.error,
        "return_code": result.return_code,
        "duration_ms": result.duration_ms,
        "policy_category": result.policy_category,
    }


# ============================================================
# SELF TEST
# ============================================================

def run_self_test() -> bool:
    """
    Validate the service boundary.

    Tests:

        1. Empty request rejection.
        2. Invalid request type rejection.
        3. Normal RAG question does not invoke a tool.
        4. Argument-requiring tool is denied.
        5. Safe argument-free intent reaches orchestration.
    """

    # --------------------------------------------------------
    # TEST 1: EMPTY REQUEST
    # --------------------------------------------------------

    result = execute_tool_request("")

    assert result.success is False
    assert result.status == INVALID
    assert result.intent == ""
    assert result.tool == ""
    assert result.command == ""

    # --------------------------------------------------------
    # TEST 2: INVALID TYPE
    # --------------------------------------------------------

    result = execute_tool_request(
        None  # type: ignore[arg-type]
    )

    assert result.success is False
    assert result.status == INVALID

    # --------------------------------------------------------
    # TEST 3: NON-TOOL SECURITY QUESTION
    # --------------------------------------------------------

    result = execute_tool_request(
        "Is there evidence of SSH brute force activity?"
    )

    assert result.success is False
    assert result.status == NO_TOOL
    assert result.command == ""

    # --------------------------------------------------------
    # TEST 4: ARGUMENT-REQUIRING NMAP
    # --------------------------------------------------------

    result = execute_tool_request(
        "Scan 192.168.1.1 with nmap."
    )

    assert result.success is False
    assert result.status == DENIED
    assert result.command == ""

    # --------------------------------------------------------
    # TEST 5: SAFE ARGUMENT-FREE REQUEST
    # --------------------------------------------------------

    result = execute_tool_request(
        "Who am I logged in as?",
        request_id="test-service-request-001",
    )

    assert result.request_id == "test-service-request-001"
    assert result.intent != ""

    if result.success:

        assert result.tool == "whoami"
        assert result.command == "whoami"
        assert result.status == SUCCESS

    else:

        # The local operating environment may reject or fail
        # execution. The service must still fail closed.
        assert result.status in {
            DENIED,
            FAILED,
            INVALID,
        }

    serialized = result_to_dict(
        result
    )

    assert isinstance(
        serialized,
        dict,
    )

    assert serialized["request_id"] == "test-service-request-001"

    print(
        "[OK] Tool service self-test passed."
    )

    return True


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    run_self_test()