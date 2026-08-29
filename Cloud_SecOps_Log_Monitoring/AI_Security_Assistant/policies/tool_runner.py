
"""
KiroTrace - Controlled Security Tool Runner

Orchestration layer for controlled security-tool execution.

Flow:

    Tool Request
        |
        v
    Policy Controller
        |
        v
    Tool Registry
        |
        v
    Command Executor
        |
        v
    Structured Result

IMPORTANT:
    - Does not bypass policy_controller.py.
    - Does not execute unregistered tools.
    - Does not use shell=True.
    - Fails closed when authorization fails.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


# ============================================================
# IMPORTS
# ============================================================

try:
    from .policy_controller import (
        ControllerResult,
        process_command,
    )
except ImportError:
    from policy_controller import (
        ControllerResult,
        process_command,
    )


# ============================================================
# STATUS VALUES
# ============================================================

SUCCESS = "SUCCESS"
FAILED = "FAILED"
DENIED = "DENIED"
INVALID = "INVALID"


# ============================================================
# RUNNER RESULT
# ============================================================

@dataclass(frozen=True)
class ToolRunResult:
    success: bool
    command: str
    status: str
    reason: str
    output: str
    error: str
    return_code: int | None
    duration_ms: int
    policy_category: str


# ============================================================
# CONTROLLED COMMAND EXECUTION
# ============================================================

def run_security_tool(
    command: str,
    timeout_seconds: int = 15,
) -> ToolRunResult:
    """
    Execute a security command through the existing
    KiroTrace policy controller.

    The policy controller remains the single authorization
    boundary.
    """

    if not isinstance(command, str):
        return ToolRunResult(
            success=False,
            command="",
            status=INVALID,
            reason="Command must be provided as text.",
            output="",
            error="Command must be provided as text.",
            return_code=None,
            duration_ms=0,
            policy_category="INVALID",
        )

    command = command.strip()

    if not command:
        return ToolRunResult(
            success=False,
            command="",
            status=INVALID,
            reason="Command cannot be empty.",
            output="",
            error="Command cannot be empty.",
            return_code=None,
            duration_ms=0,
            policy_category="INVALID",
        )

    # --------------------------------------------------------
    # CENTRAL POLICY CONTROLLER
    # --------------------------------------------------------

    try:
        result: ControllerResult = process_command(
            command=command,
            timeout_seconds=timeout_seconds,
        )

    except Exception as exc:
        # Security boundary must fail closed.
        return ToolRunResult(
            success=False,
            command=command,
            status=DENIED,
            reason=(
                "Policy controller failed closed: "
                f"{exc}"
            ),
            output="",
            error=str(exc),
            return_code=None,
            duration_ms=0,
            policy_category="DENIED",
        )

    # --------------------------------------------------------
    # MAP CONTROLLER RESULT
    # --------------------------------------------------------

    # ControllerResult is the authoritative result from the
    # existing policy/execution layer.

    success = bool(
        getattr(
            result,
            "success",
            False,
        )
    )

    command_result = str(
        getattr(
            result,
            "command",
            command,
        )
    )

    reason = str(
        getattr(
            result,
            "reason",
            "",
        )
    )

    output = str(
        getattr(
            result,
            "stdout",
            "",
        )
        or ""
    )

    error = str(
        getattr(
            result,
            "stderr",
            "",
        )
        or ""
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

    policy_category = str(
        getattr(
            result,
            "policy_category",
            "UNKNOWN",
        )
    )

    # --------------------------------------------------------
    # STATUS
    # --------------------------------------------------------

    if success:
        status = SUCCESS

    elif policy_category in {
        "DENIED",
        "INVALID",
    }:
        status = (
            DENIED
            if policy_category == "DENIED"
            else INVALID
        )

    else:
        status = FAILED

    return ToolRunResult(
        success=success,
        command=command_result,
        status=status,
        reason=reason,
        output=output,
        error=error,
        return_code=return_code,
        duration_ms=duration_ms,
        policy_category=policy_category,
    )


# ============================================================
# SERIALIZATION
# ============================================================

def result_to_dict(
    result: ToolRunResult,
) -> dict[str, Any]:
    """
    Convert a ToolRunResult into a JSON-safe dictionary.
    """

    return {
        "success": result.success,
        "command": result.command,
        "status": result.status,
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
    Validate the tool-runner boundary.

    Only safe commands are executed.
    Dangerous commands must be rejected before execution.
    """

    # --------------------------------------------------------
    # TEST 1 — SAFE COMMAND
    # --------------------------------------------------------

    result = run_security_tool(
        "whoami"
    )

    assert result.policy_category == "ALLOWED"
    assert result.status in {
        SUCCESS,
        FAILED,
    }

    # --------------------------------------------------------
    # TEST 2 — DESTRUCTIVE COMMAND
    # --------------------------------------------------------

    result = run_security_tool(
        "rm -rf /"
    )

    assert result.success is False
    assert result.status == DENIED
    assert result.return_code is None

    # --------------------------------------------------------
    # TEST 3 — COMMAND CHAINING
    # --------------------------------------------------------

    result = run_security_tool(
        "whoami && rm -rf /"
    )

    assert result.success is False
    assert result.status == DENIED
    assert result.return_code is None

    # --------------------------------------------------------
    # TEST 4 — PIPE
    # --------------------------------------------------------

    result = run_security_tool(
        "whoami | grep root"
    )

    assert result.success is False
    assert result.status == DENIED
    assert result.return_code is None

    # --------------------------------------------------------
    # TEST 5 — SHELL INTERPRETER
    # --------------------------------------------------------

    result = run_security_tool(
        "bash -c whoami"
    )

    assert result.success is False
    assert result.status == DENIED
    assert result.return_code is None

    # --------------------------------------------------------
    # TEST 6 — UNKNOWN COMMAND
    # --------------------------------------------------------

    result = run_security_tool(
        "some_unknown_tool"
    )

    assert result.success is False
    assert result.status == DENIED
    assert result.return_code is None

    # --------------------------------------------------------
    # TEST 7 — EMPTY COMMAND
    # --------------------------------------------------------

    result = run_security_tool("")

    assert result.success is False
    assert result.status == INVALID

    print(
        "[OK] Tool runner self-test passed."
    )

    return True


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    run_self_test()
