"""
KiroTrace - Security Tool Orchestrator

Controlled bridge between user/tool intent and the security-tool
execution boundaries.

Execution paths:

    User Question
          |
          v
    tool_intent.py
          |
          v
    Tool Orchestrator
          |
          v
    Argument-Free Safety Boundary
          |
          v
    Policy Authorization
          |
          +----------------------+
          |                      |
          v                      v
    tool_runner.py          sandbox.py
          |                      |
          v                      v
    Normal Execution       Sandbox Execution

IMPORTANT:
    - No arbitrary shell commands are generated here.
    - No direct subprocess execution.
    - No shell=True.
    - Tool intent is deterministic.
    - Policy authorization is mandatory before sandbox execution.
    - Unknown/unsupported tools fail closed.
    - Sandbox execution is optional.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional


# ============================================================
# IMPORTS
# ============================================================

try:
    from .tool_intent import (
        ToolIntent,
        detect_tool_intent,
        is_argument_free_tool_intent,
    )

    from .tool_runner import (
        ToolRunResult,
        run_security_tool,
    )

    from .policy_controller import (
        ToolAuthorization,
        authorize_tool_request,
    )

    from .sandbox import (
        SandboxResult,
        execute_in_sandbox,
    )

except ImportError:
    from tool_intent import (
        ToolIntent,
        detect_tool_intent,
        is_argument_free_tool_intent,
    )

    from tool_runner import (
        ToolRunResult,
        run_security_tool,
    )

    from policy_controller import (
        ToolAuthorization,
        authorize_tool_request,
    )

    from sandbox import (
        SandboxResult,
        execute_in_sandbox,
    )


# ============================================================
# STATUS VALUES
# ============================================================

EXECUTED = "EXECUTED"
SANDBOX_EXECUTED = "SANDBOX_EXECUTED"
NO_TOOL_REQUIRED = "NO_TOOL_REQUIRED"
REJECTED = "REJECTED"
FAILED = "FAILED"


# ============================================================
# ORCHESTRATOR RESULT
# ============================================================

@dataclass(frozen=True)
class ToolOrchestrationResult:
    """
    Structured result returned by the tool orchestration layer.
    """

    success: bool
    status: str
    request_id: str
    question: str
    tool: str
    command: str
    reason: str
    output: str
    error: str
    return_code: Optional[int]
    duration_ms: int
    policy_category: str
    execution_mode: str = "none"


# ============================================================
# FAILURE HELPER
# ============================================================

def _failure(
    *,
    status: str,
    request_id: str = "",
    question: str,
    reason: str,
    tool: str = "",
    command: str = "",
    policy_category: str = "",
    execution_mode: str = "none",
) -> ToolOrchestrationResult:
    """
    Build a deterministic failed orchestration result.
    """

    return ToolOrchestrationResult(
        success=False,
        status=status,
        request_id=request_id,
        question=question,
        tool=tool,
        command=command,
        reason=reason,
        output="",
        error=reason,
        return_code=None,
        duration_ms=0,
        policy_category=policy_category,
        execution_mode=execution_mode,
    )


# ============================================================
# QUESTION VALIDATION
# ============================================================

def _validate_question(
    question: str,
) -> tuple[bool, str]:
    """
    Validate user question before intent detection.
    """

    if not isinstance(question, str):
        return (
            False,
            "Question must be provided as text.",
        )

    normalized = " ".join(
        question.strip().split()
    )

    if not normalized:
        return (
            False,
            "Question cannot be empty.",
        )

    return True, normalized


# ============================================================
# NORMAL TOOL RESULT MAPPING
# ============================================================

def _map_tool_runner_result(
    *,
    request_id: str,
    question: str,
    intent: ToolIntent,
    result: ToolRunResult,
) -> ToolOrchestrationResult:
    """
    Convert a normal tool-runner result into the
    orchestrator result format.
    """

    if result.success:
        status = EXECUTED

    elif result.status in {
        "DENIED",
        "INVALID",
    }:
        status = REJECTED

    else:
        status = FAILED

    return ToolOrchestrationResult(
        success=bool(result.success),
        status=status,
        request_id=request_id,
        question=question,
        tool=intent.tool,
        command=result.command,
        reason=(
            result.reason
            or intent.reason
        ),
        output=result.output,
        error=result.error,
        return_code=result.return_code,
        duration_ms=result.duration_ms,
        policy_category=result.policy_category,
        execution_mode="normal",
    )


# ============================================================
# SANDBOX RESULT MAPPING
# ============================================================

def _map_sandbox_result(
    *,
    request_id: str,
    question: str,
    intent: ToolIntent,
    authorization: ToolAuthorization,
    result: SandboxResult,
) -> ToolOrchestrationResult:
    """
    Convert a sandbox result into the orchestrator result format.

    Sandbox execution is only reached after deterministic
    policy authorization.
    """

    if result.success:
        status = SANDBOX_EXECUTED

    else:
        status = FAILED

    return ToolOrchestrationResult(
        success=bool(result.success),
        status=status,
        request_id=request_id,
        question=question,
        tool=intent.tool,
        command=result.command,
        reason=(
            result.reason
            or authorization.policy_reason
            or intent.reason
        ),
        output=result.stdout,
        error=result.stderr,
        return_code=result.return_code,
        duration_ms=result.duration_ms,
        policy_category=authorization.policy_category,
        execution_mode="sandbox",
    )


# ============================================================
# TOOL ORCHESTRATION
# ============================================================

def orchestrate_tool_request(
    question: str,
    timeout_seconds: int = 15,
    use_sandbox: bool = False,
    request_id: str = "",
) -> ToolOrchestrationResult:
    """
    Process a user question through the controlled tool layer.

    Parameters
    ----------
    question:
        Natural-language security question.

    timeout_seconds:
        Maximum execution time.

    use_sandbox:
        When True, the approved argument-free command is executed
        through sandbox.py instead of the normal tool runner.

    IMPORTANT
    ---------
    Sandbox mode does NOT bypass policy authorization.

    The sequence is always:

        Intent
          |
        Argument-free validation
          |
        Policy authorization
          |
        Execution
    """

    valid, normalized_question = _validate_question(
        question
    )

    if not valid:
        return _failure(
            status=REJECTED,
            request_id=request_id,
            question=(
                question
                if isinstance(question, str)
                else ""
            ),
            reason=normalized_question,
        )

    # --------------------------------------------------------
    # INTENT DETECTION
    # --------------------------------------------------------

    intent: Optional[ToolIntent] = (
        detect_tool_intent(
            normalized_question
        )
    )

    # Normal security/RAG question.
    if intent is None:
        return ToolOrchestrationResult(
            success=True,
            status=NO_TOOL_REQUIRED,
            request_id=request_id,
            question=normalized_question,
            tool="",
            command="",
            reason=(
                "No controlled security-tool intent was detected. "
                "The request should remain in the normal RAG "
                "analysis pipeline."
            ),
            output="",
            error="",
            return_code=None,
            duration_ms=0,
            policy_category="",
            execution_mode="none",
        )

    # --------------------------------------------------------
    # ARGUMENT-FREE SAFETY BOUNDARY
    # --------------------------------------------------------

    if not is_argument_free_tool_intent(intent):
        return _failure(
            status=REJECTED,
            request_id=request_id,
            question=normalized_question,
            reason=(
                f"Tool '{intent.tool}' requires an execution "
                "path that is not enabled by the argument-free "
                "tool orchestration policy."
            ),
            tool=intent.tool,
            command=intent.command,
        )

    # --------------------------------------------------------
    # COMMAND MUST COME FROM DETERMINISTIC INTENT
    # --------------------------------------------------------

    command = intent.command.strip()

    if not command:
        return _failure(
            status=REJECTED,
            request_id=request_id,
            question=normalized_question,
            reason=(
                "Tool intent did not provide a valid command."
            ),
            tool=intent.tool,
        )

    # --------------------------------------------------------
    # SANDBOX PATH
    # --------------------------------------------------------

    if use_sandbox:
        try:
            authorization = authorize_tool_request(
                command
            )

        except Exception as exc:
            return _failure(
                status=FAILED,
                request_id=request_id,
                question=normalized_question,
                reason=(
                    "Tool authorization failed closed: "
                    f"{exc}"
                ),
                tool=intent.tool,
                command=command,
                policy_category="DENIED",
                execution_mode="sandbox",
            )

        # ----------------------------------------------------
        # AUTHORIZATION MUST SUCCEED BEFORE SANDBOX EXECUTION
        # ----------------------------------------------------

        if not authorization.allowed:
            return _failure(
                status=REJECTED,
                request_id=request_id,
                question=normalized_question,
                reason=authorization.policy_reason,
                tool=authorization.tool,
                command=authorization.command,
                policy_category=authorization.policy_category,
                execution_mode="sandbox",
            )

        try:
            sandbox_result = execute_in_sandbox(
                command=authorization.command,
                timeout_seconds=timeout_seconds,
            )

        except Exception as exc:
            return _failure(
                status=FAILED,
                request_id=request_id,

                question=normalized_question,
                reason=(
                    "Sandbox execution failed closed: "
                    f"{exc}"
                ),
                tool=intent.tool,
                command=authorization.command,
                policy_category=authorization.policy_category,
                execution_mode="sandbox",
            )

        return _map_sandbox_result(
            request_id=request_id,
            question=normalized_question,
            intent=intent,
            authorization=authorization,
            result=sandbox_result,
        )

    # --------------------------------------------------------
    # NORMAL CONTROLLED RUNNER
    # --------------------------------------------------------

    try:
        result: ToolRunResult = run_security_tool(
            command=command,
            timeout_seconds=timeout_seconds,
        )

    except Exception as exc:
        return _failure(
            status=FAILED,
            request_id=request_id,
            question=normalized_question,
            reason=(
                "Controlled tool runner failed closed: "
                f"{exc}"
            ),
            tool=intent.tool,
            command=command,
            execution_mode="normal",
        )

    return _map_tool_runner_result(
        request_id=request_id,
        question=normalized_question,
        intent=intent,
        result=result,
    )


# ============================================================
# SERIALIZATION
# ============================================================

def orchestration_result_to_dict(
    result: ToolOrchestrationResult,
) -> dict[str, Any]:
    """
    Convert orchestration result into a JSON-safe dictionary.
    """

    return {
        "success": result.success,
        "status": result.status,
        "request_id": result.request_id,
        "question": result.question,
        "tool": result.tool,
        "command": result.command,
        "reason": result.reason,
        "output": result.output,
        "error": result.error,
        "return_code": result.return_code,
        "duration_ms": result.duration_ms,
        "policy_category": result.policy_category,
        "execution_mode": result.execution_mode,
    }


# ============================================================
# SELF TEST
# ============================================================

def run_self_test() -> bool:
    """
    Validate normal and sandbox orchestration boundaries.
    """

    # --------------------------------------------------------
    # TEST 1: NORMAL SAFE TOOL
    # --------------------------------------------------------

    result = orchestrate_tool_request(
        "Who am I currently logged in as?",
        request_id="test-request-001",
    )

    assert result.success is True
    assert result.status == EXECUTED
    assert result.request_id == "test-request-001"
    assert result.tool == "whoami"
    assert result.command == "whoami"
    assert result.execution_mode == "normal"
    assert result.request_id == "test-request-001"

    # --------------------------------------------------------
    # TEST 2: HOSTNAME
    # --------------------------------------------------------

    result = orchestrate_tool_request(
        "What is this machine's hostname?"
    )

    assert result.success is True
    assert result.status == EXECUTED
    assert result.tool == "hostname"
    assert result.command == "hostname"

    # --------------------------------------------------------
    # TEST 3: NORMAL RAG QUESTION
    # --------------------------------------------------------

    result = orchestrate_tool_request(
        "Is there evidence of SSH brute force activity?"
    )

    assert result.success is True
    assert result.status == NO_TOOL_REQUIRED
    assert result.tool == ""
    assert result.command == ""

    # --------------------------------------------------------
    # TEST 4: EMPTY QUESTION
    # --------------------------------------------------------

    result = orchestrate_tool_request("")

    assert result.success is False
    assert result.status == REJECTED

    # --------------------------------------------------------
    # TEST 5: ARBITRARY COMMAND
    # --------------------------------------------------------

    result = orchestrate_tool_request(
        "run rm -rf /"
    )

    assert result.success is True
    assert result.status == NO_TOOL_REQUIRED
    assert result.command == ""

    # --------------------------------------------------------
    # TEST 6: COMMAND INJECTION
    # --------------------------------------------------------

    result = orchestrate_tool_request(
        "Who am I && rm -rf /"
    )

    assert result.success is True
    assert result.status == NO_TOOL_REQUIRED
    assert result.tool == ""
    assert result.command == ""
    assert result.output == ""

    # --------------------------------------------------------
    # TEST 7: NMAP REQUIRES TARGET
    # --------------------------------------------------------

    result = orchestrate_tool_request(
        "Run a network scan."
    )

    assert result.success is False
    assert result.status == REJECTED
    assert result.tool == "nmap"

    # --------------------------------------------------------
    # TEST 8: SANDBOX SAFE TOOL
    # --------------------------------------------------------

    result = orchestrate_tool_request(
        "Who am I currently logged in as?",
        use_sandbox=True,
    )

    assert result.success is True
    assert result.status == SANDBOX_EXECUTED
    assert result.tool == "whoami"
    assert result.command == "whoami"
    assert result.execution_mode == "sandbox"
    assert result.return_code == 0
    assert result.output.strip()

    # --------------------------------------------------------
    # TEST 9: SANDBOX HOSTNAME
    # --------------------------------------------------------

    result = orchestrate_tool_request(
        "What is this machine's hostname?",
        use_sandbox=True,
    )

    assert result.success is True
    assert result.status == SANDBOX_EXECUTED
    assert result.tool == "hostname"
    assert result.command == "hostname"
    assert result.execution_mode == "sandbox"

    # --------------------------------------------------------
    # TEST 10: SANDBOX MUST STILL RESPECT INTENT BOUNDARY
    # --------------------------------------------------------

    result = orchestrate_tool_request(
        "run rm -rf /",
        use_sandbox=True,
    )

    assert result.success is True
    assert result.status == NO_TOOL_REQUIRED
    assert result.command == ""

    # --------------------------------------------------------
    # TEST 11: SANDBOX COMMAND INJECTION
    # --------------------------------------------------------

    result = orchestrate_tool_request(
        "Who am I && rm -rf /",
        use_sandbox=True,
    )

    assert result.success is True
    assert result.status == NO_TOOL_REQUIRED
    assert result.tool == ""
    assert result.command == ""

    # --------------------------------------------------------
    # TEST 12: SERIALIZATION
    # --------------------------------------------------------

    serialized = orchestration_result_to_dict(
        result
    )

    assert isinstance(
        serialized,
        dict,
    )

    assert "command" in serialized
    assert "status" in serialized
    assert "request_id" in serialized
    assert "policy_category" in serialized
    assert "execution_mode" in serialized

    print(
        "[OK] Tool orchestrator self-test passed."
    )

    return True


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    run_self_test()
