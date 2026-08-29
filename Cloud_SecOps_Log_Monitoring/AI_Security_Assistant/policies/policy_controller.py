"""
KiroTrace - Policy Controller

Controlled orchestration layer for security-tool requests.

Architecture:

    User / AI request
          |
          v
    Policy Controller
          |
          +----> Tool Registry
          |
          +----> Command Policy
          |
          +----> Command Executor
          |
          v
    Structured execution result

IMPORTANT:
    - No direct shell execution.
    - No shell=True.
    - No policy bypass.
    - Unknown tools are rejected.
    - Commands remain subject to command_policy.py.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

try:
    from .command_executor import (
        DEFAULT_TIMEOUT_SECONDS,
        ExecutionResult,
        execute_command,
    )
    from .command_policy import (
        ALLOWED,
        DENIED,
        INVALID,
        PolicyDecision,
        evaluate_command,
    )
    from .tool_registry import (
        get_tool,
        is_registered_tool,
    )
except ImportError:
    from command_executor import (
        DEFAULT_TIMEOUT_SECONDS,
        ExecutionResult,
        execute_command,
    )
    from command_policy import (
        ALLOWED,
        DENIED,
        INVALID,
        PolicyDecision,
        evaluate_command,
    )
    from tool_registry import (
        get_tool,
        is_registered_tool,
    )


# ============================================================
# CONTROLLER CONFIGURATION
# ============================================================

MAX_REQUEST_LENGTH = 1000


# ============================================================
# CONTROLLER RESULT
# ============================================================

@dataclass(frozen=True)
class ControllerResult:
    """
    Final structured result returned by the policy controller.
    """

    success: bool
    stage: str
    category: str
    reason: str
    tool: str
    command: str
    return_code: Optional[int]
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool
    @property
    def policy_category(self) -> str:
        """
        Backward-compatible alias used by tool_runner.py.
        """
        return self.category

# ============================================================
# FAILURE RESULT HELPER
# ============================================================

def _failure(
    *,
    stage: str,
    category: str,
    reason: str,
    tool: str = "",
    command: str = "",
) -> ControllerResult:
    """
    Build a deterministic controller failure result.
    """

    return ControllerResult(
        success=False,
        stage=stage,
        category=category,
        reason=reason,
        tool=tool,
        command=command,
        return_code=None,
        stdout="",
        stderr="",
        duration_ms=0,
        timed_out=False,
    )


# ============================================================
# TOOL EXTRACTION
# ============================================================

def _extract_tool_name(command: str) -> str:
    """
    Extract the first executable token from a command.

    Example:
        nmap -sV 192.168.1.10

    Returns:
        nmap
    """

    if not isinstance(command, str):
        return ""

    normalized = " ".join(command.strip().split())

    if not normalized:
        return ""

    return normalized.split(" ", 1)[0].lower()


# ============================================================
# TOOL VALIDATION
# ============================================================

def validate_tool_request(command: str) -> tuple[bool, str, str]:
    """
    Validate that the requested executable is registered.

    Returns:
        (valid, tool_name, reason)
    """

    tool_name = _extract_tool_name(command)

    if not tool_name:
        return (
            False,
            "",
            "No executable tool was specified.",
        )

    if not is_registered_tool(tool_name):
        return (
            False,
            tool_name,
            (
                f"Tool '{tool_name}' is not registered "
                "in the KiroTrace tool registry."
            ),
        )

    return (
        True,
        tool_name,
        "Tool is registered.",
    )


# ============================================================
# POLICY VALIDATION
# ============================================================

def validate_command_policy(
    command: str,
) -> PolicyDecision:
    """
    Evaluate the command through the deterministic policy.

    This is a mandatory security boundary.
    """

    return evaluate_command(command)


# ============================================================
# TOOL METADATA
# ============================================================

def get_tool_metadata(
    tool_name: str,
) -> dict[str, Any] | None:
    """
    Return registered metadata for a tool.

    The registry remains the source of truth.
    """

    if not tool_name:
        return None

    try:
        metadata = get_tool(tool_name)
    except (KeyError, TypeError, ValueError):
        return None

    if metadata is None:
        return None

    if isinstance(metadata, dict):
        return metadata

    # Support registry implementations that expose
    # dataclass/object metadata.
    if hasattr(metadata, "__dict__"):
        return dict(metadata.__dict__)

    return None


# ============================================================
# REQUEST PROCESSING
# ============================================================

def process_command(
    command: str,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> ControllerResult:
    """
    Process a security-tool command through the complete
    controlled execution pipeline.

    Pipeline:

        Input validation
            |
        Tool registry
            |
        Command policy
            |
        Command executor
            |
        Structured result

    This function does NOT provide any policy bypass.
    """

    # --------------------------------------------------------
    # Basic input validation
    # --------------------------------------------------------

    if not isinstance(command, str):
        return _failure(
            stage="input_validation",
            category=INVALID,
            reason="Command must be provided as text.",
        )

    if len(command) > MAX_REQUEST_LENGTH:
        return _failure(
            stage="input_validation",
            category=DENIED,
            reason=(
                "Command exceeds the maximum permitted "
                "request length."
            ),
            command=command[:MAX_REQUEST_LENGTH],
        )

    normalized = " ".join(command.strip().split())

    if not normalized:
        return _failure(
            stage="input_validation",
            category=INVALID,
            reason="Command cannot be empty.",
        )

    # --------------------------------------------------------
    # Tool registry validation
    # --------------------------------------------------------

    valid_tool, tool_name, tool_reason = (
        validate_tool_request(normalized)
    )

    if not valid_tool:
        return _failure(
            stage="tool_registry",
            category=DENIED,
            reason=tool_reason,
            tool=tool_name,
            command=normalized,
        )

    # --------------------------------------------------------
    # Retrieve metadata
    # --------------------------------------------------------

    metadata = get_tool_metadata(tool_name)

    if metadata is None:
        return _failure(
            stage="tool_registry",
            category=DENIED,
            reason=(
                f"Registered tool '{tool_name}' could not "
                "be resolved from the tool registry."
            ),
            tool=tool_name,
            command=normalized,
        )

    # --------------------------------------------------------
    # Deterministic command policy
    # --------------------------------------------------------

    policy = validate_command_policy(normalized)

    if not policy.allowed:
        return _failure(
            stage="command_policy",
            category=policy.category,
            reason=policy.reason,
            tool=tool_name,
            command=policy.normalized_command,
        )

    # --------------------------------------------------------
    # Registry / policy consistency check
    # --------------------------------------------------------

    registry_command = metadata.get(
        "command",
        metadata.get("name", tool_name),
    )

    if isinstance(registry_command, str):
        registry_base = _extract_tool_name(
            registry_command
        )

        if registry_base and registry_base != tool_name:
            return _failure(
                stage="registry_consistency",
                category=DENIED,
                reason=(
                    "Tool registry metadata is inconsistent "
                    "with the requested executable."
                ),
                tool=tool_name,
                command=policy.normalized_command,
            )

    # --------------------------------------------------------
    # Controlled execution
    # --------------------------------------------------------

    execution: ExecutionResult = execute_command(
        policy.normalized_command,
        timeout_seconds=timeout_seconds,
    )

    return ControllerResult(
        success=execution.success,
        stage="execution",
        category=execution.policy_category,
        reason=execution.policy_reason,
        tool=tool_name,
        command=execution.command,
        return_code=execution.return_code,
        stdout=execution.stdout,
        stderr=execution.stderr,
        duration_ms=execution.duration_ms,
        timed_out=execution.timed_out,
    )

# ============================================================
# TOOL REQUEST AUTHORIZATION
# ============================================================

@dataclass(frozen=True)
class ToolAuthorization:
    """
    Deterministic authorization result for tool_runner.py.

    This is an authorization-only decision.
    It does NOT execute the command.

    Execution remains exclusively inside process_command().
    """

    allowed: bool
    policy_category: str
    policy_reason: str
    tool: str
    command: str


def authorize_tool_request(
    command: str,
) -> ToolAuthorization:
    """
    Authorize a tool request without executing it.

    Security pipeline:

        Input
          |
        Tool Registry
          |
        Command Policy
          |
        Authorization Result

    IMPORTANT:
        This function NEVER executes a command.
    """

    # --------------------------------------------------------
    # BASIC INPUT VALIDATION
    # --------------------------------------------------------

    if not isinstance(command, str):
        return ToolAuthorization(
            allowed=False,
            policy_category=INVALID,
            policy_reason="Command must be provided as text.",
            tool="",
            command="",
        )

    if len(command) > MAX_REQUEST_LENGTH:
        return ToolAuthorization(
            allowed=False,
            policy_category=DENIED,
            policy_reason=(
                "Command exceeds the maximum permitted "
                "request length."
            ),
            tool="",
            command=command[:MAX_REQUEST_LENGTH],
        )

    normalized = " ".join(
        command.strip().split()
    )

    if not normalized:
        return ToolAuthorization(
            allowed=False,
            policy_category=INVALID,
            policy_reason="Command cannot be empty.",
            tool="",
            command="",
        )

    # --------------------------------------------------------
    # TOOL REGISTRY
    # --------------------------------------------------------

    valid_tool, tool_name, tool_reason = (
        validate_tool_request(normalized)
    )

    if not valid_tool:
        return ToolAuthorization(
            allowed=False,
            policy_category=DENIED,
            policy_reason=tool_reason,
            tool=tool_name,
            command=normalized,
        )

    # --------------------------------------------------------
    # REGISTRY METADATA
    # --------------------------------------------------------

    metadata = get_tool_metadata(tool_name)

    if metadata is None:
        return ToolAuthorization(
            allowed=False,
            policy_category=DENIED,
            policy_reason=(
                f"Registered tool '{tool_name}' could not "
                "be resolved from the tool registry."
            ),
            tool=tool_name,
            command=normalized,
        )

    # --------------------------------------------------------
    # COMMAND POLICY
    # --------------------------------------------------------

    policy = validate_command_policy(
        normalized
    )

    if not policy.allowed:
        return ToolAuthorization(
            allowed=False,
            policy_category=policy.category,
            policy_reason=policy.reason,
            tool=tool_name,
            command=policy.normalized_command,
        )

    # --------------------------------------------------------
    # REGISTRY / POLICY CONSISTENCY
    # --------------------------------------------------------

    registry_command = metadata.get(
        "command",
        metadata.get(
            "name",
            tool_name,
        ),
    )

    if isinstance(
        registry_command,
        str,
    ):
        registry_base = _extract_tool_name(
            registry_command
        )

        if (
            registry_base
            and registry_base != tool_name
        ):
            return ToolAuthorization(
                allowed=False,
                policy_category=DENIED,
                policy_reason=(
                    "Tool registry metadata is inconsistent "
                    "with the requested executable."
                ),
                tool=tool_name,
                command=policy.normalized_command,
            )

    # --------------------------------------------------------
    # AUTHORIZED
    # --------------------------------------------------------

    return ToolAuthorization(
        allowed=True,
        policy_category=ALLOWED,
        policy_reason=(
            policy.reason
            or "Tool request authorized by policy."
        ),
        tool=tool_name,
        command=policy.normalized_command,
    )

# ============================================================
# SELF TEST
# ============================================================

def run_self_test() -> bool:
    """
    Validate the complete controller boundary.
    """

    # --------------------------------------------------------
    # Allowed registered command
    # --------------------------------------------------------

    result = process_command("whoami")

    assert result.tool == "whoami"
    assert result.stage == "execution"
    assert result.category == ALLOWED
    assert result.command == "whoami"

    # --------------------------------------------------------
    # Unknown tool
    # --------------------------------------------------------

    result = process_command(
        "some_unknown_tool"
    )

    assert result.success is False
    assert result.stage == "tool_registry"
    assert result.category == DENIED
    assert result.return_code is None

    # --------------------------------------------------------
    # Destructive command
    # --------------------------------------------------------

    result = process_command(
        "rm -rf /"
    )

    assert result.success is False
    assert result.stage == "tool_registry" or (
        result.stage == "command_policy"
    )
    assert result.category == DENIED
    assert result.return_code is None

    # --------------------------------------------------------
    # Shell chaining
    # --------------------------------------------------------

    result = process_command(
        "whoami && rm -rf /"
    )

    assert result.success is False
    assert result.category == DENIED
    assert result.return_code is None

    # --------------------------------------------------------
    # Shell interpreter
    # --------------------------------------------------------

    result = process_command(
        "bash -c whoami"
    )

    assert result.success is False
    assert result.category == DENIED
    assert result.return_code is None

    # --------------------------------------------------------
    # Empty request
    # --------------------------------------------------------

    result = process_command("")

    assert result.success is False
    assert result.category == INVALID

    # --------------------------------------------------------
    # Excessively long request
    # --------------------------------------------------------

    result = process_command(
        "whoami " + ("A" * MAX_REQUEST_LENGTH)
    )

    assert result.success is False
    assert result.stage == "input_validation"
    assert result.category == DENIED

    print(
        "[OK] Policy controller self-test passed."
    )

    return True


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    run_self_test()