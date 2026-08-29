"""
KiroTrace - Safe Command Executor

Controlled execution layer for security-tool commands.

Execution flow:

    Command
       |
       v
    command_policy.py
       |
       | allowed
       v
    sandbox.py
       |
       v
    Controlled subprocess execution

IMPORTANT:
    - Command policy is ALWAYS evaluated first.
    - Sandbox is the execution boundary.
    - No shell=True.
    - No shell chaining / pipes / redirection.
    - Execution timeout is enforced.
    - Output size is limited.
    - Structured execution results are returned.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

try:
    from .command_policy import (
        ALLOWED,
        DENIED,
        INVALID,
        PolicyDecision,
        evaluate_command,
    )
    from .sandbox import (
        DEFAULT_SANDBOX_TIMEOUT_SECONDS,
        execute_in_sandbox,
    )
except ImportError:
    from command_policy import (
        ALLOWED,
        DENIED,
        INVALID,
        PolicyDecision,
        evaluate_command,
    )
    from sandbox import (
        DEFAULT_SANDBOX_TIMEOUT_SECONDS,
        execute_in_sandbox,
    )


# ============================================================
# EXECUTION CONFIGURATION
# ============================================================

DEFAULT_TIMEOUT_SECONDS = DEFAULT_SANDBOX_TIMEOUT_SECONDS

MAX_OUTPUT_CHARS = 12000

MAX_COMMAND_LENGTH = 1000


# ============================================================
# EXECUTION RESULT
# ============================================================

@dataclass(frozen=True)
class ExecutionResult:
    success: bool
    policy_category: str
    policy_reason: str
    command: str
    return_code: Optional[int]
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool


# ============================================================
# OUTPUT LIMITING
# ============================================================

def _limit_output(text: str) -> str:
    """
    Prevent excessive command output from entering the application.

    Sandbox already limits output, but the executor keeps its own
    boundary so this module remains safe even if sandbox limits
    change in the future.
    """

    if not text:
        return ""

    if len(text) <= MAX_OUTPUT_CHARS:
        return text

    return (
        text[:MAX_OUTPUT_CHARS]
        + "\n[OUTPUT TRUNCATED BY KIROTRACE]"
    )


# ============================================================
# EXECUTOR
# ============================================================

def execute_command(
    command: str,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> ExecutionResult:
    """
    Validate and safely execute an explicitly allowed command.

    Security pipeline:

        Input validation
            |
        Command policy
            |
        Sandbox
            |
        Controlled subprocess

    This function does not directly call subprocess.run().
    Actual process execution is delegated to sandbox.py.
    """

    # --------------------------------------------------------
    # Basic input validation
    # --------------------------------------------------------

    if not isinstance(command, str):
        return ExecutionResult(
            success=False,
            policy_category=INVALID,
            policy_reason="Command must be provided as text.",
            command="",
            return_code=None,
            stdout="",
            stderr="",
            duration_ms=0,
            timed_out=False,
        )

    if len(command) > MAX_COMMAND_LENGTH:
        return ExecutionResult(
            success=False,
            policy_category=DENIED,
            policy_reason=(
                "Command exceeds the maximum permitted "
                "command length."
            ),
            command=command[:MAX_COMMAND_LENGTH],
            return_code=None,
            stdout="",
            stderr="",
            duration_ms=0,
            timed_out=False,
        )

    # --------------------------------------------------------
    # Timeout validation
    # --------------------------------------------------------

    if not isinstance(timeout_seconds, int):
        timeout_seconds = DEFAULT_TIMEOUT_SECONDS

    if timeout_seconds <= 0:
        timeout_seconds = DEFAULT_TIMEOUT_SECONDS

    # --------------------------------------------------------
    # POLICY CHECK — MANDATORY
    # --------------------------------------------------------

    policy: PolicyDecision = evaluate_command(command)

    if not policy.allowed:
        return ExecutionResult(
            success=False,
            policy_category=policy.category,
            policy_reason=policy.reason,
            command=policy.normalized_command,
            return_code=None,
            stdout="",
            stderr="",
            duration_ms=0,
            timed_out=False,
        )

    # --------------------------------------------------------
    # SANDBOX EXECUTION
    # --------------------------------------------------------

    try:
        sandbox_result = execute_in_sandbox(
            command=policy.normalized_command,
            timeout_seconds=timeout_seconds,
        )

    except Exception as exc:
        # Security boundary must fail closed if the sandbox
        # itself cannot be invoked correctly.
        return ExecutionResult(
            success=False,
            policy_category=DENIED,
            policy_reason=(
                "KiroTrace sandbox execution failed closed: "
                f"{exc}"
            ),
            command=policy.normalized_command,
            return_code=None,
            stdout="",
            stderr=str(exc),
            duration_ms=0,
            timed_out=False,
        )

    # --------------------------------------------------------
    # MAP SANDBOX RESULT
    # --------------------------------------------------------

    stdout = _limit_output(
        sandbox_result.stdout or ""
    )

    stderr = _limit_output(
        sandbox_result.stderr or ""
    )

    # --------------------------------------------------------
    # SUCCESS
    # --------------------------------------------------------

    if sandbox_result.success:
        return ExecutionResult(
            success=True,
            policy_category=ALLOWED,
            policy_reason=(
                "Command was authorized by the deterministic "
                "command policy and executed inside the "
                "KiroTrace sandbox."
            ),
            command=sandbox_result.command,
            return_code=sandbox_result.return_code,
            stdout=stdout,
            stderr=stderr,
            duration_ms=sandbox_result.duration_ms,
            timed_out=False,
        )

    # --------------------------------------------------------
    # TIMEOUT
    # --------------------------------------------------------

    if sandbox_result.timed_out:
        return ExecutionResult(
            success=False,
            policy_category=ALLOWED,
            policy_reason=(
                "Command was allowed by policy but exceeded "
                "the configured sandbox execution timeout."
            ),
            command=sandbox_result.command,
            return_code=None,
            stdout=stdout,
            stderr=stderr,
            duration_ms=sandbox_result.duration_ms,
            timed_out=True,
        )

    # --------------------------------------------------------
    # RUNTIME FAILURE
    # --------------------------------------------------------

    return ExecutionResult(
        success=False,
        policy_category=ALLOWED,
        policy_reason=(
            sandbox_result.reason
            or (
                "Command was allowed by policy but "
                "sandbox execution failed."
            )
        ),
        command=sandbox_result.command,
        return_code=sandbox_result.return_code,
        stdout=stdout,
        stderr=stderr,
        duration_ms=sandbox_result.duration_ms,
        timed_out=False,
    )


# ============================================================
# SELF TEST
# ============================================================

def run_self_test() -> bool:
    """
    Validate the executor and sandbox integration.

    Tests include:
        - Allowed command execution
        - Destructive command denial
        - Shell chaining denial
        - Pipe denial
        - Shell interpreter denial
        - Unknown command denial
        - Sandbox-backed execution
    """

    # --------------------------------------------------------
    # Allowed command
    # --------------------------------------------------------

    result = execute_command("whoami")

    assert result.policy_category == ALLOWED
    assert result.command == "whoami"
    assert result.success is True
    assert result.return_code == 0
    assert result.stdout.strip()

    # --------------------------------------------------------
    # Destructive command
    # --------------------------------------------------------

    result = execute_command("rm -rf /")

    assert result.success is False
    assert result.policy_category == DENIED
    assert result.return_code is None

    # --------------------------------------------------------
    # Command chaining
    # --------------------------------------------------------

    result = execute_command(
        "whoami && rm -rf /"
    )

    assert result.success is False
    assert result.policy_category == DENIED
    assert result.return_code is None

    # --------------------------------------------------------
    # Pipe
    # --------------------------------------------------------

    result = execute_command(
        "whoami | grep root"
    )

    assert result.success is False
    assert result.policy_category == DENIED
    assert result.return_code is None

    # --------------------------------------------------------
    # Shell interpreter
    # --------------------------------------------------------

    result = execute_command(
        "bash -c whoami"
    )

    assert result.success is False
    assert result.policy_category == DENIED
    assert result.return_code is None

    # --------------------------------------------------------
    # Unknown command
    # --------------------------------------------------------

    result = execute_command(
        "some_unknown_tool"
    )

    assert result.success is False
    assert result.policy_category == DENIED
    assert result.return_code is None

    # --------------------------------------------------------
    # Empty command
    # --------------------------------------------------------

    result = execute_command("")

    assert result.success is False
    assert result.policy_category == INVALID
    assert result.return_code is None

    print(
        "[OK] Command executor self-test passed."
    )

    return True


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    run_self_test()
