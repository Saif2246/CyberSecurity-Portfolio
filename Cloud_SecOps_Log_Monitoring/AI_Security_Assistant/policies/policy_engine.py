from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


# ============================================================
# KIROTRACE POLICY ENGINE
# ============================================================

ALLOWED_TOOLS = {
    "nmap",
}

ALLOWED_COMMANDS = {
    "nmap",
}


# Dangerous/destructive operations that must never be executed.
BLOCKED_PATTERNS = [
    r"\brm\s+-rf\b",
    r"\brm\s+-r\b",
    r"\bdel\s+/[sqf]+\b",
    r"\brmdir\s+/s\b",
    r"\bformat\s+[a-z]:",
    r"\bshutdown\b",
    r"\breboot\b",
    r"\bpoweroff\b",
    r"\bmkfs\b",
    r"\bdd\s+if=",
    r"\bchmod\s+777\b",
    r"\bchown\s+-r\b",
    r"\biptables\s+-f\b",
    r"\bufw\s+reset\b",
]


# Prevent arbitrary shell chaining/redirection.
BLOCKED_SHELL_OPERATORS = [
    ";",
    "&&",
    "||",
    "|",
    ">",
    "<",
    "`",
    "$(",
]


MAX_COMMAND_LENGTH = 500
MAX_QUESTION_LENGTH = 4000


@dataclass(frozen=True)
class PolicyDecision:
    """Result returned by the policy engine."""

    allowed: bool
    reason: str
    tool: Optional[str] = None
    command: Optional[str] = None


def _normalize(value: str) -> str:
    """Normalize whitespace and casing."""

    return " ".join(
        value.strip().lower().split()
    )


def validate_question(
    question: str,
) -> PolicyDecision:
    """
    Validate a security question before it enters
    the analysis pipeline.
    """

    if not isinstance(
        question,
        str,
    ):
        return PolicyDecision(
            allowed=False,
            reason="Security question must be a string.",
        )

    cleaned = question.strip()

    if not cleaned:
        return PolicyDecision(
            allowed=False,
            reason="Security question cannot be empty.",
        )

    if len(cleaned) > MAX_QUESTION_LENGTH:
        return PolicyDecision(
            allowed=False,
            reason=(
                "Security question exceeds the maximum "
                f"length of {MAX_QUESTION_LENGTH} characters."
            ),
        )

    return PolicyDecision(
        allowed=True,
        reason="Security question accepted.",
    )


def validate_tool(
    tool: str,
) -> PolicyDecision:
    """Check whether a security tool is allowed."""

    if not isinstance(
        tool,
        str,
    ):
        return PolicyDecision(
            allowed=False,
            reason="Tool name must be a string.",
        )

    normalized_tool = _normalize(
        tool
    )

    if not normalized_tool:
        return PolicyDecision(
            allowed=False,
            reason="Tool name cannot be empty.",
        )

    if normalized_tool not in ALLOWED_TOOLS:
        return PolicyDecision(
            allowed=False,
            reason=(
                f"Tool '{normalized_tool}' is not allowed "
                "by KiroTrace policy."
            ),
            tool=normalized_tool,
        )

    return PolicyDecision(
        allowed=True,
        reason="Tool is allowed by KiroTrace policy.",
        tool=normalized_tool,
    )


def _matches_blocked_pattern(
    command: str,
) -> bool:
    """Return True when a command contains a blocked pattern."""

    for pattern in BLOCKED_PATTERNS:

        if re.search(
            pattern,
            command,
            flags=re.IGNORECASE,
        ):
            return True

    return False


def validate_command(
    command: str,
) -> PolicyDecision:
    """
    Validate a command before execution.

    The policy engine only authorizes or blocks commands.
    It never executes them.
    """

    if not isinstance(
        command,
        str,
    ):
        return PolicyDecision(
            allowed=False,
            reason="Command must be a string.",
        )

    cleaned = command.strip()

    if not cleaned:
        return PolicyDecision(
            allowed=False,
            reason="Command cannot be empty.",
        )

    if len(cleaned) > MAX_COMMAND_LENGTH:
        return PolicyDecision(
            allowed=False,
            reason=(
                "Command exceeds the maximum allowed "
                f"length of {MAX_COMMAND_LENGTH} characters."
            ),
            command=cleaned,
        )

    normalized = _normalize(
        cleaned
    )

    # Block shell chaining and redirection.
    for operator in BLOCKED_SHELL_OPERATORS:

        if operator in cleaned:
            return PolicyDecision(
                allowed=False,
                reason=(
                    f"Shell operator '{operator}' is "
                    "blocked by KiroTrace policy."
                ),
                command=cleaned,
            )

    # Block destructive commands.
    if _matches_blocked_pattern(
        normalized
    ):
        return PolicyDecision(
            allowed=False,
            reason=(
                "Command matches a blocked "
                "dangerous operation."
            ),
            command=cleaned,
        )

    # Extract executable.
    executable = normalized.split(
        maxsplit=1
    )[0]

    if executable not in ALLOWED_COMMANDS:
        return PolicyDecision(
            allowed=False,
            reason=(
                f"Command '{executable}' is not allowed "
                "by KiroTrace policy."
            ),
            command=cleaned,
        )

    return PolicyDecision(
        allowed=True,
        reason="Command is allowed by KiroTrace policy.",
        command=cleaned,
    )


def authorize(
    tool: str,
    command: str,
) -> PolicyDecision:
    """
    Perform the complete tool + command policy check.
    """

    tool_decision = validate_tool(
        tool
    )

    if not tool_decision.allowed:
        return tool_decision

    command_decision = validate_command(
        command
    )

    if not command_decision.allowed:
        return PolicyDecision(
            allowed=False,
            reason=command_decision.reason,
            tool=tool_decision.tool,
            command=command,
        )

    return PolicyDecision(
        allowed=True,
        reason=(
            "Tool and command are allowed "
            "by KiroTrace policy."
        ),
        tool=tool_decision.tool,
        command=command,
    )


# ============================================================
# POLICY ENGINE SELF-TEST
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("KIROTRACE POLICY ENGINE TEST")
    print("=" * 60)

    tests = [
        (
            "Allowed tool",
            validate_tool("nmap"),
        ),
        (
            "Blocked tool",
            validate_tool("sqlmap"),
        ),
        (
            "Allowed command",
            validate_command(
                "nmap 127.0.0.1"
            ),
        ),
        (
            "Blocked shell chaining",
            validate_command(
                "nmap 127.0.0.1 && whoami"
            ),
        ),
        (
            "Blocked destructive command",
            validate_command(
                "rm -rf /"
            ),
        ),
        (
            "Blocked unknown command",
            validate_command(
                "powershell whoami"
            ),
        ),
        (
            "Authorized tool + command",
            authorize(
                "nmap",
                "nmap 127.0.0.1"
            ),
        ),
    ]

    for name, decision in tests:

        status = (
            "ALLOW"
            if decision.allowed
            else "BLOCK"
        )

        print(
            f"\n{name}: {status}"
        )

        print(
            f"Reason: {decision.reason}"
        )

    print("\n" + "=" * 60)
    print("POLICY TEST COMPLETE")
    print("=" * 60)