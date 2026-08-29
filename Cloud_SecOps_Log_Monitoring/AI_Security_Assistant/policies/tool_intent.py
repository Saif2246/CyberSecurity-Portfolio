"""
KiroTrace - Deterministic Tool Intent Mapping

Maps explicit security questions to a small set of approved,
argument-free, read-only tools.

IMPORTANT:
    - No LLM-generated shell commands.
    - No arbitrary command construction.
    - No execution in this module.
    - Actual execution is delegated to tool_runner.py.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


# ============================================================
# TOOL INTENT
# ============================================================

@dataclass(frozen=True)
class ToolIntent:
    tool: str
    command: str
    reason: str


# ============================================================
# DETERMINISTIC QUESTION PATTERNS
# ============================================================

_TOOL_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "whoami",
        (
            "whoami",
            "run whoami",
            "who am i",
            "current user",
            "current username",
            "logged in user",
            "logged-in user",
            "which user am i",
        ),
    ),
    (
        "hostname",
        (
            "hostname",
            "computer name",
            "machine name",
            "system name",
        ),
    ),
    (
        "pwd",
        (
            "current directory",
            "working directory",
            "where am i in the filesystem",
            "current working directory",
        ),
    ),
    (
        "id",
        (
            "user id",
            "uid",
            "group id",
            "user groups",
            "groups of current user",
        ),
    ),
    (
        "uname",
        (
            "operating system",
            "os information",
            "system information",
            "kernel information",
            "kernel version",
        ),
    ),
    (
        "ip",
        (
            "network interfaces",
            "network interface",
            "ip addresses",
            "ip address information",
            "routing information",
            "network configuration",
        ),
    ),
    (
        "ss",
        (
            "active connections",
            "network connections",
            "listening ports",
            "listening sockets",
            "open sockets",
        ),
    ),
    (
        "netstat",
        (
            "network statistics",
            "network connection table",
            "connection table",
        ),
    ),
    (
        "ifconfig",
        (
            "interface configuration",
            "ifconfig",
        ),
    ),

    (
        "nmap",
        (
            "nmap",
            "network scan",
            "network scanner",
            "scan with nmap",
            "scan the host",
            "scan this host",
            "scan this ip",
            "port scan",
            "port scanning",
        ),
    ),
)

# ============================================================
# INTENT DETECTION
# ============================================================
def detect_tool_intent(
    question: str,
) -> ToolIntent | None:

    if not isinstance(question, str):
        return None

    lowered = " ".join(
        question.strip().lower().split()
    )

    if not lowered:
        return None

    # --------------------------------------------------------
    # SHELL / COMMAND-INJECTION REJECTION
    # --------------------------------------------------------
    # Natural-language tool requests must never contain
    # shell-control syntax.

    _FORBIDDEN_SHELL_TOKENS = (
        "&&",
        "||",
        ";",
        "|",
        ">",
        "<",
        "`",
        "$(",
        "${",
    )

    if any(
        token in lowered
        for token in _FORBIDDEN_SHELL_TOKENS
    ):
        return None

    for tool, patterns in _TOOL_PATTERNS:
        
        for pattern in patterns:
            if pattern in lowered:
                return ToolIntent(
                    tool=tool,
                    command=tool,
                    reason=(
                        f"Question matched the controlled "
                        f"{tool} security-tool intent."
                    ),
                )

    return None


# ============================================================
# SAFETY BOUNDARY
# ============================================================

def is_argument_free_tool_intent(
    intent: Optional[ToolIntent],
) -> bool:
    """
    Return True only for the argument-free commands supported
    by this module.

    Network tools that require user-supplied targets are
    intentionally excluded from automatic execution.
    """

    if intent is None:
        return False

    return intent.command in {
        "whoami",
        "hostname",
        "pwd",
        "id",
        "uname",
        "ip",
        "ss",
        "netstat",
        "ifconfig",
    }


# ============================================================
# SELF TEST
# ============================================================

def run_self_test() -> bool:
    """Validate deterministic tool-intent mapping."""

    intent = detect_tool_intent(
        "Who am I currently logged in as?"
    )

    assert intent is not None
    assert intent.tool == "whoami"
    assert intent.command == "whoami"
    assert is_argument_free_tool_intent(intent) is True

    intent = detect_tool_intent(
        "What is this machine's hostname?"
    )

    assert intent is not None
    assert intent.tool == "hostname"

    intent = detect_tool_intent(
        "Show my network interfaces."
    )

    assert intent is not None
    assert intent.tool == "ip"

    intent = detect_tool_intent(
        "What are the listening ports?"
    )

    assert intent is not None
    assert intent.tool == "ss"
       # --------------------------------------------------------
    # NMAP MUST REQUIRE A TARGET
    # --------------------------------------------------------

    intent = detect_tool_intent(
        "Run a network scan."
    )

    assert intent is not None
    assert intent.tool == "nmap"
    assert intent.command == "nmap"

    # nmap requires a target and must not execute through
    # the current argument-free orchestration boundary.
    assert is_argument_free_tool_intent(intent) is False

    # --------------------------------------------------------
    # Normal RAG question must not trigger a tool.
    # --------------------------------------------------------

    intent = detect_tool_intent(
        "Is there evidence of SSH brute force activity?"
    )

    assert intent is None

    # --------------------------------------------------------
    # Arbitrary shell text must not become a tool request.
    # --------------------------------------------------------

    intent = detect_tool_intent(
        "run rm -rf /"
    )

    assert intent is None

    print(
        "[OK] Tool intent self-test passed."
    )

    return True


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    run_self_test()