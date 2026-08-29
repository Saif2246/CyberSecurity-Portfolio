"""
KiroTrace - Command Policy Engine

Deterministic safety layer for future security-tool execution.

IMPORTANT:
    This module NEVER executes commands.
    It only decides whether a proposed command is allowed.
"""

from __future__ import annotations

from dataclasses import dataclass
import re


# ============================================================
# POLICY RESULT
# ============================================================

@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    category: str
    reason: str
    normalized_command: str


# ============================================================
# POLICY CATEGORIES
# ============================================================

ALLOWED = "ALLOWED"
DENIED = "DENIED"
INVALID = "INVALID"


# ============================================================
# ALLOWED SECURITY / INFORMATION COMMANDS
# ============================================================

ALLOWED_COMMANDS = {
    "whoami",
    "id",
    "pwd",
    "hostname",
    "uname",
    "ip",
    "ifconfig",
    "ss",
    "netstat",
    "nmap",
    "nslookup",
    "dig",
    "host",
}


# ============================================================
# DENIED / SYSTEM-MODIFYING COMMANDS
# ============================================================

DENIED_COMMANDS = {
    "rm",
    "rmdir",
    "mkfs",
    "dd",
    "shutdown",
    "reboot",
    "poweroff",
    "halt",
    "kill",
    "pkill",
    "killall",
    "iptables",
    "nft",
    "ufw",
    "systemctl",
    "service",
    "mount",
    "umount",
    "chmod",
    "chown",
    "passwd",
    "useradd",
    "userdel",
    "usermod",
}


# ============================================================
# SHELL INTERPRETERS
# ============================================================

SHELL_COMMANDS = {
    "bash",
    "sh",
    "zsh",
    "fish",
    "cmd",
    "powershell",
    "pwsh",
}


# ============================================================
# DANGEROUS SHELL SYNTAX
# ============================================================

DANGEROUS_SYNTAX = (
    r";",
    r"\|\|",
    r"&&",
    r"\|",
    r">",
    r"<",
    r"\$\(",
    r"`",
    r"\n",
    r"\r",
)


# ============================================================
# REMOTE EXECUTION FLAGS
# ============================================================

REMOTE_FLAGS = {
    "-R",
    "--remote",
    "--target",
    "-T",
    "--targets",
}


# ============================================================
# NORMALIZATION
# ============================================================

def normalize_command(command: str) -> str:
    """
    Normalize whitespace while preserving command semantics.
    """

    if not isinstance(command, str):
        raise TypeError("Command must be a string.")

    return " ".join(command.strip().split())


# ============================================================
# BASE COMMAND
# ============================================================

def get_base_command(command: str) -> str:
    """
    Extract the first executable token.

    Example:
        nmap -sV 192.168.1.10

    Returns:
        nmap
    """

    normalized = normalize_command(command)

    if not normalized:
        return ""

    return normalized.split(" ", 1)[0].lower()


# ============================================================
# DANGEROUS SYNTAX CHECK
# ============================================================

def contains_dangerous_syntax(command: str) -> bool:
    """
    Detect shell chaining, redirection and command substitution.
    """

    return any(
        re.search(pattern, command)
        for pattern in DANGEROUS_SYNTAX
    )


# ============================================================
# REMOTE TARGET CHECK
# ============================================================

def contains_remote_target_flag(command: str) -> bool:
    """
    Detect explicit remote-target execution flags.

    Remote execution remains disabled by default.
    """

    tokens = command.split()

    return any(
        token in REMOTE_FLAGS
        for token in tokens
    )


# ============================================================
# COMMAND EVALUATION
# ============================================================

def evaluate_command(command: str) -> PolicyDecision:
    """
    Evaluate a proposed command.

    This function DOES NOT execute the command.
    """

    if not isinstance(command, str):
        return PolicyDecision(
            allowed=False,
            category=INVALID,
            reason="Command must be provided as text.",
            normalized_command="",
        )

    normalized = normalize_command(command)

    if not normalized:
        return PolicyDecision(
            allowed=False,
            category=INVALID,
            reason="Command cannot be empty.",
            normalized_command="",
        )

    # --------------------------------------------------------
    # Dangerous shell syntax
    # --------------------------------------------------------

    if contains_dangerous_syntax(normalized):
        return PolicyDecision(
            allowed=False,
            category=DENIED,
            reason=(
                "Command denied because shell chaining, "
                "redirection, command substitution, or "
                "control syntax is not permitted."
            ),
            normalized_command=normalized,
        )

    # --------------------------------------------------------
    # Base command
    # --------------------------------------------------------

    base_command = get_base_command(normalized)

    # --------------------------------------------------------
    # Shell interpreter
    # --------------------------------------------------------

    if base_command in SHELL_COMMANDS:
        return PolicyDecision(
            allowed=False,
            category=DENIED,
            reason=(
                "Shell interpreters are blocked by the "
                "KiroTrace command policy."
            ),
            normalized_command=normalized,
        )

    # --------------------------------------------------------
    # Explicitly denied command
    # --------------------------------------------------------

    if base_command in DENIED_COMMANDS:
        return PolicyDecision(
            allowed=False,
            category=DENIED,
            reason=(
                f"The command '{base_command}' is classified "
                "as potentially destructive or system-modifying."
            ),
            normalized_command=normalized,
        )

    # --------------------------------------------------------
    # Remote execution
    # --------------------------------------------------------

    if contains_remote_target_flag(normalized):
        return PolicyDecision(
            allowed=False,
            category=DENIED,
            reason=(
                "Remote-target execution is disabled by the "
                "KiroTrace command policy."
            ),
            normalized_command=normalized,
        )

    # --------------------------------------------------------
    # Explicitly allowed command
    # --------------------------------------------------------

    if base_command in ALLOWED_COMMANDS:
        return PolicyDecision(
            allowed=True,
            category=ALLOWED,
            reason=(
                "Command is permitted by the deterministic "
                "KiroTrace command policy."
            ),
            normalized_command=normalized,
        )

    # --------------------------------------------------------
    # Default deny
    # --------------------------------------------------------

    return PolicyDecision(
        allowed=False,
        category=DENIED,
        reason=(
            f"Command '{base_command}' is not explicitly "
            "allowed by the KiroTrace policy."
        ),
        normalized_command=normalized,
    )


# ============================================================
# USER REQUEST VALIDATION
# ============================================================

def validate_user_request(request: str) -> PolicyDecision:
    """
    Validate a user-provided command request.

    This does NOT execute anything.
    """

    if not isinstance(request, str):
        return PolicyDecision(
            allowed=False,
            category=INVALID,
            reason="User request must be text.",
            normalized_command="",
        )

    normalized = normalize_command(request)

    if not normalized:
        return PolicyDecision(
            allowed=False,
            category=INVALID,
            reason="User request cannot be empty.",
            normalized_command="",
        )

    return evaluate_command(normalized)


# ============================================================
# SELF TEST
# ============================================================

def run_self_test() -> bool:
    """
    Run deterministic policy tests.
    """

    # Allowed
    decision = evaluate_command(
        "nmap 192.168.33.128"
    )

    assert decision.allowed is True
    assert decision.category == ALLOWED

    # Local information command
    decision = evaluate_command(
        "whoami"
    )

    assert decision.allowed is True

    # Destructive command
    decision = evaluate_command(
        "rm -rf /"
    )

    assert decision.allowed is False
    assert decision.category == DENIED

    # Command chaining
    decision = evaluate_command(
        "nmap 192.168.33.128 && whoami"
    )

    assert decision.allowed is False

    # Pipe
    decision = evaluate_command(
        "nmap 192.168.33.128 | grep 8000"
    )

    assert decision.allowed is False

    # Shell interpreter
    decision = evaluate_command(
        "bash -c whoami"
    )

    assert decision.allowed is False

    # Firewall modification
    decision = evaluate_command(
        "iptables -F"
    )

    assert decision.allowed is False

    # Unknown command
    decision = evaluate_command(
        "some_unknown_tool"
    )

    assert decision.allowed is False

    # Empty command
    decision = evaluate_command("")

    assert decision.allowed is False
    assert decision.category == INVALID

    print("[OK] Command policy self-test passed.")

    return True


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    run_self_test()