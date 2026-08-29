
"""
KiroTrace - Security Target Validator

Purpose:
    Validate and normalize explicit targets supplied for
    controlled security-tool execution.

Security boundary:
    - Accepts IPv4 addresses.
    - Accepts IPv4 CIDR networks.
    - Accepts ordinary hostnames.
    - Rejects URLs.
    - Rejects shell syntax.
    - Rejects command fragments.
    - Rejects malformed IP/CIDR values.
    - Does NOT execute anything.
    - Does NOT perform network connectivity checks.
    - Does NOT construct shell commands.

This module is intentionally deterministic.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass


# ============================================================
# VALIDATION RESULT
# ============================================================

@dataclass(frozen=True)
class TargetValidationResult:
    """
    Stable result returned by target validation.
    """

    valid: bool
    target: str
    target_type: str
    normalized_target: str
    reason: str


# ============================================================
# LIMITS
# ============================================================

MAX_TARGET_LENGTH = 253


# ============================================================
# HOSTNAME VALIDATION
# ============================================================

_HOSTNAME_LABEL_PATTERN = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)


def _is_valid_hostname(
    target: str,
) -> bool:
    """
    Validate a conventional DNS-style hostname.

    This validates syntax only. It does not perform DNS resolution.
    """

    if not target:
        return False

    if len(target) > MAX_TARGET_LENGTH:
        return False

    # Reject a trailing dot for a deliberately simple target format.
    if target.endswith("."):
        return False

    labels = target.split(".")

    if not labels:
        return False

    for label in labels:
        if not label:
            return False

        if len(label) > 63:
            return False

        if not _HOSTNAME_LABEL_PATTERN.fullmatch(label):
            return False

    return True


# ============================================================
# DANGEROUS / SHELL SYNTAX
# ============================================================

_FORBIDDEN_TARGET_PATTERNS = (
    ";",
    "&&",
    "||",
    "|",
    "`",
    "$(",
    "${",
    ">",
    "<",
    "\n",
    "\r",
)


def _contains_forbidden_syntax(
    target: str,
) -> bool:
    """
    Reject shell metacharacters and command-construction syntax.
    """

    return any(
        pattern in target
        for pattern in _FORBIDDEN_TARGET_PATTERNS
    )


# ============================================================
# TARGET VALIDATION
# ============================================================

def validate_target(
    target: str,
) -> TargetValidationResult:
    """
    Validate and normalize a security-tool target.

    Supported:
        IPv4 address
        IPv4 CIDR
        hostname

    Unsupported:
        URLs
        IPv6
        shell expressions
        command fragments
        malformed targets

    No execution or network access occurs here.
    """

    # --------------------------------------------------------
    # TYPE VALIDATION
    # --------------------------------------------------------

    if not isinstance(target, str):
        return TargetValidationResult(
            valid=False,
            target="",
            target_type="invalid",
            normalized_target="",
            reason="Target must be provided as text.",
        )

    original = target
    target = target.strip()

    if not target:
        return TargetValidationResult(
            valid=False,
            target=original,
            target_type="invalid",
            normalized_target="",
            reason="Target cannot be empty.",
        )

    if len(target) > MAX_TARGET_LENGTH:
        return TargetValidationResult(
            valid=False,
            target=original,
            target_type="invalid",
            normalized_target="",
            reason=(
                f"Target exceeds the maximum length of "
                f"{MAX_TARGET_LENGTH} characters."
            ),
        )

    # --------------------------------------------------------
    # SHELL / COMMAND INJECTION BOUNDARY
    # --------------------------------------------------------

    if _contains_forbidden_syntax(target):
        return TargetValidationResult(
            valid=False,
            target=original,
            target_type="invalid",
            normalized_target="",
            reason=(
                "Target contains forbidden shell or "
                "command-construction syntax."
            ),
        )

    # --------------------------------------------------------
    # URL REJECTION
    # --------------------------------------------------------

    lowered = target.lower()

    if (
        lowered.startswith("http://")
        or lowered.startswith("https://")
        or lowered.startswith("ftp://")
    ):
        return TargetValidationResult(
            valid=False,
            target=original,
            target_type="invalid",
            normalized_target="",
            reason=(
                "URLs are not accepted as security-tool targets."
            ),
        )

    # --------------------------------------------------------
    # WHITESPACE REJECTION
    # --------------------------------------------------------

    if any(character.isspace() for character in target):
        return TargetValidationResult(
            valid=False,
            target=original,
            target_type="invalid",
            normalized_target="",
            reason=(
                "Target must contain no embedded whitespace."
            ),
        )

    # --------------------------------------------------------
    # IPv4 ADDRESS / CIDR
    # --------------------------------------------------------

    try:
        ipv4 = ipaddress.IPv4Address(target)

        return TargetValidationResult(
            valid=True,
            target=original,
            target_type="ipv4",
            normalized_target=str(ipv4),
            reason="Valid IPv4 address.",
        )

    except ipaddress.AddressValueError:
        pass

    try:
        network = ipaddress.IPv4Network(
            target,
            strict=False,
        )

        return TargetValidationResult(
            valid=True,
            target=original,
            target_type="ipv4_cidr",
            normalized_target=str(network),
            reason="Valid IPv4 CIDR network.",
        )

    except ValueError:
        pass

    # --------------------------------------------------------
    # IPv6 EXPLICITLY REJECTED
    # --------------------------------------------------------

    try:
        ipaddress.IPv6Address(target)

        return TargetValidationResult(
            valid=False,
            target=original,
            target_type="ipv6",
            normalized_target="",
            reason=(
                "IPv6 targets are not supported by the "
                "current controlled tool boundary."
            ),
        )

    except ipaddress.AddressValueError:
        pass
    # --------------------------------------------------------
    # MALFORMED IPv4-LIKE TARGET REJECTION
    # --------------------------------------------------------
    #
    # Prevent malformed IPv4-looking targets such as:
    #     192.168.1.999
    #
    # from falling through to hostname validation.

    hostname_labels = target.split(".")

    if (
        len(hostname_labels) == 4
        and all(
            label.isdigit()
            for label in hostname_labels
        )
    ):
        return TargetValidationResult(
            valid=False,
            target=original,
            target_type="invalid",
            normalized_target="",
            reason=(
                "Target resembles an IPv4 address but "
                "contains an invalid IPv4 octet."
            ),
        )

    # --------------------------------------------------------
    # HOSTNAME
    # --------------------------------------------------------

    if _is_valid_hostname(target):
        return TargetValidationResult(
            valid=True,
            target=original,
            target_type="hostname",
            normalized_target=target.lower(),
            reason="Valid hostname.",
        )

    # --------------------------------------------------------
    # INVALID TARGET
    # --------------------------------------------------------

    return TargetValidationResult(
        valid=False,
        target=original,
        target_type="invalid",
        normalized_target="",
        reason=(
            "Target is not a valid IPv4 address, IPv4 CIDR "
            "network, or hostname."
        ),
    )


# ============================================================
# SELF TEST
# ============================================================

def run_self_test() -> bool:
    """
    Validate the deterministic target boundary.
    """

    # --------------------------------------------------------
    # VALID IPv4
    # --------------------------------------------------------

    result = validate_target(
        "192.168.1.10"
    )

    assert result.valid is True
    assert result.target_type == "ipv4"
    assert result.normalized_target == "192.168.1.10"

    # --------------------------------------------------------
    # VALID CIDR
    # --------------------------------------------------------

    result = validate_target(
        "192.168.1.0/24"
    )

    assert result.valid is True
    assert result.target_type == "ipv4_cidr"
    assert result.normalized_target == "192.168.1.0/24"

    # --------------------------------------------------------
    # CIDR NORMALIZATION
    # --------------------------------------------------------

    result = validate_target(
        "192.168.1.25/24"
    )

    assert result.valid is True
    assert result.target_type == "ipv4_cidr"
    assert result.normalized_target == "192.168.1.0/24"

    # --------------------------------------------------------
    # VALID HOSTNAME
    # --------------------------------------------------------

    result = validate_target(
        "example.local"
    )

    assert result.valid is True
    assert result.target_type == "hostname"
    assert result.normalized_target == "example.local"

    # --------------------------------------------------------
    # HOSTNAME NORMALIZATION
    # --------------------------------------------------------

    result = validate_target(
        "SERVER01.EXAMPLE.LOCAL"
    )

    assert result.valid is True
    assert result.target_type == "hostname"
    assert result.normalized_target == "server01.example.local"

    # --------------------------------------------------------
    # EMPTY TARGET
    # --------------------------------------------------------

    result = validate_target("")

    assert result.valid is False

    # --------------------------------------------------------
    # MALFORMED IPv4
    # --------------------------------------------------------

    result = validate_target(
        "192.168.1.999"
    )

    assert result.valid is False

    # --------------------------------------------------------
    # URL
    # --------------------------------------------------------

    result = validate_target(
        "http://192.168.1.10"
    )

    assert result.valid is False

    # --------------------------------------------------------
    # SHELL INJECTION
    # --------------------------------------------------------

    result = validate_target(
        "192.168.1.10; whoami"
    )

    assert result.valid is False

    result = validate_target(
        "192.168.1.10 && whoami"
    )

    assert result.valid is False

    result = validate_target(
        "192.168.1.10 | whoami"
    )

    assert result.valid is False

    # --------------------------------------------------------
    # EMBEDDED WHITESPACE
    # --------------------------------------------------------

    result = validate_target(
        "192.168.1.10 target"
    )

    assert result.valid is False

    # --------------------------------------------------------
    # IPv6
    # --------------------------------------------------------

    result = validate_target(
        "::1"
    )

    assert result.valid is False
    assert result.target_type == "ipv6"

    # --------------------------------------------------------
    # INVALID TYPE
    # --------------------------------------------------------

    result = validate_target(
        None  # type: ignore[arg-type]
    )

    assert result.valid is False

    print(
        "[OK] Target validator self-test passed."
    )

    return True


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    run_self_test()
