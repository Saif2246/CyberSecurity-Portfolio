
"""
KiroTrace - Security Tool Registry

Deterministic registry of security tools available to the
KiroTrace AI Security Assistant.

IMPORTANT:
    This module DOES NOT execute commands.

    It only:
        1. Defines approved security tools.
        2. Defines their approved command names.
        3. Provides deterministic lookup.
        4. Keeps tool metadata separate from execution.
        5. Prevents the AI layer from inventing arbitrary tools.

Execution is handled separately by command_executor.py.
Command safety is enforced separately by command_policy.py.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


# ============================================================
# TOOL DEFINITION
# ============================================================

@dataclass(frozen=True)
class SecurityTool:
    """
    Immutable definition of an approved security tool.
    """

    name: str
    executable: str
    description: str
    category: str
    read_only: bool


# ============================================================
# TOOL CATEGORIES
# ============================================================

NETWORK_DISCOVERY = "network_discovery"
NETWORK_INFORMATION = "network_information"
SYSTEM_INFORMATION = "system_information"
DNS_ANALYSIS = "dns_analysis"


# ============================================================
# APPROVED TOOL REGISTRY
# ============================================================

TOOL_REGISTRY: dict[str, SecurityTool] = {

    # --------------------------------------------------------
    # Network discovery
    # --------------------------------------------------------

    "nmap": SecurityTool(
        name="nmap",
        executable="nmap",
        description=(
            "Network discovery and service enumeration tool."
        ),
        category=NETWORK_DISCOVERY,
        read_only=True,
    ),

    # --------------------------------------------------------
    # Network information
    # --------------------------------------------------------

    "ss": SecurityTool(
        name="ss",
        executable="ss",
        description=(
            "Displays local socket and network connection information."
        ),
        category=NETWORK_INFORMATION,
        read_only=True,
    ),

    "netstat": SecurityTool(
        name="netstat",
        executable="netstat",
        description=(
            "Displays network connection and routing information."
        ),
        category=NETWORK_INFORMATION,
        read_only=True,
    ),

    "ip": SecurityTool(
        name="ip",
        executable="ip",
        description=(
            "Displays local network interface and routing information."
        ),
        category=NETWORK_INFORMATION,
        read_only=True,
    ),

    "ifconfig": SecurityTool(
        name="ifconfig",
        executable="ifconfig",
        description=(
            "Displays local network interface configuration."
        ),
        category=NETWORK_INFORMATION,
        read_only=True,
    ),

    # --------------------------------------------------------
    # System information
    # --------------------------------------------------------

    "whoami": SecurityTool(
        name="whoami",
        executable="whoami",
        description=(
            "Displays the current operating-system user."
        ),
        category=SYSTEM_INFORMATION,
        read_only=True,
    ),

    "id": SecurityTool(
        name="id",
        executable="id",
        description=(
            "Displays the current user's identity and group information."
        ),
        category=SYSTEM_INFORMATION,
        read_only=True,
    ),

    "pwd": SecurityTool(
        name="pwd",
        executable="pwd",
        description=(
            "Displays the current working directory."
        ),
        category=SYSTEM_INFORMATION,
        read_only=True,
    ),

    "hostname": SecurityTool(
        name="hostname",
        executable="hostname",
        description=(
            "Displays the local system hostname."
        ),
        category=SYSTEM_INFORMATION,
        read_only=True,
    ),

    "uname": SecurityTool(
        name="uname",
        executable="uname",
        description=(
            "Displays basic operating-system information."
        ),
        category=SYSTEM_INFORMATION,
        read_only=True,
    ),

    # --------------------------------------------------------
    # DNS analysis
    # --------------------------------------------------------

    "nslookup": SecurityTool(
        name="nslookup",
        executable="nslookup",
        description=(
            "Performs DNS lookup and name-resolution queries."
        ),
        category=DNS_ANALYSIS,
        read_only=True,
    ),

    "dig": SecurityTool(
        name="dig",
        executable="dig",
        description=(
            "Performs detailed DNS query and analysis operations."
        ),
        category=DNS_ANALYSIS,
        read_only=True,
    ),

    "host": SecurityTool(
        name="host",
        executable="host",
        description=(
            "Performs DNS lookup operations."
        ),
        category=DNS_ANALYSIS,
        read_only=True,
    ),
}


# ============================================================
# REGISTRY LOOKUP
# ============================================================

def get_tool(tool_name: str) -> Optional[SecurityTool]:
    """
    Return an approved security tool definition.

    Unknown tools return None.
    """

    if not isinstance(tool_name, str):
        return None

    normalized_name = tool_name.strip().lower()

    if not normalized_name:
        return None

    return TOOL_REGISTRY.get(normalized_name)


# ============================================================
# TOOL EXISTENCE CHECK
# ============================================================

def is_registered_tool(tool_name: str) -> bool:
    """
    Return True only when the tool exists in the approved registry.
    """

    return get_tool(tool_name) is not None


# ============================================================
# TOOL LISTING
# ============================================================

def list_tools() -> tuple[SecurityTool, ...]:
    """
    Return all registered security tools.
    """

    return tuple(TOOL_REGISTRY.values())


# ============================================================
# CATEGORY FILTER
# ============================================================

def list_tools_by_category(
    category: str,
) -> tuple[SecurityTool, ...]:
    """
    Return registered tools belonging to a category.
    """

    if not isinstance(category, str):
        return ()

    normalized_category = category.strip().lower()

    return tuple(
        tool
        for tool in TOOL_REGISTRY.values()
        if tool.category == normalized_category
    )


# ============================================================
# EXECUTABLE VALIDATION
# ============================================================

def executable_matches_tool(
    tool_name: str,
    executable: str,
) -> bool:
    """
    Verify that an executable matches the registered tool.

    This prevents the registry from being used to silently
    substitute an arbitrary executable.
    """

    tool = get_tool(tool_name)

    if tool is None:
        return False

    if not isinstance(executable, str):
        return False

    return tool.executable == executable.strip().lower()


# ============================================================
# READ-ONLY CHECK
# ============================================================

def is_read_only_tool(tool_name: str) -> bool:
    """
    Return True when the registered tool is marked read-only.
    """

    tool = get_tool(tool_name)

    if tool is None:
        return False

    return tool.read_only


# ============================================================
# TOOL SUMMARY
# ============================================================

def get_tool_summary(tool_name: str) -> Optional[dict[str, str | bool]]:
    """
    Return structured metadata for an approved tool.
    """

    tool = get_tool(tool_name)

    if tool is None:
        return None

    return {
        "name": tool.name,
        "executable": tool.executable,
        "description": tool.description,
        "category": tool.category,
        "read_only": tool.read_only,
    }


# ============================================================
# SELF TEST
# ============================================================

def run_self_test() -> bool:
    """
    Validate the deterministic tool registry.
    """

    # --------------------------------------------------------
    # Known tool
    # --------------------------------------------------------

    tool = get_tool("nmap")

    assert tool is not None
    assert tool.name == "nmap"
    assert tool.executable == "nmap"
    assert tool.read_only is True

    # --------------------------------------------------------
    # Case normalization
    # --------------------------------------------------------

    tool = get_tool("NMAP")

    assert tool is not None
    assert tool.name == "nmap"

    # --------------------------------------------------------
    # Unknown tool
    # --------------------------------------------------------

    tool = get_tool("unknown_security_tool")

    assert tool is None
    assert is_registered_tool("unknown_security_tool") is False

    # --------------------------------------------------------
    # Tool existence
    # --------------------------------------------------------

    assert is_registered_tool("whoami") is True
    assert is_registered_tool("ss") is True
    assert is_registered_tool("dig") is True

    # --------------------------------------------------------
    # Executable validation
    # --------------------------------------------------------

    assert executable_matches_tool(
        "nmap",
        "nmap",
    ) is True

    assert executable_matches_tool(
        "nmap",
        "rm",
    ) is False

    # --------------------------------------------------------
    # Read-only validation
    # --------------------------------------------------------

    assert is_read_only_tool("nmap") is True
    assert is_read_only_tool("whoami") is True
    assert is_read_only_tool("unknown") is False

    # --------------------------------------------------------
    # Category listing
    # --------------------------------------------------------

    network_tools = list_tools_by_category(
        NETWORK_INFORMATION
    )

    assert len(network_tools) >= 1

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    summary = get_tool_summary("nmap")

    assert summary is not None
    assert summary["name"] == "nmap"
    assert summary["read_only"] is True

    print("[OK] Tool registry self-test passed.")

    return True


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    run_self_test()
