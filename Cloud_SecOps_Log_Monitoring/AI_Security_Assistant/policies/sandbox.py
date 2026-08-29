"""KiroTrace - Docker-Isolated Sandbox Execution Layer"""

from __future__ import annotations

from dataclasses import dataclass
import subprocess
import time
import uuid
from typing import Optional


# ---------------------------------------------------------------------------
# Sandbox configuration
# ---------------------------------------------------------------------------

DEFAULT_SANDBOX_TIMEOUT_SECONDS = 15
MAX_SANDBOX_OUTPUT_CHARS = 12000

DOCKER_IMAGE = "ubuntu:24.04"

# Conservative resource limits for the MVP sandbox.
SANDBOX_MEMORY_LIMIT = "256m"
SANDBOX_CPU_LIMIT = "0.50"
SANDBOX_PIDS_LIMIT = "64"

SANDBOX_WORKSPACE = "/workspace"


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SandboxResult:
    success: bool
    command: str
    return_code: Optional[int]
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool
    workspace: str
    reason: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _limit_output(text: str) -> str:
    """Limit stdout/stderr to prevent excessive output."""

    if not text:
        return ""

    if len(text) <= MAX_SANDBOX_OUTPUT_CHARS:
        return text

    return (
        text[:MAX_SANDBOX_OUTPUT_CHARS]
        + "\n[OUTPUT TRUNCATED BY KIROTRACE SANDBOX]"
    )


def _tokenize(command: str) -> list[str]:
    """
    Tokenize a command without invoking a shell.

    This intentionally does NOT use shell=True.
    """

    return command.split()


def _build_container_name() -> str:
    """Create a unique, predictable container name."""

    suffix = uuid.uuid4().hex[:12]

    return f"kirotrace-sandbox-{suffix}"


def _docker_base_command(container_name: str) -> list[str]:
    """
    Build the security-relevant Docker runtime configuration.

    Important controls:

    --rm
        Remove container after normal execution.

    --network none
        No network connectivity.

    --read-only
        Root filesystem is read-only.

    --tmpfs /workspace
        Temporary isolated workspace inside the container.

    --tmpfs /tmp
        Temporary writable /tmp.

    --memory
        Memory limit.

    --cpus
        CPU limit.

    --pids-limit
        Process-count limit.

    --cap-drop ALL
        Drop Linux capabilities.

    --security-opt no-new-privileges:true
        Prevent privilege escalation through execve.

    --user 1000:1000
        Do not run the tool as root.

    No host path is mounted.
    """

    return [
        "docker",
        "run",
        "--rm",
        "--name",
        container_name,

        # Network isolation.
        "--network",
        "none",

        # Filesystem restrictions.
        "--read-only",

        # Isolated writable workspace.
        "--tmpfs",
        (
            "/workspace:"
            "rw,"
            "nosuid,"
            "nodev,"
            "noexec,"
            "size=64m,"
            "uid=1000,"
            "gid=1000"
        ),

        # Temporary directory.
        "--tmpfs",
        (
            "/tmp:"
            "rw,"
            "nosuid,"
            "nodev,"
            "size=32m,"
            "uid=1000,"
            "gid=1000"
        ),

        # Resource controls.
        "--memory",
        SANDBOX_MEMORY_LIMIT,

        "--cpus",
        SANDBOX_CPU_LIMIT,

        "--pids-limit",
        SANDBOX_PIDS_LIMIT,

        # Privilege restrictions.
        "--cap-drop",
        "ALL",

        "--security-opt",
        "no-new-privileges:true",

        "--user",
        "1000:1000",

        # Working directory.
        "--workdir",
        SANDBOX_WORKSPACE,

        # Image.
        DOCKER_IMAGE,
    ]


def _force_remove_container(container_name: str) -> None:
    """
    Force-remove a container.

    Used after a timeout because subprocess timeout alone would otherwise
    terminate the Docker CLI process while the Docker container could
    potentially remain alive.
    """

    try:
        subprocess.run(
            [
                "docker",
                "rm",
                "-f",
                container_name,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            check=False,
        )

    except (
        subprocess.TimeoutExpired,
        FileNotFoundError,
        OSError,
    ):
        # Cleanup must never crash the caller.
        pass


def _docker_available() -> tuple[bool, str]:
    """Check whether the Docker CLI/daemon is available."""

    try:
        completed = subprocess.run(
            [
                "docker",
                "info",
                "--format",
                "{{.ServerVersion}}",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            check=False,
        )

    except FileNotFoundError:
        return (
            False,
            "Docker CLI was not found on the system.",
        )

    except subprocess.TimeoutExpired:
        return (
            False,
            "Docker daemon check timed out.",
        )

    except OSError as exc:
        return (
            False,
            f"Docker availability check failed: {exc}",
        )

    if completed.returncode != 0:
        error = (completed.stderr or "").strip()

        return (
            False,
            error
            or "Docker daemon is not available.",
        )

    return True, ""


# ---------------------------------------------------------------------------
# Main sandbox execution
# ---------------------------------------------------------------------------

def execute_in_sandbox(
    command: str,
    timeout_seconds: int = DEFAULT_SANDBOX_TIMEOUT_SECONDS,
) -> SandboxResult:
    """
    Execute an approved command inside an isolated Docker container.

    Security properties:

    - No host filesystem mounts.
    - No network access.
    - Read-only container root filesystem.
    - Temporary workspace only.
    - Non-root execution.
    - Linux capabilities dropped.
    - no-new-privileges enabled.
    - Memory limit.
    - CPU limit.
    - PID limit.
    - Hard execution timeout.
    - Output truncation.
    - Container removed after execution.
    """

    start_time = time.perf_counter()

    # ------------------------------------------------------------------
    # Input validation
    # ------------------------------------------------------------------

    if not isinstance(command, str):
        return SandboxResult(
            success=False,
            command="",
            return_code=None,
            stdout="",
            stderr="",
            duration_ms=0,
            timed_out=False,
            workspace="",
            reason="Sandbox command must be provided as text.",
        )

    normalized = " ".join(
        command.strip().split()
    )

    if not normalized:
        return SandboxResult(
            success=False,
            command="",
            return_code=None,
            stdout="",
            stderr="",
            duration_ms=0,
            timed_out=False,
            workspace="",
            reason="Sandbox command cannot be empty.",
        )

    if not isinstance(timeout_seconds, int):
        timeout_seconds = DEFAULT_SANDBOX_TIMEOUT_SECONDS

    if timeout_seconds <= 0:
        timeout_seconds = DEFAULT_SANDBOX_TIMEOUT_SECONDS

    argv = _tokenize(normalized)

    if not argv:
        return SandboxResult(
            success=False,
            command=normalized,
            return_code=None,
            stdout="",
            stderr="",
            duration_ms=int(
                (time.perf_counter() - start_time) * 1000
            ),
            timed_out=False,
            workspace="",
            reason="Sandbox command produced no executable tokens.",
        )

    # ------------------------------------------------------------------
    # Docker availability
    # ------------------------------------------------------------------

    docker_ready, docker_error = _docker_available()

    if not docker_ready:
        return SandboxResult(
            success=False,
            command=normalized,
            return_code=None,
            stdout="",
            stderr=docker_error,
            duration_ms=int(
                (time.perf_counter() - start_time) * 1000
            ),
            timed_out=False,
            workspace="",
            reason=(
                "Docker sandbox is unavailable. "
                "Start Docker Desktop and try again."
            ),
        )

    # ------------------------------------------------------------------
    # Container configuration
    # ------------------------------------------------------------------

    container_name = _build_container_name()

    docker_command = _docker_base_command(
        container_name
    )

    # IMPORTANT:
    # The user command is appended as individual argv elements.
    #
    # There is no shell=True and no "/bin/sh -c".
    #
    # Therefore:
    #
    #     whoami
    #
    # becomes:
    #
    #     docker run ... ubuntu:24.04 whoami
    #
    # instead of:
    #
    #     docker run ... ubuntu:24.04 /bin/sh -c "..."
    #
    docker_command.extend(argv)

    workspace = (
        f"docker://{container_name}"
        f"{SANDBOX_WORKSPACE}"
    )

    # ------------------------------------------------------------------
    # Execute container
    # ------------------------------------------------------------------

    try:
        completed = subprocess.run(
            docker_command,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
        )

        duration_ms = int(
            (time.perf_counter() - start_time) * 1000
        )

        stdout = _limit_output(
            completed.stdout or ""
        )

        stderr = _limit_output(
            completed.stderr or ""
        )

        if completed.returncode == 0:
            return SandboxResult(
                success=True,
                command=normalized,
                return_code=0,
                stdout=stdout,
                stderr=stderr,
                duration_ms=duration_ms,
                timed_out=False,
                workspace=workspace,
                reason=(
                    "Command executed successfully inside "
                    "the Docker-isolated KiroTrace sandbox."
                ),
            )

        return SandboxResult(
            success=False,
            command=normalized,
            return_code=completed.returncode,
            stdout=stdout,
            stderr=stderr,
            duration_ms=duration_ms,
            timed_out=False,
            workspace=workspace,
            reason=(
                "Command executed inside the Docker sandbox "
                "but returned a non-zero exit code."
            ),
        )

    # ------------------------------------------------------------------
    # Timeout
    # ------------------------------------------------------------------

    except subprocess.TimeoutExpired as exc:

        # The Docker CLI process has timed out.
        #
        # Explicitly remove the container because --rm only guarantees
        # removal after the container itself exits.
        _force_remove_container(
            container_name
        )

        stdout = exc.stdout
        stderr = exc.stderr

        if isinstance(stdout, bytes):
            stdout = stdout.decode(
                "utf-8",
                errors="replace",
            )

        if isinstance(stderr, bytes):
            stderr = stderr.decode(
                "utf-8",
                errors="replace",
            )

        return SandboxResult(
            success=False,
            command=normalized,
            return_code=None,
            stdout=_limit_output(
                stdout or ""
            ),
            stderr=_limit_output(
                stderr or ""
            ),
            duration_ms=int(
                (time.perf_counter() - start_time) * 1000
            ),
            timed_out=True,
            workspace=workspace,
            reason=(
                "Sandbox execution exceeded the configured "
                "timeout and the container was force-removed."
            ),
        )

    # ------------------------------------------------------------------
    # Docker executable missing
    # ------------------------------------------------------------------

    except FileNotFoundError:
        return SandboxResult(
            success=False,
            command=normalized,
            return_code=None,
            stdout="",
            stderr="Docker executable was not found.",
            duration_ms=int(
                (time.perf_counter() - start_time) * 1000
            ),
            timed_out=False,
            workspace=workspace,
            reason=(
                "Docker CLI is not installed or is not "
                "available in PATH."
            ),
        )

    # ------------------------------------------------------------------
    # Permission failure
    # ------------------------------------------------------------------

    except PermissionError:
        return SandboxResult(
            success=False,
            command=normalized,
            return_code=None,
            stdout="",
            stderr="Permission denied while invoking Docker.",
            duration_ms=int(
                (time.perf_counter() - start_time) * 1000
            ),
            timed_out=False,
            workspace=workspace,
            reason=(
                "Operating-system permissions prevented "
                "Docker execution."
            ),
        )

    # ------------------------------------------------------------------
    # Other OS errors
    # ------------------------------------------------------------------

    except OSError as exc:
        return SandboxResult(
            success=False,
            command=normalized,
            return_code=None,
            stdout="",
            stderr=str(exc),
            duration_ms=int(
                (time.perf_counter() - start_time) * 1000
            ),
            timed_out=False,
            workspace=workspace,
            reason=(
                "Operating-system error occurred while "
                "starting the Docker sandbox."
            ),
        )


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def run_self_test() -> bool:
    """
    Verify the Docker sandbox itself.

    Tests:

    1. Docker command execution.
    2. Container hostname.
    3. Empty command rejection.
    4. Non-existent executable handling.
    5. Shell chaining is NOT interpreted.
    6. Network isolation.
    7. Container cleanup.
    """

    # ---------------------------------------------------------------
    # Basic command execution
    # ---------------------------------------------------------------

    result = execute_in_sandbox(
        "whoami"
    )

    assert result.success is True
    assert result.return_code == 0
    assert result.stdout.strip()

    # ---------------------------------------------------------------
    # Hostname
    # ---------------------------------------------------------------

    result = execute_in_sandbox(
        "hostname"
    )

    assert result.success is True
    assert result.return_code == 0
    assert result.stdout.strip()

    # ---------------------------------------------------------------
    # Empty command
    # ---------------------------------------------------------------

    result = execute_in_sandbox(
        ""
    )

    assert result.success is False
    assert result.return_code is None

    # ---------------------------------------------------------------
    # Non-existent executable
    # ---------------------------------------------------------------

    result = execute_in_sandbox(
        "kirotrace_nonexistent_tool"
    )

    assert result.success is False
    assert result.return_code != 0

    # ---------------------------------------------------------------
    # Shell chaining must NOT execute.
    #
    # Because shell=False is used both by Python and Docker command
    # construction, "hostname" should be treated as an argument to
    # whoami rather than a second shell command.
    # ---------------------------------------------------------------

    result = execute_in_sandbox(
        "whoami && hostname"
    )

    assert result.success is False

    # ---------------------------------------------------------------
    # Network isolation.
    #
    # Ubuntu does not include ping by default, so use the shell's
    # TCP capability through /dev/tcp is unavailable in dash.
    #
    # Instead, test that network namespace is configured as "none"
    # by checking the container's network interfaces.
    # ---------------------------------------------------------------

    result = execute_in_sandbox(
        "cat /proc/net/route"
    )

    assert result.success is True

    route_output = result.stdout.strip()

    # With --network none, there should be no normal default route.
    assert (
        "00000000" not in route_output
        or route_output == ""
    )

    # ---------------------------------------------------------------
    # Container cleanup.
    # ---------------------------------------------------------------

    remaining = subprocess.run(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            "name=kirotrace-sandbox-",
            "--format",
            "{{.Names}}",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=10,
        check=False,
    )

    assert remaining.returncode == 0

    remaining_names = [
        line.strip()
        for line in remaining.stdout.splitlines()
        if line.strip()
    ]

    assert remaining_names == []

    print(
        "[OK] Docker-isolated sandbox self-test passed."
    )

    return True


if __name__ == "__main__":
    run_self_test()