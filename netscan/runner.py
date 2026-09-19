"""Run an external scanner as a fixed argv (never a shell string), with a hard
timeout and a bounded amount of captured output. One heavy scan runs at a time,
so a burst of tool calls cannot fan out into many concurrent scans (which would
multiply egress and look, from the outside, like a flood).
"""
from __future__ import annotations

import asyncio
import shutil

# One scan at a time. The tools are slow and network-heavy; serialising them
# keeps egress predictable and bounds resource use.
_LOCK = asyncio.Lock()

# Never buffer an unbounded amount of a scanner's stdout back to the model.
MAX_OUTPUT_BYTES = 512 * 1024


class ScanError(RuntimeError):
    """A scan could not be run or did not complete. Message is safe to return."""


def tool_path(name: str) -> str:
    """Absolute path to a required binary, or raise (so a missing tool is a
    clear error, not a confusing FileNotFoundError deep in asyncio)."""
    p = shutil.which(name)
    if not p:
        raise ScanError(f"required tool not found on PATH: {name}")
    return p


async def run(argv: list[str], *, timeout: float,
              stdin: bytes | None = None) -> tuple[int, str, str]:
    """Execute argv with no shell, capturing stdout/stderr up to a cap. Kills
    the whole process group on timeout. Returns (returncode, stdout, stderr).

    argv[0] is resolved to an absolute path here; every other element is passed
    through untouched, so callers MUST have validated any caller-derived element
    before now (see netscan.validate).
    """
    if not argv:
        raise ScanError("empty command")
    argv = [tool_path(argv[0]), *argv[1:]]
    async with _LOCK:
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.PIPE if stdin is not None else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,  # own process group, so we can kill children
            )
        except OSError as e:
            raise ScanError(f"could not start {argv[0]}: {e}")
        try:
            out, err = await asyncio.wait_for(
                proc.communicate(input=stdin), timeout=timeout)
        except asyncio.TimeoutError:
            _kill(proc)
            await proc.wait()
            raise ScanError(f"scan exceeded its {int(timeout)}s time limit")
        rc = proc.returncode if proc.returncode is not None else -1
        return rc, _cap(out), _cap(err)


def _kill(proc: asyncio.subprocess.Process) -> None:
    import os
    import signal
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            proc.kill()
        except ProcessLookupError:
            pass


def _cap(b: bytes) -> str:
    if len(b) > MAX_OUTPUT_BYTES:
        b = b[:MAX_OUTPUT_BYTES] + b"\n...[truncated]"
    return b.decode("utf-8", "replace")
