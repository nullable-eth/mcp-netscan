import asyncio

import pytest

from netscan import arsenal
from netscan.arsenal import ToolError


def _run(coro):
    return asyncio.run(coro)


def test_list_arsenal_groups_and_counts():
    a = arsenal.list_arsenal()
    assert a["count"] == len(arsenal.ALLOWED)
    tools = {t["tool"] for cat in a["allowed"].values() for t in cat}
    assert {"nmap", "nuclei", "sqlmap", "sslscan"} <= tools


@pytest.mark.parametrize("tool", [
    "metasploit", "msfconsole", "msfvenom", "hydra", "medusa", "ncrack",
    "john", "hashcat", "netexec", "crackmapexec", "responder", "ettercap",
    "bettercap", "nc", "ncat", "bash", "sh",
])
def test_exploit_and_shell_tools_denied(tool):
    with pytest.raises(ToolError):
        _run(arsenal.run_tool(tool, []))


@pytest.mark.parametrize("bad", ["", "../nmap", "/bin/sh", "n map", "NMAP", "a;b", "-nmap"])
def test_bad_tool_name_rejected(bad):
    with pytest.raises(ToolError):
        _run(arsenal.run_tool(bad, []))


def test_args_must_be_list_of_strings():
    with pytest.raises(ToolError):
        _run(arsenal.run_tool("nmap", "not-a-list"))
    with pytest.raises(ToolError):
        _run(arsenal.run_tool("nmap", [1, 2]))


def test_arg_limits():
    with pytest.raises(ToolError):
        _run(arsenal.run_tool("nmap", ["x"] * (arsenal.MAX_ARGS + 1)))
    with pytest.raises(ToolError):
        _run(arsenal.run_tool("nmap", ["a" * (arsenal.MAX_ARG_LEN + 1)]))
    with pytest.raises(ToolError):
        _run(arsenal.run_tool("nmap", ["a\x00b"]))


def test_happy_path_builds_argv_and_returns_output(monkeypatch):
    async def fake_run(argv, *, timeout, stdin=None):
        assert argv == ["nmap", "-sV", "10.0.0.1"]
        assert timeout == 10
        return 0, "open 80/tcp", ""

    monkeypatch.setattr(arsenal.runner, "run", fake_run)
    res = _run(arsenal.run_tool("nmap", ["-sV", "10.0.0.1"], timeout=10))
    assert res["returncode"] == 0
    assert res["stdout"] == "open 80/tcp"
    assert res["timed_out"] is False


def test_timeout_returns_partial_not_error(monkeypatch):
    async def fake_run(argv, *, timeout, stdin=None):
        raise arsenal.runner.ScanError("scan exceeded its 10s time limit")

    monkeypatch.setattr(arsenal.runner, "run", fake_run)
    res = _run(arsenal.run_tool("nmap", ["-sV"], timeout=10))
    assert res["timed_out"] is True


def test_missing_binary_is_clean_tool_error(monkeypatch):
    async def fake_run(argv, *, timeout, stdin=None):
        raise arsenal.runner.ScanError("required tool not found on PATH: sqlmap")

    monkeypatch.setattr(arsenal.runner, "run", fake_run)
    with pytest.raises(ToolError):
        _run(arsenal.run_tool("sqlmap", ["--version"]))


def test_timeout_clamped_to_max(monkeypatch):
    seen = {}

    async def fake_run(argv, *, timeout, stdin=None):
        seen["t"] = timeout
        return 0, "", ""

    monkeypatch.setattr(arsenal.runner, "run", fake_run)
    _run(arsenal.run_tool("nmap", [], timeout=99999))
    assert seen["t"] == arsenal.MAX_TIMEOUT
