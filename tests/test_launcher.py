from __future__ import annotations

import base64
import re
from collections.abc import Iterable, Sequence
from typing import Any

import pytest

import goodwinrm.goodwinrm as app
from goodwinrm._gwspawn import GWSPAWN_X64_B64, GWSPAWN_X86_B64
from goodwinrm.goodwinrm import (
    SPAWN_USAGE,
    CommandResult,
    GoodWinRMError,
    WinRMShell,
    dispatch_command,
    launch_spawn,
    parse_helper_output,
    parse_spawn_request,
    win_quote,
)

ARCH_PROBE = "$env:PROCESSOR_ARCHITECTURE"


class LauncherShell:
    def __init__(
        self,
        arch: str | None = None,
        ps_results: list[CommandResult] | None = None,
        native_results: list[CommandResult] | None = None,
    ) -> None:
        self.current_directory = "C:\\Work"
        self.arch = arch
        self.ps_results = list(ps_results or [])
        self.native_results = list(native_results or [])
        self.scripts: list[str] = []
        self.native_calls: list[tuple[str, list[str]]] = []
        self.payloads: list[bytes] = []

    def run(self, script: str) -> CommandResult:
        self.scripts.append(script)
        if "Remove-Item" in script:
            return CommandResult("", "", 0)
        if script == ARCH_PROBE and self.arch is not None:
            return CommandResult(self.arch, "", 0)
        if "$src=" in script and self.payloads:
            return CommandResult(str(len(self.payloads[-1])), "", 0)
        if self.ps_results:
            return self.ps_results.pop(0)
        return CommandResult("", "", 0)

    def run_with_input(self, script: str, chunks: Iterable[bytes]) -> CommandResult:
        self.scripts.append(script)
        payload = bytearray()
        for encoded_chunk in chunks:
            payload.extend(base64.b64decode(encoded_chunk.strip()))
        self.payloads.append(bytes(payload))
        return CommandResult(str(len(payload)), "", 0)

    def run_native(self, executable: str, arguments: Sequence[str]) -> CommandResult:
        self.native_calls.append((executable, list(arguments)))
        if self.native_results:
            return self.native_results.pop(0)
        return CommandResult("PID 4242", "", 0)


class NativeProtocol:
    def __init__(self, output: tuple[bytes, bytes, int]) -> None:
        self.output = output
        self.calls: list[dict[str, Any]] = []
        self.cleaned: list[str] = []

    def run_command(
        self,
        shell_id: str,
        command: str,
        arguments: Iterable[str] = (),
        console_mode_stdin: bool = True,
        skip_cmd_shell: bool = False,
    ) -> str:
        self.calls.append(
            {
                "shell_id": shell_id,
                "command": command,
                "arguments": list(arguments),
                "console_mode_stdin": console_mode_stdin,
                "skip_cmd_shell": skip_cmd_shell,
            }
        )
        return "command-1"

    def get_command_output(self, shell_id: str, command_id: str) -> tuple[bytes, bytes, int]:
        return self.output

    def cleanup_command(self, shell_id: str, command_id: str) -> None:
        self.cleaned.append(command_id)


def test_helper_blobs_are_nonempty_pe_images() -> None:
    for blob in (GWSPAWN_X64_B64, GWSPAWN_X86_B64):
        image = base64.b64decode(blob)
        assert image[:2] == b"MZ"
        assert len(image) > 10000


def test_parse_helper_output_reads_pid() -> None:
    assert parse_helper_output("PID 123") == 123
    assert parse_helper_output("junk\r\nPID 456\r\n") == 456


def test_parse_helper_output_raises_on_error_code() -> None:
    with pytest.raises(GoodWinRMError, match="launcher helper failed with code 5"):
        parse_helper_output("ERR 5")


def test_parse_helper_output_rejects_unparsable_output() -> None:
    with pytest.raises(GoodWinRMError, match="Cannot determine spawned process id"):
        parse_helper_output("nothing useful")


def test_run_native_skips_cmd_shell_and_cleans_up() -> None:
    protocol = NativeProtocol((b"PID 123\r\n", b"", 0))
    shell = WinRMShell(protocol, "shell", "server.test", "C:\\")  # type: ignore[arg-type]

    result = shell.run_native("C:\\Work\\.ab123.exe", ["breakaway", "C:\\Work\\svc.exe"])

    assert result == CommandResult("PID 123", "", 0)
    assert len(protocol.calls) == 1
    call = protocol.calls[0]
    assert call["command"] == "C:\\Work\\.ab123.exe"
    assert call["arguments"] == ['"breakaway"', '"C:\\Work\\svc.exe"']
    assert call["skip_cmd_shell"] is True
    assert protocol.cleaned == ["command-1"]


def test_run_native_quotes_spaced_agent_path_as_argument() -> None:
    protocol = NativeProtocol((b"PID 42\r\n", b"", 0))
    shell = WinRMShell(protocol, "shell", "server.test", "C:\\")  # type: ignore[arg-type]

    shell.run_native(
        "C:\\Windows\\Temp\\.ab12cd34.exe",
        ["breakaway", "C:\\Windows\\Temp\\ver hb.exe", "-d", "host with space:443"],
    )

    call = protocol.calls[0]
    assert call["command"] == "C:\\Windows\\Temp\\.ab12cd34.exe"
    assert call["arguments"] == [
        '"breakaway"',
        '"C:\\Windows\\Temp\\ver hb.exe"',
        '"-d"',
        '"host with space:443"',
    ]
    assert call["skip_cmd_shell"] is True


def test_run_native_rejects_executable_path_with_whitespace() -> None:
    shell = WinRMShell(NativeProtocol((b"", b"", 0)), "shell", "server.test", "C:\\")  # type: ignore[arg-type]

    with pytest.raises(GoodWinRMError, match="space-free path"):
        shell.run_native("C:\\Program Files\\.ab12cd34.exe", ["breakaway", "C:\\Tools\\svc.exe"])


def test_run_native_rejects_tab_in_executable_path() -> None:
    shell = WinRMShell(NativeProtocol((b"", b"", 0)), "shell", "server.test", "C:\\")  # type: ignore[arg-type]

    with pytest.raises(GoodWinRMError, match="space-free path"):
        shell.run_native("C:\\Windows\\Temp\t.exe", [])


def crt_argv(command_line: str) -> list[str]:
    argv: list[str] = []
    argument = ""
    backslashes = 0
    in_quotes = False
    for char in command_line:
        if char == "\\":
            backslashes += 1
            continue
        if char == '"':
            argument += "\\" * (backslashes // 2)
            if backslashes % 2 == 1:
                argument += '"'
            else:
                in_quotes = not in_quotes
            backslashes = 0
            continue
        argument += "\\" * backslashes
        backslashes = 0
        if char in " \t" and not in_quotes:
            argv.append(argument)
            argument = ""
            continue
        argument += char
    argument += "\\" * backslashes
    argv.append(argument)
    return argv


@pytest.mark.parametrize(
    "arguments",
    [
        ["C:\\Program Files\\ver hb.exe", "-d", "host with space:443"],
        ['say "hi"', 'two \\" quotes\\', "C:\\dst\\"],
        [""],
        ["tab\there", "plain", "a\\" * 5 + '"'],
        ["C:\\Tools\\svc.exe"],
    ],
)
def test_launcher_quoting_round_trips_through_crt_argv_rules(arguments: list[str]) -> None:
    command_line = " ".join([win_quote("C:\\h.exe"), *(win_quote(a) for a in arguments)])

    assert crt_argv(command_line) == ["C:\\h.exe", *arguments]


def test_parse_spawn_request_reads_launcher_and_stage_dir() -> None:
    request = parse_spawn_request(
        [
            "--launcher",
            "breakaway",
            "--stage-dir",
            "C:\\Windows\\Temp",
            "--stdout",
            "C:\\o.log",
            "C:\\Tools\\svc.exe",
            "-d",
            "h",
        ]
    )

    assert request.launcher == "breakaway"
    assert request.stage_dir == "C:\\Windows\\Temp"
    assert request.stdout_path == "C:\\o.log"
    assert request.executable == "C:\\Tools\\svc.exe"
    assert request.arguments == ("-d", "h")
    assert not request.use_schtasks


def test_parse_spawn_request_schtasks_flags_stay_equivalent() -> None:
    legacy = parse_spawn_request(["--schtasks", "C:\\Tools\\svc.exe"])
    explicit = parse_spawn_request(["--launcher", "schtasks", "C:\\Tools\\svc.exe"])

    assert legacy.launcher == explicit.launcher == "schtasks"
    assert legacy.use_schtasks
    assert explicit.use_schtasks
    assert legacy.executable == explicit.executable


def test_parse_spawn_request_defaults_to_auto() -> None:
    request = parse_spawn_request(["C:\\Tools\\svc.exe"])

    assert request.launcher == "auto"
    assert request.stage_dir is None
    assert not request.use_schtasks


@pytest.mark.parametrize(
    "tokens",
    [
        ["--launcher"],
        ["--launcher", "wmi"],
        ["--launcher", "--stdout"],
        ["--stage-dir"],
    ],
)
def test_parse_spawn_request_rejects_invalid_launcher_usage(tokens: list[str]) -> None:
    with pytest.raises(GoodWinRMError, match=re.escape(SPAWN_USAGE)):
        parse_spawn_request([*tokens, "C:\\Tools\\svc.exe"])


def test_launch_spawn_breakaway_stages_helper_in_default_dir() -> None:
    shell = LauncherShell(arch="AMD64")
    request = parse_spawn_request(["--launcher", "breakaway", "C:\\Tools\\svc.exe", "-d", "h"])

    launch_spawn(shell, request)  # type: ignore[arg-type]

    assert len(shell.native_calls) == 1
    helper_remote, arguments = shell.native_calls[0]
    assert re.fullmatch(r"C:\\Windows\\Temp\\\.[0-9a-f]{8}\.exe", helper_remote)
    assert arguments == ["breakaway", "C:\\Tools\\svc.exe", "-d", "h"]
    assert shell.payloads == [base64.b64decode(GWSPAWN_X64_B64)]
    assert any("Remove-Item" in script and helper_remote in script for script in shell.scripts)
    assert all("goodwinrm" not in script for script in shell.scripts)


def test_launch_spawn_spaced_agent_path_uses_space_free_helper_dir() -> None:
    shell = LauncherShell(arch="AMD64")
    request = parse_spawn_request(
        ["--launcher", "breakaway", "C:\\Program Files\\ver hb.exe", "-d", "host with space:443"]
    )

    launch_spawn(shell, request)  # type: ignore[arg-type]

    helper_remote, arguments = shell.native_calls[0]
    assert re.fullmatch(r"C:\\Windows\\Temp\\\.[0-9a-f]{8}\.exe", helper_remote)
    assert arguments == ["breakaway", "C:\\Program Files\\ver hb.exe", "-d", "host with space:443"]


def test_launch_spawn_rejects_stage_dir_with_whitespace() -> None:
    shell = LauncherShell(arch="AMD64")
    request = parse_spawn_request(
        ["--launcher", "breakaway", "--stage-dir", "C:\\Program Files", "C:\\Tools\\svc.exe"]
    )

    with pytest.raises(GoodWinRMError, match="must not contain whitespace"):
        launch_spawn(shell, request)  # type: ignore[arg-type]

    assert shell.native_calls == []


def test_launch_spawn_honors_stage_dir() -> None:
    shell = LauncherShell(arch="AMD64")
    request = parse_spawn_request(
        ["--launcher", "wmi-native", "--stage-dir", "C:\\Windows\\Temp", "C:\\Tools\\svc.exe"]
    )

    launch_spawn(shell, request)  # type: ignore[arg-type]

    helper_remote, arguments = shell.native_calls[0]
    assert helper_remote.startswith("C:\\Windows\\Temp\\.")
    assert arguments[0] == "wmi"


def test_launch_spawn_x86_target_uses_x86_helper() -> None:
    shell = LauncherShell(arch="x86")
    request = parse_spawn_request(["--launcher", "breakaway", "C:\\Tools\\svc.exe"])

    launch_spawn(shell, request)  # type: ignore[arg-type]

    assert shell.payloads == [base64.b64decode(GWSPAWN_X86_B64)]


def test_launch_spawn_explicit_failure_does_not_fall_back() -> None:
    shell = LauncherShell(arch="AMD64", native_results=[CommandResult("ERR 5", "", 1)])
    request = parse_spawn_request(["--launcher", "breakaway", "C:\\Tools\\svc.exe"])

    with pytest.raises(GoodWinRMError, match="ERR 5"):
        launch_spawn(shell, request)  # type: ignore[arg-type]

    assert "Invoke-CimMethod" not in "".join(shell.scripts)


def test_launch_spawn_auto_falls_back_to_next_native_launcher() -> None:
    shell = LauncherShell(
        arch="AMD64",
        native_results=[CommandResult("ERR 5", "", 1), CommandResult("PID 2200", "", 0)],
    )
    request = parse_spawn_request(["C:\\Tools\\svc.exe"])

    launch_spawn(shell, request)  # type: ignore[arg-type]

    modes = [arguments[0] for _, arguments in shell.native_calls]
    assert modes == ["breakaway", "wmi"]
    assert "Invoke-CimMethod" not in "".join(shell.scripts)


def test_launch_spawn_auto_falls_back_to_wmi_ps() -> None:
    shell = LauncherShell(
        arch="AMD64",
        native_results=[CommandResult("ERR 5", "", 1), CommandResult("ERR 21", "", 1)],
        ps_results=[CommandResult("3131", "", 0)],
    )
    request = parse_spawn_request(["C:\\Tools\\svc.exe"])

    launch_spawn(shell, request)  # type: ignore[arg-type]

    assert len(shell.native_calls) == 2
    assert "Invoke-CimMethod -ClassName Win32_Process -MethodName Create" in "".join(shell.scripts)


def test_launch_spawn_auto_skips_native_on_unsupported_architecture() -> None:
    shell = LauncherShell(arch="ARM64", ps_results=[CommandResult("3131", "", 0)])
    request = parse_spawn_request(["C:\\Tools\\svc.exe"])

    launch_spawn(shell, request)  # type: ignore[arg-type]

    assert shell.native_calls == []
    assert "Invoke-CimMethod" in "".join(shell.scripts)


def test_launch_spawn_auto_skips_native_when_redirects_requested() -> None:
    shell = LauncherShell(arch="AMD64", ps_results=[CommandResult("77", "", 0)])
    request = parse_spawn_request(["--stdout", "C:\\o.log", "C:\\Tools\\svc.exe"])

    launch_spawn(shell, request)  # type: ignore[arg-type]

    assert shell.native_calls == []
    assert ARCH_PROBE not in shell.scripts


def test_launch_spawn_native_with_redirects_falls_back_to_wmi_ps() -> None:
    shell = LauncherShell(arch="AMD64", ps_results=[CommandResult("77", "", 0)])
    request = parse_spawn_request(
        ["--launcher", "breakaway", "--stdout", "C:\\o.log", "C:\\Tools\\svc.exe"]
    )

    launch_spawn(shell, request)  # type: ignore[arg-type]

    assert shell.native_calls == []
    assert "Invoke-CimMethod" in "".join(shell.scripts)


def test_launch_spawn_auto_reports_when_every_launcher_fails() -> None:
    shell = LauncherShell(
        arch="AMD64",
        native_results=[CommandResult("ERR 5", "", 1), CommandResult("ERR 21", "", 1)],
        ps_results=[CommandResult("", "Win32_Process.Create failed: 9", 1)],
    )
    request = parse_spawn_request(["C:\\Tools\\svc.exe"])

    with pytest.raises(GoodWinRMError, match="No spawn launcher succeeded"):
        launch_spawn(shell, request)  # type: ignore[arg-type]


def test_dispatch_spawn_schtasks_still_works(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(app, "USE_COLOR", False)
    shell = LauncherShell(ps_results=[CommandResult("", "", 0)])

    assert dispatch_command(
        "spawn --schtasks C:\\Windows\\Temp\\svc.exe",
        shell,  # type: ignore[arg-type]
    )

    output = capsys.readouterr().out
    assert "scheduled task" in output
    assert "schtasks /f /create" in "".join(shell.scripts)


def test_dispatch_spawn_auto_prints_working_launcher(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(app, "USE_COLOR", False)
    shell = LauncherShell(arch="AMD64")

    assert dispatch_command(
        "spawn C:\\Windows\\Temp\\love.exe -d host:2308",
        shell,  # type: ignore[arg-type]
    )

    output = capsys.readouterr().out
    assert "PID 4242" in output
    assert "via breakaway" in output
