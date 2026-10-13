from __future__ import annotations

import base64
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pytest

import goodwinrm.goodwinrm as app
from goodwinrm.goodwinrm import (
    PS_PROGRESS_SILENCE,
    SPAWN_USAGE,
    CommandResult,
    GoodWinRMError,
    WinRMShell,
    build_process_command_line,
    build_schtasks_spawn_script,
    build_wmi_spawn_script,
    dispatch_command,
    execute_foreground,
    execute_script_block,
    parse_spawn_request,
    read_multiline_script,
    spawn_scheduled,
    spawn_wmi,
    upload_file,
    win_quote,
)


class ExecShell:
    def __init__(self, results: list[CommandResult] | None = None) -> None:
        self.current_directory = "C:\\Work"
        self.identity = "DOMAIN\\User"
        self.hostname = "SERVER"
        self.host = "server.test"
        self.results = list(results or [])
        self.scripts: list[str] = []

    def run(self, script: str) -> CommandResult:
        self.scripts.append(script)
        if self.results:
            return self.results.pop(0)
        return CommandResult("", "", 0)


class UploadShell:
    def __init__(self) -> None:
        self.current_directory = "C:\\Work"
        self.payload = bytearray()
        self.scripts: list[str] = []

    def run_with_input(self, script: str, chunks: Iterable[bytes]) -> CommandResult:
        self.scripts.append(script)
        for encoded_chunk in chunks:
            self.payload.extend(base64.b64decode(encoded_chunk.strip()))
        return CommandResult(str(len(self.payload)), "", 0)

    def run(self, script: str) -> CommandResult:
        self.scripts.append(script)
        if "$src=" in script:
            return CommandResult(str(len(self.payload)), "", 0)
        return CommandResult("", "", 0)


class FakeProtocol:
    def __init__(self, outputs: list[tuple[bytes, bytes, int]]) -> None:
        self.outputs = outputs
        self.scripts: list[str] = []

    def run_command(self, shell_id: str, command: str, args: list[str]) -> str:
        assert command == "powershell.exe"
        assert args[-2] == "-EncodedCommand"
        self.scripts.append(base64.b64decode(args[-1]).decode("utf-16-le"))
        return f"command-{len(self.scripts)}"

    def get_command_output(self, shell_id: str, command_id: str) -> tuple[bytes, bytes, int]:
        return self.outputs.pop(0)

    def send_command_input(
        self, shell_id: str, command_id: str, value: bytes, end: bool = False
    ) -> None:
        pass

    def cleanup_command(self, shell_id: str, command_id: str) -> None:
        pass


def make_shell(protocol: Any) -> WinRMShell:
    return WinRMShell(protocol, "shell", "server.test", "C:\\")


def test_parse_spawn_request_collects_options_before_executable() -> None:
    request = parse_spawn_request(
        [
            "--schtasks",
            "--stdout",
            "C:\\Windows\\Temp\\out.log",
            "--stderr",
            "C:\\Windows\\Temp\\err.log",
            "C:\\Tools\\svc.exe",
            "-d",
            "10.0.0.5:443",
            "--foreground",
        ]
    )

    assert request.executable == "C:\\Tools\\svc.exe"
    assert request.arguments == ("-d", "10.0.0.5:443", "--foreground")
    assert request.stdout_path == "C:\\Windows\\Temp\\out.log"
    assert request.stderr_path == "C:\\Windows\\Temp\\err.log"
    assert request.use_schtasks


def test_parse_spawn_request_treats_unknown_options_as_arguments() -> None:
    request = parse_spawn_request(["tool.exe", "--stdout", "keep.log"])

    assert request.executable == "tool.exe"
    assert request.arguments == ("--stdout", "keep.log")
    assert request.stdout_path is None
    assert request.stderr_path is None
    assert not request.use_schtasks


@pytest.mark.parametrize("tokens", [[], ["--schtasks"], ["--stdout", "out.log"]])
def test_parse_spawn_request_requires_executable(tokens: list[str]) -> None:
    with pytest.raises(GoodWinRMError, match=re.escape(SPAWN_USAGE)):
        parse_spawn_request(tokens)


def test_build_process_command_line_quotes_values_with_spaces() -> None:
    command_line = build_process_command_line(
        "C:\\Program Files\\tool.exe", ["config one", "-d", ""]
    )

    assert command_line == '"C:\\Program Files\\tool.exe" "config one" "-d" ""'


def test_build_process_command_line_wraps_redirection_in_cmd() -> None:
    command_line = build_process_command_line(
        "C:\\Tools\\svc.exe",
        ["-d", "10.0.0.5:443"],
        stdout_path="C:\\Windows\\Temp\\out file.log",
        stderr_path="C:\\Windows\\Temp\\err.log",
    )

    assert command_line.startswith('cmd /c "')
    assert command_line.endswith('"')
    assert '"C:\\Tools\\svc.exe" "-d" "10.0.0.5:443"' in command_line
    assert '> "C:\\Windows\\Temp\\out file.log"' in command_line
    assert '2> "C:\\Windows\\Temp\\err.log"' in command_line


def test_build_wmi_spawn_script_uses_win32_process_create() -> None:
    script = build_wmi_spawn_script('"C:\\Tools\\svc.exe" -d 10.0.0.5:443', "C:\\Work")

    assert "Invoke-CimMethod -ClassName Win32_Process -MethodName Create" in script
    assert (
        "@{CommandLine='\"C:\\Tools\\svc.exe\" -d 10.0.0.5:443';CurrentDirectory='C:\\Work'}"
        in script
    )
    assert "$r.ReturnValue -ne 0" in script
    assert script.endswith("$r.ProcessId")


def test_build_schtasks_spawn_script_creates_runs_and_deletes() -> None:
    script = build_schtasks_spawn_script('"C:\\Tools\\svc.exe" run', "ab12cd34ef56")

    assert "schtasks /f /create /ru SYSTEM /rl HIGHEST /tn $n" in script
    assert "schtasks /run /tn $n" in script
    assert "schtasks /delete /f /tn $n" in script
    assert "$n='ab12cd34ef56'" in script
    assert "$a='\\\"C:\\Tools\\svc.exe\\\" run'" in script


def test_build_schtasks_spawn_script_verifies_last_result_before_reporting() -> None:
    script = build_schtasks_spawn_script('"C:\\Tools\\svc.exe" run', "ab12cd34ef56")

    assert "Start-Sleep -Seconds 2" in script
    assert "LastTaskResult" in script
    assert "Schedule.Service" in script
    assert "$lr -ne 267009" in script
    assert "scheduled task did not start" in script
    assert script.index("LastTaskResult") < script.index("schtasks /delete")
    assert script.count("schtasks /delete /f /tn $n") == 1
    assert script.count("2>$null") == 3


def test_spawn_scheduled_raises_when_task_did_not_start() -> None:
    shell = ExecShell(
        [CommandResult("", "scheduled task did not start (last result 2147942405)", 1)]
    )
    request = parse_spawn_request(["--schtasks", "C:\\Tools\\svc.exe"])

    with pytest.raises(GoodWinRMError, match=re.escape("last result 2147942405")):
        spawn_scheduled(shell, request)  # type: ignore[arg-type]


def test_dispatch_run_builds_invocation_with_quoted_paths() -> None:
    shell = ExecShell()

    assert dispatch_command(
        'run "C:\\Program Files\\tool.exe" "arg one" -d',
        shell,  # type: ignore[arg-type]
    )

    assert shell.scripts == [
        "Set-Location -LiteralPath 'C:\\Work' -ErrorAction Stop;"
        "& 'C:\\Program Files\\tool.exe' 'arg one' '-d';"
        "if($null -ne $LASTEXITCODE){exit $LASTEXITCODE}else{exit 1}"
    ]


def test_execute_foreground_starts_in_tracked_directory() -> None:
    shell = ExecShell()

    execute_foreground(shell, "C:\\Tools\\tool.exe", ["-d"])  # type: ignore[arg-type]

    assert shell.scripts[0].startswith("Set-Location -LiteralPath 'C:\\Work' -ErrorAction Stop;")
    assert "& 'C:\\Tools\\tool.exe' '-d'" in shell.scripts[0]
    assert shell.scripts[0].endswith("if($null -ne $LASTEXITCODE){exit $LASTEXITCODE}else{exit 1}")


def test_execute_foreground_resolves_relative_executable_from_cwd_first() -> None:
    shell = ExecShell()

    execute_foreground(shell, "tool.exe", ["-d", "h"])  # type: ignore[arg-type]

    script = shell.scripts[0]
    assert "Resolve-Path -LiteralPath 'tool.exe' -ErrorAction SilentlyContinue" in script
    assert "& $(if($e){$e.Path}else{'tool.exe'}) '-d' 'h'" in script
    assert script.startswith("Set-Location -LiteralPath 'C:\\Work' -ErrorAction Stop;")


def test_win_quote_round_trips_trailing_backslashes() -> None:
    assert win_quote("C:\\dst\\") == '"C:\\dst\\\\"'
    assert win_quote("C:\\a b\\dir\\") == '"C:\\a b\\dir\\\\"'
    assert win_quote("") == '""'


def test_win_quote_round_trips_embedded_quotes_and_backslash_runs() -> None:
    assert win_quote('say "hi"') == '"say \\"hi\\""'
    assert win_quote('two \\" quotes\\') == '"two \\\\\\" quotes\\\\"'


def test_dispatch_exec_alias_matches_run() -> None:
    run_shell = ExecShell()
    exec_shell = ExecShell()

    dispatch_command("run tool.exe -d host", run_shell)  # type: ignore[arg-type]
    dispatch_command("exec tool.exe -d host", exec_shell)  # type: ignore[arg-type]

    assert run_shell.scripts == exec_shell.scripts


def test_dispatch_run_reports_nonzero_exit_without_raising(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(app, "USE_COLOR", False)
    shell = ExecShell([CommandResult("partial output", "boom", 7)])

    assert dispatch_command("run C:\\Tools\\tool.exe", shell)  # type: ignore[arg-type]

    output = capsys.readouterr().out
    assert "partial output" in output
    assert "boom" in output
    assert "exited with code 7" in output


def test_dispatch_run_requires_executable() -> None:
    with pytest.raises(GoodWinRMError, match="Usage: run"):
        dispatch_command("run", ExecShell())  # type: ignore[arg-type]


def test_spawn_wmi_returns_process_id() -> None:
    shell = ExecShell([CommandResult("4242", "", 0)])
    request = parse_spawn_request(["C:\\Tools\\svc.exe", "-d", "10.0.0.5:443"])

    assert spawn_wmi(shell, request) == 4242  # type: ignore[arg-type]

    assert "Invoke-CimMethod -ClassName Win32_Process -MethodName Create" in shell.scripts[0]
    assert 'CommandLine=\'"C:\\Tools\\svc.exe" "-d" "10.0.0.5:443"\'' in shell.scripts[0]
    assert "CurrentDirectory='C:\\Work'" in shell.scripts[0]


def test_spawn_wmi_raises_when_return_value_is_nonzero() -> None:
    shell = ExecShell([CommandResult("", "Win32_Process.Create failed: 9", 1)])
    request = parse_spawn_request(["C:\\Tools\\svc.exe"])

    with pytest.raises(GoodWinRMError, match=re.escape("Win32_Process.Create failed: 9")):
        spawn_wmi(shell, request)  # type: ignore[arg-type]


def test_spawn_wmi_rejects_unparsable_process_id() -> None:
    shell = ExecShell([CommandResult("not-a-pid", "", 0)])
    request = parse_spawn_request(["C:\\Tools\\svc.exe"])

    with pytest.raises(GoodWinRMError, match="Cannot determine spawned process id"):
        spawn_wmi(shell, request)  # type: ignore[arg-type]


def test_dispatch_spawn_prints_process_id(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(app, "USE_COLOR", False)
    shell = ExecShell([CommandResult("1516", "", 0)])

    assert dispatch_command(
        "spawn --launcher wmi-ps C:\\Windows\\Temp\\svc.exe -d 10.0.0.5:443 --foreground",
        shell,  # type: ignore[arg-type]
    )

    assert "PID 1516" in capsys.readouterr().out


def test_dispatch_spawn_parses_quoted_paths_and_redirects() -> None:
    shell = ExecShell([CommandResult("77", "", 0)])

    assert dispatch_command(
        'spawn --stdout "C:\\Windows\\Temp\\out file.log" "C:\\Tools\\svc exe.exe" -d h',
        shell,  # type: ignore[arg-type]
    )

    assert (
        'CommandLine=\'cmd /c ""C:\\Tools\\svc exe.exe" "-d" "h" '
        '> "C:\\Windows\\Temp\\out file.log""\'' in shell.scripts[0]
    )


def test_dispatch_spawn_requires_executable() -> None:
    with pytest.raises(GoodWinRMError, match="Usage: spawn"):
        dispatch_command("spawn", ExecShell())  # type: ignore[arg-type]


def test_dispatch_spawn_schtasks_confirms_task(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(app, "USE_COLOR", False)
    shell = ExecShell([CommandResult("", "", 0)])

    assert dispatch_command(
        "spawn --schtasks --stdout C:\\Windows\\Temp\\out.log C:\\Tools\\svc.exe run",
        shell,  # type: ignore[arg-type]
    )

    output = capsys.readouterr().out
    assert "scheduled task" in output
    assert "svc.exe" in output


def test_spawn_scheduled_raises_on_schtasks_failure() -> None:
    shell = ExecShell([CommandResult("", "schtasks /run failed: 1", 1)])
    request = parse_spawn_request(["--schtasks", "C:\\Tools\\svc.exe"])

    with pytest.raises(GoodWinRMError, match="schtasks /run failed"):
        spawn_scheduled(shell, request)  # type: ignore[arg-type]


def test_dispatch_spawn_schtasks_uses_random_task_name() -> None:
    shell = ExecShell([CommandResult("", "", 0), CommandResult("", "", 0)])

    dispatch_command("spawn --schtasks C:\\Tools\\svc.exe", shell)  # type: ignore[arg-type]
    dispatch_command("spawn --schtasks C:\\Tools\\svc.exe", shell)  # type: ignore[arg-type]

    names = []
    for script in shell.scripts:
        match = re.search(r"\$n='([^']+)'", script)
        assert match is not None
        names.append(match.group(1))
    assert len(names) == 2
    assert names[0] != names[1]


def test_upload_temporary_name_carries_no_tool_signature(tmp_path: Path) -> None:
    local = tmp_path / "tool.exe"
    local.write_bytes(b"payload")
    shell = UploadShell()

    destination, size = upload_file(str(local), "C:\\Work\\tool.exe", shell)  # type: ignore[arg-type]

    assert destination == "C:\\Work\\tool.exe"
    assert size == 7
    assert all("goodwinrm" not in script for script in shell.scripts)

    match = re.search(r"\[IO\.File\]::Open\('([^']+)'", shell.scripts[0])
    assert match is not None
    temporary = match.group(1)
    assert temporary.startswith("C:\\Work\\.tmp-")
    assert re.fullmatch(r"[0-9a-f]{8}", temporary.removeprefix("C:\\Work\\.tmp-"))

    assert "$src=" in shell.scripts[1]
    assert "Move-Item" in shell.scripts[1]


def test_upload_temporary_names_differ_between_uploads(tmp_path: Path) -> None:
    local = tmp_path / "payload.bin"
    local.write_bytes(b"payload")

    first = UploadShell()
    second = UploadShell()
    upload_file(str(local), "C:\\Work\\payload.bin", first)  # type: ignore[arg-type]
    upload_file(str(local), "C:\\Work\\payload.bin", second)  # type: ignore[arg-type]

    names = []
    for shell in (first, second):
        match = re.search(r"\[IO\.File\]::Open\('([^']+)'", shell.scripts[0])
        assert match is not None
        names.append(match.group(1))
    assert names[0] != names[1]


def test_every_wire_script_suppresses_progress_reporting() -> None:
    protocol = FakeProtocol([(b"hi\r\n", b"", 0), (b"2\r\n", b"", 0)])
    shell = make_shell(protocol)

    shell.run("Write-Output hi")
    shell.run_with_input("read", [b"one\n"])

    assert protocol.scripts == [
        PS_PROGRESS_SILENCE + "Write-Output hi",
        PS_PROGRESS_SILENCE + "read",
    ]


def test_keepalive_cli_flags_disable_or_tune_interval() -> None:
    defaults = app.parse_args(["-i", "server.test"])
    assert defaults.keepalive_interval == 45.0
    assert not defaults.no_keepalive

    disabled = app.parse_args(["-i", "server.test", "--no-keepalive"])
    assert disabled.no_keepalive

    zeroed = app.parse_args(["-i", "server.test", "--keepalive-interval", "0"])
    assert zeroed.keepalive_interval == 0.0

    tuned = app.parse_args(["-i", "server.test", "--keepalive-interval", "120"])
    assert tuned.keepalive_interval == 120.0


def test_open_remote_shell_rejects_negative_keepalive_interval() -> None:
    args = app.parse_args(["-i", "server.test", "-u", "user", "--keepalive-interval", "-5"])

    with pytest.raises(GoodWinRMError, match="Keepalive interval cannot be negative"):
        app.open_remote_shell(args)


def test_main_honors_keepalive_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    class KeepaliveShell(ExecShell):
        def __init__(self) -> None:
            super().__init__()
            self.intervals: list[float] = []
            self.closed = False

        def start_keepalive(self, interval: float = 45.0) -> None:
            self.intervals.append(interval)

        def close(self) -> None:
            self.closed = True

    disabled = KeepaliveShell()
    tuned = KeepaliveShell()
    monkeypatch.setattr(app, "USE_COLOR", False)
    monkeypatch.setattr(app, "interactive_loop", lambda *args, **kwargs: None)

    monkeypatch.setattr(app, "open_remote_shell", lambda args: disabled)
    assert app.main(["-i", "server.test", "-u", "user", "-p", "secret", "--no-keepalive"]) == 0
    assert disabled.intervals == []

    monkeypatch.setattr(app, "open_remote_shell", lambda args: tuned)
    assert (
        app.main(["-i", "server.test", "-u", "user", "-p", "secret", "--keepalive-interval", "30"])
        == 0
    )
    assert tuned.intervals == [30.0]


def test_help_lists_run_exec_spawn(capsys: pytest.CaptureFixture[str]) -> None:
    assert dispatch_command("help", ExecShell())  # type: ignore[arg-type]

    output = capsys.readouterr().out
    assert "run EXE" in output
    assert "exec EXE" in output
    assert "spawn [OPTIONS] EXE" in output


class FakePromptSession:
    def __init__(self, lines: list[str]) -> None:
        self.lines = list(lines)

    def prompt(self, *args: Any, **kwargs: Any) -> str:
        return self.lines.pop(0)


def test_execute_script_block_wraps_param_and_quotes_args() -> None:
    shell = ExecShell()
    execute_script_block(shell, "param($a)\nWrite-Output $a", ["hello world"])  # type: ignore[arg-type]
    assert shell.scripts == ["& {\nparam($a)\nWrite-Output $a\n} 'hello world'"]


def test_runps_reads_local_script(tmp_path: Path) -> None:
    script = tmp_path / "payload.ps1"
    script.write_text("param($x='d')\n'ran'", encoding="utf-8")
    shell = ExecShell([CommandResult("ran", "", 0)])

    assert dispatch_command(f"runps {script}", shell)  # type: ignore[arg-type]
    assert shell.scripts == ["& {\nparam($x='d')\n'ran'\n}"]


def test_runps_requires_path() -> None:
    with pytest.raises(GoodWinRMError):
        dispatch_command("runps", ExecShell())  # type: ignore[arg-type]


def test_runps_missing_file() -> None:
    with pytest.raises(GoodWinRMError):
        dispatch_command("runps /definitely/not/here.ps1", ExecShell())  # type: ignore[arg-type]


def test_read_multiline_script_stops_at_dot() -> None:
    session = FakePromptSession(["param($a)", "Write-Output 1", ".", "ignored"])
    assert read_multiline_script(session) == ["param($a)", "Write-Output 1"]  # type: ignore[arg-type]


def test_help_lists_runps_and_script(capsys: pytest.CaptureFixture[str]) -> None:
    assert dispatch_command("help", ExecShell())  # type: ignore[arg-type]
    output = capsys.readouterr().out
    assert "runps LOCAL.ps1" in output
    assert "script | paste" in output
