from __future__ import annotations

import base64
from pathlib import Path
from typing import Any, cast

import pytest

import goodwinrm.goodwinrm as app
from goodwinrm.goodwinrm import (
    CommandResult,
    GoodWinRMError,
    WinRMShell,
    change_directory,
    dispatch_command,
)


class FakeTransport:
    def __init__(self) -> None:
        self.closed = 0

    def close_session(self) -> None:
        self.closed += 1


class FakeProtocol:
    def __init__(self, outputs: list[tuple[bytes, bytes, int]]) -> None:
        self.outputs = outputs
        self.scripts: list[str] = []
        self.cleaned: list[str] = []
        self.closed: list[str] = []
        self.inputs: list[tuple[bytes, bool]] = []
        self.transport = FakeTransport()

    def run_command(self, shell_id: str, command: str, args: list[str]) -> str:
        assert shell_id == "shell"
        assert command == "powershell.exe"
        assert args[-2] == "-EncodedCommand"
        self.scripts.append(base64.b64decode(args[-1]).decode("utf-16-le"))
        return f"command-{len(self.scripts)}"

    def get_command_output(self, shell_id: str, command_id: str) -> tuple[bytes, bytes, int]:
        return self.outputs.pop(0)

    def cleanup_command(self, shell_id: str, command_id: str) -> None:
        self.cleaned.append(command_id)

    def send_command_input(
        self, shell_id: str, command_id: str, value: bytes, end: bool = False
    ) -> None:
        self.inputs.append((value, end))

    def close_shell(self, shell_id: str) -> None:
        self.closed.append(shell_id)


def make_shell(protocol: Any) -> WinRMShell:
    return WinRMShell(protocol, "shell", "server.test", "C:\\")


def test_run_decodes_output_and_always_cleans_command() -> None:
    protocol = FakeProtocol([(b"hello\r\n", b"plain error\r\n", 1)])
    shell = make_shell(protocol)

    result = shell.run("Write-Output hello")

    assert result == CommandResult("hello", "plain error", 1)
    assert protocol.scripts == ["Write-Output hello"]
    assert protocol.cleaned == ["command-1"]


def test_run_cleans_command_when_output_collection_fails() -> None:
    protocol = FakeProtocol([])

    def fail(shell_id: str, command_id: str) -> tuple[bytes, bytes, int]:
        raise RuntimeError("network failure")

    protocol.get_command_output = fail  # type: ignore[method-assign]
    shell = make_shell(protocol)

    with pytest.raises(RuntimeError, match="network failure"):
        shell.run("hostname")
    assert protocol.cleaned == ["command-1"]


def test_run_with_input_streams_chunks_and_closes_stdin() -> None:
    protocol = FakeProtocol([(b"7\r\n", b"", 0)])
    shell = make_shell(protocol)

    result = shell.run_with_input("read stdin", [b"one\n", b"two\n"])

    assert result == CommandResult("7", "", 0)
    assert protocol.scripts == ["read stdin"]
    assert protocol.inputs == [(b"one\n", False), (b"two\n", False), (b"", True)]
    assert protocol.cleaned == ["command-1"]


def test_run_checked_returns_success_and_raises_with_remote_error() -> None:
    protocol = FakeProtocol([(b"ok\r\n", b"", 0), (b"", b"denied\r\n", 1)])
    shell = make_shell(protocol)

    assert shell.run_checked("success", "Run command") == CommandResult("ok", "", 0)
    with pytest.raises(GoodWinRMError, match="Run command: denied"):
        shell.run_checked("failure", "Run command")


def test_keepalive_starts_once_and_stops_after_protocol_failure() -> None:
    protocol = FakeProtocol([(b"", b"", 0)])
    shell = make_shell(protocol)

    shell.start_keepalive(interval=0)
    thread = shell._keepalive_thread
    shell.start_keepalive(interval=0)
    assert shell._keepalive_thread is thread
    assert thread is not None
    thread.join(timeout=1)

    assert not thread.is_alive()
    assert len(protocol.scripts) == 2


def test_initialize_uses_plain_pwd_path() -> None:
    protocol = FakeProtocol(
        [
            (b"DOMAIN\\User\r\n", b"", 0),
            (b"SERVER\r\n", b"", 0),
            (b"C:\\Windows\r\n", b"", 0),
        ]
    )
    shell = make_shell(protocol)
    shell.current_directory = "C:\\Windows"

    shell.initialize()

    assert shell.identity == "DOMAIN\\User"
    assert shell.hostname == "SERVER"
    assert shell.current_directory == "C:\\Windows"
    assert protocol.scripts[-1].endswith(";$PWD.Path")


def test_close_is_idempotent() -> None:
    protocol = FakeProtocol([])
    shell = make_shell(protocol)

    shell.close()
    shell.close()

    assert protocol.closed == ["shell"]
    assert protocol.transport.closed == 1


class StubShell:
    def __init__(self, results: list[CommandResult] | None = None) -> None:
        self.current_directory = "C:\\Work"
        self.identity = "DOMAIN\\User"
        self.hostname = "SERVER"
        self.host = "server.test"
        self.results = results or []
        self.scripts: list[str] = []
        self.keepalive_started = False
        self.closed = False

    def run(self, script: str) -> CommandResult:
        self.scripts.append(script)
        return self.results.pop(0) if self.results else CommandResult("", "", 0)

    def start_keepalive(self) -> None:
        self.keepalive_started = True

    def close(self) -> None:
        self.closed = True


def test_change_directory_tracks_only_the_path_line() -> None:
    shell = StubShell([CommandResult("C:\\Program Files", "", 0)])
    assert change_directory(shell, "Program Files") == "C:\\Program Files"  # type: ignore[arg-type]
    assert shell.current_directory == "C:\\Program Files"
    assert "-LiteralPath 'Program Files'" in shell.scripts[0]
    assert shell.scripts[0].endswith(";$PWD.Path")


def test_change_directory_does_not_mutate_state_on_error() -> None:
    shell = StubShell([CommandResult("", "missing", 1)])
    with pytest.raises(GoodWinRMError, match="Cannot cd"):
        change_directory(shell, "missing")  # type: ignore[arg-type]
    assert shell.current_directory == "C:\\Work"


def test_clear_does_not_reset_current_directory(capsys: pytest.CaptureFixture[str]) -> None:
    shell = StubShell()
    assert dispatch_command("clear", shell)  # type: ignore[arg-type]
    assert shell.current_directory == "C:\\Work"
    assert "\x1b[H\x1b[J" in capsys.readouterr().out


def test_regular_command_runs_in_current_directory(capsys: pytest.CaptureFixture[str]) -> None:
    shell = StubShell([CommandResult("DOMAIN\\user", "", 0)])
    assert dispatch_command("whoami", shell)  # type: ignore[arg-type]
    assert "Set-Location -LiteralPath 'C:\\Work'" in shell.scripts[0]
    assert shell.scripts[0].endswith(";whoami")
    assert capsys.readouterr().out.strip() == "DOMAIN\\user"


def test_cd_parses_a_quoted_path() -> None:
    shell = StubShell([CommandResult("C:\\Program Files", "", 0)])
    assert dispatch_command('cd "C:\\Program Files"', shell)  # type: ignore[arg-type]
    assert shell.current_directory == "C:\\Program Files"


def test_exit_only_matches_builtin_without_arguments() -> None:
    shell = StubShell([CommandResult("", "", 0)])
    assert dispatch_command("exit 7", shell)  # type: ignore[arg-type]
    assert shell.scripts
    assert not dispatch_command("exit", shell)  # type: ignore[arg-type]


def test_pwd_and_help_builtins(capsys: pytest.CaptureFixture[str]) -> None:
    shell = StubShell()
    assert dispatch_command("pwd", shell)  # type: ignore[arg-type]
    assert dispatch_command("help", shell)  # type: ignore[arg-type]
    output = capsys.readouterr().out
    assert "C:\\Work" in output
    assert "upload LOCAL" in output


def test_ls_builtin_prints_output(capsys: pytest.CaptureFixture[str]) -> None:
    shell = StubShell([CommandResult("report.txt", "", 0)])
    assert dispatch_command("ls *.txt", shell)  # type: ignore[arg-type]
    assert "Get-ChildItem -Force -Path '*.txt'" in shell.scripts[0]
    assert capsys.readouterr().out.strip() == "report.txt"


def test_ls_builtin_reports_remote_failure() -> None:
    shell = StubShell([CommandResult("", "access denied", 1)])
    with pytest.raises(GoodWinRMError, match="Cannot list directory: access denied"):
        dispatch_command("ls", shell)  # type: ignore[arg-type]


def test_cd_without_path_uses_remote_profile() -> None:
    shell = StubShell(
        [
            CommandResult("C:\\Users\\User", "", 0),
            CommandResult("C:\\Users\\User", "", 0),
        ]
    )
    assert dispatch_command("cd", shell)  # type: ignore[arg-type]
    assert shell.current_directory == "C:\\Users\\User"


def test_cd_without_path_reports_missing_remote_profile() -> None:
    shell = StubShell([CommandResult("", "profile unavailable", 1)])
    with pytest.raises(GoodWinRMError, match="Cannot determine remote home"):
        dispatch_command("cd", shell)  # type: ignore[arg-type]


def test_transfer_builtins_parse_quoted_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    shell = StubShell()
    uploads: list[tuple[str, str | None]] = []
    downloads: list[tuple[str, str | None]] = []

    def fake_upload(local: str, remote: str | None, active_shell: object) -> tuple[str, int]:
        uploads.append((local, remote))
        return remote or "C:\\Work\\local file.bin", 12

    def fake_download(remote: str, local: str | None, active_shell: object) -> tuple[Path, int]:
        downloads.append((remote, local))
        return tmp_path / "local result.bin", 13

    monkeypatch.setattr(app, "upload_file", fake_upload)
    monkeypatch.setattr(app, "download_file", fake_download)
    monkeypatch.setattr(app, "USE_COLOR", False)

    assert dispatch_command('upload "/tmp/local file.bin" "C:\\Temp\\remote file.bin"', shell)  # type: ignore[arg-type]
    assert dispatch_command('download "C:\\Temp\\remote file.bin" "/tmp/result file.bin"', shell)  # type: ignore[arg-type]

    assert uploads == [("/tmp/local file.bin", "C:\\Temp\\remote file.bin")]
    assert downloads == [("C:\\Temp\\remote file.bin", "/tmp/result file.bin")]
    assert "Uploaded" in capsys.readouterr().out


@pytest.mark.parametrize(
    "command",
    ["cd one two", "ls one two", "upload", "upload one two three", "download"],
)
def test_builtin_usage_errors(command: str) -> None:
    with pytest.raises(GoodWinRMError, match="Usage"):
        dispatch_command(command, StubShell())  # type: ignore[arg-type]


def test_regular_command_prints_clean_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(app, "USE_COLOR", False)
    shell = StubShell([CommandResult("", "command failed", 1)])
    assert dispatch_command("Get-Missing", shell)  # type: ignore[arg-type]
    assert "command failed" in capsys.readouterr().out


def test_empty_and_nonzero_commands_without_output(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(app, "USE_COLOR", False)
    shell = StubShell([CommandResult("", "", 7)])

    assert dispatch_command("", shell)  # type: ignore[arg-type]
    assert dispatch_command("failure", shell)  # type: ignore[arg-type]
    assert "exited with code 7" in capsys.readouterr().out


def test_history_uses_sanitized_per_target_filename(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    shell = StubShell()
    shell.host = "server:name"

    history = app._history(shell, "DOMAIN\\User")  # type: ignore[arg-type]
    filename = Path(cast(str, history.filename))

    assert filename.name == "server_name_DOMAIN_User.history"
    assert filename.parent.parent == tmp_path / ".goodwinrm"


def test_interactive_loop_dispatches_until_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    shell = StubShell()
    commands = iter(["pwd", "exit"])

    class FakeSession:
        def __init__(self, history: object) -> None:
            pass

        def prompt(self, prompt: object, completer: object) -> str:
            return next(commands)

    monkeypatch.setattr(app, "PromptSession", FakeSession)
    monkeypatch.setattr(app, "USE_COLOR", False)
    app.interactive_loop(shell, "User", history_enabled=False)  # type: ignore[arg-type]


def test_main_closes_shell_on_success(monkeypatch: pytest.MonkeyPatch) -> None:
    shell = StubShell()
    monkeypatch.setattr(app, "open_remote_shell", lambda args: shell)
    monkeypatch.setattr(app, "interactive_loop", lambda *args, **kwargs: None)

    assert app.main(["-i", "server.test", "-u", "user", "-p", "secret", "--no-color"]) == 0
    assert shell.keepalive_started
    assert shell.closed


def test_main_reports_connection_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail(args: object) -> None:
        raise GoodWinRMError("offline")

    monkeypatch.setattr(app, "open_remote_shell", fail)
    assert app.main(["-i", "server.test", "-u", "user", "-p", "secret", "--no-color"]) == 1
    assert "offline" in capsys.readouterr().out
