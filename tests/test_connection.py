from __future__ import annotations

import argparse
import base64
import os
from pathlib import Path
from typing import Any, ClassVar

import pytest

import goodwinrm.goodwinrm as app
from goodwinrm.goodwinrm import (
    ZERO_LM_HASH,
    GoodWinRMError,
    _configure_ccache,
    _connection_password,
    open_remote_shell,
    parse_args,
)


def namespace(**values: Any) -> argparse.Namespace:
    defaults = {"nt_hash": None, "transport": "ntlm", "password": None, "cert_pem": None}
    defaults.update(values)
    return argparse.Namespace(**defaults)


def test_connection_password_modes(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _connection_password(namespace(password="secret")) == "secret"
    assert _connection_password(namespace(transport="kerberos")) is None
    assert _connection_password(namespace(transport="certificate")) is None
    assert _connection_password(namespace(transport="ssl", cert_pem="client.pem")) is None

    monkeypatch.setattr(app.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(app.getpass, "getpass", lambda prompt: "prompted")
    assert _connection_password(namespace()) == "prompted"


def test_connection_password_requires_value_without_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app.sys.stdin, "isatty", lambda: False)
    with pytest.raises(GoodWinRMError, match="non-interactive"):
        _connection_password(namespace())


def test_configure_ccache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ccache = tmp_path / "ticket.ccache"
    ccache.write_bytes(b"ticket")
    monkeypatch.delenv("KRB5CCNAME", raising=False)

    _configure_ccache(f"FILE:{ccache}")

    assert os.environ["KRB5CCNAME"] == f"FILE:{ccache}"


def test_configure_ccache_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(GoodWinRMError, match="not found"):
        _configure_ccache(str(tmp_path / "missing.ccache"))


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (["-i", "server.test", "-p", "secret"], "requires --username"),
        (
            ["-i", "server.test", "-u", "user", "-t", "certificate"],
            "Certificate transport requires",
        ),
        (
            ["-i", "server.test", "-u", "user", "--cert-pem", "client.pem"],
            "Both --cert-pem",
        ),
        (
            [
                "-i",
                "server.test",
                "-u",
                "user",
                "-p",
                "secret",
                "--cert-pem",
                "client.pem",
                "--cert-key-pem",
                "key.pem",
            ],
            "Client certificates require",
        ),
        (
            ["-i", "server.test", "-u", "user", "-p", "secret", "--ccache", "ticket"],
            "--ccache requires",
        ),
        (
            ["-i", "server.test", "-t", "kerberos", "-p", "secret"],
            "--password is not supported",
        ),
        (
            ["-i", "server.test", "-u", "user", "-p", "secret", "--operation-timeout", "0"],
            "Timeouts must be positive",
        ),
        (
            [
                "-i",
                "server.test",
                "-u",
                "user",
                "-p",
                "secret",
                "--operation-timeout",
                "30",
                "--read-timeout",
                "20",
            ],
            "Read timeout must be greater",
        ),
    ],
)
def test_open_remote_shell_validates_arguments(argv: list[str], message: str) -> None:
    with pytest.raises(GoodWinRMError, match=message):
        open_remote_shell(parse_args(argv))


class FakeTransport:
    def __init__(self) -> None:
        self.closed = False

    def close_session(self) -> None:
        self.closed = True


class FakeProtocol:
    instances: ClassVar[list[FakeProtocol]] = []
    outputs: ClassVar[list[tuple[bytes, bytes, int]]] = [
        (b"DOMAIN\\User\r\n", b"", 0),
        (b"SERVER\r\n", b"", 0),
        (b"C:\\\r\n", b"", 0),
    ]
    open_error: Exception | None = None

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.transport = FakeTransport()
        self.closed_shells: list[str] = []
        self.responses = list(self.outputs)
        self.__class__.instances.append(self)

    def open_shell(self, **kwargs: Any) -> str:
        self.open_kwargs = kwargs
        if self.open_error:
            raise self.open_error
        return "shell-id"

    def run_command(self, shell_id: str, command: str, args: list[str]) -> str:
        base64.b64decode(args[-1]).decode("utf-16-le")
        return f"command-{len(self.responses)}"

    def get_command_output(self, shell_id: str, command_id: str) -> tuple[bytes, bytes, int]:
        return self.responses.pop(0)

    def cleanup_command(self, shell_id: str, command_id: str) -> None:
        pass

    def close_shell(self, shell_id: str) -> None:
        self.closed_shells.append(shell_id)


def test_open_remote_shell_builds_ntlm_hash_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeProtocol.instances.clear()
    FakeProtocol.open_error = None
    monkeypatch.setattr(app, "Protocol", FakeProtocol)

    shell = open_remote_shell(
        parse_args(["-i", "server.test:7777", "-u", "DOMAIN\\User", "-H", "a" * 32])
    )

    protocol = FakeProtocol.instances[-1]
    assert protocol.kwargs["endpoint"] == "http://server.test:7777/wsman"
    assert protocol.kwargs["password"] == f"{ZERO_LM_HASH}:{'A' * 32}"
    assert protocol.kwargs["transport"] == "ntlm"
    assert shell.identity == "DOMAIN\\User"
    assert shell.hostname == "SERVER"
    shell.close()


def test_ssl_client_certificate_does_not_require_username(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    FakeProtocol.instances.clear()
    FakeProtocol.open_error = None
    monkeypatch.setattr(app, "Protocol", FakeProtocol)
    certificate = tmp_path / "client.pem"
    key = tmp_path / "key.pem"
    certificate.touch()
    key.touch()

    shell = open_remote_shell(
        parse_args(
            [
                "-i",
                "server.test",
                "-t",
                "ssl",
                "--cert-pem",
                str(certificate),
                "--cert-key-pem",
                str(key),
            ]
        )
    )

    protocol = FakeProtocol.instances[-1]
    assert protocol.kwargs["endpoint"] == "https://server.test:5986/wsman"
    assert protocol.kwargs["username"] is None
    assert protocol.kwargs["password"] is None
    shell.close()


def test_open_remote_shell_maps_authentication_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeProtocol.instances.clear()
    FakeProtocol.open_error = RuntimeError("401 credentials rejected")
    monkeypatch.setattr(app, "Protocol", FakeProtocol)

    with pytest.raises(GoodWinRMError, match="Authentication denied"):
        open_remote_shell(parse_args(["-i", "server.test", "-u", "user", "-p", "secret"]))

    assert FakeProtocol.instances[-1].transport.closed


def test_open_remote_shell_wraps_protocol_constructor_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_protocol(**kwargs: Any) -> None:
        raise RuntimeError("missing backend")

    monkeypatch.setattr(app, "Protocol", fail_protocol)
    with pytest.raises(GoodWinRMError, match="Connection failed: missing backend"):
        open_remote_shell(parse_args(["-i", "server.test", "-u", "user", "-p", "secret"]))


def test_open_remote_shell_cleans_up_after_initialization_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeProtocol.instances.clear()
    FakeProtocol.open_error = None
    monkeypatch.setattr(
        FakeProtocol,
        "outputs",
        [
            (b"DOMAIN\\User\r\n", b"", 0),
            (b"SERVER\r\n", b"", 0),
            (b"", b"missing directory", 1),
        ],
    )
    monkeypatch.setattr(app, "Protocol", FakeProtocol)

    with pytest.raises(GoodWinRMError, match="Invalid initial directory"):
        open_remote_shell(parse_args(["-i", "server.test", "-u", "user", "-p", "secret"]))

    protocol = FakeProtocol.instances[-1]
    assert protocol.closed_shells == ["shell-id"]
    assert protocol.transport.closed
