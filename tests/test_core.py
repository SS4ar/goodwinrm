from __future__ import annotations

import argparse

import pytest

from goodwinrm.goodwinrm import (
    ZERO_LM_HASH,
    GoodWinRMError,
    TransferError,
    _connection_password,
    clean_powershell_error,
    normalize_nt_hash,
    parse_endpoint,
    ps_quote,
    resolve_remote_path,
    split_shell_args,
)


@pytest.mark.parametrize(
    ("address", "port", "https", "path", "expected", "host"),
    [
        ("server.test", 0, False, "/wsman", "http://server.test:5985/wsman", "server.test"),
        ("10.0.0.5:7777", 0, False, "wsman", "http://10.0.0.5:7777/wsman", "10.0.0.5"),
        ("server.test", 443, True, "/custom", "https://server.test:443/custom", "server.test"),
        (
            "https://server.test:8443/alt",
            0,
            False,
            "/wsman",
            "https://server.test:8443/alt",
            "server.test",
        ),
        (
            "[2001:db8::1]:5986",
            0,
            True,
            "/wsman",
            "https://[2001:db8::1]:5986/wsman",
            "2001:db8::1",
        ),
        ("2001:db8::2", 0, False, "/wsman", "http://[2001:db8::2]:5985/wsman", "2001:db8::2"),
    ],
)
def test_parse_endpoint(
    address: str,
    port: int,
    https: bool,
    path: str,
    expected: str,
    host: str,
) -> None:
    assert parse_endpoint(address, port, https, path) == (expected, host)


@pytest.mark.parametrize(
    "address",
    [
        "",
        "ftp://server.test/wsman",
        "http://server.test:70000/wsman",
        "http://server.test/wsman?q=1",
        "http://[invalid/wsman",
        "server.test:not-a-port",
        "server.test:70000",
        "[invalid",
    ],
)
def test_parse_endpoint_rejects_invalid_targets(address: str) -> None:
    with pytest.raises(GoodWinRMError):
        parse_endpoint(address)


def test_explicit_port_overrides_inline_port() -> None:
    assert parse_endpoint("server.test:5985", port=1234)[0] == "http://server.test:1234/wsman"


def test_parse_endpoint_rejects_invalid_explicit_port() -> None:
    with pytest.raises(GoodWinRMError, match="Port"):
        parse_endpoint("server.test", port=-1)


def test_normalize_nt_hash() -> None:
    nt_hash = "a" * 32
    assert normalize_nt_hash(nt_hash) == f"{ZERO_LM_HASH}:{nt_hash.upper()}"
    assert normalize_nt_hash(f"{'b' * 32}:{nt_hash}") == f"{'B' * 32}:{'A' * 32}"


@pytest.mark.parametrize("value", ["", "abcd", "g" * 32, "a" * 31, f"{'a' * 32}:bad"])
def test_normalize_nt_hash_rejects_malformed_values(value: str) -> None:
    with pytest.raises(GoodWinRMError):
        normalize_nt_hash(value)


def test_connection_password_rejects_hash_with_non_ntlm_transport() -> None:
    args = argparse.Namespace(nt_hash="a" * 32, transport="kerberos", password=None)
    with pytest.raises(GoodWinRMError, match="requires NTLM"):
        _connection_password(args)


def test_powershell_literal_quoting() -> None:
    assert ps_quote("C:\\User's Files\\$report") == "'C:\\User''s Files\\$report'"


def test_resolve_remote_path() -> None:
    assert resolve_remote_path("report.txt", "C:\\Work") == "C:\\Work\\report.txt"
    assert resolve_remote_path("C:\\Temp\\report.txt", "C:\\Work") == "C:\\Temp\\report.txt"
    assert resolve_remote_path("..\\report.txt", "C:\\Work\\Data") == "C:\\Work\\report.txt"
    with pytest.raises(TransferError):
        resolve_remote_path("", "C:\\Work")


def test_split_shell_args_preserves_windows_backslashes_and_quotes() -> None:
    assert split_shell_args('"/tmp/local file" "C:\\Remote Files\\tool.exe"') == [
        "/tmp/local file",
        "C:\\Remote Files\\tool.exe",
    ]
    assert split_shell_args("C:\\Temp\\one.bin C:\\Temp\\two.bin") == [
        "C:\\Temp\\one.bin",
        "C:\\Temp\\two.bin",
    ]


def test_split_shell_args_rejects_unclosed_quote() -> None:
    with pytest.raises(GoodWinRMError, match="Cannot parse arguments"):
        split_shell_args('"unclosed')


def test_clean_powershell_error_extracts_only_error_nodes() -> None:
    value = (
        b'#< CLIXML\r\n<Objs xmlns="http://schemas.microsoft.com/powershell/2004/04">'
        b'<Obj S="progress"><MS><S N="Status">Preparing modules</S></MS></Obj>'
        b'<S S="Error">Failure_x000D__x000A_At line:1</S></Objs>'
    )
    assert clean_powershell_error(value) == "Failure\nAt line:1"


def test_clean_powershell_error_discards_progress_only_clixml() -> None:
    value = (
        b'#< CLIXML\r\n<Objs xmlns="http://schemas.microsoft.com/powershell/2004/04">'
        b'<Obj S="progress"><MS><S N="Status">Preparing modules</S></MS></Obj></Objs>'
    )
    assert clean_powershell_error(value) == ""


def test_clean_powershell_error_preserves_plain_text() -> None:
    assert clean_powershell_error(b"plain error\r\n") == "plain error"


def test_clean_powershell_error_preserves_malformed_clixml() -> None:
    malformed = b"#< CLIXML\r\n<Objs>"
    assert clean_powershell_error(malformed) == malformed.decode()
