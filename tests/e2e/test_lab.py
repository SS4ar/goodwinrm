from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path

import pytest
from spnego._ntlm_raw.crypto import ntowfv1

from goodwinrm.goodwinrm import (
    GoodWinRMError,
    WinRMShell,
    change_directory,
    download_file,
    list_directory,
    open_remote_shell,
    parse_args,
    ps_quote,
    upload_file,
)

HOST = os.environ.get("GOODWINRM_E2E_HOST")
USERNAME = os.environ.get("GOODWINRM_E2E_USERNAME")
PASSWORD = os.environ.get("GOODWINRM_E2E_PASSWORD")
DOMAIN = os.environ.get("GOODWINRM_E2E_DOMAIN")
REMOTE_DIR = os.environ.get("GOODWINRM_E2E_REMOTE_DIR", "C:\\Windows\\Temp")

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(
        not (HOST and USERNAME and PASSWORD),
        reason="set GOODWINRM_E2E_HOST, GOODWINRM_E2E_USERNAME, and GOODWINRM_E2E_PASSWORD",
    ),
]


def _username(account_type: str) -> str:
    assert USERNAME
    if account_type == "domain":
        if not DOMAIN:
            pytest.skip("GOODWINRM_E2E_DOMAIN is not configured")
        return f"{DOMAIN}\\{USERNAME}"
    return USERNAME


def _connect(account_type: str = "local", nt_hash: str | None = None) -> WinRMShell:
    assert HOST and PASSWORD
    argv = ["-i", HOST, "-u", _username(account_type), "--no-color", "--no-history"]
    if nt_hash:
        argv += ["-H", nt_hash]
    else:
        argv += ["-p", PASSWORD]
    return open_remote_shell(parse_args(argv))


@pytest.mark.parametrize("account_type", ["domain", "local"])
def test_password_authentication(account_type: str) -> None:
    assert USERNAME
    shell = _connect(account_type)
    try:
        assert shell.identity.lower().endswith(f"\\{USERNAME.lower()}")
        assert shell.hostname
    finally:
        shell.close()


@pytest.mark.parametrize("account_type", ["domain", "local"])
def test_pass_the_hash_authentication(account_type: str) -> None:
    assert PASSWORD and USERNAME
    nt_hash = ntowfv1(PASSWORD).hex()
    shell = _connect(account_type, nt_hash=nt_hash)
    try:
        assert shell.identity.lower().endswith(f"\\{USERNAME.lower()}")
    finally:
        shell.close()


def test_powershell_navigation_and_errors() -> None:
    shell = _connect("domain" if DOMAIN else "local")
    original = shell.current_directory
    try:
        unicode_result = shell.run("Write-Output 'Привет — GoodWinRM'")
        assert unicode_result.status_code == 0
        assert unicode_result.stdout == "Привет — GoodWinRM"

        error_result = shell.run("Get-Item -LiteralPath 'C:\\goodwinrm-definitely-missing'")
        assert error_result.status_code != 0
        assert "Cannot find path" in error_result.stderr
        assert "CLIXML" not in error_result.stderr

        assert change_directory(shell, "Windows").lower().endswith("\\windows")
        assert change_directory(shell, "..") == "C:\\"
        assert "Windows" in list_directory(shell, "Win*")
        with pytest.raises(GoodWinRMError):
            change_directory(shell, "goodwinrm-definitely-missing")
    finally:
        shell.current_directory = original
        shell.close()


def test_file_transfer_roundtrip(tmp_path: Path) -> None:
    shell = _connect("local")
    run_id = uuid.uuid4().hex
    fixtures = {
        "empty file.bin": b"",
        "small file.bin": b"GoodWinRM" + bytes(range(256)),
        "large Unicode файл.bin": os.urandom(100_000),
    }
    remote_paths: list[str] = []
    try:
        for filename, payload in fixtures.items():
            local = tmp_path / filename
            local.write_bytes(payload)
            remote = f"{REMOTE_DIR}\\goodwinrm-{run_id}-{filename}"
            remote_paths.append(remote)

            uploaded_path, uploaded_size = upload_file(str(local), remote, shell)
            downloaded = tmp_path / f"downloaded-{filename}"
            downloaded_path, downloaded_size = download_file(uploaded_path, str(downloaded), shell)

            assert uploaded_size == len(payload)
            assert downloaded_size == len(payload)
            assert (
                hashlib.sha256(downloaded_path.read_bytes()).digest()
                == hashlib.sha256(payload).digest()
            )

        overwrite_source = tmp_path / "overwrite.bin"
        overwrite_payload = os.urandom(75_000)
        overwrite_source.write_bytes(overwrite_payload)
        overwrite_remote = remote_paths[-1]
        upload_file(str(overwrite_source), overwrite_remote, shell)
        overwrite_result = tmp_path / "overwrite-result.bin"
        download_file(overwrite_remote, str(overwrite_result), shell)
        assert overwrite_result.read_bytes() == overwrite_payload
    finally:
        for remote in remote_paths:
            shell.run(
                f"Remove-Item -LiteralPath {ps_quote(remote)} -Force -ErrorAction SilentlyContinue"
            )
        shell.close()


def test_kerberos_ccache_when_configured() -> None:
    ccache = os.environ.get("GOODWINRM_E2E_CCACHE")
    kerberos_host = os.environ.get("GOODWINRM_E2E_KERBEROS_HOST")
    if not (ccache and kerberos_host):
        pytest.skip("Kerberos E2E variables are not configured")

    shell = open_remote_shell(
        parse_args(
            [
                "-i",
                kerberos_host,
                "-t",
                "kerberos",
                "--ccache",
                ccache,
                "--no-color",
                "--no-history",
            ]
        )
    )
    try:
        assert shell.identity
    finally:
        shell.close()
