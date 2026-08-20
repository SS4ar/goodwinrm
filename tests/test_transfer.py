from __future__ import annotations

import base64
from collections.abc import Iterable
from pathlib import Path

import pytest

from goodwinrm.goodwinrm import (
    DOWNLOAD_CHUNK_SIZE,
    UPLOAD_CHUNK_SIZE,
    CommandResult,
    TransferError,
    download_file,
    upload_file,
)


class UploadShell:
    def __init__(
        self,
        fail_chunk: int | None = None,
        upload_result: CommandResult | None = None,
        finalize_result: CommandResult | None = None,
    ) -> None:
        self.current_directory = "C:\\Work"
        self.payload = bytearray()
        self.chunk_calls = 0
        self.fail_chunk = fail_chunk
        self.upload_result = upload_result
        self.finalize_result = finalize_result
        self.cleanup_called = False
        self.scripts: list[str] = []

    def run_with_input(self, script: str, chunks: Iterable[bytes]) -> CommandResult:
        self.scripts.append(script)
        self.payload.clear()
        for encoded_chunk in chunks:
            self.chunk_calls += 1
            if self.fail_chunk == self.chunk_calls:
                return CommandResult("", "remote write failed", 1)
            self.payload.extend(base64.b64decode(encoded_chunk.strip()))
        return self.upload_result or CommandResult(str(len(self.payload)), "", 0)

    def run(self, script: str) -> CommandResult:
        self.scripts.append(script)
        if script.startswith("Remove-Item"):
            self.cleanup_called = True
            return CommandResult("", "", 0)
        if "$src=" in script:
            return self.finalize_result or CommandResult(str(len(self.payload)), "", 0)
        raise AssertionError(f"Unexpected script: {script}")


@pytest.mark.parametrize(
    "payload",
    [b"", b"small", bytes(range(256)) * 192, bytes(range(256)) * 400],
)
def test_upload_handles_empty_and_multichunk_files(tmp_path: Path, payload: bytes) -> None:
    local = tmp_path / "local file.bin"
    local.write_bytes(payload)
    shell = UploadShell()

    destination, size = upload_file(str(local), "remote file.bin", shell)  # type: ignore[arg-type]

    assert destination == "C:\\Work\\remote file.bin"
    assert size == len(payload)
    assert bytes(shell.payload) == payload
    assert "$src=" in shell.scripts[-1]


def test_upload_cleans_partial_remote_file_on_failure(tmp_path: Path) -> None:
    local = tmp_path / "large.bin"
    local.write_bytes(bytes(range(256)) * 400)
    shell = UploadShell(fail_chunk=2)

    with pytest.raises(TransferError, match=f"after {UPLOAD_CHUNK_SIZE * 2} bytes"):
        upload_file(str(local), None, shell)  # type: ignore[arg-type]

    assert shell.cleanup_called


def test_upload_rejects_missing_local_file(tmp_path: Path) -> None:
    with pytest.raises(TransferError, match="Local file not found"):
        upload_file(str(tmp_path / "missing"), None, UploadShell())  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("upload_result", "message"),
    [
        (CommandResult("not-a-size", "", 0), "Cannot verify temporary"),
        (CommandResult("0", "", 0), "Upload size mismatch"),
    ],
)
def test_upload_rejects_unverifiable_temporary_file(
    tmp_path: Path, upload_result: CommandResult, message: str
) -> None:
    local = tmp_path / "payload.bin"
    local.write_bytes(b"payload")
    shell = UploadShell(upload_result=upload_result)

    with pytest.raises(TransferError, match=message):
        upload_file(str(local), None, shell)  # type: ignore[arg-type]

    assert shell.cleanup_called


@pytest.mark.parametrize(
    ("finalize_result", "message"),
    [
        (CommandResult("", "move failed", 1), "Cannot finalize upload"),
        (CommandResult("not-a-size", "", 0), "Cannot verify uploaded file size"),
        (CommandResult("0", "", 0), "Upload size mismatch"),
    ],
)
def test_upload_rejects_failed_or_unverifiable_finalization(
    tmp_path: Path, finalize_result: CommandResult, message: str
) -> None:
    local = tmp_path / "payload.bin"
    local.write_bytes(b"payload")
    shell = UploadShell(finalize_result=finalize_result)

    with pytest.raises(TransferError, match=message):
        upload_file(str(local), None, shell)  # type: ignore[arg-type]

    assert shell.cleanup_called


class DownloadShell:
    def __init__(
        self,
        payload: bytes,
        fail: bool = False,
        invalid_base64: bool = False,
        size_result: CommandResult | None = None,
        reported_size: int | None = None,
    ) -> None:
        self.current_directory = "C:\\Work"
        self.payload = payload
        self.fail = fail
        self.invalid_base64 = invalid_base64
        self.size_result = size_result
        self.reported_size = reported_size
        self.scripts: list[str] = []

    def run(self, script: str) -> CommandResult:
        self.scripts.append(script)
        if "Remote file not found" in script:
            return self.size_result or CommandResult(
                str(self.reported_size if self.reported_size is not None else len(self.payload)),
                "",
                0,
            )
        if self.fail:
            return CommandResult("", "remote read failed", 1)
        if self.invalid_base64:
            return CommandResult("not base64!", "", 0)
        encoded = "\n".join(
            base64.b64encode(self.payload[offset : offset + DOWNLOAD_CHUNK_SIZE]).decode()
            for offset in range(0, len(self.payload), DOWNLOAD_CHUNK_SIZE)
        )
        return CommandResult(encoded, "", 0)


@pytest.mark.parametrize("payload", [b"", b"small", bytes(range(256)) * 400])
def test_download_handles_empty_and_multichunk_files(tmp_path: Path, payload: bytes) -> None:
    shell = DownloadShell(payload)
    destination = tmp_path / "downloaded file.bin"

    path, size = download_file("remote file.bin", str(destination), shell)  # type: ignore[arg-type]

    assert path == destination
    assert size == len(payload)
    assert destination.read_bytes() == payload
    assert len(shell.scripts) == 2


def test_download_is_atomic_on_remote_failure(tmp_path: Path) -> None:
    destination = tmp_path / "existing.bin"
    destination.write_bytes(b"keep me")
    shell = DownloadShell(bytes(range(256)) * 400, fail=True)

    with pytest.raises(TransferError, match="remote read failed"):
        download_file("remote.bin", str(destination), shell)  # type: ignore[arg-type]

    assert destination.read_bytes() == b"keep me"
    assert not list(tmp_path.glob(".existing.bin.goodwinrm-*"))


def test_download_rejects_invalid_base64_and_cleans_temp_file(tmp_path: Path) -> None:
    destination = tmp_path / "bad.bin"
    shell = DownloadShell(b"payload", invalid_base64=True)

    with pytest.raises(TransferError, match="invalid base64"):
        download_file("remote.bin", str(destination), shell)  # type: ignore[arg-type]

    assert not destination.exists()
    assert not list(tmp_path.glob(".bad.bin.goodwinrm-*"))


def test_download_rejects_missing_remote_file_before_creating_temp(tmp_path: Path) -> None:
    destination = tmp_path / "missing.bin"
    shell = DownloadShell(b"", size_result=CommandResult("", "Remote file not found", 1))

    with pytest.raises(TransferError, match="Remote file not found"):
        download_file("missing.bin", str(destination), shell)  # type: ignore[arg-type]

    assert not destination.exists()
    assert not list(tmp_path.glob(".missing.bin.goodwinrm-*"))


def test_download_rejects_invalid_remote_size(tmp_path: Path) -> None:
    shell = DownloadShell(b"payload", size_result=CommandResult("unknown", "", 0))

    with pytest.raises(TransferError, match="Cannot determine remote file size"):
        download_file("remote.bin", str(tmp_path / "result.bin"), shell)  # type: ignore[arg-type]


def test_download_rejects_size_mismatch_and_preserves_destination(tmp_path: Path) -> None:
    destination = tmp_path / "existing.bin"
    destination.write_bytes(b"keep me")
    shell = DownloadShell(b"payload", reported_size=100)

    with pytest.raises(TransferError, match="Download size mismatch"):
        download_file("remote.bin", str(destination), shell)  # type: ignore[arg-type]

    assert destination.read_bytes() == b"keep me"
    assert not list(tmp_path.glob(".existing.bin.goodwinrm-*"))


def test_download_infers_filename_and_accepts_local_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    target_directory = tmp_path / "downloads"
    target_directory.mkdir()

    inferred, _ = download_file(
        "remote.bin",
        None,
        DownloadShell(b"inferred"),  # type: ignore[arg-type]
    )
    nested, _ = download_file(
        "nested.bin",
        str(target_directory),
        DownloadShell(b"nested"),  # type: ignore[arg-type]
    )

    assert inferred == Path("remote.bin")
    assert (tmp_path / inferred).read_bytes() == b"inferred"
    assert nested == target_directory / "nested.bin"
    assert nested.read_bytes() == b"nested"


def test_download_requires_remote_filename(tmp_path: Path) -> None:
    with pytest.raises(TransferError, match="infer a local filename"):
        download_file("C:\\", str(tmp_path), DownloadShell(b""))  # type: ignore[arg-type]
