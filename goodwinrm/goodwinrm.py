from __future__ import annotations

import argparse
import base64
import binascii
import getpass
import ntpath
import os
import re
import shlex
import sys
import tempfile
import threading
import uuid
import xml.etree.ElementTree as ET
from collections.abc import Iterable, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from prompt_toolkit import ANSI, HTML, PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.history import FileHistory
from prompt_toolkit.shortcuts import print_formatted_text
from winrm.protocol import Protocol

from ._gwspawn import GWSPAWN_X64_B64, GWSPAWN_X86_B64

VERSION = "0.2.0"
UPLOAD_CHUNK_SIZE = 48 * 1024
DOWNLOAD_CHUNK_SIZE = 48 * 1024
ZERO_LM_HASH = "0" * 32
NT_HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$")
LM_NT_HASH_RE = re.compile(r"^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$")
TRANSPORTS = ("ntlm", "kerberos", "credssp", "basic", "plaintext", "ssl", "certificate")
PS_PROGRESS_SILENCE = "$ProgressPreference='SilentlyContinue';"
SPAWN_USAGE = (
    "Usage: spawn [--launcher auto|breakaway|wmi-native|wmi-ps|schtasks] [--stage-dir DIR] "
    "[--stdout PATH] [--stderr PATH] <remote executable> [arguments...]"
)
LAUNCHERS = ("auto", "breakaway", "wmi-native", "wmi-ps", "schtasks")
HELPER_MODES = {"breakaway": "breakaway", "wmi-native": "wmi"}
DEFAULT_STAGE_DIR = "C:\\Windows\\Temp"

USE_COLOR = True


class GoodWinRMError(Exception):
    """Base exception for user-facing GoodWinRM failures."""


class TransferError(GoodWinRMError):
    """Raised when an upload or download cannot complete safely."""


@dataclass(frozen=True)
class CommandResult:
    stdout: str
    stderr: str
    status_code: int


@dataclass(frozen=True)
class SpawnRequest:
    executable: str
    arguments: tuple[str, ...]
    stdout_path: str | None = None
    stderr_path: str | None = None
    use_schtasks: bool = False
    launcher: str = "auto"
    stage_dir: str | None = None


def _message(symbol: str, color: str, message: str) -> None:
    if USE_COLOR:
        print_formatted_text(ANSI(f"\x1b[{color}m{symbol} {message}\x1b[0m"))
    else:
        print(f"{symbol} {message}")


def print_error(message: str) -> None:
    _message("✖", "31", message)


def print_success(message: str) -> None:
    _message("✔", "32", message)


def print_info(message: str) -> None:
    _message("⠿", "36", message)


def banner() -> None:
    if not USE_COLOR:
        print(f"GoodWinRM {VERSION} — Python WinRM interactive shell")
        return

    print_formatted_text(
        HTML(
            f"""
> <ansigreen>┏┓     ┓┓ ┏•  ┳┓ ┳┳┓</ansigreen>  <b>GoodWinRM - v{VERSION}</b>
> <ansigreen>┃┓┏┓┏┓┏┫┃┃┃┓┏┓┣┻┓┃┃┃</ansigreen>  Python WinRM Interactive Shell
> <ansigreen>┗┛┗┛┗┛┗┻┗┻┛┗┛┗┛ ┗┛ ┗</ansigreen>  <ansiblue>https://github.com/SS4ar/goodwinrm</ansiblue>
    """
        )
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="WinRM interactive shell with file transfer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Password:
    goodwinrm -i 10.10.30.10 -u 'DOMAIN\\Administrator' -p 'Pass123'

  Pass-The-Hash:
    goodwinrm -i 10.10.30.10 -u Administrator -H A87E1E9015421162B6D958BBF7453C8D

  Kerberos ccache:
    goodwinrm -i dc.domain.local -t kerberos --ccache /tmp/admin.ccache

Quote paths containing spaces:
  upload "/tmp/tool build.exe" "C:\\Windows\\Temp\\tool build.exe"
        """,
    )
    parser.add_argument("-i", "--ip", required=True, help="Target IP, hostname, or URL")
    parser.add_argument(
        "-u", "--username", help="Username (DOMAIN\\user, user@DOMAIN, or local user)"
    )
    credentials = parser.add_mutually_exclusive_group()
    credentials.add_argument("-p", "--password", help="Password; prompt securely when omitted")
    credentials.add_argument("-H", "--nt-hash", help="NT hash or LM:NT pair for pass-the-hash")
    parser.add_argument("-t", "--transport", default="ntlm", choices=TRANSPORTS)
    parser.add_argument(
        "-v",
        "--server-cert-validation",
        default="ignore",
        choices=("ignore", "validate"),
    )
    parser.add_argument(
        "-d", "--directory", default="C:\\", help="Initial remote working directory"
    )
    parser.add_argument("-S", "--https", action="store_true", help="Use HTTPS")
    parser.add_argument("-P", "--port", type=int, default=0, help="Custom port")
    parser.add_argument("-U", "--url", default="/wsman", help="WinRM endpoint path")
    parser.add_argument("--cert-pem", help="Client certificate in PEM format")
    parser.add_argument("--cert-key-pem", help="Client private key in PEM format")
    parser.add_argument("--ccache", help="Kerberos ccache path (sets KRB5CCNAME)")
    parser.add_argument("--spn-hostname", help="Kerberos SPN hostname override")
    parser.add_argument("--spn-service", default="HTTP", help="Kerberos SPN service")
    parser.add_argument("--operation-timeout", type=int, default=20, help="WinRM operation timeout")
    parser.add_argument("--read-timeout", type=int, default=30, help="HTTP read timeout")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    parser.add_argument(
        "--no-history", action="store_true", help="Disable persistent command history"
    )
    parser.add_argument(
        "--no-keepalive",
        action="store_true",
        help="Disable background keepalive PowerShell commands",
    )
    parser.add_argument(
        "--keepalive-interval",
        type=float,
        default=45.0,
        help="Seconds between keepalive commands (0 disables keepalive)",
    )
    parser.add_argument("--version", action="version", version=f"GoodWinRM {VERSION}")
    return parser


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    return build_parser().parse_args(argv)


def parse_endpoint(
    address: str, port: int = 0, https: bool = False, path: str = "/wsman"
) -> tuple[str, str]:
    target = address.strip()
    if not target:
        raise GoodWinRMError("Target cannot be empty")
    if not 0 <= port <= 65535:
        raise GoodWinRMError("Port must be between 1 and 65535")

    scheme = "https" if https else "http"
    inline_port: int | None = None
    endpoint_path = path

    if "://" in target:
        try:
            parsed = urlsplit(target)
        except ValueError as exc:
            raise GoodWinRMError("Target URL is invalid") from exc
        if parsed.scheme not in {"http", "https"}:
            raise GoodWinRMError("Target URL must use http or https")
        if parsed.query or parsed.fragment:
            raise GoodWinRMError("Target URL must not contain a query or fragment")
        scheme = parsed.scheme
        host = parsed.hostname
        try:
            inline_port = parsed.port
        except ValueError as exc:
            raise GoodWinRMError("Target URL contains an invalid port") from exc
        if parsed.path and parsed.path != "/":
            endpoint_path = parsed.path
    else:
        host = target
        if target.startswith("["):
            try:
                parsed = urlsplit(f"//{target}")
                host = parsed.hostname
                inline_port = parsed.port
            except ValueError as exc:
                raise GoodWinRMError("Target is invalid") from exc
        elif target.count(":") == 1:
            maybe_host, maybe_port = target.rsplit(":", 1)
            if not maybe_host or not maybe_port.isdigit():
                raise GoodWinRMError("Target contains an invalid port")
            host = maybe_host
            inline_port = int(maybe_port)

    if not host:
        raise GoodWinRMError("Target hostname is invalid")
    final_port = port or inline_port or (5986 if scheme == "https" else 5985)
    if not 1 <= final_port <= 65535:
        raise GoodWinRMError("Port must be between 1 and 65535")
    if not endpoint_path.startswith("/"):
        endpoint_path = f"/{endpoint_path}"

    endpoint_host = f"[{host}]" if ":" in host else host
    return f"{scheme}://{endpoint_host}:{final_port}{endpoint_path}", host


def normalize_nt_hash(value: str) -> str:
    candidate = value.strip()
    if NT_HASH_RE.fullmatch(candidate):
        return f"{ZERO_LM_HASH}:{candidate.upper()}"
    if LM_NT_HASH_RE.fullmatch(candidate):
        return candidate.upper()
    raise GoodWinRMError("NT hash must be 32 hexadecimal characters or an LM:NT pair")


def ps_quote(value: str) -> str:
    """Quote arbitrary text as a literal PowerShell single-quoted string."""

    return "'" + value.replace("'", "''") + "'"


def resolve_remote_path(path: str, current_directory: str) -> str:
    expanded = path.strip()
    if not expanded:
        raise TransferError("Remote path cannot be empty")
    if ntpath.isabs(expanded):
        return ntpath.normpath(expanded)
    return ntpath.normpath(ntpath.join(current_directory, expanded))


def split_shell_args(value: str) -> list[str]:
    lexer = shlex.shlex(value, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    lexer.escape = ""
    try:
        return list(lexer)
    except ValueError as exc:
        raise GoodWinRMError(f"Cannot parse arguments: {exc}") from exc


def _decode_output(value: bytes) -> str:
    return value.decode("utf-8", "replace").strip()


def clean_powershell_error(value: bytes) -> str:
    text = value.decode("utf-8", "replace")
    if not text.startswith("#< CLIXML"):
        return text.strip()

    _, _, xml_text = text.partition("\n")
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return text.strip()

    errors: list[str] = []
    for node in root.iter():
        if node.tag.rsplit("}", 1)[-1] != "S" or node.attrib.get("S") != "Error" or not node.text:
            continue
        message = node.text.replace("_x000D__x000A_", "\n").replace("_x000A_", "\n")
        errors.append(message)
    return "".join(errors).strip()


class WinRMShell:
    def __init__(
        self, protocol: Protocol, shell_id: str, host: str, current_directory: str
    ) -> None:
        self.protocol = protocol
        self.shell_id = shell_id
        self.host = host
        self.current_directory = current_directory
        self.identity = "unknown"
        self.hostname = host
        self._lock = threading.Lock()
        self._stop_keepalive = threading.Event()
        self._keepalive_thread: threading.Thread | None = None
        self._closed = False

    def run(self, script: str) -> CommandResult:
        encoded = base64.b64encode((PS_PROGRESS_SILENCE + script).encode("utf-16-le")).decode(
            "ascii"
        )
        command_id: str | None = None
        with self._lock:
            try:
                command_id = self.protocol.run_command(
                    self.shell_id,
                    "powershell.exe",
                    [
                        "-NoLogo",
                        "-NoProfile",
                        "-NonInteractive",
                        "-EncodedCommand",
                        encoded,
                    ],
                )
                stdout, stderr, status_code = self.protocol.get_command_output(
                    self.shell_id, command_id
                )
            finally:
                if command_id is not None:
                    with suppress(Exception):
                        self.protocol.cleanup_command(self.shell_id, command_id)

        return CommandResult(
            stdout=_decode_output(stdout),
            stderr=clean_powershell_error(stderr),
            status_code=status_code,
        )

    def run_with_input(self, script: str, input_chunks: Iterable[bytes]) -> CommandResult:
        """Run PowerShell and stream ASCII-safe data to its standard input."""

        encoded = base64.b64encode((PS_PROGRESS_SILENCE + script).encode("utf-16-le")).decode(
            "ascii"
        )
        command_id: str | None = None
        with self._lock:
            try:
                command_id = self.protocol.run_command(
                    self.shell_id,
                    "powershell.exe",
                    [
                        "-NoLogo",
                        "-NoProfile",
                        "-NonInteractive",
                        "-EncodedCommand",
                        encoded,
                    ],
                )
                for chunk in input_chunks:
                    self.protocol.send_command_input(self.shell_id, command_id, chunk)
                self.protocol.send_command_input(self.shell_id, command_id, b"", end=True)
                stdout, stderr, status_code = self.protocol.get_command_output(
                    self.shell_id, command_id
                )
            finally:
                if command_id is not None:
                    with suppress(Exception):
                        self.protocol.cleanup_command(self.shell_id, command_id)

        return CommandResult(
            stdout=_decode_output(stdout),
            stderr=clean_powershell_error(stderr),
            status_code=status_code,
        )

    def run_native(self, executable: str, arguments: Sequence[str]) -> CommandResult:
        """Run a remote executable directly with quoted arguments, no cmd.exe."""

        if any(char.isspace() for char in executable):
            raise GoodWinRMError(
                f"Cannot run {executable!r} natively: the executable must live in a "
                "space-free path (stage it in a directory without whitespace)"
            )
        command_id: str | None = None
        with self._lock:
            try:
                command_id = self.protocol.run_command(
                    self.shell_id,
                    executable,
                    [win_quote(argument) for argument in arguments],
                    skip_cmd_shell=True,
                )
                stdout, stderr, status_code = self.protocol.get_command_output(
                    self.shell_id, command_id
                )
            finally:
                if command_id is not None:
                    with suppress(Exception):
                        self.protocol.cleanup_command(self.shell_id, command_id)

        return CommandResult(
            stdout=_decode_output(stdout),
            stderr=_decode_output(stderr),
            status_code=status_code,
        )

    def run_checked(self, script: str, action: str) -> CommandResult:
        result = self.run(script)
        if result.status_code != 0:
            detail = result.stderr or result.stdout or f"exit code {result.status_code}"
            raise GoodWinRMError(f"{action}: {detail}")
        return result

    def initialize(self) -> None:
        identity = self.run("[Security.Principal.WindowsIdentity]::GetCurrent().Name")
        hostname = self.run("[System.Net.Dns]::GetHostName()")
        directory = self.run(
            f"Set-Location -LiteralPath {ps_quote(self.current_directory)} "
            "-ErrorAction Stop;$PWD.Path"
        )
        if identity.status_code == 0 and identity.stdout:
            self.identity = identity.stdout.splitlines()[-1]
        if hostname.status_code == 0 and hostname.stdout:
            self.hostname = hostname.stdout.splitlines()[-1]
        if directory.status_code != 0 or not directory.stdout:
            detail = directory.stderr or directory.stdout or "unknown directory"
            raise GoodWinRMError(f"Invalid initial directory: {detail}")
        self.current_directory = directory.stdout.splitlines()[-1]

    def start_keepalive(self, interval: float = 45.0) -> None:
        if self._keepalive_thread is not None:
            return

        def keepalive() -> None:
            while not self._stop_keepalive.wait(interval):
                try:
                    self.run("[System.Int32]::MinValue | Out-Null")
                except Exception:
                    return

        self._keepalive_thread = threading.Thread(
            target=keepalive, daemon=True, name="goodwinrm-keepalive"
        )
        self._keepalive_thread.start()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._stop_keepalive.set()
        with self._lock, suppress(Exception):
            self.protocol.close_shell(self.shell_id)
        with suppress(Exception):
            self.protocol.transport.close_session()


def _connection_password(args: argparse.Namespace) -> str | None:
    if args.nt_hash:
        if args.transport != "ntlm":
            raise GoodWinRMError("Pass-the-hash requires NTLM transport")
        return normalize_nt_hash(args.nt_hash)
    if args.transport in {"kerberos", "certificate"} or (args.transport == "ssl" and args.cert_pem):
        return None
    if args.password is not None:
        return args.password
    if not sys.stdin.isatty():
        raise GoodWinRMError("Password is required in non-interactive mode")
    return getpass.getpass("Password: ")


def _configure_ccache(value: str | None) -> None:
    if not value:
        return
    cache_path = value.removeprefix("FILE:")
    expanded = Path(cache_path).expanduser()
    if not expanded.is_file():
        raise GoodWinRMError(f"Kerberos ccache not found: {expanded}")
    cache_value = f"FILE:{expanded}" if value.startswith("FILE:") else str(expanded)
    os.environ["KRB5CCNAME"] = cache_value


def open_remote_shell(args: argparse.Namespace) -> WinRMShell:
    client_certificate = args.transport in {"certificate", "ssl"} and args.cert_pem
    if not args.username and args.transport != "kerberos" and not client_certificate:
        raise GoodWinRMError(f"{args.transport} transport requires --username")
    if (args.cert_pem is None) != (args.cert_key_pem is None):
        raise GoodWinRMError("Both --cert-pem and --cert-key-pem are required for certificate auth")
    if args.transport == "certificate" and not args.cert_pem:
        raise GoodWinRMError("Certificate transport requires --cert-pem and --cert-key-pem")
    if args.cert_pem and args.transport not in {"certificate", "ssl"}:
        raise GoodWinRMError("Client certificates require certificate or ssl transport")
    if args.ccache and args.transport != "kerberos":
        raise GoodWinRMError("--ccache requires Kerberos transport")
    if args.transport == "kerberos" and args.password is not None:
        raise GoodWinRMError("Kerberos transport uses a ccache; --password is not supported")
    if args.operation_timeout <= 0 or args.read_timeout <= 0:
        raise GoodWinRMError("Timeouts must be positive")
    if args.read_timeout <= args.operation_timeout:
        raise GoodWinRMError("Read timeout must be greater than operation timeout")
    if args.keepalive_interval < 0:
        raise GoodWinRMError("Keepalive interval cannot be negative")

    _configure_ccache(args.ccache)
    use_https = args.https or args.transport in {"ssl", "certificate"}
    endpoint, host = parse_endpoint(args.ip, args.port, use_https, args.url)
    password = _connection_password(args)

    protocol: Protocol | None = None
    shell_id: str | None = None
    try:
        protocol = Protocol(
            endpoint=endpoint,
            transport=args.transport,
            username=args.username,
            password=password,
            server_cert_validation=args.server_cert_validation,
            cert_pem=args.cert_pem,
            cert_key_pem=args.cert_key_pem,
            kerberos_hostname_override=args.spn_hostname,
            service=args.spn_service,
            operation_timeout_sec=args.operation_timeout,
            read_timeout_sec=args.read_timeout,
        )
        shell_id = protocol.open_shell(codepage=65001, working_directory=args.directory)
        shell = WinRMShell(protocol, shell_id, host, args.directory)
        shell.initialize()
        return shell
    except Exception as exc:
        if protocol is not None and shell_id is not None:
            with suppress(Exception):
                protocol.close_shell(shell_id)
        if protocol is not None:
            with suppress(Exception):
                protocol.transport.close_session()
        message = str(exc)
        if "credentials" in message.lower() or "401" in message:
            raise GoodWinRMError("Authentication denied") from exc
        raise GoodWinRMError(f"Connection failed: {message}") from exc


def _show_progress(transferred: int, total: int) -> None:
    if not sys.stdout.isatty() or total <= 0:
        return
    percent = transferred * 100 / total
    sys.stdout.write(
        f"\r   ⠿ {transferred / 1048576:.2f}/{total / 1048576:.2f} MiB ({percent:.0f}%)"
    )
    sys.stdout.flush()


def upload_file(local_path: str, remote_path: str | None, shell: WinRMShell) -> tuple[str, int]:
    local = Path(local_path).expanduser()
    if not local.is_file():
        raise TransferError(f"Local file not found: {local}")

    destination = resolve_remote_path(remote_path or local.name, shell.current_directory)
    temporary = ntpath.join(ntpath.dirname(destination), f".tmp-{uuid.uuid4().hex[:8]}")
    total = local.stat().st_size
    transferred = 0

    try:

        def encoded_chunks() -> Iterable[bytes]:
            nonlocal transferred
            with local.open("rb") as stream:
                while chunk := stream.read(UPLOAD_CHUNK_SIZE):
                    transferred += len(chunk)
                    _show_progress(transferred, total)
                    yield base64.b64encode(chunk) + b"\n"

        upload_script = (
            f"$s=[IO.File]::Open({ps_quote(temporary)},[IO.FileMode]::Create,"
            "[IO.FileAccess]::Write,[IO.FileShare]::None);try{"
            "while(($line=[Console]::In.ReadLine()) -ne $null){"
            "if($line.Length -eq 0){continue};"
            "$b=[Convert]::FromBase64String($line);$s.Write($b,0,$b.Length)};"
            "$s.Flush()}finally{$s.Dispose()};"
            f"([IO.FileInfo]{ps_quote(temporary)}).Length"
        )
        result = shell.run_with_input(upload_script, encoded_chunks())
        if result.status_code != 0 or result.stderr:
            detail = result.stderr or result.stdout or f"exit code {result.status_code}"
            raise TransferError(f"Upload failed after {transferred} bytes: {detail}")
        try:
            temporary_size = int(result.stdout.splitlines()[-1])
        except (IndexError, ValueError) as exc:
            raise TransferError("Cannot verify temporary uploaded file size") from exc
        if temporary_size != total:
            raise TransferError(f"Upload size mismatch: local={total}, remote={temporary_size}")

        commit = (
            f"$src={ps_quote(temporary)};$dst={ps_quote(destination)};"
            "Move-Item -LiteralPath $src -Destination $dst -Force -ErrorAction Stop;"
            "([IO.FileInfo]$dst).Length"
        )
        result = shell.run(commit)
        if result.status_code != 0 or result.stderr:
            detail = result.stderr or result.stdout or f"exit code {result.status_code}"
            raise TransferError(f"Cannot finalize upload: {detail}")
        try:
            remote_size = int(result.stdout.splitlines()[-1])
        except (IndexError, ValueError) as exc:
            raise TransferError("Cannot verify uploaded file size") from exc
        if remote_size != total:
            raise TransferError(f"Upload size mismatch: local={total}, remote={remote_size}")
    except BaseException:
        with suppress(Exception):
            shell.run(
                f"Remove-Item -LiteralPath {ps_quote(temporary)} -Force "
                "-ErrorAction SilentlyContinue"
            )
        raise
    finally:
        if sys.stdout.isatty() and total > 0:
            sys.stdout.write("\n")

    return destination, total


def _local_download_target(remote_path: str, local_path: str | None) -> Path:
    remote_name = ntpath.basename(remote_path.rstrip("\\/"))
    if not remote_name:
        raise TransferError("Cannot infer a local filename from the remote path")
    target = Path(local_path).expanduser() if local_path else Path(remote_name)
    if target.is_dir():
        target /= remote_name
    return target


def download_file(remote_path: str, local_path: str | None, shell: WinRMShell) -> tuple[Path, int]:
    source = resolve_remote_path(remote_path, shell.current_directory)
    target = _local_download_target(source, local_path)
    target.parent.mkdir(parents=True, exist_ok=True)

    size_result = shell.run(
        f"$p={ps_quote(source)};if(-not [IO.File]::Exists($p)){{throw 'Remote file not found'}};"
        "([IO.FileInfo]$p).Length"
    )
    if size_result.status_code != 0 or size_result.stderr:
        detail = size_result.stderr or size_result.stdout or "remote file not found"
        raise TransferError(f"Cannot download {source}: {detail}")
    try:
        total = int(size_result.stdout.splitlines()[-1])
    except (IndexError, ValueError) as exc:
        raise TransferError("Cannot determine remote file size") from exc

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".part", dir=target.parent
    )
    temporary = Path(temporary_name)
    transferred = 0
    try:
        with os.fdopen(descriptor, "wb") as stream:
            download_script = (
                f"$s=[IO.File]::OpenRead({ps_quote(source)});try{{"
                f"$b=New-Object byte[] {DOWNLOAD_CHUNK_SIZE};"
                "while(($n=$s.Read($b,0,$b.Length)) -gt 0){"
                "[Console]::Out.WriteLine([Convert]::ToBase64String($b,0,$n))}"
                "}finally{$s.Dispose()}"
            )
            result = shell.run(download_script)
            if result.status_code != 0 or result.stderr:
                detail = result.stderr or result.stdout or f"exit code {result.status_code}"
                raise TransferError(f"Download failed: {detail}")

            for encoded_chunk in result.stdout.splitlines():
                try:
                    chunk = base64.b64decode(encoded_chunk, validate=True)
                except (binascii.Error, ValueError) as exc:
                    raise TransferError("Remote host returned invalid base64 data") from exc
                if not chunk:
                    raise TransferError("Remote host returned an empty transfer chunk")
                stream.write(chunk)
                transferred += len(chunk)
                _show_progress(transferred, total)

        if transferred != total:
            raise TransferError(f"Download size mismatch: expected={total}, received={transferred}")
        os.replace(temporary, target)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    finally:
        if sys.stdout.isatty() and total > 0:
            sys.stdout.write("\n")

    return target, total


def change_directory(shell: WinRMShell, path: str) -> str:
    result = shell.run(
        f"Set-Location -LiteralPath {ps_quote(shell.current_directory)} -ErrorAction Stop;"
        f"Set-Location -LiteralPath {ps_quote(path)} -ErrorAction Stop;$PWD.Path"
    )
    if result.status_code != 0 or not result.stdout:
        detail = result.stderr or result.stdout or "path does not exist"
        raise GoodWinRMError(f"Cannot cd to {path!r}: {detail}")
    shell.current_directory = result.stdout.splitlines()[-1]
    return shell.current_directory


def list_directory(shell: WinRMShell, pattern: str | None = None) -> str:
    command = (
        f"Set-Location -LiteralPath {ps_quote(shell.current_directory)} -ErrorAction Stop;"
        "Get-ChildItem -Force"
    )
    if pattern:
        command += f" -Path {ps_quote(pattern)}"
    command += " | Format-Table -AutoSize | Out-String -Width 4096"
    result = shell.run(command)
    if result.status_code != 0:
        detail = result.stderr or result.stdout or f"exit code {result.status_code}"
        raise GoodWinRMError(f"Cannot list directory: {detail}")
    return result.stdout


def win_quote(value: str) -> str:
    quoted = ['"']
    backslashes = 0
    for char in value:
        if char == "\\":
            backslashes += 1
            continue
        if char == '"':
            quoted.append("\\" * (backslashes * 2 + 1) + '"')
        else:
            quoted.append("\\" * backslashes + char)
        backslashes = 0
    quoted.append("\\" * (backslashes * 2) + '"')
    return "".join(quoted)


def resolve_executable(executable: str, current_directory: str) -> str:
    if ntpath.isabs(executable) or "/" in executable or "\\" in executable:
        return resolve_remote_path(executable, current_directory)
    return executable


def build_process_command_line(
    executable: str,
    arguments: Sequence[str],
    stdout_path: str | None = None,
    stderr_path: str | None = None,
) -> str:
    command_line = " ".join([win_quote(executable), *(win_quote(arg) for arg in arguments)])
    if stdout_path is None and stderr_path is None:
        return command_line
    command_line = 'cmd /c "' + command_line
    if stdout_path is not None:
        command_line += f" > {win_quote(stdout_path)}"
    if stderr_path is not None:
        command_line += f" 2> {win_quote(stderr_path)}"
    return command_line + '"'


def build_wmi_spawn_script(command_line: str, current_directory: str) -> str:
    return (
        "$r=Invoke-CimMethod -ClassName Win32_Process -MethodName Create "
        f"-Arguments @{{CommandLine={ps_quote(command_line)};"
        f"CurrentDirectory={ps_quote(current_directory)}}};"
        'if($r.ReturnValue -ne 0){throw "Win32_Process.Create failed: '
        '$($r.ReturnValue)"};$r.ProcessId'
    )


def build_schtasks_spawn_script(command_line: str, task_name: str) -> str:
    task_action = command_line.replace('"', '\\"')
    return (
        f"$n={ps_quote(task_name)};$a={ps_quote(task_action)};"
        "schtasks /f /create /ru SYSTEM /rl HIGHEST /tn $n /tr $a /sc once /st 00:00"
        " 2>$null|Out-Null;"
        'if($LASTEXITCODE -ne 0){throw "schtasks /create failed: $($LASTEXITCODE)"};'
        "schtasks /run /tn $n 2>$null|Out-Null;"
        'if($LASTEXITCODE -ne 0){throw "schtasks /run failed: $($LASTEXITCODE)"};'
        "Start-Sleep -Seconds 2;$lr=$null;"
        "try{$s=New-Object -ComObject Schedule.Service;$s.Connect();"
        "$lr=[int]$s.GetFolder('\\').GetTask($n).LastTaskResult}catch{};"
        "schtasks /delete /f /tn $n 2>$null|Out-Null;"
        "if($null -eq $lr){throw 'cannot read scheduled task last result'};"
        'if($lr -ne 0 -and $lr -ne 267009){throw "scheduled task did not start '
        '(last result $($lr))"};'
        'if($LASTEXITCODE -ne 0){throw "schtasks /delete failed: $($LASTEXITCODE)"}'
    )


def parse_spawn_request(tokens: Sequence[str]) -> SpawnRequest:
    stdout_path: str | None = None
    stderr_path: str | None = None
    launcher = "auto"
    stage_dir: str | None = None
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "--schtasks":
            launcher = "schtasks"
            index += 1
            continue
        if token == "--launcher":
            if index + 1 >= len(tokens) or tokens[index + 1] not in LAUNCHERS:
                raise GoodWinRMError(SPAWN_USAGE)
            launcher = tokens[index + 1]
            index += 2
            continue
        if token == "--stage-dir":
            if index + 1 >= len(tokens):
                raise GoodWinRMError(SPAWN_USAGE)
            stage_dir = tokens[index + 1]
            index += 2
            continue
        if token in {"--stdout", "--stderr"}:
            if index + 1 >= len(tokens):
                raise GoodWinRMError(SPAWN_USAGE)
            if token == "--stdout":
                stdout_path = tokens[index + 1]
            else:
                stderr_path = tokens[index + 1]
            index += 2
            continue
        break
    if index >= len(tokens):
        raise GoodWinRMError(SPAWN_USAGE)
    return SpawnRequest(
        executable=tokens[index],
        arguments=tuple(tokens[index + 1 :]),
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        use_schtasks=launcher == "schtasks",
        launcher=launcher,
        stage_dir=stage_dir,
    )


def execute_foreground(
    shell: WinRMShell, executable: str, arguments: Sequence[str]
) -> CommandResult:
    arguments_script = " ".join(ps_quote(arg) for arg in arguments)
    if ntpath.isabs(executable) or "/" in executable or "\\" in executable:
        target = resolve_executable(executable, shell.current_directory)
        invocation = f"& {ps_quote(target)} {arguments_script}"
    else:
        invocation = (
            f"$e=Resolve-Path -LiteralPath {ps_quote(executable)} -ErrorAction SilentlyContinue;"
            f"& $(if($e){{$e.Path}}else{{{ps_quote(executable)}}}) {arguments_script}"
        )
    return shell.run(
        f"Set-Location -LiteralPath {ps_quote(shell.current_directory)} -ErrorAction Stop;"
        f"{invocation};if($null -ne $LASTEXITCODE){{exit $LASTEXITCODE}}else{{exit 1}}"
    )


def spawn_wmi(shell: WinRMShell, request: SpawnRequest) -> int:
    target = resolve_executable(request.executable, shell.current_directory)
    command_line = build_process_command_line(
        target, request.arguments, request.stdout_path, request.stderr_path
    )
    result = shell.run(build_wmi_spawn_script(command_line, shell.current_directory))
    if result.status_code != 0 or result.stderr:
        detail = result.stderr or result.stdout or f"exit code {result.status_code}"
        raise GoodWinRMError(f"Cannot spawn {request.executable}: {detail}")
    try:
        return int(result.stdout.splitlines()[-1])
    except (IndexError, ValueError) as exc:
        raise GoodWinRMError("Cannot determine spawned process id") from exc


def spawn_scheduled(shell: WinRMShell, request: SpawnRequest) -> str:
    target = resolve_executable(request.executable, shell.current_directory)
    command_line = build_process_command_line(
        target, request.arguments, request.stdout_path, request.stderr_path
    )
    task_name = uuid.uuid4().hex[:12]
    result = shell.run(build_schtasks_spawn_script(command_line, task_name))
    if result.status_code != 0:
        detail = result.stderr or result.stdout or f"exit code {result.status_code}"
        raise GoodWinRMError(f"Cannot spawn {request.executable}: {detail}")
    return task_name


def parse_helper_output(stdout: str) -> int:
    for line in reversed(stdout.splitlines()):
        stripped = line.strip()
        if stripped.startswith("PID "):
            value = stripped.removeprefix("PID ").strip()
            if value.isdigit():
                return int(value)
            break
        if stripped.startswith("ERR "):
            raise GoodWinRMError(f"launcher helper failed with code {stripped[4:].strip()}")
    raise GoodWinRMError("Cannot determine spawned process id")


def _select_helper_blob(shell: WinRMShell) -> str | None:
    result = shell.run("$env:PROCESSOR_ARCHITECTURE")
    if result.status_code != 0 or not result.stdout:
        return None
    architecture = result.stdout.splitlines()[-1].strip().upper()
    if architecture == "AMD64":
        return GWSPAWN_X64_B64
    if architecture == "X86":
        return GWSPAWN_X86_B64
    return None


def _stage_helper(blob: str, stage_dir: str, shell: WinRMShell) -> str:
    remote_helper = ntpath.join(stage_dir, f".{uuid.uuid4().hex[:8]}.exe")
    descriptor, temporary_name = tempfile.mkstemp(suffix=".exe")
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(base64.b64decode(blob))
        upload_file(temporary_name, remote_helper, shell)
    finally:
        temporary.unlink(missing_ok=True)
    return remote_helper


def _resolve_stage_dir(request: SpawnRequest, shell: WinRMShell) -> str:
    if request.stage_dir is not None:
        stage_dir = resolve_remote_path(request.stage_dir, shell.current_directory)
    else:
        stage_dir = DEFAULT_STAGE_DIR
    if any(char.isspace() for char in stage_dir):
        raise GoodWinRMError(
            f"Cannot stage the native launcher helper in {stage_dir!r}: the staging "
            "directory must not contain whitespace"
        )
    return stage_dir


def spawn_native(shell: WinRMShell, request: SpawnRequest, launcher: str, blob: str | None) -> int:
    if blob is None:
        raise GoodWinRMError(
            f"Cannot spawn {request.executable}: {launcher} helper is unavailable "
            "for this target architecture"
        )
    target = resolve_executable(request.executable, shell.current_directory)
    helper_remote = _stage_helper(blob, _resolve_stage_dir(request, shell), shell)
    try:
        result = shell.run_native(
            helper_remote, [HELPER_MODES[launcher], target, *request.arguments]
        )
        if result.status_code != 0 or result.stderr:
            detail = result.stderr or result.stdout or f"exit code {result.status_code}"
            raise GoodWinRMError(f"Cannot spawn {request.executable} via {launcher}: {detail}")
        return parse_helper_output(result.stdout)
    finally:
        with suppress(Exception):
            shell.run(
                f"Remove-Item -LiteralPath {ps_quote(helper_remote)} -Force "
                "-ErrorAction SilentlyContinue"
            )


def launch_spawn(shell: WinRMShell, request: SpawnRequest) -> None:
    launcher = request.launcher
    if launcher in HELPER_MODES and (request.stdout_path or request.stderr_path):
        print_info(f"{launcher} does not support output redirection; using wmi-ps")
        launcher = "wmi-ps"
    if launcher == "auto":
        blob = None if (request.stdout_path or request.stderr_path) else _select_helper_blob(shell)
        attempts = ["breakaway", "wmi-native", "wmi-ps"] if blob is not None else ["wmi-ps"]
        failures: list[str] = []
        for candidate in attempts:
            try:
                if candidate in HELPER_MODES:
                    pid = spawn_native(shell, request, candidate, blob)
                else:
                    pid = spawn_wmi(shell, request)
            except GoodWinRMError as exc:
                failures.append(f"{candidate}: {exc}")
                continue
            print_success(f"Spawned {request.executable} with PID {pid} via {candidate}")
            return
        raise GoodWinRMError(f"No spawn launcher succeeded ({'; '.join(failures)})")
    if launcher == "schtasks":
        task_name = spawn_scheduled(shell, request)
        print_success(f"Spawned {request.executable} via scheduled task {task_name}")
        return
    if launcher == "wmi-ps":
        pid = spawn_wmi(shell, request)
        print_success(f"Spawned {request.executable} with PID {pid} via wmi-ps")
        return
    pid = spawn_native(shell, request, launcher, _select_helper_blob(shell))
    print_success(f"Spawned {request.executable} with PID {pid} via {launcher}")


def _builtin_help() -> None:
    print(
        "Commands:\n"
        "  pwd                      Show remote working directory\n"
        "  cd [PATH]                Change directory (home when omitted)\n"
        "  ls [PATTERN]             List files\n"
        "  upload LOCAL [REMOTE]    Upload a file\n"
        "  download REMOTE [LOCAL]  Download a file\n"
        "  runps LOCAL.ps1 [ARGS...]  Run a local PowerShell script remotely\n"
        "  script | paste           Multi-line mode (paste, end with a line '.')\n"
        "  run EXE [ARGS...]        Execute a remote binary and report its exit code\n"
        "  exec EXE [ARGS...]       Alias for run\n"
        "  spawn [OPTIONS] EXE [ARGS...]\n"
        "                           Launch a detached process that survives disconnect\n"
        "    --launcher MODE        auto (default), breakaway, wmi-native, wmi-ps, schtasks\n"
        "    --stage-dir DIR        Remote directory for the native launcher helper\n"
        "    --stdout PATH          Redirect spawned stdout to a remote file\n"
        "    --stderr PATH          Redirect spawned stderr to a remote file\n"
        "    --schtasks             Alias for --launcher schtasks\n"
        "    (breakaway/wmi-native do not redirect output; wmi-ps is used instead)\n"
        "  clear | cls              Clear the terminal\n"
        "  exit                     Close the session\n"
        "Any other input is executed as PowerShell in the current directory."
    )


SCRIPT_USAGE = "Usage: runps <local .ps1> [arguments...]"


def execute_script_block(
    shell: WinRMShell, script_text: str, arguments: Sequence[str] = ()
) -> CommandResult:
    """Run an arbitrary (possibly multi-line) PowerShell script remotely.

    The script is wrapped in a script block so a top-level ``param(...)`` is
    valid, and it is executed as an encoded command rather than a ``.ps1`` file
    so a restrictive ExecutionPolicy (e.g. AllSigned) does not block it.
    """

    invocation = "& {\n" + script_text.rstrip("\n") + "\n}"
    if arguments:
        invocation += " " + " ".join(ps_quote(argument) for argument in arguments)
    return shell.run(invocation)


def print_command_result(result: CommandResult) -> None:
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print_error(result.stderr)
    elif result.status_code != 0:
        print_error(f"PowerShell exited with code {result.status_code}")


def read_multiline_script(session: PromptSession[str]) -> list[str]:
    print_info("Multi-line mode: paste the script, end with a line containing only '.'")
    lines: list[str] = []
    while True:
        try:
            line = session.prompt("... ")
        except KeyboardInterrupt:
            print()
            return []
        except EOFError:
            print()
            break
        if line.strip() == ".":
            break
        lines.append(line)
    return lines


def dispatch_command(command: str, shell: WinRMShell) -> bool:
    stripped = command.strip()
    if not stripped:
        return True

    verb, _, raw_args = stripped.partition(" ")
    verb = verb.lower()
    raw_args = raw_args.strip()

    if verb == "exit" and not raw_args:
        return False
    if verb in {"clear", "cls"} and not raw_args:
        print("\033[H\033[J", end="")
        return True
    if verb in {"help", "menu"} and not raw_args:
        _builtin_help()
        return True
    if verb == "pwd" and not raw_args:
        print(shell.current_directory)
        return True
    if verb == "cd":
        if raw_args:
            values = split_shell_args(raw_args)
            if len(values) != 1:
                raise GoodWinRMError("Usage: cd <remote path>")
            destination = values[0]
        else:
            result = shell.run("[Environment]::GetFolderPath('UserProfile')")
            if result.status_code != 0 or not result.stdout:
                raise GoodWinRMError("Cannot determine remote home directory")
            destination = result.stdout.splitlines()[-1]
        change_directory(shell, destination)
        return True
    if verb == "ls":
        values = split_shell_args(raw_args) if raw_args else []
        if len(values) > 1:
            raise GoodWinRMError("Usage: ls [pattern]")
        output = list_directory(shell, values[0] if values else None)
        if output:
            print(output)
        return True
    if verb == "upload":
        values = split_shell_args(raw_args)
        if not 1 <= len(values) <= 2:
            raise GoodWinRMError("Usage: upload <local path> [remote path]")
        destination, size = upload_file(values[0], values[1] if len(values) == 2 else None, shell)
        print_success(f"Uploaded {values[0]} -> {destination} ({size} bytes)")
        return True
    if verb == "download":
        values = split_shell_args(raw_args)
        if not 1 <= len(values) <= 2:
            raise GoodWinRMError("Usage: download <remote path> [local path]")
        local_destination, size = download_file(
            values[0], values[1] if len(values) == 2 else None, shell
        )
        print_success(f"Downloaded {values[0]} -> {local_destination} ({size} bytes)")
        return True

    if verb in {"runps", "runscript"}:
        values = split_shell_args(raw_args)
        if not values:
            raise GoodWinRMError(SCRIPT_USAGE)
        try:
            script_text = Path(values[0]).read_text(encoding="utf-8-sig")
        except OSError as exc:
            raise GoodWinRMError(f"Cannot read {values[0]}: {exc}") from exc
        print_command_result(execute_script_block(shell, script_text, values[1:]))
        return True
    if verb in {"run", "exec"}:
        values = split_shell_args(raw_args)
        if not values:
            raise GoodWinRMError("Usage: run <remote executable> [arguments...]")
        result = execute_foreground(shell, values[0], values[1:])
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print_error(result.stderr)
        if result.status_code != 0:
            print_error(f"{values[0]} exited with code {result.status_code}")
        return True
    if verb == "spawn":
        if not raw_args:
            raise GoodWinRMError(SPAWN_USAGE)
        request = parse_spawn_request(split_shell_args(raw_args))
        launch_spawn(shell, request)
        return True

    result = shell.run(
        f"Set-Location -LiteralPath {ps_quote(shell.current_directory)} "
        f"-ErrorAction Stop;{stripped}"
    )
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print_error(result.stderr)
    elif result.status_code != 0:
        print_error(f"PowerShell exited with code {result.status_code}")
    return True


def _history(shell: WinRMShell, username: str | None) -> FileHistory:
    directory = Path.home() / ".goodwinrm" / "history"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{shell.host}_{username or 'default'}")
    return FileHistory(str(directory / f"{safe_name}.history"))


def interactive_loop(shell: WinRMShell, username: str | None, history_enabled: bool = True) -> None:
    completions = [
        "exit",
        "clear",
        "cls",
        "help",
        "menu",
        "pwd",
        "ls",
        "cd",
        "upload",
        "download",
        "run",
        "exec",
        "runps",
        "runscript",
        "script",
        "paste",
        "spawn",
        "whoami",
        "hostname",
        "ipconfig",
        "Get-Process",
        "Get-Service",
    ]
    history = _history(shell, username) if history_enabled else None
    session: PromptSession[str] = PromptSession(history=history)
    completer = WordCompleter(completions, ignore_case=True)

    while True:
        prompt = (
            f"\x1b[34m{shell.identity}\x1b[0m@\x1b[34m{shell.hostname}\x1b[0m "
            f"\x1b[33m{shell.current_directory}\x1b[0m > "
        )
        try:
            command = session.prompt(
                ANSI(prompt)
                if USE_COLOR
                else f"{shell.identity}@{shell.hostname} {shell.current_directory} > ",
                completer=completer,
            )
            if command.strip().lower() in {"script", "paste", "multiline"}:
                lines = read_multiline_script(session)
                if lines:
                    print_command_result(execute_script_block(shell, "\n".join(lines)))
                continue
            if not dispatch_command(command, shell):
                return
        except KeyboardInterrupt:
            print()
        except EOFError:
            return
        except GoodWinRMError as exc:
            print_error(str(exc))


def main(argv: Sequence[str] | None = None) -> int:
    global USE_COLOR

    args = parse_args(argv)
    USE_COLOR = not args.no_color
    banner()
    shell: WinRMShell | None = None
    try:
        shell = open_remote_shell(args)
        print_success(f"Authenticated to {shell.host} as {shell.identity}")
        if not args.no_keepalive and args.keepalive_interval > 0:
            shell.start_keepalive(interval=args.keepalive_interval)
        interactive_loop(shell, args.username, history_enabled=not args.no_history)
    except GoodWinRMError as exc:
        print_error(str(exc))
        return 1
    finally:
        if shell is not None:
            shell.close()
    print_info("Session closed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
