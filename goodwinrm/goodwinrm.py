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

VERSION = "0.2.0"
UPLOAD_CHUNK_SIZE = 48 * 1024
DOWNLOAD_CHUNK_SIZE = 48 * 1024
ZERO_LM_HASH = "0" * 32
NT_HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$")
LM_NT_HASH_RE = re.compile(r"^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$")
TRANSPORTS = ("ntlm", "kerberos", "credssp", "basic", "plaintext", "ssl", "certificate")

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
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
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

        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
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
    temporary = f"{destination}.goodwinrm-{uuid.uuid4().hex}.tmp"
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
        prefix=f".{target.name}.goodwinrm-", dir=target.parent
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


def _builtin_help() -> None:
    print(
        "Commands:\n"
        "  pwd                      Show remote working directory\n"
        "  cd [PATH]                Change directory (home when omitted)\n"
        "  ls [PATTERN]             List files\n"
        "  upload LOCAL [REMOTE]    Upload a file\n"
        "  download REMOTE [LOCAL]  Download a file\n"
        "  clear | cls              Clear the terminal\n"
        "  exit                     Close the session\n"
        "Any other input is executed as PowerShell in the current directory."
    )


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
        shell.start_keepalive()
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
