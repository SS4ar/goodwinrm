from __future__ import annotations

import argparse
import base64
import ntpath
import os
import re
import shlex
import sys
import tempfile
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from collections.abc import Iterable, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from prompt_toolkit import print_formatted_text as printf, HTML, ANSI, PromptSession
from prompt_toolkit.completion import WordCompleter
from winrm.protocol import Protocol

from ._gwspawn import GWSPAWN_X64_B64, GWSPAWN_X86_B64

# Must keep the resulting `powershell -enc <b64>` command line under the
# cmd.exe 8191-char limit: 8192-byte chunks blow past it and fail on >~2.2KB files.
B64_CHUNK = 2048

PS_PROGRESS_SILENCE = "$ProgressPreference='SilentlyContinue';"
SPAWN_USAGE = (
    "Usage: spawn [--launcher auto|breakaway|wmi-native|wmi-ps|schtasks] [--stage-dir DIR] "
    "[--stdout PATH] [--stderr PATH] <remote executable> [arguments...]"
)
SCRIPT_USAGE = "Usage: runps <local .ps1> [arguments...]"
LAUNCHERS = ("auto", "breakaway", "wmi-native", "wmi-ps", "schtasks")
HELPER_MODES = {"breakaway": "breakaway", "wmi-native": "wmi"}
DEFAULT_STAGE_DIR = "C:\\Windows\\Temp"


class GoodWinRMError(Exception):
    """Base exception for user-facing Good WinRM failures."""


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


def print_error(msg):
    printf(ANSI("\x1b[31m✖ %s\x1b[0m" % msg))


def print_success(msg):
    printf(ANSI("\x1b[32m✔ %s\x1b[0m" % msg))


def print_info(msg):
    printf(ANSI("\x1b[36m⠿ %s\x1b[0m" % msg))


def normalize_ccache_hostname(spn_host):
    """krb5 lowercases the hostname part of the SPN before looking it up in the
    ccache, and the lookup is case-sensitive. Rewrite any case variant of the
    hostname inside the ccache file so the ticket always matches. Case-only
    replacement keeps the byte length, so the length-prefixed ccache stays valid."""
    ccache = os.environ.get("KRB5CCNAME", "")
    if not ccache or not spn_host:
        return
    if ccache.upper().startswith("FILE:"):
        ccache = ccache[5:]
    if "://" in ccache or ccache.upper().startswith("DIR:"):
        return
    path = os.path.expanduser(ccache)
    if not os.path.isfile(path):
        return
    try:
        with open(path, "rb") as f:
            data = f.read()
        pattern = re.compile(re.escape(spn_host.encode()), re.IGNORECASE)
        fixed = pattern.sub(spn_host.lower().encode(), data)
        if fixed != data:
            with open(path, "wb") as f:
                f.write(fixed)
            print_info("Normalized SPN host case in %s -> %s" % (path, spn_host.lower()))
    except OSError:
        pass


def banner():
    printf(HTML("""
> <ansigreen>┏┓     ┓┓ ┏•  ┳┓ ┳┳┓</ansigreen>  <b>GoodWinRM - v0.2</b>
> <ansigreen>┃┓┏┓┏┓┏┫┃┃┃┓┏┓┣┻┓┃┃┃</ansigreen>  Python WinRM Interactive Shell
> <ansigreen>┗┛┗┛┗┛┗┻┗┻┛┗┛┗┛ ┗┛ ┗</ansigreen>  <ansiblue>https://github.com/h3x0c4t/goodwinrm</ansiblue>
    """))


def parse_args():
    parser = argparse.ArgumentParser(
        description="WinRM Interactive Shell with file transfer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Password:
    goodwinrm -i 10.10.30.10 -u 'DOMAIN\\Administrator' -p 'Pass123' -t ntlm

  Pass-The-Hash:
    goodwinrm -i 10.10.30.10 -u 'Administrator' --nt-hash 'A87E1E9015421162B6D958BBF7453C8D' -t ntlm

  Kerberos:
    export KRB5CCNAME=/tmp/admin.ccache
    goodwinrm -i dc.domain.local -u 'admin@DOMAIN.LOCAL' -t kerberos

Shell commands:
  upload LOCAL REMOTE    Upload file (base64 chunked)
  download REMOTE LOCAL  Download file (base64 chunked)
  ls [pattern]           List files
  cd <path>              Change directory
  pwd                    Print working directory
  run/exec EXE [ARGS...] Execute a remote binary, report its exit code
  spawn [--launcher auto|breakaway|wmi-native|wmi-ps|schtasks]
        [--stage-dir DIR] [--stdout PATH] [--stderr PATH] EXE [ARGS...]
                         Launch a detached process that survives disconnect
  runps LOCAL.ps1 [ARGS...]
                         Run a local PowerShell script remotely (single
                         encoded command, no .ps1 written on the target)
  script | paste         Multi-line mode: paste a script, end with a
                         line containing only '.'
  exit                   Close session
  clear                  Clear terminal
        """)
    parser.add_argument("-i", "--ip", required=True, help="Target host")
    parser.add_argument("-u", "--username", required=True, help="Username")
    parser.add_argument("-p", "--password", default="", help="Password")
    parser.add_argument("--nt-hash", default=None, help="NT hash for Pass-The-Hash")
    parser.add_argument("-t", "--transport", default="ntlm",
                        choices=["basic", "ntlm", "kerberos", "credssp", "ssl", "certificate"])
    parser.add_argument("-v", "--server_cert_validation", default="ignore",
                        choices=["ignore", "validate"])
    parser.add_argument("-d", "--directory", default="C:\\", help="Working directory")
    parser.add_argument("--https", action="store_true", help="Use HTTPS")
    parser.add_argument("--port", type=int, default=0, help="Custom port")
    parser.add_argument("--krb-hostname", default=None,
                        help="Kerberos SPN hostname override (for tunnels/jump hosts). "
                             "E.g. host reached at 127.0.0.1 but ticket is for exchange.naliway.local")
    parser.add_argument("--krb-service", default=None,
                        help="Kerberos SPN service (default: HTTP). "
                             "Match the service and case shown by klist, e.g. HOST or WSMAN")
    return parser.parse_args()


def parse_endpoint(addr, port, https):
    parts = addr.strip().split(":")
    host = parts[0]
    if len(parts) == 2 and parts[1].isdigit():
        port = int(parts[1])
    port = port or (5986 if https else 5985)
    return "%s://%s:%d/wsman" % ("https" if https else "http", host, port), host


def open_session(args):
    endpoint, host = parse_endpoint(args.ip, args.port, args.https)
    password = args.password

    if args.nt_hash and args.transport == "ntlm":
        nt = args.nt_hash.strip().upper()
        if ":" not in nt:
            nt = ":%s" % nt
        password = nt
        print_info("NTLM Pass-The-Hash (NT: %s)" % nt.split(":", 1)[-1])
    elif args.nt_hash:
        print_error("--nt-hash requires --transport ntlm")
        sys.exit(1)

    if args.transport == "kerberos":
        ccache = os.environ.get("KRB5CCNAME", "")
        if ccache:
            print_info("Kerberos ccache: %s" % ccache)
        else:
            print_info("Kerberos auth — no KRB5CCNAME set, using default")
        password = ""
        if args.username and "@" in args.username:
            user, _, realm = args.username.partition("@")
            args.username = "%s@%s" % (user, realm.upper())
        normalize_ccache_hostname(args.krb_hostname or host)

    kwargs = {}
    if args.krb_hostname:
        kwargs["kerberos_hostname_override"] = args.krb_hostname
    if args.krb_service:
        kwargs["service"] = args.krb_service

    try:
        proto = Protocol(
            endpoint=endpoint,
            transport=args.transport,
            username=args.username,
            password=password,
            server_cert_validation=args.server_cert_validation,
            message_encryption="auto",
            **kwargs,
        )
        shell_id = proto.open_shell(codepage=65001, working_directory=args.directory)
        print_success("Authenticated to %s" % host)
        print()
        return proto, shell_id, host
    except Exception as e:
        err = str(e)
        if "invalid credentials" in err.lower() or "401" in err:
            print_error("Authentication denied")
        else:
            print_error("Connection failed: %s" % err)
        if args.transport == "kerberos" and "matching credential not found" in err.lower():
            print_info("Requested Kerberos service: %s/%s. Check klist; "
                       "use --krb-service to match the ticket's service and case "
                       "(e.g. HOST or WSMAN), and --krb-hostname if the hostname differs."
                       % (args.krb_service or "HTTP", args.krb_hostname or host))
        sys.exit(1)


def run_cmd(cmd, proto, shell_id):
    full = PS_PROGRESS_SILENCE + cmd
    b64 = base64.b64encode(full.encode("utf-16-le")).decode("ascii")
    cid = proto.run_command(shell_id, "powershell -enc %s" % b64)
    stdout, stderr, rc = proto.get_command_output(shell_id, cid)
    proto.cleanup_command(shell_id, cid)
    return stdout, stderr, rc


def cmd_out(cmd, proto, shell_id):
    stdout, _, rc = run_cmd(cmd, proto, shell_id)
    return stdout.decode("utf-8", "replace").strip(), rc


def upload(local_path, remote_path, proto, shell_id):
    if not os.path.isfile(local_path):
        print_error("File not found: %s" % local_path)
        return

    with open(local_path, "rb") as f:
        raw = f.read()

    if not raw:
        print_success("Uploaded (empty): %s -> %s" % (local_path, remote_path))
        return

    total = len(raw)
    remote_safe = remote_path.replace('"', '""')
    chunks = []
    for i in range(0, total, B64_CHUNK):
        chunks.append(base64.b64encode(raw[i:i + B64_CHUNK]).decode("ascii"))

    for idx, b64chunk in enumerate(chunks):
        if idx == 0:
            ps = ('$bt=[Convert]::FromBase64String("%s"); '
                  '[System.IO.File]::WriteAllBytes("%s",$bt)' % (b64chunk, remote_safe))
        else:
            # System.IO.File has no AppendAllBytes; use FileStream in Append mode
            ps = ('$bt=[Convert]::FromBase64String("%s"); '
                  '$fs=[System.IO.File]::Open("%s",[System.IO.FileMode]::Append); '
                  '$fs.Write($bt,0,$bt.Length); $fs.Close()' % (b64chunk, remote_safe))

        _, rc = cmd_out(ps, proto, shell_id)
        if rc != 0:
            print_error("Upload error at chunk %d/%d" % (idx + 1, len(chunks)))
            return

        progress = min((idx + 1) * B64_CHUNK, total)
        pct = progress * 100.0 / total
        sys.stdout.write("\r   \u283f %d/%d MB (%.0f%%)" % (progress / 1048576, total / 1048576, pct))
        sys.stdout.flush()

    sys.stdout.write("\n")
    print_success("Uploaded %s -> %s (%.2f MB, %d chunks)" %
                  (local_path, remote_path, total / 1048576, len(chunks)))


def download(remote_path, local_path, proto, shell_id):
    remote_safe = remote_path.replace('"', '""')

    result, _ = cmd_out('Test-Path "%s"' % remote_safe, proto, shell_id)
    if result != "True":
        print_error("Remote file not found: %s" % remote_path)
        return

    read_ps = ('$bytes=[System.IO.File]::ReadAllBytes("%s"); '
               '[Convert]::ToBase64String($bytes)' % remote_safe)
    b64_data, rc = cmd_out(read_ps, proto, shell_id)

    if rc != 0 or not b64_data:
        print_error("Failed to read file: %s" % remote_path)
        return

    raw = base64.b64decode(b64_data)
    parent = os.path.dirname(local_path)
    if parent:
        os.makedirs(parent, exist_ok=True)

    with open(local_path, "wb") as f:
        f.write(raw)

    print_success("Downloaded %s -> %s (%.2f MB)" % (remote_path, local_path, len(raw) / 1048576))


def shell_ls(pattern, proto, shell_id, cdir):
    safe = cdir.replace('"', '""')
    if pattern:
        ps = ('Set-Location "%s"; Get-ChildItem -Force "%s" |'
              ' Format-Table -AutoSize | Out-String -Width 4096'
              % (safe, pattern.replace('"', '')))
    else:
        ps = ('Set-Location "%s"; Get-ChildItem -Force |'
              ' Format-Table -AutoSize | Out-String -Width 4096'
              % safe)
    out, _ = cmd_out(ps, proto, shell_id)
    if out:
        print(out.rstrip())


def shell_cd(path, proto, shell_id, cdir):
    if path == ".":
        return cdir
    safe = path.replace('"', '""')
    cdir_safe = cdir.replace('"', '""')
    # Два Set-Location — первый из cdir, второй к цели. Работает для всех типов путей.
    # $PWD.Path — сам $PWD форматируется как таблица (PathInfo object)
    ps = '3>$null; Set-Location "%s" -EA Stop; Set-Location "%s" -EA Stop; $PWD.Path' % (cdir_safe, safe)
    out, rc = cmd_out(ps, proto, shell_id)
    if rc != 0 or not out:
        print_error("Cannot cd to '%s'" % path)
    else:
        return out.rstrip()


def keep_alive(proto, shell_id):
    while True:
        time.sleep(45)
        try:
            cmd_out("[System.Int32]::MinValue", proto, shell_id)
        except Exception:
            break


def ps_quote(value: str) -> str:
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


class _Shell:
    def __init__(self, protocol: Protocol, shell_id: str, host: str, current_directory: str):
        self.protocol = protocol
        self.shell_id = shell_id
        self.host = host
        self.current_directory = current_directory

    def run(self, script: str) -> CommandResult:
        stdout, stderr, rc = run_cmd(script, self.protocol, self.shell_id)
        return CommandResult(_decode_output(stdout), clean_powershell_error(stderr), rc)

    def run_with_input(self, script: str, input_chunks: Iterable[bytes]) -> CommandResult:
        encoded = base64.b64encode((PS_PROGRESS_SILENCE + script).encode("utf-16-le")).decode("ascii")
        command_id = None
        try:
            command_id = self.protocol.run_command(
                self.shell_id, "powershell.exe",
                ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded])
            for chunk in input_chunks:
                self.protocol.send_command_input(self.shell_id, command_id, chunk)
            self.protocol.send_command_input(self.shell_id, command_id, b"", end=True)
            stdout, stderr, status_code = self.protocol.get_command_output(self.shell_id, command_id)
        finally:
            if command_id is not None:
                with suppress(Exception):
                    self.protocol.cleanup_command(self.shell_id, command_id)
        return CommandResult(_decode_output(stdout), clean_powershell_error(stderr), status_code)

    def run_native(self, executable: str, arguments: Sequence[str]) -> CommandResult:
        if any(char.isspace() for char in executable):
            raise GoodWinRMError(
                f"Cannot run {executable!r} natively: the executable must live in a "
                "space-free path (stage it in a directory without whitespace)")
        command_id = None
        try:
            command_id = self.protocol.run_command(
                self.shell_id, executable,
                [win_quote(argument) for argument in arguments],
                skip_cmd_shell=True)
            stdout, stderr, status_code = self.protocol.get_command_output(self.shell_id, command_id)
        finally:
            if command_id is not None:
                with suppress(Exception):
                    self.protocol.cleanup_command(self.shell_id, command_id)
        return CommandResult(_decode_output(stdout), _decode_output(stderr), status_code)


def _show_progress(transferred: int, total: int) -> None:
    if not sys.stdout.isatty() or total <= 0:
        return
    percent = transferred * 100 / total
    sys.stdout.write(
        f"\r   ⠿ {transferred / 1048576:.2f}/{total / 1048576:.2f} MiB ({percent:.0f}%)")
    sys.stdout.flush()


def upload_file(local_path: str, remote_path: str | None, shell: _Shell) -> tuple[str, int]:
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
                while chunk := stream.read(48 * 1024):
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
        arguments=tuple(tokens[index + 1:]),
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        use_schtasks=launcher == "schtasks",
        launcher=launcher,
        stage_dir=stage_dir,
    )


def execute_foreground(shell: _Shell, executable: str, arguments: Sequence[str]) -> CommandResult:
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


def spawn_wmi(shell: _Shell, request: SpawnRequest) -> int:
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


def spawn_scheduled(shell: _Shell, request: SpawnRequest) -> str:
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


def _select_helper_blob(shell: _Shell) -> str | None:
    result = shell.run("$env:PROCESSOR_ARCHITECTURE")
    if result.status_code != 0 or not result.stdout:
        return None
    architecture = result.stdout.splitlines()[-1].strip().upper()
    if architecture == "AMD64":
        return GWSPAWN_X64_B64
    if architecture == "X86":
        return GWSPAWN_X86_B64
    return None


def _stage_helper(blob: str, stage_dir: str, shell: _Shell) -> str:
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


def _resolve_stage_dir(request: SpawnRequest, shell: _Shell) -> str:
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


def spawn_native(shell: _Shell, request: SpawnRequest, launcher: str, blob: str | None) -> int:
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


def launch_spawn(shell: _Shell, request: SpawnRequest) -> None:
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


def execute_script_block(shell: _Shell, script_text: str, arguments: Sequence[str] = ()) -> CommandResult:
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


def read_multiline_script(session: PromptSession) -> list[str]:
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


def main():
    banner()
    args = parse_args()
    proto, shell_id, host = open_session(args)

    enc = "utf-8"

    whoami_out, _ = cmd_out(
        '([Security.Principal.WindowsIdentity]::GetCurrent()).Name', proto, shell_id)
    hostname_out, _ = cmd_out('hostname', proto, shell_id)
    cdir = args.directory
    sh = _Shell(proto, shell_id, host, cdir)

    completions = ["exit", "clear", "pwd", "ls", "cd",
                    "upload", "download", "run", "exec", "spawn",
                    "runps", "runscript", "script", "paste",
                    "whoami", "hostname", "ipconfig", "Get-Process", "Get-Service"]
    completer = WordCompleter(completions, ignore_case=True)
    session = PromptSession()
    threading.Thread(target=keep_alive, args=(proto, shell_id), daemon=True).start()

    while True:
        prompt = ("\x1b[34m%s\x1b[0m@\x1b[34m%s\x1b[0m "
                  "\x1b[33m%s\x1b[0m > " % (whoami_out, hostname_out, cdir))
        try:
            cmd = session.prompt(ANSI(prompt), completer=completer)
        except KeyboardInterrupt:
            print()
            continue
        except EOFError:
            break

        cmd = cmd.strip()
        if not cmd:
            continue
        if cmd == "exit":
            break
        if cmd == "clear":
            print("\033[H\033[J")
            cdir = args.directory
            sh.current_directory = cdir
            continue
        if cmd.lower() in {"script", "paste", "multiline"}:
            lines = read_multiline_script(session)
            if lines:
                print_command_result(execute_script_block(sh, "\n".join(lines)))
            continue

        words = cmd.split(None, 1)
        verb = words[0].lower()
        arg = words[1].strip() if len(words) > 1 else ""

        if verb == "pwd":
            printf(ANSI("\x1b[33m%s\x1b[0m" % cdir))
            continue

        if verb == "ls":
            shell_ls(arg, proto, shell_id, cdir)
            continue

        if verb == "cd":
            if arg:
                new_dir = shell_cd(arg, proto, shell_id, cdir)
                if new_dir:
                    cdir = new_dir
                    sh.current_directory = cdir
            else:
                home_out, _ = cmd_out('[System.Environment]::GetFolderPath("UserProfile")', proto, shell_id)
                if home_out:
                    cdir = home_out
                    sh.current_directory = cdir
            continue

        if verb == "upload":
            sub = arg.split(None, 1)
            if len(sub) != 2:
                print_info("Usage: upload <local> <remote>")
                continue
            upload(sub[0], sub[1], proto, shell_id)
            continue

        if verb == "download":
            sub = arg.split(None, 1)
            if len(sub) != 2:
                print_info("Usage: download <remote> <local>")
                continue
            download(sub[0], sub[1], proto, shell_id)
            continue

        if verb in {"run", "exec"}:
            try:
                values = split_shell_args(arg)
                if not values:
                    raise GoodWinRMError("Usage: run <remote executable> [arguments...]")
                result = execute_foreground(sh, values[0], values[1:])
                if result.stdout:
                    print(result.stdout)
                if result.stderr:
                    print_error(result.stderr)
                if result.status_code != 0:
                    print_error(f"{values[0]} exited with code {result.status_code}")
            except GoodWinRMError as exc:
                print_error(str(exc))
            continue

        if verb == "spawn":
            try:
                if not arg:
                    raise GoodWinRMError(SPAWN_USAGE)
                launch_spawn(sh, parse_spawn_request(split_shell_args(arg)))
            except GoodWinRMError as exc:
                print_error(str(exc))
            continue

        if verb in {"runps", "runscript"}:
            try:
                values = split_shell_args(arg)
                if not values:
                    raise GoodWinRMError(SCRIPT_USAGE)
                try:
                    script_text = Path(values[0]).read_text(encoding="utf-8-sig")
                except OSError as exc:
                    raise GoodWinRMError(f"Cannot read {values[0]}: {exc}") from exc
                print_command_result(execute_script_block(sh, script_text, values[1:]))
            except GoodWinRMError as exc:
                print_error(str(exc))
            continue

        # Regular command
        safe = cdir.replace('"', '""')
        full = '3>$null; Set-Location "%s" -EA Stop; %s' % (safe, cmd)
        stdout, stderr, rc = run_cmd(full, proto, shell_id)
        out = stdout.decode(enc, "replace").strip()
        err = stderr.decode(enc, "replace").strip()
        if out:
            print(out)
        if rc != 0 and err:
            print_error(err)

    proto.close_shell(shell_id)
    print_info("Session closed.")


if __name__ == "__main__":
    main()
