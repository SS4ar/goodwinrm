import argparse
import os
import sys
import time
import threading
import base64
from prompt_toolkit import print_formatted_text as printf, HTML, ANSI, PromptSession
from prompt_toolkit.completion import WordCompleter
from winrm.protocol import Protocol

# Must keep the resulting `powershell -enc <b64>` command line under the
# cmd.exe 8191-char limit: 8192-byte chunks blow past it and fail on >~2.2KB files.
B64_CHUNK = 2048


def print_error(msg):
    printf(ANSI("\x1b[31m✖ %s\x1b[0m" % msg))


def print_success(msg):
    printf(ANSI("\x1b[32m✔ %s\x1b[0m" % msg))


def print_info(msg):
    printf(ANSI("\x1b[36m⠿ %s\x1b[0m" % msg))


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
            message_encryption="always" if args.transport == "kerberos" and not args.https else "auto",
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
    b64 = base64.b64encode(cmd.encode("utf-16-le")).decode("ascii")
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


def main():
    banner()
    args = parse_args()
    proto, shell_id, host = open_session(args)

    enc = "utf-8"

    whoami_out, _ = cmd_out(
        '([Security.Principal.WindowsIdentity]::GetCurrent()).Name', proto, shell_id)
    hostname_out, _ = cmd_out('hostname', proto, shell_id)
    cdir = args.directory

    completions = ["exit", "clear", "pwd", "ls", "cd",
                    "upload", "download", "whoami", "hostname",
                    "ipconfig", "Get-Process", "Get-Service"]
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
            else:
                home_out, _ = cmd_out('[System.Environment]::GetFolderPath("UserProfile")', proto, shell_id)
                if home_out:
                    cdir = home_out
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
