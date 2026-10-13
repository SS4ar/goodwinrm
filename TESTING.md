# Testing GoodWinRM

The test strategy is based on WinRM actions commonly needed in an authorized
GOAD-style lab: obtaining a shell with plaintext or NTLM material, navigating
the host, running PowerShell, and moving enumeration artifacts and binaries.
It validates GoodWinRM's documented scope; it does not claim Evil-WinRM's
in-memory DLL/assembly loaders, AMSI/ETW bypasses, or service-permission audit.

## Local test gates

```bash
python -m pip install -e '.[dev]'
ruff check .
ruff format --check .
mypy goodwinrm tests
pytest -m 'not e2e' --cov=goodwinrm --cov-fail-under=90
python -m build
```

The automated suite covers:

- endpoint parsing for hostname, custom port, URL path, HTTPS, and IPv6;
- NT/LM hash validation and the `LM:NT` value required by `pyspnego`;
- PowerShell literal quoting and CLIXML error decoding;
- cleanup after command and transfer failures;
- current-directory behavior and quoted shell arguments;
- empty, one-chunk, boundary, and multi-chunk binary transfers;
- atomic local download and partial-file cleanup;
- `run`/`exec`/`spawn` argument parsing with quoted paths and spaces;
- WMI launcher generation (PID on success, error on nonzero ReturnValue),
  `schtasks` create/run/delete generation with `/ru SYSTEM /rl HIGHEST`,
  last-result verification, and random task names;
- launcher selection: `--launcher auto|breakaway|wmi-native|wmi-ps|schtasks`
  and legacy `--schtasks` parsing, helper `PID`/`ERR` output parsing,
  `run_native` issuing `run_command(..., skip_cmd_shell=True)` with a
  CommandLineToArgvW-quoted command line (paths and arguments with spaces),
  quoting round-trips under CRT argv rules, x64/x86 PE blob sanity (`MZ`
  prefix), neutral staged helper names, `--stage-dir` handling, and auto
  fallback `breakaway` → `wmi-native` → `wmi-ps` (including architecture and
  redirection skips);
- `run` launching in the tracked remote directory with cwd-first resolution
  of bare executable names;
- `win_quote` round-tripping of trailing backslashes and embedded quotes
  under `CommandLineToArgvW` rules;
- neutral upload temporary names (no tool token) and progress suppression
  prepended to every script that reaches the wire;
- keepalive CLI flags (`--no-keepalive`, `--keepalive-interval`) and
  rejection of negative intervals.

## Authorized-lab E2E matrix

| Area | Cases |
|---|---|
| Authentication | domain password, local password, domain PTH, local PTH |
| Session | identity, hostname, Unicode stdout, readable stderr, nonzero exit |
| Navigation | root, relative path, absolute path, spaces, missing directory, wildcard listing |
| Transfer | empty, small, multi-chunk, random binary, spaces/Unicode, overwrite, missing source |
| Execution | `run` stdout/stderr/exit code, missing binary, Unicode output |
| Detachment | `spawn` PID alive after `close_shell` and connection drop for every launcher (`breakaway`, `wmi-native`, `wmi-ps`), observed parent process, `--schtasks` fallback, stdout/stderr redirection (falls back to `wmi-ps`), helper removal after launch |
| Lifecycle | command cleanup, clean shell close, repeated sessions |
| Optional transports | Kerberos ccache, HTTPS, CredSSP, certificate when the lab exposes them |

E2E tests are opt-in and never contain credentials or a fixed target. Configure
only an authorized host:

```bash
export GOODWINRM_E2E_HOST='winhost.example.test'
export GOODWINRM_E2E_USERNAME='Administrator'
export GOODWINRM_E2E_PASSWORD='...'
export GOODWINRM_E2E_DOMAIN='EXAMPLE'
export GOODWINRM_E2E_REMOTE_DIR='C:\Windows\Temp'

pytest -m e2e -v
```

Kerberos is skipped unless a cache is explicitly supplied:

```bash
export GOODWINRM_E2E_CCACHE='/tmp/administrator.ccache'
export GOODWINRM_E2E_KERBEROS_HOST='winhost.example.test'
pytest -m e2e -v
```

Every transfer test uses a randomized filename under
`GOODWINRM_E2E_REMOTE_DIR` and removes its artifacts in `finally` cleanup.

## OPSEC / detection tradeoffs

The unit gates verify the OPSEC hardening that is testable offline:
neutral (tool-token-free) upload temporary names and progress suppression
on every wire script. The remaining artifacts are inherent to the transport
and are documented in the README "OPSEC / detection tradeoffs" section:
`-EncodedCommand` visibility in 4688/Sysmon1/4104 (where those audit sources
are enabled), launcher telemetry for `spawn` (helper and control-channel
`powershell.exe` commands for `breakaway`, WMI exposure incl. ASR d1e49aac for
the WMI launchers with WMI-Activity being host-dependent, task events for
`--schtasks`), short-lived upload temporaries and staged helper executables,
periodic keepalive `powershell.exe` invocations, and no AMSI or ETW bypass by
design.
