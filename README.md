# GoodWinRM

Python WinRM Interactive Shell with file transfer support.

![test](.github/goodwinrm.jpg)

## Features

- Interactive PowerShell over WinRM
- **Password, Pass-The-Hash, Kerberos ccachе auth**
- **File upload / download** (evil-winrm style, base64 chunked)
- Native `ls` / `cd` / `pwd` — preserved directory state per-process

## Installation

```bash
pipx install git+https://github.com/SS4ar/goodwinrm
pipx ensurepath
```

## Usage

### Password (NTLM)
```bash
goodwinrm -i 10.10.30.10 -u 'DOMAIN\Administrator' -p 'Password123' -t ntlm
```

### Pass-The-Hash
```bash
goodwinrm -i 10.10.30.10 -u 'Administrator' --nt-hash 'A87E1E9015421162B6D958BBF7453C8D' -t ntlm
```

### Kerberos (ccache)
```bash
export KRB5CCNAME=/tmp/admin.ccache
goodwinrm -i dc.domain.local -u 'admin@DOMAIN.LOCAL' -t kerberos
```

The default Kerberos service is `HTTP`. If your ccache contains only a service
ticket for `HOST/server` or `WSMAN/server`, select that service explicitly,
preserving the case shown by `klist`:

```bash
goodwinrm -i dc.domain.local -u 'admin@DOMAIN.LOCAL' -t kerberos --krb-service HOST
# For a WSMAN ticket, use --krb-service WSMAN instead.
```

`Matching credential not found` can mean that the requested SPN does not match
the cached ticket. Use `--krb-hostname` if the ticket's hostname differs from the
connection address (for example, when connecting through a tunnel). These
options select the requested SPN; the server must also accept the ticket.

Use the full client principal shown by `klist`, including the realm's exact
capitalization. If the cache contains only a TGT, Kerberos must be able to locate
and reach the KDC to obtain the target's service ticket (`HTTP` by default,
or the service selected with `--krb-service`).

Kerberos message encryption requires `pykerberos`, installed by the
`pywinrm[kerberos]` dependency. The separate `kerberos` package uses the same
Python module name but lacks the required WinRM encryption support. If an older
installation returns HTTP 500, repair its dependencies in the same environment:

```bash
pipx runpip goodwinrm uninstall -y kerberos pykerberos
pipx runpip goodwinrm install 'pywinrm[kerberos]>=0.4.3'
```

## CLI Options

| Flag                | Description                                   |
|---------------------|-----------------------------------------------|
| `-i`, `--ip`        | Target host (IP or FQDN)                      |
| `-u`, `--username`  | Username (`DOMAIN\User` or `user@DOMAIN`)     |
| `-p`, `--password`  | Password (empty for Kerberos ccache)          |
| `--nt-hash`         | NT hash for Pass-The-Hash (`NT` or `LM:NT`)   |
| `--krb-service`     | Kerberos SPN service (default `HTTP`; match the case in `klist`) |
| `--krb-hostname`    | Kerberos SPN hostname override               |
| `-t`, `--transport` | Auth transport: `ntlm` (default), `kerberos`, `credssp`, `basic`, `ssl`, `certificate` |
| `--https`           | Use HTTPS (port 5986)                         |
| `--port PORT`       | Custom port                                   |
| `-d`, `--directory` | Initial working directory (default `C:\`)     |
| `-v`, `--server_cert_validation` | `ignore` or `validate` (default `ignore`)|

## Shell Commands

| Command         | Description                          |
|-----------------|--------------------------------------|
| `ls [pattern]`  | List files (`Get-ChildItem`)         |
| `cd <path>`     | Change directory                     |
| `pwd`           | Print working directory              |
| `upload local remote`  | Upload file (base64 chunked)   |
| `download remote local` | Download file (base64 chunked) |
| `clear`         | Clear terminal                       |
| `exit`          | Close session                        |

Any other input is executed as a PowerShell command in the current working directory.
