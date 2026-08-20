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
- atomic local download and partial-file cleanup.

## Authorized-lab E2E matrix

| Area | Cases |
|---|---|
| Authentication | domain password, local password, domain PTH, local PTH |
| Session | identity, hostname, Unicode stdout, readable stderr, nonzero exit |
| Navigation | root, relative path, absolute path, spaces, missing directory, wildcard listing |
| Transfer | empty, small, multi-chunk, random binary, spaces/Unicode, overwrite, missing source |
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
