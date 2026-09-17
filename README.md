# sftp-mcp

MCP server (stdio) that uploads local files to **pre-configured** hosts over SFTP or FTPS.
The AI only ever sees host *names*: hosts, credentials, and allowed directories live in your config.

## Tools

| Tool | Purpose |
|---|---|
| `list_hosts` | Configured hosts (no credentials) |
| `upload_file(host, localPath, remotePath)` | Upload one file. Atomic (`.part` + rename). Parent dir must exist. |
| `list_dir(host, remotePath)` | List a remote directory (max 1000 entries) |
| `stat(host, remotePath)` | Exists / type / size |

Relative `localPath` resolves against the host's `localRoot`; relative `remotePath` against `remoteRoot`.

## Install

```bash
npm install && npm run build
export PROD_KEY_PASS=...
claude mcp add sftp-mcp \
  -e SFTP_MCP_CONFIG=$HOME/.config/sftp-mcp/hosts.json \
  -- node /absolute/path/to/sftp-mcp/dist/index.js
```

Export secret env vars (like `PROD_KEY_PASS`) in the shell that launches Claude Code, or source them from a secrets manager. Do not pass them via `-e`: Claude Code stores `-e` values in plaintext in `~/.claude.json`, or in a committable `.mcp.json` with `--scope project`.

## Config

`chmod 600` the file (the server refuses to start otherwise). On WSL keep it on the Linux filesystem, not `/mnt/c`.

```json
{
  "hosts": {
    "prod-web": {
      "protocol": "sftp",
      "host": "10.0.0.5",
      "username": "deploy",
      "auth": { "type": "key", "keyPath": "~/.ssh/id_ed25519", "passphraseEnv": "PROD_KEY_PASS" },
      "hostKeySha256": ["SHA256:..."],
      "remoteRoot": "/var/www/app",
      "localRoot": "~/builds",
      "allowOverwrite": false,
      "maxBytes": 104857600
    },
    "files": {
      "protocol": "ftps",
      "tls": "explicit",
      "host": "ftp.example.com",
      "username": "uploader",
      "auth": { "type": "password", "passwordEnv": "FTPS_PASS" },
      "remoteRoot": "/incoming",
      "localRoot": "~/outbox"
    }
  }
}
```

| Field | Notes |
|---|---|
| `protocol` | `sftp` or `ftps` |
| `port` | default 22 / 21 (explicit) / 990 (implicit) |
| `auth` (sftp) | `password` (`passwordEnv`), `key` (`keyPath`, `passphraseEnv?`), `agent` (`agentSocket?`, default `SSH_AUTH_SOCK`) |
| `auth` (ftps) | `password` (`passwordEnv`) |
| `hostKeySha256` / `knownHostsPath` | sftp: exactly one required |
| `tls` | ftps: `explicit` or `implicit` |
| `caPath` | ftps: extra trusted CA (PEM) for private/self-signed certs |
| `insecurePlainFtp` | ftps: `true` allows plain FTP; every result carries a warning |
| `allowOverwrite` | default `false` |
| `maxBytes`, `connectTimeoutMs` | optional; timeout default 15000 |

Secrets are only referenced by env var name; literal `password` fields are rejected.

Get a host key fingerprint from a trusted channel (for example, on the server itself):
```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

## Security model

- **SFTP:** host key must match a pinned SHA256 fingerprint or a `known_hosts` entry (plain or hashed; `@revoked` honored). No trust-on-first-use. Modern algorithms only (curve25519/ECDH/DH-group14+ kex, AES-GCM/CTR or ChaCha20, SHA-2 MACs, no ssh-rsa/SHA-1).
- **FTPS:** full certificate + hostname verification, TLS 1.2+, protected data channel.
- **Paths:** remote paths with `..`, backslashes, or NUL are rejected; results must stay inside `remoteRoot`. Local paths are resolved with `realpath` (symlinks followed) and must stay inside `localRoot`.
- **Overwrite:** off by default. Uploads write `.<name>.<random>.part` then rename.
- **Errors:** configured secret values are redacted from tool errors and logs. Logs go to stderr.

**Known limits:** remote symlinks inside `remoteRoot` that point elsewhere are not detected (server-side). `known_hosts` wildcard/negated patterns are ignored. Existence check and rename are not atomic together. FTPS overwrite needs a server whose RNTO replaces existing files (e.g. not IIS); SFTP overwrite needs the OpenSSH posix-rename extension. Integration tests need `openssl`, `ssh-keygen`, `ssh-agent`, and `ssh-add` on the host.

## Development

```bash
npm test                 # unit tests
npm run test:integration # needs Docker: generates fixtures, starts SFTP + FTPS servers
docker compose -f docker-compose.test.yml down
```
