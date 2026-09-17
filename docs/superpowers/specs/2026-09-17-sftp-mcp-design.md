# sftp-mcp — Design

Date: 2026-09-17
Status: Approved (approach A)

## Goal

An MCP server (stdio) that lets an AI client upload local files to pre-configured
remote hosts over SFTP or FTPS, and inspect the remote side (list / stat), with
protocol-level verification (host keys, TLS certificates) and strict path
confinement so the AI cannot reach hosts, files, or directories the operator
did not allow.

## Non-goals (v1)

- Download, delete, mkdir, rename as tools
- Creating missing remote directories during upload (target dir must exist)
- Connection pooling / persistent sessions (one connection per tool call)
- AI-supplied hosts or credentials
- Trust-on-first-use for host keys

## Stack

- TypeScript, Node >= 22, ESM
- `@modelcontextprotocol/sdk` (stdio transport)
- `ssh2-sftp-client` (wraps `ssh2`) for SFTP
- `basic-ftp` for FTPS
- `zod` for config and tool-input validation
- Tests: `node:test` + `tsx`; integration via Docker (`atmoz/sftp`, `delfer/alpine-ftp-server`)

## Configuration

Path from env `SFTP_MCP_CONFIG`. Loaded once at startup; invalid config = process exits non-zero with a message on stderr.

On POSIX, the config file must not be group/world readable (`mode & 0o077 === 0`), else refuse to start. Skipped when `process.platform === "win32"`. (Note for WSL: keep the config on the Linux filesystem, `/mnt/c` reports 0777.)

```json
{
  "hosts": {
    "prod-web": {
      "protocol": "sftp",
      "host": "10.0.0.5",
      "port": 22,
      "username": "deploy",
      "auth": { "type": "key", "keyPath": "~/.ssh/id_ed25519", "passphraseEnv": "PROD_KEY_PASS" },
      "hostKeySha256": ["SHA256:abc..."],
      "remoteRoot": "/var/www/app",
      "localRoot": "/home/xdark/builds",
      "allowOverwrite": false,
      "maxBytes": 104857600
    },
    "files-ftps": {
      "protocol": "ftps",
      "tls": "explicit",
      "host": "ftp.example.com",
      "port": 21,
      "username": "uploader",
      "auth": { "type": "password", "passwordEnv": "FTPS_PASS" },
      "caPath": "/etc/ssl/private-ca.pem",
      "remoteRoot": "/incoming",
      "localRoot": "/home/xdark/outbox",
      "allowOverwrite": true
    }
  }
}
```

### Schema rules

Host name (the key): `^[a-z0-9][a-z0-9_-]{0,63}$`.

Common fields:

| Field | Required | Notes |
|---|---|---|
| `protocol` | yes | `"sftp"` \| `"ftps"` |
| `host` | yes | hostname or IP |
| `port` | no | default 22 (sftp), 21 (ftps explicit), 990 (ftps implicit) |
| `username` | yes | |
| `auth` | yes | see below |
| `remoteRoot` | yes | absolute POSIX path |
| `localRoot` | yes | absolute local path; resolved with `realpath` at startup, must exist and be a directory |
| `allowOverwrite` | no | default `false` |
| `maxBytes` | no | positive integer; no limit if omitted |
| `connectTimeoutMs` | no | default 15000 |

SFTP-only:

| Field | Notes |
|---|---|
| `auth.type` | `"password"` (`passwordEnv`), `"key"` (`keyPath`, optional `passphraseEnv`), `"agent"` (uses `SSH_AUTH_SOCK`; optional `agentSocket` override) |
| `hostKeySha256` | array of OpenSSH-style fingerprints `SHA256:<base64 no padding>` |
| `knownHostsPath` | alternative to `hostKeySha256`; supports plain and hashed (`|1|salt|hash`) entries, matching `host` for port 22 and `[host]:port` otherwise |

Exactly one of `hostKeySha256` / `knownHostsPath` is required. Neither → config invalid.

FTPS-only:

| Field | Notes |
|---|---|
| `auth.type` | `"password"` only (`passwordEnv`) |
| `tls` | `"explicit"` (AUTH TLS) \| `"implicit"` |
| `caPath` | optional PEM added as trusted CA (for private CAs / self-signed) |
| `insecurePlainFtp` | optional `true`; only then may `tls` be omitted. Plain FTP. |

Secrets:
- Passwords/passphrases are referenced by env var name only. A literal `password`/`passphrase` field is a schema error.
- Referenced env vars must be set and non-empty at startup, else config invalid (fail fast, not at first call).
- `keyPath` supports leading `~`; file must be readable at startup.
- Secrets never appear in tool output, errors, or logs.

## MCP tools

All tools take `host` (must be a configured name). Unknown host → tool error `Unknown host`.

### `list_hosts()`
Returns `[{ name, protocol, host, port, remoteRoot, allowOverwrite, insecure }]` where `insecure` is `true` for `insecurePlainFtp`. No auth details.

### `upload_file({ host, localPath, remotePath })`
- `localPath`: absolute, or relative to the host's `localRoot`.
- `remotePath`: absolute, or relative to `remoteRoot`. Must name a file, not end in `/`.
- Returns `{ remotePath, bytes, overwritten }` (plus `warning` for plain FTP).

### `list_dir({ host, remotePath })`
- Returns up to 1000 entries `[{ name, type: "file"|"dir"|"link"|"other", size, modifiedAt }]` and `truncated: boolean`.

### `stat({ host, remotePath })`
- Returns `{ exists: false }` or `{ exists: true, type, size, modifiedAt }`.

## Security controls

### 1. SFTP host key verification
`ssh2` `hostVerifier(key: Buffer)` computes `SHA256:` + base64(sha256(key)) without padding and compares (constant-time) against `hostKeySha256`, or matches `knownHostsPath` entries (key type + base64 blob). Mismatch or no entry → connection aborted, error `Host key verification failed for <name>`. No TOFU, no bypass flag.

### 2. SSH algorithm restrictions
Passed as `algorithms`:
- kex: `curve25519-sha256`, `curve25519-sha256@libssh.org`, `ecdh-sha2-nistp256`, `ecdh-sha2-nistp384`, `ecdh-sha2-nistp521`, `diffie-hellman-group16-sha512`, `diffie-hellman-group18-sha512`, `diffie-hellman-group14-sha256`
- cipher: `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`, `aes128-gcm@openssh.com`, `aes256-ctr`, `aes192-ctr`, `aes128-ctr`
- hmac: `hmac-sha2-256-etm@openssh.com`, `hmac-sha2-512-etm@openssh.com`, `hmac-sha2-256`, `hmac-sha2-512`
- serverHostKey: `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`, `rsa-sha2-512`, `rsa-sha2-256`

### 3. FTPS certificate verification
`basic-ftp` `access({ secure: true | "implicit", secureOptions })` with `rejectUnauthorized: true`, `servername: host`, `minVersion: "TLSv1.2"`, and `ca: [...tls.rootCertificates, caPEM]` when `caPath` is set. Hostname checked by Node's default `checkServerIdentity`. Data channel also TLS (basic-ftp uses PROT P when secure).

Plain FTP only with `insecurePlainFtp: true`; every tool result for that host includes `warning: "plain FTP: credentials and data sent unencrypted"`, and a stderr warning is printed at startup.

### 4. Path confinement
`paths.ts`, pure functions, fully unit tested.

Remote (`resolveRemote(remoteRoot, input)`):
- Reject NUL bytes, backslashes, and any `..` segment in the input (before normalization).
- Join with `remoteRoot` if relative, `path.posix.normalize`.
- Result must equal `remoteRoot` or start with `remoteRoot + "/"`. (For `upload_file`, must not equal `remoteRoot`.)

Local (`resolveLocal(localRoot, input)`):
- Reject NUL bytes.
- Resolve against `localRoot` if relative, then `fs.realpath` (follows symlinks).
- Real path must be inside real `localRoot` (same prefix rule with `path.sep`).
- Must be a regular file (`fs.stat().isFile()`).

Known limit: remote symlinks inside `remoteRoot` pointing outside it are not detected (server-side; operator responsibility, documented in README).

### 5. Overwrite & atomic upload
1. `stat` target. Exists and `allowOverwrite: false` → error `Remote file exists and overwrite is disabled`. Exists and is a directory → error.
2. Upload to `<dir>/.<basename>.<8 random hex>.part`.
3. Rename into place:
   - SFTP: `posixRename` (OpenSSH extension, atomic replace) when available; else, if target doesn't exist, plain `rename`; else error.
   - FTPS: `RNFR`/`RNTO` via `client.rename`.
4. On any failure after step 2 starts: best-effort delete of the `.part` file, then rethrow.

Known limit: check-then-rename race if another writer creates the target concurrently. Acceptable for v1.

### 6. Limits
- `maxBytes`: checked against local file size before connecting.
- `connectTimeoutMs` for connect/handshake (`readyTimeout` in ssh2, `timeout` in basic-ftp).
- Every connection closed in `finally`.

### 7. Error & log hygiene
- Logs go to stderr only (stdout is MCP transport).
- Tool errors return `isError: true` with a short message; stack traces only to stderr.
- A `redact()` helper replaces any configured secret value found in error messages with `***` before returning or logging.

## Code layout

```
src/
  index.ts    MCP server, tool registration, input schemas, dispatch
  config.ts   load + zod schema + env/secret resolution + startup checks
  paths.ts    resolveRemote / resolveLocal
  hostkey.ts  fingerprint + known_hosts matching
  sftp.ts     connect, stat, list, upload (SFTP)
  ftp.ts      connect, stat, list, upload (FTPS)
test/
  paths.test.ts
  config.test.ts
  hostkey.test.ts
  integration.test.ts   (skipped unless INTEGRATION=1)
docker-compose.test.yml
README.md
```

`sftp.ts` and `ftp.ts` export the same three functions `(hostCfg, ...) => Promise<...>`; `index.ts` picks by `protocol`. No shared interface class.

## Testing

Unit (always run):
- `paths`: `..` escape, encoded/absolute escape, NUL, backslash, prefix trick (`/var/www/app2`), symlink escaping `localRoot`, directory as local file.
- `config`: missing host key pin, literal password rejected, missing env var, plain FTP without flag, bad host name.
- `hostkey`: fingerprint format, hashed known_hosts entry, non-standard port entry.

Integration (`INTEGRATION=1`, docker compose up):
- SFTP password, key, and agent (agent via `ssh-agent` spawned in test) upload succeeds.
- Wrong `hostKeySha256` → fails with host key error, nothing uploaded.
- Upload with `allowOverwrite: false` onto existing file → refused; with `true` → replaced.
- FTPS explicit upload with `caPath` to test CA succeeds; without `caPath` → cert error.
- FTPS implicit upload succeeds.
- `list_dir` / `stat` return expected entries.

## Success criteria

- All unit tests pass; integration suite passes against the Docker targets.
- Server registered in Claude Code (`claude mcp add sftp-mcp -- node dist/index.js` with `SFTP_MCP_CONFIG`) can list hosts and upload a file end to end.
- No test or manual attempt can: connect with an unpinned/mismatched host key, accept an invalid TLS cert, write outside `remoteRoot`, read outside `localRoot`, or leak a secret in tool output.
