# Security Model

## Threat Model

### Assumptions

- The server runs on a **trusted LAN** alongside the Synology NAS
- The MCP client (Claude Desktop, Claude Code, GoClaw) runs on the same machine or a trusted LAN host
- The NAS is **not exposed to the public internet** via this server
- The operator controls the NAS and its TLS certificate

### In-scope threats

| Threat | Mitigation |
|---|---|
| Credential theft from logs | Credentials and session IDs are redacted from all log output via `redactSensitive()` |
| Path traversal to escape Drive root | `sanitizePath()` blocks `..` sequences and rejects any path outside the configured Drive roots (`/mydrive`, `/team-folders`, `/home`) at the tool boundary |
| Unauthenticated SSE access from network | Bearer-token auth required for non-loopback SSE; server refuses to start without it |
| Cross-origin SSE hijacking | `isOriginAllowed()` validates the `Origin` header; `isHostAllowed()` validates the `Host` header — both are required to block DNS rebinding |
| MITM between server and NAS | TLS verification enabled by default; `SYNO_IGNORE_CERT=true` is opt-in and logged at `warn` level on every startup |
| Accidental destructive operations | All write/delete/send tools require explicit `"confirm": true` in tool input |
| Supply-chain compromise of published package | `pnpm-lock.yaml` is committed and CI installs with `--frozen-lockfile`; npm publish uses `--provenance` for SLSA attestation |
| Header injection via upload file names | `sanitizeFileName()` / `sanitizeMimeType()` strip CR/LF and other unsafe characters before they reach multipart headers |
| Credential leak through error messages | Detailed diagnostics (DSM host, port, username) are written to the server log only; MCP clients receive a generic failure |

### Out-of-scope threats

- NAS compromise via DSM vulnerabilities (not this server's responsibility)
- Physical access to the NAS
- Compromise of the MCP client itself
- Public internet exposure (by design — not supported without explicit operator setup)

---

## Credential Handling

- Credentials (`SYNO_PASSWORD`, `SYNO_OTP_CODE`) are read from environment variables at startup and never written to disk by this server
- Login uses `POST` with an `application/x-www-form-urlencoded` body — credentials never appear in URLs or access logs
- The session ID (`sid`) is forwarded via `Cookie: id=<sid>` header, keeping it out of URL query strings and server access logs
- `redactSensitive()` strips `passwd`, `_sid`, `otp_code`, and bearer token values from any object before it is logged

---

## Transport Security

### stdio (default)

No network socket is opened. Communication is over stdin/stdout with the MCP client process. No auth required — the OS process model provides isolation.

### SSE

- Binds to `127.0.0.1` by default
- When `MCP_SSE_HOST` is set to a non-loopback address, `MCP_AUTH_TOKEN` is **mandatory** — the server refuses to start without it
- `verifyBearer()` uses constant-time comparison (`crypto.timingSafeEqual`) to prevent timing attacks
- `isOriginAllowed()` rejects SSE requests with unexpected `Origin` headers to block cross-origin access. Requests carrying an `Origin` header are only accepted when the origin is listed in `MCP_ALLOWED_ORIGINS`
- `isHostAllowed()` rejects SSE requests whose `Host` header does not name the bound host. This is the DNS-rebinding defence: an attacker-controlled domain resolving to the server's address still sends its own name in the `Host` header
- When `MCP_SSE_HOST` is a wildcard address (`0.0.0.0`), the loopback names plus every hostname in `MCP_ALLOWED_HOSTS` are accepted. A wildcard bind does **not** accept arbitrary `Host` values

**Generating a strong token:**

```bash
openssl rand -hex 32
```

**Exposing SSE beyond localhost:**

```bash
MCP_TRANSPORT=sse
MCP_SSE_HOST=0.0.0.0
MCP_AUTH_TOKEN="$(openssl rand -hex 32)"
# Names clients actually use to reach the server — required for a wildcard bind.
MCP_ALLOWED_HOSTS=nas.local,192.168.1.100
# Origins allowed to issue browser requests (comma-separated, exact match).
MCP_ALLOWED_ORIGINS=http://192.168.1.100:3100
```

---

## Two-Factor Authentication

DSM does **not** support app-specific / application passwords. That is a Google/Microsoft concept; the Synology DSM user interface has no such feature.

Options for an unattended automation account:

1. **Dedicated DSM service account without 2FA** — the only fully supported path, and required by the Spreadsheet `/authorize` endpoint, which does not accept an OTP code.
   - ⚠️ Such an account has **no MFA protection**. Use a dedicated, non-personal account, grant it only the DSM privileges it needs, and scope it to a dedicated shared space.
2. **`SYNO_OTP_CODE` with a current TOTP code** — works only for single-session setups, since TOTP codes expire in 30 seconds, and is not supported by the Spreadsheet `/authorize` endpoint.

---

## TLS Certificate Verification

TLS verification is **on by default**. The `undici` HTTP agent enforces certificate validation for all NAS connections.

`SYNO_IGNORE_CERT=true` disables certificate verification. Use only:
- On a trusted home LAN
- With a self-signed certificate you generated and control
- When you understand the MITM risk

This setting is logged at `warn` level on every startup.

---

## Log Redaction Policy

The following values are automatically redacted (replaced with `[REDACTED]`) before any log output:

- `passwd` / `password` fields
- `_sid` / `sid` session identifiers
- `otp_code` values
- `Authorization` bearer token values
- `MCP_AUTH_TOKEN` value

Redaction is applied by `src/utils/redact.ts` and is called at every log site. If you find a log statement that leaks a sensitive value, please report it per the [vulnerability disclosure process](./SECURITY.md).

---

## Confirm-Required Operations

The following tools require `"confirm": true` in the input to prevent accidental destructive actions:

| Tool | Risk |
|---|---|
| `drive_delete_file` | Permanent deletion |
| `drive_move_file` | Overwrites destination if it exists |
| `spreadsheet_write_cells` | Overwrites cell content |
| `spreadsheet_append_rows` | Modifies spreadsheet data |
| `spreadsheet_batch_update` | Inserts/deletes rows or columns |
| `spreadsheet_rename_sheet` | Renames a sheet tab |
| `spreadsheet_delete_sheet` | Deletes a sheet tab |
| `spreadsheet_delete_file` | Permanently deletes an entire spreadsheet |
| `mailplus_send_message` | Sends an email |
| `mailplus_move_messages` | Moves messages (irreversible without moving back) |
| `calendar_create_event` | Creates calendar entry |
| `calendar_update_event` | Modifies calendar entry |
| `calendar_delete_event` | Deletes calendar entry |

When `confirm` is absent or `false`, the tool returns an error without performing the action.

Tools that create new content without modifying or removing anything
(`drive_upload_file`, `drive_create_folder`, `spreadsheet_create`,
`spreadsheet_add_sheet`, `spreadsheet_write_styles`, `mailplus_mark_messages`,
`calendar_create_calendar`) do **not** require `confirm`.

---

## Vulnerability Disclosure

See [SECURITY.md](./SECURITY.md) for the private disclosure process. Do not open public GitHub issues for security vulnerabilities.
