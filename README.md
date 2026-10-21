# Cisco Duo MCP Server

MCP server for [Cisco Duo](https://duo.com/)'s identity/MFA administration API - read-only visibility into users, their enrolled MFA methods, phones, hardware and desktop tokens, groups, integrations, and the authentication/administrator/telephony logs, for AI assistants and the WYRE Conduit gateway.

Duo has no machine-readable OpenAPI spec; every endpoint in this connector was manually verified against Duo's published docs ([Admin API](https://duo.com/docs/adminapi), [Auth API](https://duo.com/docs/authapi)) and cross-checked against Duo's own reference client, [`duo_client_python`](https://github.com/duosecurity/duo_client_python).

## Authentication

Duo authenticates with a **signed-request scheme**, not OAuth2 and not a bearer token. This connector implements **Duo Auth Signature v5 (HMAC-SHA512)** - the current recommended method - not the legacy v2 (HMAC-SHA1) scheme.

Three credential fields are required:

| Field | Description |
|---|---|
| `ikey` | Integration key - identifies the integration. Sent as the Basic-auth username. Not secret. |
| `skey` | Secret key - the HMAC-SHA512 signing key. Bearer-equivalent for this integration's admin scope; never sent over the wire itself, never logged. |
| `apiHost` | This account's Duo API hostname, e.g. `api-xxxxxxxx.duosecurity.com`. Not secret. |

Every request is signed fresh, per call, in `src/client.ts`'s `signV5Get()`. The 7-line canonical string (date, method, host, path, sorted query params, SHA-512 body hash, SHA-512 signed-headers hash) is joined with `\n` and HMAC-SHA512-signed with `skey`; the hex signature is sent as `Authorization: Basic base64(ikey:signature)` alongside a `Date` header carrying the exact same RFC 2822 timestamp that was signed. This connector is GET-only, so the body hash is always the digest of the empty string, and no additional `X-Duo-*` signed headers are used, so the header hash is always the digest of the empty string too.

In gateway mode the three fields arrive per-request via `X-Duo-Ikey` / `X-Duo-Skey` / `X-Duo-Api-Host` headers, injected by the Conduit gateway. They are not read from the environment, and a request missing any of them is rejected with 401. In local/stdio mode they're read once from `DUO_IKEY` / `DUO_SKEY` / `DUO_API_HOST`. The stdio transport does not use `CONDUIT_S2S_SECRET`.

**What the credential itself can do vs. what this connector calls.** This connector's code is read-only by construction (see Scope, below), but that describes this codebase, not Duo's server-side enforcement. Duo Admin API integrations carry their own independently-configured permission grants (`Grant Read Resource`, `Grant Write Resource`, `Grant Read Log`, `Grant Read Settings`, `Grant Write Settings`, etc., set in the Duo Admin Panel when the integration is created) and Duo **does** enforce these server-side - an integration without `Grant Write Resource` gets a real authorization error from Duo itself on any write attempt, confirmed against Duo's docs and community reports of exactly that failure mode. This connector never exercises anything beyond read permissions, but the `ikey`/`skey` pair a customer supplies is only as narrowly scoped as the permissions they granted that integration in Duo - if a customer grants this integration `Grant Write Resource` (unnecessary for this connector), the credential itself would be capable of writes even though this connector's code never calls one. **Recommend granting this integration only `Grant Read Resource` (and `Grant Read Log` if the log tools are wanted) in Duo's Admin Panel** - least-privilege at the credential level, on top of this connector's own code-level restriction.

**Defensive field-stripping**: Duo's Integrations endpoints are known to echo secret-shaped fields in some read responses, and the API has no machine-readable schema to verify this exhaustively per integration type. Every response from every tool in this connector - not just Integrations - passes through `stripSecretFields()` before it ever reaches the model: any object key matching `/secret|skey/i`, at any depth, is dropped. This is a blanket safety net on top of, not instead of, the endpoint-level exclusions below.

## Configuration

Copy [`.env.example`](.env.example) and set the variables below. Leave `CONDUIT_S2S_SECRET` empty in that file.

| Env var | Description |
|---|---|
| `DUO_IKEY` | Duo integration key. Required for stdio and `AUTH_MODE=env`. Not set on the gateway Compose service. |
| `DUO_SKEY` | Duo secret key (HMAC-SHA512 signing secret). Required for stdio and `AUTH_MODE=env`. Not set on the gateway Compose service. |
| `DUO_API_HOST` | This account's Duo API hostname. Required for stdio and `AUTH_MODE=env`. Not set on the gateway Compose service. |
| `MCP_TRANSPORT` | `stdio` (default) or `http`. |
| `AUTH_MODE` | `env` (default, reads the vars above) or `gateway` (Docker image and Compose default). Gateway mode requires `X-Duo-Ikey`, `X-Duo-Skey`, and `X-Duo-Api-Host` on each `/mcp` request and never falls back to `DUO_*`. |
| `CONDUIT_S2S_SECRET` | Required to start the HTTP transport. The process logs an error and exits non-zero when this is empty or a known placeholder (`changeme`, `placeholder`, `your-s2s-secret`, `replace-me`, an unresolved `${...}` or `<...>` template, and the other values listed in `src/http.ts`). Compose will not start when it is unset. Never commit a real value. The value is never logged. |
| `MCP_ALLOW_INSECURE_DEV` | Set to exactly `1` only for local development to start HTTP without a usable `CONDUIT_S2S_SECRET`. The process logs a warning, does not enforce `X-Gateway-S2S`, and listens on `127.0.0.1` only. A non-loopback `MCP_HTTP_HOST` (including `0.0.0.0`) is ignored and the override is logged. |
| `MCP_HTTP_HOST` | Bind address when a real `CONDUIT_S2S_SECRET` is set. Unset keeps the historical default `0.0.0.0`. The container image sets `0.0.0.0`. Without a usable secret the listener is forced to `127.0.0.1`. |
| `MCP_TLS_CERT_FILE` | PEM certificate path. Set together with `MCP_TLS_KEY_FILE` to serve HTTPS in-process. Setting only one of the two is a startup error. |
| `MCP_TLS_KEY_FILE` | PEM private key path. Set together with `MCP_TLS_CERT_FILE`. |
| `MCP_TRUSTED_TLS_INGRESS` | Set to exactly `1` when TLS terminates at a trusted ingress in front of this listener. Allows plain HTTP on a non-loopback bind and logs a warning. |
| `MCP_HTTP_PORT` | HTTP port. Defaults to `8080`. |
| `LOG_LEVEL` | `debug` \| `info` (default) \| `warn` \| `error`. |

`/health` stays unauthenticated and does not read Duo credentials or the S2S secret.

### Transport security (TLS)

`X-Duo-Skey` and `X-Duo-Ikey` travel on every `/mcp` request, so a non-loopback bind refuses to start (exit 1) unless one of these is set:

- `MCP_TLS_CERT_FILE` + `MCP_TLS_KEY_FILE`: the server serves HTTPS in-process.
- `MCP_TRUSTED_TLS_INGRESS=1`: plain HTTP, with a logged warning. Use only when TLS terminates at a trusted ingress (for example Azure Container Apps internal ingress) and the hop to the listener is private.

Loopback binds (`127.0.0.1`, any `127.0.0.0/8` address, `::1`, `localhost`) are always allowed over plain HTTP. Setting only one of the two TLS variables, or pointing at an unreadable file, is a startup error.

Startup order: (1) the `CONDUIT_S2S_SECRET` check, (2) resolve the listen host, (3) the TLS/bind check, (4) listen. With a usable secret and `MCP_HTTP_HOST` unset, the host still defaults to `0.0.0.0`, so that case now refuses to start unless TLS or `MCP_TRUSTED_TLS_INGRESS=1` is configured. The container image binds `0.0.0.0` and does not set either, so deployments must.

### HTTP authentication

With `MCP_TRANSPORT=http` and a real `CONDUIT_S2S_SECRET`, every `/mcp` request must include `X-Gateway-S2S`. A missing or invalid header returns 401 before any Duo credential is read.

The header value is `t=<unix seconds>,v1=<hex>`. `<hex>` is the lowercase hex HMAC-SHA256 of the ASCII string `t=<unix seconds>` (the same `t=` prefix), keyed with `CONDUIT_S2S_SECRET`. The timestamp must be within 300 seconds of the server clock. Example shape: `t=1710000000,v1=<64 lowercase hex chars>`.

```javascript
import { createHmac } from 'node:crypto';

const t = Math.floor(Date.now() / 1000);
const mac = createHmac('sha256', process.env.CONDUIT_S2S_SECRET).update(`t=${t}`).digest('hex');
const xGatewayS2s = `t=${t},v1=${mac}`;
```

In `AUTH_MODE=gateway`, `/mcp` also requires `X-Duo-Ikey`, `X-Duo-Skey`, and `X-Duo-Api-Host`. Those headers are the only credential source for that request. A request missing any of them returns 401 and does not fall back to `DUO_*`.

```javascript
await fetch('http://127.0.0.1:8080/mcp', {
  method: 'POST',
  headers: {
    'content-type': 'application/json',
    accept: 'application/json, text/event-stream',
    'x-gateway-s2s': xGatewayS2s,
    'x-duo-ikey': ikey,
    'x-duo-skey': skey,
    'x-duo-api-host': apiHost,
  },
  body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
});
```

## Tools

All 22 tools are read-only and classified `isAdmin: true` in Conduit's `VENDOR_TOOL_CONFIG` regardless of verb - this is identity/MFA administration data (PII: phone numbers, email, device OS, and enrolled-factor details), sensitive even as a plain read.

### Users
- `duo_list_users` - list users, optionally filtered by exact username.
- `duo_get_user` - get full detail for a user.
- `duo_list_user_groups` - list the groups a user belongs to.
- `duo_list_user_phones` - list the phones enrolled to a user.
- `duo_list_user_tokens` - list the hardware tokens enrolled to a user.
- `duo_list_user_webauthn_credentials` - list a user's WebAuthn credentials.
- `duo_list_user_u2f_tokens` - list a user's legacy U2F security keys.

### Phones
- `duo_list_phones` - list phones, optionally filtered by number/extension.
- `duo_get_phone` - get full detail for a phone.

### Tokens
- `duo_list_hardware_tokens` - list hardware tokens (HOTP/TOTP/YubiKey).
- `duo_get_hardware_token` - get full detail for a hardware token.
- `duo_list_desktop_tokens` - list Duo Desktop tokens.
- `duo_get_desktop_token` - get full detail for a Duo Desktop token.

### Groups
- `duo_list_groups` - list groups.
- `duo_get_group` - get full detail for a group.
- `duo_list_group_users` - list the users belonging to a group.

### Integrations (metadata only)
- `duo_list_integrations` - list configured integrations.
- `duo_get_integration` - get full metadata for an integration.

### Logs
- `duo_get_authentication_log` - the authentication log (v2), time-filterable.
- `duo_get_administrator_log` - the administrator action log (v1).
- `duo_get_telephony_log` - the telephony (call/SMS credit) log (v2).

### Auth
- `duo_check_credentials` - validate credentials and Auth API connectivity. Side-effect-free; does not initiate any MFA transaction.

## Scope

**This is a deliberately narrow, read-only v1 surface, built for an identity/MFA administration product where the wrong endpoint is unusually consequential.** `src/client.ts` implements exactly one HTTP verb function (`doGet`) - there is no `doPost`/`doPut`/`doDelete` anywhere in this codebase, so every exclusion below is structurally enforced, not just documented. `src/__tests__/tool-set.test.ts` pins the exact 22-tool set and asserts no tool name matches `/bypass|delete|disassociate|deactivate|revoke|enroll/i`.

**Hard-excluded (credential-exposing) - never implemented:**
- `GET /admin/v1/users/{user_id}/bypass_codes` (`get_user_bypass_codes`) - returns **live, usable MFA-bypass codes**. Even as a read, this is the single most sensitive primitive in the API and is excluded alongside its generator, not treated as a safe list/detail read.
- `POST /admin/v1/users/{user_id}/bypass_codes` (`add_user_bypass_codes`) - generates bypass codes.

**Hard-excluded (provisioning/mutation) - never implemented:**
- `DELETE /admin/v1/users/{user_id}`, `DELETE /admin/v1/phones/{phone_id}`, `DELETE /admin/v1/tokens/{token_id}`, `DELETE /admin/v1/desktoptokens/{desktoptoken_id}`, `DELETE /admin/v1/groups/{group_id}`, `DELETE /admin/v3/integrations/{integration_key}` - all object deletes.
- `DELETE /admin/v1/users/{user_id}/phones/{phone_id}` (`delete_user_phone`), `DELETE /admin/v1/users/{user_id}/tokens/{token_id}` (`delete_user_token`) - disassociate operations.
- `POST /admin/v1/users/{user_id}/phones` (`add_user_phone`), `POST /admin/v1/users/{user_id}/tokens` (`add_user_token`) - associate operations.
- `POST /admin/v1/users`, `POST /admin/v1/phones`, `POST /admin/v1/tokens` (all `add_*_token` variants), `POST /admin/v1/desktoptokens`, `POST /admin/v1/groups`, `POST /admin/v3/integrations` - all object creates.
- `POST`/`PUT` update endpoints for every object type above (`update_phone`, `update_token`, `resync_hotp_token`, `update_desktoptoken`, `activate_desktoptoken`, `update_group`, integration config updates) and any policy-write endpoint (`POST /admin/v1/settings`).
- `POST /auth/v2/preauth`, `POST /auth/v2/auth`, `POST /auth/v2/enroll`, `POST /auth/v2/enroll_status` - Auth API endpoints that trigger a real user-facing MFA transaction or create an identity.

**Out of v1 scope** (not credential/provisioning, just not part of this connector's read surface - could be added later as a deliberate follow-up):
- `GET /auth/v2/ping` - unauthenticated API liveness check, no admin-relevant data.
- `GET /auth/v2/auth_status` - a poll for a live `/auth` transaction's status; no standalone utility without the excluded `/auth`/`/preauth` endpoints.
- `GET /admin/v1/admins` - the Duo administrator roster (distinct from end-user accounts). Not part of the task's requested tool categories (user/phone/token/group listing+detail, logs, integration metadata, auth-status checks).
- `GET /admin/v1/billing/*`, `GET /admin/v1/info/summary`, `GET /admin/v1/settings` - account summary/billing/settings reads.
- `GET /admin/v1/users/directorysync` - directory sync listing.
- **Accounts API (MSP)** - deprecated by Cisco as of 2026-06-11; subaccount management folded into the Admin API's billing endpoints. No separate surface exists to implement.
- **Device API** (Trusted Endpoints device cache) - uses a separate `mkey`/`skey` credential pair scoped per management-system integration, a different credential model than the account-level `ikey`/`skey` this connector is built around. Not implemented in v1; would need its own deliberate credential-shape decision if added.

They can be added as a follow-up if there's demand, after a deliberate scope decision - not by default.

## Development

```bash
npm install
npm run build
npm test
npm run lint   # tsc --noEmit
```

## Docker

The image listens on `0.0.0.0` inside the container (`MCP_HTTP_HOST`) and defaults to `AUTH_MODE=gateway`. Publish the port on loopback, pass the S2S secret, and set `MCP_TRUSTED_TLS_INGRESS=1` or the TLS file variables (see Transport security). In gateway mode, Duo credentials arrive on each request as headers; they are not read from the environment.

```bash
docker build -t cisco-duo-mcp .
docker run \
  -e CONDUIT_S2S_SECRET="$CONDUIT_S2S_SECRET" \
  -e MCP_TRUSTED_TLS_INGRESS=1 \
  -p 127.0.0.1:8080:8080 \
  cisco-duo-mcp
```

Compose refuses to start when `CONDUIT_S2S_SECRET` is unset or empty, sets `AUTH_MODE=gateway`, publishes `127.0.0.1:8080:8080`, sets `MCP_TRUSTED_TLS_INGRESS=1` (safe because the host publish is loopback-only), and does not pass `DUO_IKEY`, `DUO_SKEY`, or `DUO_API_HOST` into the container:

```bash
CONDUIT_S2S_SECRET="$CONDUIT_S2S_SECRET" docker compose up
```

Single-tenant HTTP (`AUTH_MODE=env`) still requires the S2S secret, then uses `DUO_IKEY`, `DUO_SKEY`, and `DUO_API_HOST`:

```bash
docker run \
  -e CONDUIT_S2S_SECRET="$CONDUIT_S2S_SECRET" \
  -e MCP_TRUSTED_TLS_INGRESS=1 \
  -e AUTH_MODE=env \
  -e DUO_IKEY="$DUO_IKEY" \
  -e DUO_SKEY="$DUO_SKEY" \
  -e DUO_API_HOST="$DUO_API_HOST" \
  -p 127.0.0.1:8080:8080 \
  cisco-duo-mcp
```

Local HTTP without a secret is development-only. It binds `127.0.0.1` even if `MCP_HTTP_HOST` is `0.0.0.0`, and logs a warning:

```bash
MCP_TRANSPORT=http MCP_ALLOW_INSECURE_DEV=1 npm run start:http
```
