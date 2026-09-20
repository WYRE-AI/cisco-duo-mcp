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

In gateway mode the three fields arrive per-request via `X-Duo-Ikey` / `X-Duo-Skey` / `X-Duo-Api-Host` headers, injected by the Conduit gateway. In local/stdio mode they're read once from `DUO_IKEY` / `DUO_SKEY` / `DUO_API_HOST`.

**What the credential itself can do vs. what this connector calls.** This connector's code is read-only by construction (see Scope, below), but that describes this codebase, not Duo's server-side enforcement. Duo Admin API integrations carry their own independently-configured permission grants (`Grant Read Resource`, `Grant Write Resource`, `Grant Read Log`, `Grant Read Settings`, `Grant Write Settings`, etc., set in the Duo Admin Panel when the integration is created) and Duo **does** enforce these server-side - an integration without `Grant Write Resource` gets a real authorization error from Duo itself on any write attempt, confirmed against Duo's docs and community reports of exactly that failure mode. This connector never exercises anything beyond read permissions, but the `ikey`/`skey` pair a customer supplies is only as narrowly scoped as the permissions they granted that integration in Duo - if a customer grants this integration `Grant Write Resource` (unnecessary for this connector), the credential itself would be capable of writes even though this connector's code never calls one. **Recommend granting this integration only `Grant Read Resource` (and `Grant Read Log` if the log tools are wanted) in Duo's Admin Panel** - least-privilege at the credential level, on top of this connector's own code-level restriction.

**Defensive field-stripping**: Duo's Integrations endpoints are known to echo secret-shaped fields in some read responses, and the API has no machine-readable schema to verify this exhaustively per integration type. Every response from every tool in this connector - not just Integrations - passes through `stripSecretFields()` before it ever reaches the model: any object key matching `/secret|skey/i`, at any depth, is dropped. This is a blanket safety net on top of, not instead of, the endpoint-level exclusions below.

## Configuration

| Env var | Description |
|---|---|
| `DUO_IKEY` | Duo integration key. |
| `DUO_SKEY` | Duo secret key (HMAC-SHA512 signing secret). |
| `DUO_API_HOST` | This account's Duo API hostname. |
| `MCP_TRANSPORT` | `stdio` (default) or `http`. |
| `AUTH_MODE` | `env` (default, reads the vars above) or `gateway` (credentials arrive per-request via `X-Duo-Ikey`/`X-Duo-Skey`/`X-Duo-Api-Host` headers, injected by the Conduit gateway). |
| `CONDUIT_S2S_SECRET` | When set, the HTTP transport requires a valid `X-Gateway-S2S` header (Conduit sidecar auth) on every `/mcp` request. |
| `LOG_LEVEL` | `debug` \| `info` (default) \| `warn` \| `error`. |

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

```bash
docker build -t cisco-duo-mcp .
docker run -p 8080:8080 -e DUO_IKEY=... -e DUO_SKEY=... -e DUO_API_HOST=... cisco-duo-mcp
```
