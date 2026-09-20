import { AsyncLocalStorage } from 'node:async_hooks';
import { createHash, createHmac } from 'node:crypto';
import { logger } from './utils/logger.js';
import { DuoApiError, DuoAuthError, DuoRateLimitError } from './types.js';
import type { DuoCredentials, DuoListResponse, DuoLogV2Response, DuoObjectResponse, PageParams } from './types.js';

// Request-scoped credential store. In gateway mode the HTTP layer runs each
// request inside runWithCredentials({ikey,skey,apiHost}); getCredentials()
// reads from it. Falls back to process.env for stdio/single-tenant mode.
const credStore = new AsyncLocalStorage<DuoCredentials>();

export function runWithCredentials<T>(creds: DuoCredentials, fn: () => T): T {
  return credStore.run(creds, fn);
}

export function getCredentials(): DuoCredentials | null {
  const scoped = credStore.getStore();
  if (scoped?.ikey && scoped?.skey && scoped?.apiHost) return scoped;
  const ikey = process.env.DUO_IKEY;
  const skey = process.env.DUO_SKEY;
  const apiHost = process.env.DUO_API_HOST;
  if (!ikey || !skey || !apiHost) {
    logger.warn('Missing credentials', { hasIkey: !!ikey, hasSkey: !!skey, hasApiHost: !!apiHost });
    return null;
  }
  return { ikey, skey, apiHost };
}

// ---------------------------------------------------------------------
// Duo Auth Signature v5 (HMAC-SHA512) - see README's Authentication
// section for the full write-up and a link to Duo's docs. This is the
// current recommended signing method; the legacy v2 (HMAC-SHA1, 5-line
// canonical string, no body/header hashing) is intentionally not
// implemented here.
//
// Canonical string is 7 lines, joined by "\n":
//   1. Date - RFC 2822, byte-identical to the Date header sent.
//   2. HTTP method, uppercase.
//   3. API hostname, lowercase.
//   4. Request path.
//   5. URL-encoded "key=value" query params, lexicographically sorted
//      (blank line if none).
//   6. SHA-512 hex digest of the request body (this connector is
//      GET-only, so always the digest of the empty string).
//   7. SHA-512 hex digest of the canonicalized set of additional
//      X-Duo-* signed headers (this connector signs none, so always
//      the digest of the empty string).
//
// Signature = hex(HMAC-SHA512(skey, canonical_string)).
// Authorization: Basic base64(ikey:signature).
// ---------------------------------------------------------------------

function sha512Hex(input: string): string {
  return createHash('sha512').update(input, 'utf8').digest('hex');
}

/** RFC 2822 date string, byte-identical in format to Duo's own example ("Tue, 21 Aug 2012 17:29:18 -0000"). */
function rfc2822Date(now: Date = new Date()): string {
  return now.toUTCString().replace('GMT', '-0000');
}

/** URL-encodes and lexicographically sorts query params into Duo's canonical "key=value&key=value" form. */
function canonicalParams(params: Record<string, unknown> = {}): string {
  const pairs: string[] = [];
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue;
    pairs.push(`${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`);
  }
  pairs.sort();
  return pairs.join('&');
}

interface SignedRequest {
  url: string;
  headers: Record<string, string>;
}

/** Builds a Duo v5-signed GET request. Exported for direct unit testing of the signing math. */
export function signV5Get(creds: DuoCredentials, path: string, params: Record<string, unknown> = {}): SignedRequest {
  const date = rfc2822Date();
  const host = creds.apiHost.toLowerCase();
  const query = canonicalParams(params);
  const bodyHash = sha512Hex(''); // GET requests never carry a body
  const headersHash = sha512Hex(''); // no additional X-Duo-* signed headers used
  // Duo's 7-line v5 canonical string, joined by "\n": date, method, host,
  // path, sorted query params, body hash, signed-headers hash.
  const canonical = [date, 'GET', host, path, query, bodyHash, headersHash].join('\n');
  const signature = createHmac('sha512', creds.skey).update(canonical, 'utf8').digest('hex');
  const authorization = 'Basic ' + Buffer.from(`${creds.ikey}:${signature}`).toString('base64');
  const qs = query ? `?${query}` : '';
  return {
    url: `https://${host}${path}${qs}`,
    headers: { Authorization: authorization, Date: date, Accept: 'application/json' },
  };
}

// ---------------------------------------------------------------------
// Defensive field-stripping. Duo's Admin API is not documented via a
// machine-readable OpenAPI spec, and at least one endpoint family
// (Integrations) is known to echo secret-shaped fields in its read
// response for some integration types. Rather than special-case one
// endpoint, every response from this connector is passed through this
// stripper before it ever reaches the model - any key matching /secret|skey/i
// is dropped, recursively, at any depth. This is a blanket safety net,
// not a substitute for the hard endpoint-level exclusions in README.
// ---------------------------------------------------------------------
const SECRET_FIELD_RE = /(secret|skey)/i;

export function stripSecretFields<T>(value: T): T {
  if (Array.isArray(value)) {
    return value.map((item) => stripSecretFields(item)) as unknown as T;
  }
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [key, v] of Object.entries(value as Record<string, unknown>)) {
      if (SECRET_FIELD_RE.test(key)) continue;
      out[key] = stripSecretFields(v);
    }
    return out as T;
  }
  return value;
}

async function doGet<T>(creds: DuoCredentials, path: string, params: Record<string, unknown> = {}): Promise<T> {
  const { url, headers } = signV5Get(creds, path, params);
  const res = await fetch(url, { method: 'GET', headers, signal: AbortSignal.timeout(15_000) });

  // 401 (bad ikey/skey/signature/clock-skew) and 429 (rate-limited) are
  // distinct failure modes with distinct remediations - grouping them
  // under one generic auth-error class hides a transient rate limit
  // behind a message that reads like bad credentials.
  if (res.status === 401) {
    throw new DuoAuthError(`Duo rejected the signed request (HTTP 401): ${path}`);
  }
  if (res.status === 429) {
    throw new DuoRateLimitError(`Duo rate-limited the request (HTTP 429): ${path}`);
  }
  if (!res.ok) {
    throw new DuoApiError(`Duo ${path} failed: HTTP ${res.status}`, res.status);
  }

  const json = (await res.json()) as { stat?: string; code?: number; message?: string; message_detail?: string };
  if (json.stat === 'FAIL') {
    throw new DuoApiError(
      `Duo ${path} failed: ${json.message || 'unknown error'}${json.message_detail ? ` (${json.message_detail})` : ''}`,
      res.status,
      json.code
    );
  }
  return stripSecretFields(json as T);
}

// ---------------------------------------------------------------------
// Users - GET /admin/v1/users/...
// ---------------------------------------------------------------------

export interface ListUsersParams extends PageParams {
  username?: string;
}

export async function listUsers(creds: DuoCredentials, params: ListUsersParams = {}): Promise<DuoListResponse<unknown>> {
  return doGet(creds, '/admin/v1/users', { ...params });
}

export async function getUser(creds: DuoCredentials, userId: string): Promise<DuoObjectResponse<unknown>> {
  return doGet(creds, `/admin/v1/users/${encodeURIComponent(userId)}`);
}

export async function listUserGroups(
  creds: DuoCredentials,
  userId: string,
  params: PageParams = {}
): Promise<DuoListResponse<unknown>> {
  return doGet(creds, `/admin/v1/users/${encodeURIComponent(userId)}/groups`, { ...params });
}

export async function listUserPhones(
  creds: DuoCredentials,
  userId: string,
  params: PageParams = {}
): Promise<DuoListResponse<unknown>> {
  return doGet(creds, `/admin/v1/users/${encodeURIComponent(userId)}/phones`, { ...params });
}

export async function listUserTokens(
  creds: DuoCredentials,
  userId: string,
  params: PageParams = {}
): Promise<DuoListResponse<unknown>> {
  return doGet(creds, `/admin/v1/users/${encodeURIComponent(userId)}/tokens`, { ...params });
}

export async function listUserWebauthnCredentials(
  creds: DuoCredentials,
  userId: string,
  params: PageParams = {}
): Promise<DuoListResponse<unknown>> {
  return doGet(creds, `/admin/v1/users/${encodeURIComponent(userId)}/webauthncredentials`, { ...params });
}

export async function listUserU2fTokens(
  creds: DuoCredentials,
  userId: string,
  params: PageParams = {}
): Promise<DuoListResponse<unknown>> {
  return doGet(creds, `/admin/v1/users/${encodeURIComponent(userId)}/u2ftokens`, { ...params });
}

// ---------------------------------------------------------------------
// Phones - GET /admin/v1/phones/...
// ---------------------------------------------------------------------

export interface ListPhonesParams extends PageParams {
  number?: string;
  extension?: string;
}

export async function listPhones(creds: DuoCredentials, params: ListPhonesParams = {}): Promise<DuoListResponse<unknown>> {
  return doGet(creds, '/admin/v1/phones', { ...params });
}

export async function getPhone(creds: DuoCredentials, phoneId: string): Promise<DuoObjectResponse<unknown>> {
  return doGet(creds, `/admin/v1/phones/${encodeURIComponent(phoneId)}`);
}

// ---------------------------------------------------------------------
// Hardware tokens - GET /admin/v1/tokens/... (note: NOT /hardware_tokens -
// that path does not exist in Duo's API; verified against duo_client_python)
// ---------------------------------------------------------------------

export interface ListHardwareTokensParams extends PageParams {
  type?: string;
  serial?: string;
}

export async function listHardwareTokens(
  creds: DuoCredentials,
  params: ListHardwareTokensParams = {}
): Promise<DuoListResponse<unknown>> {
  return doGet(creds, '/admin/v1/tokens', { ...params });
}

export async function getHardwareToken(creds: DuoCredentials, tokenId: string): Promise<DuoObjectResponse<unknown>> {
  return doGet(creds, `/admin/v1/tokens/${encodeURIComponent(tokenId)}`);
}

// ---------------------------------------------------------------------
// Desktop tokens - GET /admin/v1/desktoptokens/...
// ---------------------------------------------------------------------

export async function listDesktopTokens(creds: DuoCredentials, params: PageParams = {}): Promise<DuoListResponse<unknown>> {
  return doGet(creds, '/admin/v1/desktoptokens', { ...params });
}

export async function getDesktopToken(creds: DuoCredentials, desktoptokenId: string): Promise<DuoObjectResponse<unknown>> {
  return doGet(creds, `/admin/v1/desktoptokens/${encodeURIComponent(desktoptokenId)}`);
}

// ---------------------------------------------------------------------
// Groups - GET /admin/v1/groups/..., GET /admin/v2/groups/{id}/users
// ---------------------------------------------------------------------

export async function listGroups(creds: DuoCredentials, params: PageParams = {}): Promise<DuoListResponse<unknown>> {
  return doGet(creds, '/admin/v1/groups', { ...params });
}

export async function getGroup(creds: DuoCredentials, groupId: string): Promise<DuoObjectResponse<unknown>> {
  return doGet(creds, `/admin/v1/groups/${encodeURIComponent(groupId)}`);
}

/** Duo's own reference client uses the v2 path specifically for this one sub-resource. */
export async function listGroupUsers(
  creds: DuoCredentials,
  groupId: string,
  params: PageParams = {}
): Promise<DuoListResponse<unknown>> {
  return doGet(creds, `/admin/v2/groups/${encodeURIComponent(groupId)}/users`, { ...params });
}

// ---------------------------------------------------------------------
// Integrations - GET /admin/v3/integrations/... (metadata only; the
// response passes through stripSecretFields() same as every other call,
// as a defensive measure since Duo's Integrations schema is not fully
// documented in machine-readable form for every integration type).
// ---------------------------------------------------------------------

export async function listIntegrations(creds: DuoCredentials, params: PageParams = {}): Promise<DuoListResponse<unknown>> {
  return doGet(creds, '/admin/v3/integrations', { ...params });
}

export async function getIntegration(creds: DuoCredentials, integrationKey: string): Promise<DuoObjectResponse<unknown>> {
  return doGet(creds, `/admin/v3/integrations/${encodeURIComponent(integrationKey)}`);
}

// ---------------------------------------------------------------------
// Logs
// ---------------------------------------------------------------------

export interface GetAuthenticationLogParams {
  mintime: number;
  maxtime?: number;
  limit?: number;
  next_offset?: string;
  sort?: 'asc' | 'desc';
}

/** GET /admin/v2/logs/authentication - the current (v2) authentication log, richer filtering than v1. */
export async function getAuthenticationLog(
  creds: DuoCredentials,
  params: GetAuthenticationLogParams
): Promise<DuoLogV2Response<unknown>> {
  return doGet(creds, '/admin/v2/logs/authentication', { ...params });
}

export interface GetAdministratorLogParams {
  mintime?: number;
}

/** GET /admin/v1/logs/administrator - no v2 variant exists for this log. */
export async function getAdministratorLog(
  creds: DuoCredentials,
  params: GetAdministratorLogParams = {}
): Promise<DuoListResponse<unknown>> {
  return doGet(creds, '/admin/v1/logs/administrator', { ...params });
}

export interface GetTelephonyLogParams {
  mintime?: number;
  maxtime?: number;
  limit?: number;
  next_offset?: string;
}

/** GET /admin/v2/logs/telephony - the current (v2) telephony log. */
export async function getTelephonyLog(
  creds: DuoCredentials,
  params: GetTelephonyLogParams = {}
): Promise<DuoLogV2Response<unknown>> {
  return doGet(creds, '/admin/v2/logs/telephony', { ...params });
}

// ---------------------------------------------------------------------
// Auth API - GET /auth/v2/check. Same host, same v5 signing scheme as the
// Admin API. A lightweight, side-effect-free credential/connectivity
// check - it does not initiate any MFA transaction. duo_ping and
// auth_status are deliberately not implemented; see README's Scope
// section.
// ---------------------------------------------------------------------

export async function checkCredentials(creds: DuoCredentials): Promise<DuoObjectResponse<{ time: number }>> {
  return doGet(creds, '/auth/v2/check');
}
