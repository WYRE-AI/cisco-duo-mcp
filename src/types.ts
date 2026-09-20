/**
 * Duo authenticates with a signed-request scheme (Duo Auth Signature v5,
 * HMAC-SHA512) - not OAuth2, not a bearer token. Every request is signed
 * with the integration's secret key (`skey`); the `skey` never leaves this
 * process and is never itself sent over the wire. This connector never
 * performs any OAuth-style exchange: the three credential fields below are
 * static, customer-provided values (ikey/skey pair + the account's Duo API
 * hostname), held for the lifetime of a request and used to compute a fresh
 * signature per call. See README's Authentication section and client.ts's
 * signV5() for the exact canonical-string construction.
 */
export interface DuoCredentials {
  /** Integration key - identifies the integration, sent as the Basic-auth username. Not secret. */
  ikey: string;
  /** Secret key - HMAC-SHA512 signing key. Bearer-equivalent for this integration's admin scope; never logged, never echoed back. */
  skey: string;
  /** This account's Duo API hostname, e.g. "api-xxxxxxxx.duosecurity.com". Not secret. */
  apiHost: string;
}

/** Thrown when Duo rejects the signed request (HTTP 401) - bad ikey/skey, clock skew, or a malformed signature. */
export class DuoAuthError extends Error {}

/** Thrown when Duo rate-limits the request (HTTP 429) - distinct from an auth failure. */
export class DuoRateLimitError extends Error {}

/** Thrown for any other non-2xx response, or a `{"stat":"FAIL"}` envelope on an otherwise-200 response. */
export class DuoApiError extends Error {
  constructor(message: string, readonly status?: number, readonly duoCode?: number) {
    super(message);
  }
}

export interface PageParams {
  limit?: number;
  offset?: number;
}

/** Duo's standard list envelope: { stat, response: T[], metadata: { next_offset?, total_objects? } }. */
export interface DuoListResponse<T> {
  stat: 'OK' | 'FAIL';
  response: T[];
  metadata?: { next_offset?: string; total_objects?: number; [key: string]: unknown };
  code?: number;
  message?: string;
  message_detail?: string;
}

/** Duo's standard single-object envelope: { stat, response: T }. */
export interface DuoObjectResponse<T> {
  stat: 'OK' | 'FAIL';
  response: T;
  code?: number;
  message?: string;
  message_detail?: string;
}

/** v2 log envelope: { stat, response: { items: T[], metadata: { next_offset: [string,string] | null } } }. */
export interface DuoLogV2Response<T> {
  stat: 'OK' | 'FAIL';
  response: {
    items: T[];
    metadata?: { next_offset?: [string, string] | null; total_objects?: number };
  };
  code?: number;
  message?: string;
  message_detail?: string;
}
