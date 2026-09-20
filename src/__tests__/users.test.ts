import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { handleUserTool } from '../tools/users.js';
import { runWithCredentials } from '../client.js';
import { duoList, duoObject, jsonResponse, textOf } from './test-helpers.js';

describe('handleUserTool', () => {
  const fetchMock = vi.fn();
  const creds = { ikey: 'DIXXXXXXXXXXXXXXXXXX', skey: 'a-real-secret-key', apiHost: 'api-xxxxxxxx.duosecurity.com' };

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock);
    fetchMock.mockReset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('duo_list_users signs the request with Basic auth and sends the username filter', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(duoList([{ user_id: 'U1', username: 'alice' }])));

    const result = await runWithCredentials(creds, () => handleUserTool('duo_list_users', { username: 'alice' }));

    expect(result.isError).toBeUndefined();
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const parsed = new URL(url);
    expect(parsed.pathname).toBe('/admin/v1/users');
    expect(parsed.searchParams.get('username')).toBe('alice');
    expect((init.headers as Record<string, string>).Authorization.startsWith('Basic ')).toBe(true);
    expect(JSON.parse(textOf(result)).response[0].username).toBe('alice');
  });

  it('duo_get_user requests the exact user_id path', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(duoObject({ user_id: 'U1', username: 'alice', status: 'active' })));

    const result = await runWithCredentials(creds, () => handleUserTool('duo_get_user', { userId: 'U1' }));

    expect(new URL(fetchMock.mock.calls[0][0] as string).pathname).toBe('/admin/v1/users/U1');
    expect(JSON.parse(textOf(result)).response.status).toBe('active');
  });

  it('duo_list_user_phones scopes to the given user and never exposes a phone_users reverse-lookup tool', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(duoList([{ phone_id: 'P1', number: '+15555550100' }])));

    const result = await runWithCredentials(creds, () => handleUserTool('duo_list_user_phones', { userId: 'U1' }));

    expect(new URL(fetchMock.mock.calls[0][0] as string).pathname).toBe('/admin/v1/users/U1/phones');
    expect(result.isError).toBeUndefined();
  });

  it('surfaces a 401 as a readable auth error rather than throwing', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ message: 'invalid signature' }, 401));

    const result = await runWithCredentials(creds, () => handleUserTool('duo_get_user', { userId: 'U1' }));

    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/rejected the signed request/i);
  });

  it('surfaces a stat:FAIL 200 response as an error, not a silent success', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ stat: 'FAIL', code: 40002, message: 'Invalid request parameters' }, 200));

    const result = await runWithCredentials(creds, () => handleUserTool('duo_get_user', { userId: 'nonexistent' }));

    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/Invalid request parameters/);
  });

  it('returns a credential error without calling fetch when no credentials are configured', async () => {
    const result = await handleUserTool('duo_list_users', {});

    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/DUO_IKEY/);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
