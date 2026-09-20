import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { handleLogTool } from '../tools/logs.js';
import { runWithCredentials } from '../client.js';
import { jsonResponse, textOf } from './test-helpers.js';

describe('handleLogTool', () => {
  const fetchMock = vi.fn();
  const creds = { ikey: 'DIXXXXXXXXXXXXXXXXXX', skey: 'a-real-secret-key', apiHost: 'api-xxxxxxxx.duosecurity.com' };

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock);
    fetchMock.mockReset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('duo_get_authentication_log hits the v2 path and forwards mintime/limit/next_offset', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ stat: 'OK', response: { items: [{ txid: 't1', result: 'SUCCESS' }], metadata: { next_offset: null } } })
    );

    const result = await runWithCredentials(creds, () =>
      handleLogTool('duo_get_authentication_log', { mintime: 1735689600000, limit: 50 })
    );

    const url = new URL(fetchMock.mock.calls[0][0] as string);
    expect(url.pathname).toBe('/admin/v2/logs/authentication');
    expect(url.searchParams.get('mintime')).toBe('1735689600000');
    expect(url.searchParams.get('limit')).toBe('50');
    expect(result.isError).toBeUndefined();
  });

  it('duo_get_administrator_log hits the v1 path (no v2 variant exists for this log)', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ stat: 'OK', response: [{ action: 'user_update' }] }));

    await runWithCredentials(creds, () => handleLogTool('duo_get_administrator_log', { mintime: 0 }));

    expect(new URL(fetchMock.mock.calls[0][0] as string).pathname).toBe('/admin/v1/logs/administrator');
  });

  it('duo_get_telephony_log hits the v2 path', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ stat: 'OK', response: { items: [{ context: 'authentication', credits: 1 }], metadata: {} } })
    );

    const result = await runWithCredentials(creds, () => handleLogTool('duo_get_telephony_log', {}));

    expect(new URL(fetchMock.mock.calls[0][0] as string).pathname).toBe('/admin/v2/logs/telephony');
    expect(textOf(result)).not.toMatch(/password|otp|bypass/i);
  });
});
