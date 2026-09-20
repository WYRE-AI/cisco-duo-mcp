import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { handleIntegrationTool } from '../tools/integrations.js';
import { runWithCredentials } from '../client.js';
import { duoList, duoObject, jsonResponse, textOf } from './test-helpers.js';

describe('handleIntegrationTool - secret-field stripping', () => {
  const fetchMock = vi.fn();
  const creds = { ikey: 'DIXXXXXXXXXXXXXXXXXX', skey: 'a-real-secret-key', apiHost: 'api-xxxxxxxx.duosecurity.com' };

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock);
    fetchMock.mockReset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('duo_get_integration strips a secret_key field even if Duo echoes one in the raw response', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(
        duoObject({
          integration_key: 'DIABCDEF0123456789AB',
          secret_key: 'LEAKED-SECRET-SHOULD-NEVER-REACH-THE-MODEL',
          name: 'Okta SSO',
          type: 'ssoconfig',
        })
      )
    );

    const result = await runWithCredentials(creds, () =>
      handleIntegrationTool('duo_get_integration', { integrationKey: 'DIABCDEF0123456789AB' })
    );

    expect(new URL(fetchMock.mock.calls[0][0] as string).pathname).toBe('/admin/v3/integrations/DIABCDEF0123456789AB');
    const text = textOf(result);
    expect(text).not.toMatch(/LEAKED-SECRET/);
    const parsed = JSON.parse(text);
    expect(parsed.response.secret_key).toBeUndefined();
    expect(parsed.response.name).toBe('Okta SSO');
  });

  it('duo_list_integrations strips secret fields from every item in a list response', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(
        duoList([
          { integration_key: 'DI1', skey: 'LEAKED-1', name: 'App One' },
          { integration_key: 'DI2', secret_key: 'LEAKED-2', name: 'App Two' },
        ])
      )
    );

    const result = await runWithCredentials(creds, () => handleIntegrationTool('duo_list_integrations', {}));

    const text = textOf(result);
    expect(text).not.toMatch(/LEAKED-1|LEAKED-2/);
    const parsed = JSON.parse(text);
    expect(parsed.response).toHaveLength(2);
    expect(parsed.response[0].skey).toBeUndefined();
    expect(parsed.response[1].secret_key).toBeUndefined();
  });
});
