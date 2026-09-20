import { describe, expect, it } from 'vitest';
import { ALL_TOOLS } from '../tools/index.js';

/**
 * This test is the connector's hard backstop against scope creep. Cisco
 * Duo is an identity/MFA administration product - the two most dangerous
 * classes of endpoint (bypass-code exposure and account/policy mutation)
 * must never be reachable through this server, ever, even by an
 * unreviewed future change. If this test starts failing because someone
 * added a new tool, that is a signal to re-read README's Scope section,
 * not to update the expected list.
 */
describe('ALL_TOOLS - exact set, no bypass/delete/disassociate/mutation tool', () => {
  it('exposes exactly these 22 read-only tools - nothing more, nothing less', () => {
    const names = ALL_TOOLS.map((t) => t.name).sort();
    expect(names).toEqual(
      [
        'duo_check_credentials',
        'duo_get_administrator_log',
        'duo_get_authentication_log',
        'duo_get_desktop_token',
        'duo_get_group',
        'duo_get_hardware_token',
        'duo_get_integration',
        'duo_get_phone',
        'duo_get_telephony_log',
        'duo_get_user',
        'duo_list_desktop_tokens',
        'duo_list_group_users',
        'duo_list_groups',
        'duo_list_hardware_tokens',
        'duo_list_integrations',
        'duo_list_phones',
        'duo_list_user_groups',
        'duo_list_user_phones',
        'duo_list_user_tokens',
        'duo_list_user_u2f_tokens',
        'duo_list_user_webauthn_credentials',
        'duo_list_users',
      ].sort()
    );
  });

  it('never names a bypass-code, delete, disassociate, mutation, or enrollment tool', () => {
    for (const tool of ALL_TOOLS) {
      expect(tool.name).not.toMatch(/bypass|delete|disassociate|deactivate|revoke|enroll|create|update|add_|reset|resync|activate|settings/i);
    }
  });

  it('every tool description reads as a read (get/list/check), never a write verb', () => {
    for (const tool of ALL_TOOLS) {
      expect(tool.name).toMatch(/^duo_(list|get|check)_?/);
    }
  });
});
