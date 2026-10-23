import test from 'node:test';
import assert from 'node:assert/strict';
import { ensureVerifiedRole } from '../vorkenRoles.js';

function fixture(roles, features = []) {
  const created = [];
  return { id: 'guild', features, created, roles: { cache: new Map(roles.map(role => [role.id, role])), create: async data => { created.push(data); return { id: 'new', ...data }; } } };
}
test('reuses established player role instead of stored duplicate, preserving icon and members', async () => {
  const existing = { id: 'original', name: 'Jogador verificado', icon: 'custom-seal', color: 123, members: 112 };
  const guild = fixture([{ id: 'duplicate', name: '✅ Verificado' }, existing]);
  assert.equal(await ensureVerifiedRole(guild, 'duplicate'), existing);
  assert.equal(existing.icon, 'custom-seal');
  assert.equal(existing.members, 112);
  assert.equal(guild.created.length, 0);
});
test('recognizes equivalent names and preserves a configured custom role', async () => {
  for (const name of ['✅ VERIFICADO', 'Jogadores verificados', 'Verified player']) {
    const role = { id: 'role', name };
    assert.equal(await ensureVerifiedRole(fixture([role])), role);
  }
  const custom = { id: 'custom', name: 'Comunidade aprovada' };
  assert.equal(await ensureVerifiedRole(fixture([custom]), 'custom'), custom);
});
test('creates only when no equivalent exists, ignoring managed and unverified roles', async () => {
  const guild = fixture([{ id: 'guild', name: 'Verificado' }, { id: 'managed', name: 'Jogador verificado', managed: true }, { id: 'no', name: 'Não verificado' }], ['ROLE_ICONS']);
  const role = await ensureVerifiedRole(guild);
  assert.equal(guild.created.length, 1);
  assert.equal(role.name, '✅ Jogador verificado');
  assert.equal(role.color, 0x2ecc71);
  assert.equal(role.unicodeEmoji, '✅');
  assert.deepEqual(role.permissions, []);
});
