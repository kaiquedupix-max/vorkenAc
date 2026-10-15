import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

test('generated network bridge has one consumer and never cascades association bans',()=>{
  const source=fs.readFileSync(new URL('../plugins/Vorken.cs',import.meta.url),'utf8');
  assert.equal(source.match(/public List<BridgeNetworkBan> networkBans;/g)?.length,1);
  assert.equal(source.match(/foreach \(BridgeNetworkBan ban in data.networkBans\)/g)?.length,1);
  const apply=source.slice(source.indexOf('private void ApplyNetworkBan('),source.indexOf('private void Init()'));
  assert.match(apply,/ServerUsers.Set\(steamId, ServerUsers.UserGroup.Banned, name, ban.reason, expiry\)/);
  assert.match(apply,/existing.expiry <= 0/);
  assert(!apply.includes('SetVorkenBan('));
  assert(!apply.includes('bridge.Events.Add'));
});
