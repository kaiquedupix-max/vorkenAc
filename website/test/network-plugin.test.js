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

test('generated unban checks the current ban and remains available for inactive installations',()=>{
  const source=fs.readFileSync(new URL('../plugins/Vorken.cs',import.meta.url),'utf8');
  const start=source.indexOf('else if (command.action == "unban")');
  const block=source.slice(start,source.indexOf('else if (command.action == "ban_prior")',start));
  assert(start>0);assert.match(block,/Array.IndexOf\(command.expectedReasons, user.notes\)/);
  assert.match(block,/ServerUsers.Remove\(steamId\)/);assert.match(block,/ServerUsers.Save\(\)/);
  assert.match(source,/cleanup.action == "unban"/);assert.match(source,/version = "2.0.11"/);
});
