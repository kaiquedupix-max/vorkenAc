import test from 'node:test';
import assert from 'node:assert/strict';
import {applyDiscordBan} from '../discordBans.js';
import {publicNotice} from '../vorkenSettings.js';

test('association banfeed distinguishes teammates from confirmed offenders', () => {
  const embed=publicNotice('public_ban',{kind:'association',playerName:'Duo',steamId:'76561198000000061',sourceSteamId:'76561198000000060',sourcePlayerName:'Origem',duration:'7 dia(s)',reason:'Associação',serverName:'Rust'});
  assert.match(embed.title,/associação/);
  assert.match(embed.description,/temporário/);
  assert.equal(embed.fields.find(f=>f.name==='Duração').value,String.raw`7 dia\(s\)`);
  assert.match(embed.fields.find(f=>f.name==='Jogador de origem').value,/Origem/);
  assert.equal(publicNotice('public_ban',{playerName:'Principal'}).title,'🔨 Banimento aplicado');
});

test('Discord ban uses only a linked account in the originating guild and server', async () => {
  let called;
  const db={query:async(sql,params)=>{
    assert.match(sql,/s.guild_id=\$2/);
    assert.match(sql,/v.server_id=\$1/);
    assert.deepEqual(params,[42,'123456789012345678','76561198000000001']);
    return {rows:[{discord_user_id:'234567890123456789'}]};
  }};
  const guild={id:'123456789012345678',members:{ban:async(...args)=>{called=args;}}};
  assert.equal(await applyDiscordBan(db,guild,42,'76561198000000001','Recusa'),true);
  assert.equal(called[0],'234567890123456789');
  assert.equal(called[1].deleteMessageSeconds,0);
  assert.match(called[1].reason,/Recusa/);
});

test('missing or invalid Discord link never targets an account; API failures remain retryable', async () => {
  const guild={id:'123456789012345678',members:{ban:async()=>{throw Error('Missing Permissions');}}};
  for(const rows of [[],[{discord_user_id:'invalid'}]])
    assert.equal(await applyDiscordBan({query:async()=>({rows})},guild,42,'76561198000000001','Ban'),false);
  await assert.rejects(applyDiscordBan({query:async()=>({rows:[{discord_user_id:'234567890123456789'}]})},guild,42,'76561198000000001','Ban'),/Missing Permissions/);
});
