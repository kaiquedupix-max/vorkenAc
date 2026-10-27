import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFileSync} from 'node:fs';
import {Collection,OverwriteType,PermissionFlagsBits as P,PermissionOverwrites,PermissionsBitField} from 'discord.js';

const source=readFileSync(new URL('../vorkenBot.js',import.meta.url),'utf8');
const guildId='111111111111111111',botId='222222222222222222',staffId='333333333333333333';
const guild={id:guildId,roles:{cache:new Collection([[staffId,{id:staffId,permissions:new PermissionsBitField(P.BanMembers)}]]),resolve:()=>null},client:{users:{resolve:()=>null}}};
const context={guild,botId,staffRoles:guild.roles.cache,client:{user:{id:botId}},P,OverwriteType,
 session:{discord_user_id:'444444444444444444'},admin:{id:'555555555555555555'}};

test('SDK reproduces the reported error for an uncached user without overwrite type',()=>{
 assert.throws(()=>PermissionOverwrites.resolve({id:context.session.discord_user_id,allow:[P.ViewChannel]},guild),/cached User or Role/);
});
test('actual channel and ticket permission definitions resolve with empty Discord user and role caches',()=>{
 const definitions=[...source.matchAll(/const (privateOverwrites|overwrites)=(\[[\s\S]*?\]);/g)];
 assert.equal(definitions.length,2);
 for(const [,name,expression] of definitions){
  let script=`const ${name}=${expression};`;
  if(name==='overwrites'){
   for(const match of source.matchAll(/if\((?:session\.discord_user_id|admin\.id)[^\n]+overwrites\.push\([^\n]+/g))script+=match[0]+'\n';
  }
  const rows=vm.runInNewContext(script+name,context);
  const resolved=rows.map(row=>PermissionOverwrites.resolve(row,guild));
  assert.equal(resolved.find(row=>row.id===guildId).deny,String(P.ViewChannel));
  assert.equal(resolved.find(row=>row.id===botId).type,OverwriteType.Member);
  assert.equal(resolved.find(row=>row.id===staffId).type,OverwriteType.Role);
  if(name==='overwrites')for(const id of [context.session.discord_user_id,context.admin.id])assert.equal(resolved.find(row=>row.id===id).type,OverwriteType.Member);
 }
});
