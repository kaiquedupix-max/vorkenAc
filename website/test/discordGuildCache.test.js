import test from 'node:test';
import assert from 'node:assert/strict';
import { createDiscordGuildCache } from '../discordGuildCache.js';

test('guild reads coalesce, isolate logins and refresh after expiry',async()=>{
  let time=0,calls=0;
  const get=createDiscordGuildCache(async key=>{calls++;return [key];},{now:()=>time});
  assert.deepEqual(await Promise.all([get('owner'),get('owner')]),[['owner'],['owner']]);assert.equal(calls,1);
  assert.deepEqual(await get('team'),['team']);assert.equal(calls,2);
  await get('owner');assert.equal(calls,2);
  time=60001;await get('owner');assert.equal(calls,3);
});
test('guild retries honor Discord cooldown and never keep authorization failures',async()=>{
  let time=0,calls=0,status=429;
  const get=createDiscordGuildCache(async()=>{calls++;if(status)throw Object.assign(new Error('Discord'),{status,retryAfter:12});return [];},{now:()=>time});
  await assert.rejects(get('a'));await assert.rejects(get('a'));assert.equal(calls,1);
  time=12001;status=401;await assert.rejects(get('a'));await assert.rejects(get('a'));assert.equal(calls,3);
  status=0;assert.deepEqual(await get('a'),[]);assert.equal(calls,4);
});
