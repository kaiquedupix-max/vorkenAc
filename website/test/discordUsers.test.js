import test from 'node:test';
import assert from 'node:assert/strict';
import {createDiscordUserLookup} from '../discordUsers.js';
const id='981331661461536799';
test('resolves public identity, keeps snowflake precision and deduplicates lookups',async()=>{
  let calls=0,time=0;
  const lookup=createDiscordUserLookup({token:()=> 'secret',now:()=>time,ttl:100,fetchImpl:async(url,options)=>{
    calls++;assert.equal(url,'https://discord.com/api/v10/users/'+id);
    assert.equal(options.headers.Authorization,'Bot secret');
    return {ok:true,json:async()=>({id,username:'example',global_name:'Example',email:'private'})};
  }});
  const [a,b]=await Promise.all([lookup(id),lookup(id)]);
  assert.deepEqual(a,{id,username:'example',displayName:'Example',profileUrl:'https://discord.com/users/'+id});
  assert.equal(a,b);assert.equal(calls,1);
  await lookup(id);assert.equal(calls,1);
  time=101;await lookup(id);assert.equal(calls,2);
});
test('invalid IDs, missing credentials and API failures preserve access',async()=>{
  let calls=0;
  const fetchImpl=async()=>{calls++;throw Error('offline')};
  const missing=createDiscordUserLookup({token:()=>'',fetchImpl});
  assert.equal(await missing(id),null);assert.equal(calls,0);
  const lookup=createDiscordUserLookup({token:()=> 'secret',fetchImpl});
  assert.equal(await lookup('../@me'),null);assert.equal(calls,0);
  assert.equal(await lookup(id),null);assert.equal(await lookup(id),null);assert.equal(calls,1);
});
test('rate limits pause further lookups and recover afterwards',async()=>{
  let time=0,calls=0;
  const lookup=createDiscordUserLookup({token:()=> 'secret',now:()=>time,fetchImpl:async()=>{
    calls++;return {status:429,json:async()=>({retry_after:2})};
  }});
  assert.equal(await lookup(id),null);
  assert.equal(await lookup('981331661461536798'),null);assert.equal(calls,1);
  time=2001;await lookup('981331661461536798');assert.equal(calls,2);
});
