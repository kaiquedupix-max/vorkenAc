import test from 'node:test';
import assert from 'node:assert/strict';
import { communityVerificationEmbed,instructionMessagesToRemove } from '../vorkenInstructions.js';
import { verificationEmbed } from '../vorkenSettings.js';

test('one Rust server preserves its complete rules; multiple servers share community instructions without mixing rules',()=>{
 const servers=[{id:'a',name:'Guerra Fria 2',verification_settings:{rules:'REGRA DOIS',timeoutSeconds:300}},{id:'b',name:'Guerra Fria Trio',verification_settings:{rules:'REGRA TRIO',timeoutSeconds:600}}];
 assert.deepEqual(communityVerificationEmbed([servers[0]],'Guerra Fria'),verificationEmbed(servers[0]));
 for(const lang of ['pt','en','es']){const shared=communityVerificationEmbed(servers,'Guerra Fria',lang);assert(shared.title.includes('Guerra Fria'));assert(!shared.description.includes('REGRA DOIS'));assert(!shared.description.includes('REGRA TRIO'));assert(!shared.description.includes('⏱️'));assert(shared.fields[0].value.includes('Guerra Fria 2'));assert(shared.fields[0].value.includes('Guerra Fria Trio'));}
 assert(verificationEmbed(servers[1]).description.includes('10 minutos'));
});

test('instruction consolidation only removes this bot duplicates and preserves players, other bots and unrelated messages',()=>{
 const msg=(id,author,customId)=>({id,author:{id:author},components:customId?[{components:[{customId}]}]:[]});
 const messages=[msg('keep','vorken','vorken_guild_lang:pt:g'),msg('old','vorken','vorken_lang:pt:s'),msg('known','vorken'),msg('player','player','vorken_lang:pt:s'),msg('other-bot','other','vorken_lang:pt:s'),msg('ticket','vorken','vorken_ticket_lang:pt:s'),msg('notice','vorken')];
 assert.deepEqual(instructionMessagesToRemove(messages,'vorken','keep',['known','player','other-bot']).map(m=>m.id),['old','known']);
});
