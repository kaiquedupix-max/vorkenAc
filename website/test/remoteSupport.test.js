import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile,readdir,access} from 'node:fs/promises';
const root=new URL('../../',import.meta.url);
test('remote capture and input implementation is removed from shipped source',async()=>{
 for(const file of ['agent/RemoteSupportClient.cs','website/remoteSupport.js']) await assert.rejects(access(new URL(file,root)));
 const server=await readFile(new URL('website/server.js',root),'utf8');
 assert.ok(!server.includes('installRemoteSupport('));assert.ok(server.includes('remote_support_removed'));
 const ui=await readFile(new URL('website/public/admin.html',root),'utf8');assert.ok(!ui.includes('id="remoteAdminsPanel"'));
});
test('agent has no process memory reader, module enumeration or remote input API',async()=>{
 for(const name of (await readdir(new URL('agent/',root))).filter(n=>n.endsWith('.cs'))){
  const source=await readFile(new URL('agent/'+name,root),'utf8');
  assert.doesNotMatch(source,/\b(?:ReadProcessMemory|OpenProcess|VirtualQueryEx|SendInput|CopyFromScreen|GetWindowDisplayAffinity|EnumWindows)\s*\(|\.MainModule\b|\.Modules\b/,name);
 }
});
