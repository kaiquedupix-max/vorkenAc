import test from 'node:test';
import assert from 'node:assert/strict';
import {buildProcessSessions} from '../processSessions.js';
import {buildProcessActivity} from '../processActivity.js';
const boot='2026-10-26T10:00:00Z',captured='2026-10-26T12:00:00Z',path='C:\\Apps\\Discord.exe';
const row=(action,timeUtc,pid='42',source='Security')=>({path,name:'Discord.exe',action,timeUtc,pid,source});
test('each recorded run retains its opening and closing time despite PID reuse',()=>{
 const sessions=buildProcessSessions([
  row('opened','2026-10-26T10:01:00Z','0x2a'),row('closed','2026-10-26T10:02:00Z'),
  row('opened','2026-10-26T11:01:00Z')
 ],boot);
 assert.equal(sessions.length,2);assert.equal(sessions[0].state,'opened');
 assert.equal(sessions[1].state,'closed');assert.equal(sessions[1].closedAtUtc,'2026-10-26T10:02:00Z');
});
test('missing close times are never invented; close-only records keep unknown start',()=>{
 const sessions=buildProcessSessions([row('opened','2026-10-26T10:01:00Z'),row('closed','2026-10-26T11:00:00Z','43')],boot);
 assert.equal(sessions.find(r=>r.pid==='42').state,'opened');assert.equal(sessions.find(r=>r.pid==='42').closedAtUtc,null);
 assert.equal(sessions.find(r=>r.pid==='43').openedAtUtc,null);
});
test('Security and Sysmon duplicate records merge into one historical execution',()=>{
 const sessions=buildProcessSessions([
  row('opened','2026-10-26T10:01:00Z'),row('closed','2026-10-26T11:00:00Z'),
  {...row('opened','2026-10-26T10:01:00.100Z','42','Sysmon'),processGuid:'guid1'},
  {...row('closed','2026-10-26T11:00:00.100Z','42','Sysmon'),processGuid:'guid1'}
 ],boot);
 assert.equal(sessions.length,1);assert.equal(sessions[0].state,'closed');
});
test('Journal records Discord opening at 07:30 and closing at 08:00 regardless of current snapshot',()=>{
 const processJournal={bootTimeUtc:'2026-10-26T06:00:00Z',capturedAtUtc:captured,collectionScope:'retained-history',events:[
  {processPath:path,processId:'42',eventId:4688,timeCreatedUtc:'2026-10-26T07:30:00Z'},
  {processPath:path,processId:'42',eventId:4689,timeCreatedUtc:'2026-10-26T08:00:00Z'}]};
 const first=buildProcessActivity({processJournal}).journal.sessions;
 const second=buildProcessActivity({processJournal,processes:[{path,pid:55,startTimeUtc:'2026-10-26T11:00:00Z'}]}).journal.sessions;
 assert.deepEqual(first,second);assert.equal(first.length,1);
 assert.equal(first[0].openedAtUtc,'2026-10-26T07:30:00Z');assert.equal(first[0].closedAtUtc,'2026-10-26T08:00:00Z');
});
test('full history includes retained events before boot; boot filter excludes those runs',()=>{
 const result=buildProcessActivity({processJournal:{bootTimeUtc:boot,capturedAtUtc:captured,collectionScope:'retained-history',events:[
  {processPath:path,processId:'1',eventId:4688,timeCreatedUtc:'2026-10-25T10:00:00Z'},
  {processPath:path,processId:'1',eventId:4689,timeCreatedUtc:'2026-10-25T11:00:00Z'},
  {processPath:path,processId:'2',eventId:4688,timeCreatedUtc:'2026-10-26T11:00:00Z'}
 ]}});
 assert.equal(result.journal.fullHistory,true);assert.equal(result.journal.sessions.length,2);
 assert.equal(result.journal.sessions.filter(r=>r.sinceBoot).length,1);
});
test('System32 filtering uses the directory reported by Windows, independent of executable name/signature',()=>{
 const processes=[{path:'D:\\OS\\System32\\WebTouch.exe'},{path:'D:\\OS\\System32\\sub\\comhost.exe'},
  {path:'C:\\Users\\Player\\Windows\\System32\\WebTouch.exe'},{path:'D:\\OS\\System32-fake\\app.exe'},
  {path:'D:\\OS\\System32\\..\\Other\\app.exe'}];
 const result=buildProcessActivity({processJournal:{systemDirectory:'D:\\OS\\System32'},processes});
 assert.equal(result.open.commonCount,2);assert.equal(result.open.items.length,3);
 assert.equal(buildProcessActivity({processes:[{path:'C:\\Windows\\System32\\WebTouch.exe'}]}).open.items.length,0);
});
test('legacy reports hide unsigned System32 processes from snapshots and both Journal periods',()=>{
 const events=['conhost.exe','wevtutil.exe'].map((name,index)=>({processPath:'C:\\Windows\\System32\\'+name,processId:String(index+1),eventId:5,timeCreatedUtc:'2026-10-26T11:00:00Z',signed:false}));
 const result=buildProcessActivity({processes:events.map(row=>({path:row.processPath,pid:row.processId,signed:false})),processJournal:{bootTimeUtc:boot,capturedAtUtc:captured,collectionScope:'retained-history',events}});
 assert.equal(result.open.items.length,0);assert.equal(result.journal.items.length,0);assert.equal(result.journal.sessions.length,0);
 const copies=buildProcessActivity({processes:[{path:'C:\\Users\\Player\\Windows\\System32\\conhost.exe'},{path:'C:\\Windows\\System32-copy\\wevtutil.exe'}]});
 assert.equal(copies.open.items.length,2);
});
