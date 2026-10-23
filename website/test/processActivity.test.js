import test from 'node:test';
import assert from 'node:assert/strict';
import {buildProcessActivity} from '../processActivity.js';
import {projectReportPayloadForAdmin} from '../reportPayloadProjection.js';
const bootTimeUtc='2026-10-23T10:00:00Z',capturedAtUtc='2026-10-23T12:00:00Z';
test('common components require trusted signature and location; scripts remain visible',()=>{
 const result=buildProcessActivity({processes:[{name:'svchost.exe',path:'C:\\Windows\\System32\\svchost.exe',signed:true,signerSubject:'Microsoft Corporation'},{name:'svchost.exe',path:'C:\\Temp\\svchost.exe',signed:true,signerSubject:'Microsoft Corporation'},{name:'powershell.exe',path:'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',signed:true,signerSubject:'Microsoft Corporation'}]});
 assert.equal(result.open.commonCount,1);assert.equal(result.open.items.length,2);
});
test('game and EAC excluded; excluded parent metadata not exposed',()=>{
 const result=buildProcessActivity({processes:[{name:'RustClient.exe'},{path:'C:\\SteamLibrary\\steamapps\\common\\OtherName\\x.dll'},{path:'C:\\Program Files\\EasyAntiCheat_EOS\\x.exe'},{path:'C:\\Tools\\app.exe',parentProcessName:'Rust.exe',parentProcessPath:'C:\\Rust\\Rust.exe',commandLine:'secret'}]});
 assert.equal(result.open.excludedCount,3);assert.equal(result.open.items.length,1);assert.equal(result.open.items[0].parentName,'');assert.equal(result.open.items[0].parentPath,'');assert.ok(!('commandLine' in result.open.items[0]));
});
test('Journal enforces this boot window and discloses source limitations',()=>{
 const row=timeCreatedUtc=>({processPath:'C:\\Tools\\app.exe',timeCreatedUtc});
 const result=buildProcessActivity({processJournal:{bootTimeUtc,capturedAtUtc,events:[row('2026-10-22T12:00:00Z'),row('2026-10-23T11:00:00Z'),row('2026-10-23T13:00:00Z')],sources:[{state:'available',limitReached:true}]}});
 assert.equal(result.journal.items.length,1);assert.equal(result.journal.coverage,'limited');
 assert.equal(buildProcessActivity({processCreationEvents:[row('2026-10-23T11:00:00Z')]}).journal.coverage,'legacy');
});
test('projection retains all relevant rows and correlation overrides common suppression',()=>{
 const processes=Array.from({length:80},(_,pid)=>({pid,path:'C:\\Tools\\app'+pid+'.exe'}));
 assert.equal(projectReportPayloadForAdmin({processes}).processActivity.open.items.length,80);
 const item={name:'svchost.exe',path:'C:\\Windows\\System32\\svchost.exe',signed:true,signerSubject:'Microsoft Corporation'};
 assert.equal(buildProcessActivity({processes:[item]},[{severity:'high',artifact_value:item.path}]).open.items.length,1);
});
