import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {withDownloadOrigins} from '../evidenceOrigins.js';
import {projectFindingEvidenceForAdmin} from '../reportPayloadProjection.js';

test('executable evidence includes download origin only for its full Windows path',()=>{
  const finding={artifact_value:'C:\\Users\\Test\\Downloads\\random.exe',evidence:{note:'Executed'}};
  const payload={browserDownloads:[
    {targetPath:'c:/users/test/downloads/RANDOM.exe',sourceUrl:'https://example.com/file',browser:'Edge',profile:'Default',urlChain:['https://example.com/start']},
    {targetPath:'C:\\Other\\random.exe',sourceUrl:'https://wrong.example/file'},
    {fileName:'random.exe',sourceUrl:'https://unproven.example/file'}
  ]};
  const result=projectFindingEvidenceForAdmin(withDownloadOrigins(finding,payload));
  assert.equal(result.note,'Executed');assert.equal(result.downloadOrigins.length,1);
  assert.equal(result.downloadOrigins[0].sourceUrl,'https://example.com/file');
  assert.equal(finding.evidence.downloadOrigins,undefined);
  assert.equal(withDownloadOrigins({artifact_value:'random.exe'},payload).downloadOrigins,undefined);
});

const source=fs.readFileSync(new URL('../public/evidence-inspector.js',import.meta.url),'utf8');
test('inspector preserves source and referrer labels and blocks executable URL schemes',()=>{
  const context={URL};vm.runInNewContext(source,context);
  const api=context.VorkenEvidenceInspector;
  assert.equal(api.safeUrl('javascript:alert(1)'),'');assert.equal(api.safeUrl('file:///C:/secret'),'');
  const links=api.origins({finalUrl:'https://cdn.example/file',downloadOrigins:[{sourceUrl:'https://site.example/download',referrerUrl:'https://site.example/page'}]});
  assert.equal(links.length,3);assert.equal(links[2].label,'Página de referência');
});

test('click event opens an accessible dialog inside the report and close works',()=>{
  const listeners={},nodes=new Map();
  const element=tag=>({tag,children:[],open:false,appendChild(child){this.children.push(child);if(child.id)nodes.set(child.id,child);},
    setAttribute(key,value){this[key]=value;},replaceChildren(){this.children=[];},addEventListener(event,fn){this[event]=fn;},
    showModal(){this.open=true;},close(){this.open=false;},focus(){this.focused=true;}});
  const document={createElement:element,getElementById:id=>nodes.get(id),body:element('body')};
  const context={URL,document,window:{addEventListener:(name,fn)=>listeners[name]=fn}};
  vm.runInNewContext(source,context);
  listeners['vorken:inspect']({detail:{title:'Random executable',artifact_value:'C:\\Downloads\\random.exe',evidence:{sourceUrl:'https://example.com/<script>'}}});
  const dialog=nodes.get('vorkenEvidenceDialog');assert.equal(dialog.open,true);
  assert.equal(dialog['aria-labelledby'],'vorkenEvidenceTitle');assert.equal(dialog.children[0].focused,true);
  assert(dialog.children.some(node=>node.tag==='div'&&node.children.some(child=>child.tag==='a')));
  dialog.children[0].click();assert.equal(dialog.open,false);
  listeners['vorken:inspect']({detail:{title:'No origin',evidence:{}}});
  assert.equal(dialog.open,true);assert(dialog.children.some(node=>node.textContent?.includes('não foi registrada')));
});
