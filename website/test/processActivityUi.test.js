import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFileSync} from 'node:fs';
test('process and Journal lists render safely, search, paginate, and disclose unavailable logs',()=>{
 class Node{constructor(){this.children=[];this.handlers={};this.value='';this.textContent='';this.hidden=false}append(n){this.children.push(n)}replaceChildren(){this.children=[]}addEventListener(k,v){this.handlers[k]=v}}
 const nodes=new Map();const get=id=>{if(!nodes.has(id))nodes.set(id,new Node());return nodes.get(id)};const events={};
 const context={document:{getElementById:get,createElement:()=>new Node()},window:{addEventListener:(name,fn)=>events[name]=fn}};
 vm.runInNewContext(readFileSync(new URL('../public/process-activity-ui.js',import.meta.url),'utf8'),context);
 events['vorken:report']({detail:{report:{payload:{processActivity:{open:{items:Array.from({length:80},(_,pid)=>({pid,name:pid===0?'<img src=x onerror=alert(1)>':'app'+pid,path:'C:\\Tools\\app'+pid+'.exe',reasons:[]}))},journal:{items:[],sources:[{channel:'Security',state:'unavailable'}]}}}}}});
 assert.equal(get('activity-open-list').children.length,50);assert.equal(get('activity-open-more').hidden,false);
 assert.equal(get('activity-open-list').children[0].children[0].textContent,'<img src=x onerror=alert(1)>');
 get('activity-open-more').handlers.click();assert.equal(get('activity-open-list').children.length,80);
 get('activity-open-search').value='app79';get('activity-open-search').handlers.input();assert.equal(get('activity-open-list').children.length,1);
 assert.match(get('activity-journal-status').textContent,/fonte indisponível/);
});
