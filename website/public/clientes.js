const $=id=>document.getElementById(id),esc=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const money=value=>new Intl.NumberFormat('pt-BR',{style:'currency',currency:'BRL'}).format(value/100);
const date=value=>value?new Date(value).toLocaleDateString('pt-BR'):'—';
let data=null;
function notice(message,error=false){$('notice').textContent=message;$('notice').hidden=false;$('notice').classList.toggle('error',error);}
async function api(path,options={}){
  const r=await fetch('/api/vorken'+path,{...options,headers:{'Content-Type':'application/json','X-Vorken-Request':'portal',...options.headers}});
  const b=await r.json();if(!r.ok)throw Object.assign(new Error(b.message||'Entre com a senha administrativa.'),{status:r.status});return b;
}
async function run(fn,b){if(b)b.disabled=true;try{await fn();}catch(e){notice(e.message,true);}finally{if(b)b.disabled=false;}}
const licenseActive=c=>c.status==='active'&&c.license_status==='active'&&new Date(c.license_until)>new Date();
function renderCustomers(){
  const q=$('search').value.toLowerCase();
  $('customers').innerHTML=data.customers.filter(c=>(c.name+' '+c.discord_id).toLowerCase().includes(q)).map(c=>'<tr><td>'+esc(c.name)+'<small>'+esc(c.discord_id)+'<br>'+esc(c.email||'')+'</small></td><td>'+esc(c.status)+'</td><td><span class="badge '+(licenseActive(c)?'active':'inactive')+'">'+(licenseActive(c)?'Ativa':esc(c.license_status||'Sem licença'))+'</span></td><td>'+date(c.license_until)+'</td><td>'+'<label class="quota-label">Servidores liberados<input data-quota-input="'+c.id+'" aria-label="Servidores liberados para '+esc(c.name)+'" type="number" min="1" max="100" step="1" value="'+Number(c.max_servers||1)+'" '+(!c.license_status?'disabled':'')+'></label><button data-quota="'+c.id+'" '+(!c.license_status?'disabled':'')+'>Salvar limite</button>'+'</td><td><select data-period="'+c.id+'">'+data.plans.map(p=>'<option value="'+p.id+'">'+esc(p.name)+'</option>').join('')+'</select><div class="actions"><button data-grant="'+c.id+'">Conceder / renovar</button><button data-license="'+c.id+'" data-action="'+(c.license_status==='suspended'?'resume':'suspend')+'">'+(c.license_status==='suspended'?'Reativar':'Suspender')+'</button><button data-license="'+c.id+'" data-action="revoke" class="danger">Revogar</button><button data-customer="'+c.id+'" data-status="'+(c.status==='active'?'suspended':'active')+'">'+(c.status==='active'?'Bloquear cadastro':'Reativar cadastro')+'</button></div></td></tr>').join('')||'<tr><td colspan="6">Nenhum cliente encontrado.</td></tr>';
}
async function refresh(){
  try{data=await api('/admin');}catch(e){if(e.status===401){$('login').hidden=false;$('admin-workspace').hidden=true;return;}throw e;}
  $('login').hidden=true;$('admin-workspace').hidden=false;$('refresh').hidden=false;
  const active=data.customers.filter(licenseActive).length,online=data.servers.filter(s=>s.enabled&&s.last_seen&&Date.now()-new Date(s.last_seen)<90000).length;
  const paid=data.orders.filter(o=>o.status==='paid').reduce((sum,o)=>sum+o.price_cents,0);
  $('stats').innerHTML=[['Clientes',data.customers.length],['Licenças ativas',active],['Servidores conectados',online],['Recebido nos pedidos exibidos',money(paid)]].map(([name,n])=>'<div><small>'+name+'</small><strong>'+n+'</strong></div>').join('');
  $('readiness').textContent='Discord: '+(data.readiness.discord?'configurado':'aguardando credenciais')+' · Mercado Pago: '+(data.readiness.payments?'configurado':'aguardando credenciais');
  renderCustomers();
  const owners=new Map(data.customers.map(c=>[c.id,c.name]));
  $('servers').innerHTML=data.servers.map(s=>'<tr><td>'+esc(s.name)+'</td><td>'+esc(owners.get(s.customer_id)||s.customer_id)+'</td><td>'+date(s.last_seen)+'<small>'+esc(s.plugin_version||'Não instalado')+'</small></td><td>'+ (s.enabled?'Habilitado':'Desativado')+'</td><td><button data-server="'+s.id+'" data-enabled="'+(!s.enabled)+'">'+(s.enabled?'Desativar':'Habilitar')+'</button></td></tr>').join('')||'<tr><td colspan="5">Nenhum servidor cadastrado.</td></tr>';
  $('plans').innerHTML=data.plans.map(p=>'<form class="plan" data-plan="'+p.id+'"><h3>'+esc(p.name)+'</h3><label>Preço em reais<input name="price" type="number" step=".01" min=".01" max="100000" required value="'+(p.price_cents/100).toFixed(2)+'"></label><label>Servidores por licença<input name="maxServers" type="number" min="1" max="100" required value="'+p.max_servers+'"></label><label><input name="enabled" type="checkbox" '+(p.enabled?'checked':'')+'>Disponível para compra</label><button class="primary">Salvar plano</button></form>').join('');
  $('orders').innerHTML=data.orders.map(o=>'<tr><td>'+esc(o.name)+'</td><td>'+esc(o.plan_id)+'</td><td>'+money(o.price_cents)+'</td><td>'+esc(o.status)+'</td><td>'+date(o.created_at)+'</td></tr>').join('')||'<tr><td colspan="5">Nenhum pedido registrado.</td></tr>';
  $('bans').innerHTML=data.bans.map(b=>'<tr><td>'+esc(b.steam_id)+'</td><td>'+esc(b.server_name)+'</td><td>'+esc(b.reason)+'</td><td><button data-ban="'+b.id+'" data-active="'+(!b.active)+'">'+(b.active?'Remover da rede':'Republicar alerta')+'</button></td></tr>').join('')||'<tr><td colspan="4">Nenhum banimento compartilhado.</td></tr>';
  $('audit').innerHTML=data.audits.map(a=>'<div class="audit-line"><span>'+date(a.created_at)+'</span><span>'+esc(a.action)+'</span><span>'+esc(a.actor)+'</span></div>').join('')||'<p class="muted">Sem ações registradas.</p>';
}
$('admin-login').addEventListener('submit',e=>{e.preventDefault();run(async()=>{
  const r=await fetch('/api/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:new FormData(e.target).get('password')})});
  if(!r.ok)throw new Error('Senha administrativa inválida.');e.target.reset();await refresh();
},e.target.querySelector('button'));});
document.addEventListener('submit',e=>{if(!e.target.dataset.plan)return;e.preventDefault();run(async()=>{
  const form=e.target,v=new FormData(form);
  await api('/admin/plans/'+form.dataset.plan,{method:'PATCH',body:JSON.stringify({priceCents:Math.round(Number(v.get('price'))*100),maxServers:Number(v.get('maxServers')),enabled:v.has('enabled')})});
  notice('Plano atualizado.');await refresh();
},e.target.querySelector('button'));});
document.addEventListener('click',e=>{const b=e.target.closest('button');if(!b)return;run(async()=>{
  let path,body;
  if(b.dataset.grant){path='/admin/customers/'+b.dataset.grant+'/license';body={action:'grant',planId:document.querySelector('[data-period="'+b.dataset.grant+'"]').value};}
  if(b.dataset.license){
    if(!confirm('Confirmar '+b.dataset.action+' desta licença? Sessões em andamento serão encerradas se ela ficar inativa.'))return;
    path='/admin/customers/'+b.dataset.license+'/license';body={action:b.dataset.action};
  }
  if(b.dataset.quota){path='/admin/customers/'+b.dataset.quota+'/quota';body={maxServers:Number(document.querySelector('[data-quota-input="'+b.dataset.quota+'"]').value)};}
  if(b.dataset.customer){path='/admin/customers/'+b.dataset.customer;body={status:b.dataset.status};}
  if(b.dataset.server){path='/admin/servers/'+b.dataset.server;body={enabled:b.dataset.enabled==='true'};}
  if(b.dataset.ban){path='/admin/bans/'+b.dataset.ban;body={active:b.dataset.active==='true'};}
  if(path){await api(path,{method:path.endsWith('/license')?'POST':'PATCH',body:JSON.stringify(body)});notice('Alteração registrada.');await refresh();}
},b);});
$('search').addEventListener('input',renderCustomers);$('refresh').addEventListener('click',()=>run(refresh,$('refresh')));
refresh().catch(e=>notice(e.message,true));
