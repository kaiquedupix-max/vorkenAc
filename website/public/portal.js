const $=id=>document.getElementById(id);
const escape=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const money=cents=>new Intl.NumberFormat('pt-BR',{style:'currency',currency:'BRL'}).format(cents/100);
const date=value=>value?new Date(value).toLocaleString('pt-BR'):'—';
const states={active:'Ativa',inactive:'Inativa',suspended:'Suspensa',revoked:'Revogada',pending:'Pendente',paid:'Pago',approved:'Liberado',denied:'Banido',ended:'Encerrada',redeemed:'Em análise',deciding:'Aguardando Rust',waiting:'Aguardando',completed:'Concluída',processing:'Processando',refunded:'Estornado',charged_back:'Contestado'};
let account=null,plans=[],reportId=null,site=null,billingReady=false;
async function api(path,options={}){
  const response=await fetch('/api/vorken'+path,{credentials:'same-origin',...options,headers:{'Content-Type':'application/json','X-Vorken-Request':'portal',...options.headers}});
  const body=await response.json();
  if(!response.ok)throw Object.assign(new Error(body.message||'Não foi possível concluir.'),{status:response.status});
  return body;
}
function notice(message,error=false){$('notice').hidden=false;$('notice').textContent=message;$('notice').classList.toggle('error',error);}
async function action(fn,button){
  if(button)button.disabled=true;
  try{await fn();}catch(e){notice(e.message,true);}finally{if(button)button.disabled=false;}
}
function renderPlans(){
  const monthly=plans.find(p=>p.id==='mensal')?.price_cents||5000;
  $('plans').innerHTML=plans.map(p=>{
    const discount=Math.max(0,Math.round((1-p.price_cents/(monthly*p.months))*100));
    return '<article class="plan '+(p.id==='anual'?'featured':'')+'"><span class="eyebrow">'+p.months+' '+(p.months===1?'MÊS':'MESES')+'</span><h3>'+escape(p.name)+'</h3><p class="price">'+money(p.price_cents)+'</p><small>'+money(p.price_cents/p.months)+' / mês equivalente</small><p class="discount">'+(discount?'Economize '+discount+'% no período':'Flexibilidade para começar')+'</p><p class="muted">'+p.max_servers+' servidor'+(p.max_servers>1?'es':'')+' Rust<br>Bot Discord e plugin incluídos</p><button data-plan="'+escape(p.id)+'" class="'+(p.id==='anual'?'primary':'outline')+'" '+(billingReady?'':'disabled')+'>'+(billingReady?'Escolher '+escape(p.name):'Compras em breve')+'</button></article>';
  }).join('');
}
async function refresh(){
  const [p,s]=await Promise.all([api('/plans'),api('/site')]);plans=p.plans;billingReady=p.billingReady;site=s;renderPlans();
  if(site.server)$('workspace-title').textContent='Painel · '+site.name;
  try{
    account=await api('/me');$('account').hidden=false;$('signed-out').hidden=true;$('logout').hidden=false;$('refresh').hidden=false;
    const l=account.license;
    const teamOnly=account.servers.length>0&&!account.servers.some(s=>s.owned);
    $('license').innerHTML='<span class="badge '+(l.active?'active':'inactive')+'">'+(l.active?'LICENÇA ATIVA':escape(states[l.license_status]||'SEM LICENÇA ATIVA'))+'</span> <strong>'+escape(account.customer.name)+'</strong><p class="muted">'+(l.active?'Válida até '+date(l.license_until)+' · '+l.max_servers+' servidor(es) Rust.':'Escolha um plano ou solicite a ativação ao suporte.')+'</p>';
    if(teamOnly)$('license').innerHTML='<span class="badge active">EQUIPE DE ADMINISTRAÇÃO</span> <strong>'+escape(account.customer.name)+'</strong><p class="muted">Escolha abaixo o servidor que deseja administrar. A licença pertence ao dono do servidor.</p>';
    $('server-form').closest('section').hidden=teamOnly;
    $('guilds').innerHTML=account.guilds.length?account.guilds.map(g=>'<option value="'+escape(g.id)+'">'+escape(g.name)+'</option>').join(''):'<option value="">Você não administra nenhum Discord</option>';
    $('server-form').querySelector('button').disabled=!l.active||!account.guilds.length;
    const servers=account.servers.filter(s=>!site.server||s.id===site.server.id);
    $('servers').innerHTML=servers.length?servers.map(s=>{
      const online=s.last_seen&&Date.now()-new Date(s.last_seen)<90000;
      return '<article class="server-card"><h3>'+escape(s.name)+'</h3><span class="badge '+(online&&s.enabled?'active':'inactive')+'">'+(!s.enabled?'DESATIVADO':online?'CONECTADO':'AGUARDANDO PLUGIN')+'</span><p><a href="'+escape(s.portalUrl)+'">'+escape(new URL(s.portalUrl).hostname)+'</a></p><small class="muted">Última conexão: '+date(s.last_seen)+'</small><div class="actions">'+(s.owned?'<a class="button outline" href="/api/vorken/servers/'+s.id+'/bot" target="_blank" rel="noopener">Adicionar bot ↗</a><button data-download="'+s.id+'" class="primary" '+(!l.active||!s.enabled?'disabled':'')+'>Baixar plugin</button><button data-edit="'+s.id+'" class="quiet">Configurar servidor</button><button data-botconfig="'+s.id+'">Configurar bot e avisos</button><button data-team="'+s.id+'">Equipe e convites</button>':'<span class="badge">EQUIPE DE ADMINISTRAÇÃO</span>')+'</div></article>';
    }).join(''):'<div class="empty"><p>Nenhum servidor conectado ainda. Cadastre seu Rust para começar.</p></div>';
    const sessions=(await api('/sessions')).sessions.filter(s=>!site.server||s.server_id===site.server.id);
    $('sessions').innerHTML=sessions.length?sessions.map(s=>'<tr><td>'+escape(s.player_name)+'<small>'+escape(s.steam_id)+'</small></td><td>'+escape(s.server_name)+'</td><td>'+escape(states[s.analysis_status]||s.analysis_status||'Aguardando código')+'</td><td>'+escape(states[s.status]||s.status)+'</td><td>'+(s.analysis_id?'<button data-report="'+s.id+'">Revisar provas</button>':'—')+'</td></tr>').join(''):'<tr><td colspan="5">Nenhuma verificação. Use /telagem no Discord para iniciar.</td></tr>';
    $('orders').innerHTML=account.orders.length?account.orders.map(o=>'<div class="audit-line"><span>'+date(o.created_at)+'</span><span>'+escape(o.plan_id)+' · '+money(o.price_cents)+'</span><span>'+escape(states[o.status]||o.status)+'</span></div>').join(''):'<p class="muted">Você ainda não fez nenhuma compra.</p>';
    if(new URLSearchParams(location.search).has('pagamento'))notice('O pedido será ativado após a confirmação do Mercado Pago. Clique em Atualizar para acompanhar.');
    const alertId=new URLSearchParams(location.search).get('alert');
    if(alertId&&!$('report').open){
      const alert=await api('/alerts/'+encodeURIComponent(alertId));
      $('report-body').innerHTML='<span class="eyebrow">BANIMENTO ANTERIOR · REDE VORKEN</span><h2>'+escape(alert.playerName)+'</h2><p>SteamID '+escape(alert.steamId)+'</p>'+(alert.bans||[]).map(b=>'<article class="finding"><h3>'+escape(b.server_name)+'</h3><p>'+escape(b.reason)+'</p><small>'+date(b.created_at)+'</small><details><summary>Provas registradas</summary><pre>'+escape(JSON.stringify(b.evidence,null,2))+'</pre></details></article>').join('');
      $('report').showModal();
    }
  }catch(e){if(e.status!==401)throw e;account=null;$('account').hidden=true;$('signed-out').hidden=false;}
}
async function openReport(id){
  const {session:s,findings}=await api('/sessions/'+id+'/report');reportId=id;
  const groups={all:findings,critical:findings.filter(f=>f.severity==='critical'),review:findings.filter(f=>['high','medium'].includes(f.severity)),info:findings.filter(f=>!['critical','high','medium'].includes(f.severity))};
  const result=groups.critical.length?'Evidências críticas encontradas':groups.review.length?'Revisão administrativa necessária':'Nenhum sinal crítico registrado';
  const cards=[['all','Visão geral','Todos'],['critical','Crítico',groups.critical.length],['review','Laranja · revisar',groups.review.length],['info','Informativo',groups.info.length]];
  $('report-body').innerHTML='<div class="report-heading"><div><span class="eyebrow">✦ RELATÓRIO DA ANÁLISE</span><h2>#'+escape(s.analysis_id)+' · '+escape(s.player_name)+'</h2><a class="steam-link" href="https://steamcommunity.com/profiles/'+encodeURIComponent(s.steam_id)+'" target="_blank" rel="noopener">◉ Perfil Steam ↗</a><p class="muted">SteamID '+escape(s.steam_id)+'</p></div><span class="badge active">VORKEN · DECISÃO MANUAL</span></div><div class="report-tabs" role="group" aria-label="Filtrar evidências">'+cards.map(([key,label,value])=>'<button class="report-metric '+key+'" data-report-filter="'+key+'" aria-pressed="'+(key==='all')+'"><small>'+label+'</small><strong>'+value+'</strong></button>').join('')+'</div><div class="report-status">'+escape(states[s.analysis_status]||s.analysis_status)+' · '+escape(states[s.status]||s.status)+'</div><div class="report-layout"><div><section class="report-summary"><span class="eyebrow">RESUMO DA SESSÃO</span><h3>'+escape(s.player_name)+'</h3><p>Análise #'+escape(s.analysis_id)+' · '+date(s.created_at)+'</p><p class="muted">Revise cada evidência antes de decidir. Marque como confiáveis apenas os falsos positivos confirmados.</p></section><div class="report-evidence-heading"><h3>Evidências da análise</h3><label>Pesquisar evidências<input id="report-search" type="search" placeholder="Nome, arquivo ou tipo de evidência"></label></div><div id="report-findings">'+
    (findings.length?findings.map(f=>'<article class="finding report-finding '+(f.severity==='critical'?'critical':['high','medium'].includes(f.severity)?'review':'info')+'" data-severity="'+escape(f.severity)+'"><span class="badge">'+escape(({critical:'Crítico',high:'Revisar · alto',medium:'Revisar',info:'Informativo',low:'Informativo'})[f.severity]||f.severity)+'</span><h3>'+escape(f.title)+'</h3><p>'+escape(f.artifact_type)+': '+escape(f.artifact_value)+'</p><details><summary>Ver evidência técnica</summary><pre>'+escape(JSON.stringify(f.evidence,null,2))+'</pre></details><label><input type="checkbox" name="proof" value="'+f.id+'">Prova de banimento</label><label><input type="checkbox" name="trust" value="'+f.id+'">Falso positivo confirmado</label></article>').join(''):'<p>Nenhum sinal registrado nesta análise.</p>')+'</div><p id="report-no-match" class="muted" hidden>Nenhuma evidência corresponde ao filtro.</p></div><aside class="report-overview"><section><span class="eyebrow">RESULTADO DA ANÁLISE</span><h3 class="'+(groups.critical.length?'critical':'review')+'">'+result+'</h3><p>A decisão final depende da revisão da administração.</p></section><section><span class="eyebrow">ESTATÍSTICAS DA ANÁLISE</span><p>◈ '+findings.length+' evidências registradas<br>◈ '+groups.critical.length+' críticas<br>◈ '+groups.review.length+' para revisão<br>◈ '+groups.info.length+' informativas</p></section><section><span class="eyebrow">RECOMENDAÇÃO</span><p>'+(groups.critical.length?'Priorize as evidências críticas e confira os detalhes técnicos antes de decidir.':'Confira os sinais e o contexto da sessão antes de liberar o jogador.')+'</p></section></aside></div><section class="report-decision">'+
    '<label>Motivo da decisão<textarea id="decision-reason" maxlength="500" placeholder="Descreva sua avaliação"></textarea></label><div class="actions"><button data-decision="approve" class="primary" '+(s.analysis_status==='completed'&&s.status==='redeemed'?'':'disabled')+'>Liberar jogador</button><button data-decision="deny" class="danger" '+(s.analysis_status==='completed'&&s.status==='redeemed'?'':'disabled')+'>Banir com as provas selecionadas</button></div><p class="muted">A decisão será aplicada no servidor de origem. Banimentos com provas geram alertas nos outros servidores Vorken.</p>';
  $('report-body').insertAdjacentHTML('beforeend','</section>');
  let selected='all';
  const filter=()=>{let visible=0;const query=$('report-search').value.trim().toLocaleLowerCase();$('report-findings').querySelectorAll('.finding').forEach(row=>{const severity=row.dataset.severity;row.hidden=!(selected==='all'||selected==='critical'&&severity==='critical'||selected==='review'&&['high','medium'].includes(severity)||selected==='info'&&!['critical','high','medium'].includes(severity))||!row.textContent.toLocaleLowerCase().includes(query);if(!row.hidden)visible++;});$('report-no-match').hidden=visible>0||!findings.length;};
  $('report-body').querySelectorAll('[data-report-filter]').forEach(button=>button.addEventListener('click',()=>{selected=button.dataset.reportFilter;$('report-body').querySelectorAll('[data-report-filter]').forEach(b=>b.setAttribute('aria-pressed',String(b===button)));filter();}));
  $('report-search').addEventListener('input',filter);
  $('report').showModal();
}
document.addEventListener('click',e=>{
  const b=e.target.closest('button');if(!b)return;
  if(b.dataset.plan)action(async()=>{
    if(!account){location.href='/api/vorken/auth/discord';return;}
    const r=await api('/checkout',{method:'POST',body:JSON.stringify({planId:b.dataset.plan})});location.href=r.url;
  },b);
  if(b.dataset.download)action(async()=>{
    const server=account.servers.find(s=>s.id===b.dataset.download);
    if(server.last_seen&&!confirm('Baixar novamente substitui a chave de instalação. Instale o novo arquivo para reconectar este servidor. Continuar?'))return;
    const r=await fetch('/api/vorken/servers/'+b.dataset.download+'/plugin',{method:'POST',headers:{'X-Vorken-Request':'portal'}});
    if(!r.ok)throw new Error((await r.json()).message);
    const url=URL.createObjectURL(await r.blob()),a=document.createElement('a');a.href=url;a.download='Vorken.cs';a.click();setTimeout(()=>URL.revokeObjectURL(url),30000);
    notice('Plugin baixado. Coloque Vorken.cs em oxide/plugins no seu Rust. Ele se conecta automaticamente.');await refresh();
  },b);
  if(b.dataset.edit)action(async()=>{
    const s=account.servers.find(x=>x.id===b.dataset.edit),name=prompt('Nome do servidor',s.name);if(name===null)return;
    const discordInvite=prompt('Convite do Discord exibido no Rust',s.discord_invite);if(discordInvite===null)return;
    await api('/servers/'+s.id,{method:'PATCH',body:JSON.stringify({name,discordInvite})});notice('Configuração salva. O plugin recebe a atualização automaticamente.');await refresh();
  },b);
  if(b.dataset.report)action(()=>openReport(b.dataset.report),b);
  if(b.dataset.decision)action(async()=>{
    const ids=name=>[...$('report').querySelectorAll('input[name="'+name+'"]:checked')].map(x=>Number(x.value));
    const evidenceIds=ids('proof'),trustedIds=ids('trust');
    if(evidenceIds.some(id=>trustedIds.includes(id)))throw new Error('Uma evidência não pode ser prova de banimento e falso positivo ao mesmo tempo.');
    if(b.dataset.decision==='deny'&&!confirm('Aplicar banimento no Rust e publicar as provas selecionadas na rede Vorken?'))return;
    const r=await api('/sessions/'+reportId+'/decision',{method:'POST',body:JSON.stringify({decision:b.dataset.decision,reason:$('decision-reason').value,evidenceIds,trustedIds})});
    $('report').close();notice(r.message);await refresh();
  },b);
});
$('server-form').addEventListener('submit',e=>{e.preventDefault();action(async()=>{
  const data=Object.fromEntries(new FormData(e.target));await api('/servers',{method:'POST',body:JSON.stringify(data)});
  e.target.reset();notice('Servidor cadastrado. Adicione o bot e baixe seu plugin.');await refresh();
},e.target.querySelector('button'));});
$('refresh').addEventListener('click',()=>action(refresh,$('refresh')));
$('logout').addEventListener('click',()=>action(async()=>{await api('/logout',{method:'POST',body:'{}'});location.reload();},$('logout')));
refresh().catch(e=>notice(e.message,true));
