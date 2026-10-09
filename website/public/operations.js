for(const root of document.querySelectorAll('[data-vorken-operations]')){
  const esc=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const base='/api/vorken/'+(root.dataset.vorkenOperations==='owner'?'admin/':'')+'operations';
  const api=async(path='',body)=>{
    const r=await fetch(base+path,{method:body?'POST':'GET',headers:{'Content-Type':'application/json','X-Vorken-Request':'portal'},body:body?JSON.stringify(body):undefined});
    const result=await r.json();if(!r.ok)throw new Error(result.message||'Não foi possível concluir.');return result;
  };
  root.innerHTML='<div class="card"><h2 data-operations-title>Jogadores online</h2><p>Selecione o servidor para iniciar telagens e revisar verificações pelo painel.</p><label>Servidor Rust<select data-server-select><option value="">Selecione um servidor</option></select></label><p data-status role="status" aria-live="polite"></p><div data-players-pane><label>Buscar jogador<input data-player-search type="search" placeholder="Nome ou SteamID"></label><button data-reload type="button">Atualizar jogadores</button><div class="table-wrap"><table><thead><tr><th>Jogador</th><th>SteamID</th><th>Telagem</th></tr></thead><tbody data-players></tbody></table></div></div><div data-analyses-pane hidden><h3>Análises e verificações</h3><p>Revise os relatórios e as provas de cada jogador deste servidor.</p><div data-sessions></div></div></div><dialog data-report><button type="button" data-close>Fechar</button><div data-report-body></div></dialog>';
  const get=name=>root.querySelector('[data-'+name+']'),status=message=>{get('status').textContent=message;};
  let initialized=false,busy=false,data=null,reportSession=null,reportServer=null;
  function activate(tab){
    const operational=['players','analyses'].includes(tab);
    root.hidden=!operational;
    document.querySelectorAll('[data-workspace-pane]').forEach(p=>p.hidden=p.dataset.workspacePane!==tab);
    document.querySelectorAll('[data-workspace-tab]').forEach(b=>{if(b.dataset.workspaceTab===tab)b.setAttribute('aria-current','page');else b.removeAttribute('aria-current');});
    get('players-pane').hidden=tab==='analyses';get('analyses-pane').hidden=tab!=='analyses';
    get('operations-title').textContent=tab==='analyses'?'Análises':'Jogadores online';
    if(operational)refresh();
  }
  document.querySelectorAll('[data-workspace-tab]').forEach(b=>b.addEventListener('click',()=>activate(b.dataset.workspaceTab)));
  if(!document.querySelector('[data-workspace-tab]'))get('analyses-pane').hidden=false;

  window.addEventListener('message',event=>{if(event.origin===location.origin&&event.source===get('report-body').querySelector('iframe')?.contentWindow&&event.data?.type==='vorken-report-close'){get('report').close();refresh();}});
  const selected=()=>get('server-select').value;
  function renderPlayers(){
    const q=get('player-search').value.trim().toLocaleLowerCase('pt-BR');
    get('players').innerHTML=(data?.players||[]).filter(p=>(p.name+' '+p.steamId).toLocaleLowerCase('pt-BR').includes(q)).map(p=>{
      const session=data.sessions.find(s=>s.steam_id===p.steamId&&['pending','redeemed','deciding'].includes(s.status));
      const command=data.commands.find(c=>c.steam_id===p.steamId);
      return '<tr><td>'+esc(p.name)+'</td><td>'+esc(p.steamId)+'</td><td>'+(session?'Verificação em andamento':command?.status==='pending'?'Aguardando Rust':'<button type="button" data-screen="'+p.steamId+'" '+(!data.active?'disabled':'')+'>Iniciar telagem</button>')+'</td></tr>';
    }).join('')||'<tr><td colspan="3">'+(!selected()?'Selecione um servidor.':!data?.fresh?'Aguardando lista atualizada do plugin.':'Nenhum jogador encontrado.')+'</td></tr>';
  }
  async function refresh(){
    if(busy)return;busy=true;
    try{
      if(!initialized){
        const previous=selected();
        const result=await api();get('server-select').innerHTML='<option value="">Selecione um servidor</option>'+result.servers.map(s=>'<option value="'+s.id+'">'+esc(s.customer_name+' · '+s.name)+'</option>').join('');
        if(result.servers.some(s=>s.id===previous))get('server-select').value=previous;
        else if(result.servers.length===1)get('server-select').value=result.servers[0].id;
        initialized=true;
      }
      if(!selected()){data=null;renderPlayers();get('sessions').textContent='Selecione o servidor que deseja administrar.';return;}
      const serverId=selected(),result=await api('/'+serverId);if(serverId!==selected())return;data=result;
      status(!data.connected?'Plugin desconectado.':!data.fresh?'Plugin conectado; aguardando lista de jogadores.':!data.active?'Licença ou servidor inativo.':data.players.length+' jogadores online · Atualizado em '+new Date(data.updatedAt).toLocaleTimeString('pt-BR'));
      renderPlayers();
      get('sessions').innerHTML=data.sessions.map(s=>'<article class="finding"><strong>'+esc(s.player_name)+'</strong> · '+esc(s.steam_id)+'<p>'+esc(s.status)+' · '+esc(s.analysis_status||'Aguardando código do jogador')+'</p>'+(s.analysis_id?'<button type="button" data-session="'+s.id+'">Revisar provas e verificar</button>':'')+'</article>').join('')||'<p>Nenhuma verificação neste servidor.</p>';
    }catch(e){status(e.message);initialized=false;}finally{busy=false;}
  }
  get('server-select').addEventListener('change',()=>{data=null;renderPlayers();get('sessions').textContent='Carregando…';refresh();});
  get('player-search').addEventListener('input',renderPlayers);
  get('reload').addEventListener('click',()=>{initialized=false;refresh();});
  root.addEventListener('click',async e=>{
    const b=e.target.closest('button');if(!b)return;
    if(b.hasAttribute('data-close')){get('report').close();return;}
    b.disabled=true;
    try{
      if(b.dataset.screen){
        const serverId=selected(),result=await api('/'+serverId+'/telagem',{steamId:b.dataset.screen});
        await refresh();if(document.querySelector('[data-workspace-tab]'))activate('analyses');status(result.message);
      }
      if(b.dataset.session){
        const serverId=selected(),result=await api('/'+serverId+'/sessions/'+b.dataset.session+'/report');
        reportSession=result.session.id;reportServer=serverId;
        get('report-body').innerHTML='<iframe class="full-report-frame" title="Relatório completo da análise" src="/relatorio?session='+encodeURIComponent(reportSession)+'&server='+encodeURIComponent(reportServer)+'&owner='+(root.dataset.vorkenOperations==='owner'?'1':'0')+'"></iframe>';
        get('report').showModal();
      }
      if(b.dataset.decide){
        const ids=name=>[...root.querySelectorAll('[data-'+name+']:checked')].map(i=>Number(i.value));
        if(b.dataset.decide==='deny'&&!confirm('Confirmar banimento no Rust e compartilhar as provas selecionadas na rede Vorken?'))return;
        const result=await api('/'+reportServer+'/sessions/'+reportSession+'/decision',{decision:b.dataset.decide,reason:get('reason').value,evidenceIds:ids('proof'),trustedIds:ids('trust')});
        get('report').close();await refresh();status(result.message);
      }
    }catch(e){if(get('report').open&&get('report-status'))get('report-status').textContent=e.message;else status(e.message);}finally{b.disabled=false;}
  });
  const visible=()=>root.getClientRects().length>0&&!document.hidden;
  new MutationObserver(()=>{if(visible()&&!initialized)refresh();}).observe(document.body,{attributes:true,subtree:true,attributeFilter:['class','hidden']});
  setInterval(()=>{if(visible())refresh();},15000);
  if(visible())refresh();
}
