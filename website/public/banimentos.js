const get=id=>document.getElementById(id),esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let offset=0,rows=[],busy=false;
async function load(){
  if(busy)return;busy=true;get('status').textContent='Carregando auditoria…';
  try{
    const response=await fetch('/api/vorken/admin/bans?offset='+offset+'&q='+encodeURIComponent(get('search').value));
    const result=await response.json();if(!response.ok)throw new Error(response.status===401?'Entre no painel administrativo para acessar a auditoria.':result.message||'Não foi possível carregar.');
    rows=result.bans;get('status').textContent=result.total+' registros · '+(offset+1)+'–'+(offset+rows.length);
    get('bans').innerHTML=rows.map((b,index)=>'<tr><td><a class="ban-profile" href="https://steamcommunity.com/profiles/'+encodeURIComponent(b.steam_id)+'" target="_blank" rel="noopener"><img src="'+esc(safeAvatar(b.profile?.avatar))+'" alt="" loading="lazy"><span>'+esc(b.player_name||b.profile?.personaName||'Nome não registrado')+'<small>'+esc(b.steam_id)+' · Perfil Steam ↗</small></span></a></td><td>'+esc(b.server_name)+'</td><td>'+esc(b.administrator||'Decisão: ADM não registrado')+(b.verification_administrator?'<small>Responsável pela telagem: '+esc(b.verification_administrator)+'</small>':'')+'</td><td>'+esc(b.reason)+'</td><td>'+esc(new Date(b.created_at).toLocaleString('pt-BR'))+'<small>'+(b.active?'Ativo':'Revogado')+'</small></td><td><button data-evidence="'+index+'">Ver provas</button></td></tr>').join('')||'<tr><td colspan="6">Nenhum banimento encontrado.</td></tr>';
    get('previous').disabled=offset===0;get('next').disabled=offset+rows.length>=result.total;
  }catch(error){get('status').textContent=error.message;}finally{busy=false;}
}
get('search-button').onclick=()=>{offset=0;load();};get('search').onkeydown=e=>{if(e.key==='Enter'){offset=0;load();}};
get('previous').onclick=()=>{offset=Math.max(0,offset-100);load();};get('next').onclick=()=>{offset+=100;load();};
function safeAvatar(value){try{const u=new URL(value);return u.protocol==='https:'&&/^(avatars\.(steamstatic\.com|akamai\.steamstatic\.com)|cdn\.akamai\.steamstatic\.com)$/.test(u.hostname)?u.href:'/vorken-logo.svg';}catch{return '/vorken-logo.svg';}}
function details(value){if(value==null)return '';if(typeof value!=='object')return esc(value);return '<dl class="proof-details">'+Object.entries(value).map(([key,item])=>'<dt>'+esc(key)+'</dt><dd>'+details(item)+'</dd>').join('')+'</dl>';}
get('bans').onclick=e=>{
 const button=e.target.closest('[data-evidence]');if(!button)return;
 const b=rows[Number(button.dataset.evidence)],proofs=Array.isArray(b.evidence)?b.evidence:[];
 get('evidence-body').innerHTML='<div class="ban-profile"><img src="'+esc(safeAvatar(b.profile?.avatar))+'" alt=""><div><h3>'+esc(b.player_name||b.profile?.personaName||b.steam_id)+'</h3><a href="https://steamcommunity.com/profiles/'+encodeURIComponent(b.steam_id)+'" target="_blank" rel="noopener">Perfil Steam ↗</a></div></div><section class="ban-context"><strong>'+esc(b.server_name)+'</strong><p>'+esc(b.reason)+'</p><small>'+esc(new Date(b.created_at).toLocaleString('pt-BR'))+' · '+esc(b.administrator||'Administrador da decisão não registrado')+'</small></section>'+(b.analysis_id?'<a class="button outline" href="/admin?analysis='+encodeURIComponent(b.analysis_id)+'" target="_blank" rel="noopener">Abrir relatório completo #'+esc(b.analysis_id)+'</a>':'')+
 (proofs.length?proofs.map(f=>'<article class="finding proof-card '+esc(f.severity||'policy')+'"><span class="badge">'+esc(({critical:'Crítica',high:'Revisar · alta',medium:'Revisar',low:'Informativa',info:'Informativa'})[f.severity]||'Regra de verificação')+'</span><h3>'+esc(f.title||'Ocorrência de verificação')+'</h3>'+(f.artifactValue||f.artifact_value?'<p class="proof-artifact">'+esc(f.artifactValue||f.artifact_value)+'</p>':'')+'<p>'+esc(f.evidence?.note||f.reason||'')+'</p><details><summary>Detalhes registrados na decisão</summary>'+details(f.evidence||f)+'</details></article>').join(''):'<div class="empty">O registro histórico não contém provas anexadas. O motivo original foi preservado.</div>');
 get('evidence').showModal();
};load();
