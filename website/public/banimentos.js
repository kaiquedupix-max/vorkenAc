const get=id=>document.getElementById(id),esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let offset=0,rows=[],busy=false;
async function load(){
  if(busy)return;busy=true;get('status').textContent='Carregando auditoria…';
  try{
    const response=await fetch('/api/vorken/admin/bans?offset='+offset+'&q='+encodeURIComponent(get('search').value));
    const result=await response.json();if(!response.ok)throw new Error(response.status===401?'Entre no painel administrativo para acessar a auditoria.':result.message||'Não foi possível carregar.');
    rows=result.bans;get('status').textContent=result.total+' registros · '+(offset+1)+'–'+(offset+rows.length);
    get('bans').innerHTML=rows.map((b,index)=>'<tr><td>'+esc(b.player_name||'Nome não registrado')+'<small>'+esc(b.steam_id)+'</small></td><td>'+esc(b.server_name)+'</td><td>'+esc(b.administrator||'Não registrado')+'</td><td>'+esc(b.reason)+'</td><td>'+esc(new Date(b.created_at).toLocaleString('pt-BR'))+'<small>'+(b.active?'Ativo':'Revogado')+'</small></td><td><button data-evidence="'+index+'">Ver provas</button></td></tr>').join('')||'<tr><td colspan="6">Nenhum banimento encontrado.</td></tr>';
    get('previous').disabled=offset===0;get('next').disabled=offset+rows.length>=result.total;
  }catch(error){get('status').textContent=error.message;}finally{busy=false;}
}
get('search-button').onclick=()=>{offset=0;load();};get('search').onkeydown=e=>{if(e.key==='Enter'){offset=0;load();}};
get('previous').onclick=()=>{offset=Math.max(0,offset-100);load();};get('next').onclick=()=>{offset+=100;load();};
get('bans').onclick=e=>{const button=e.target.closest('[data-evidence]');if(!button)return;get('evidence-body').textContent=JSON.stringify(rows[Number(button.dataset.evidence)].evidence,null,2);get('evidence').showModal();};load();
