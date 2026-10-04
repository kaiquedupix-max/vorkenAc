const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const api=async(path,method='GET',body)=>{
  const r=await fetch('/api/vorken'+path,{method,headers:{'Content-Type':'application/json','X-Vorken-Request':'portal'},body:body?JSON.stringify(body):undefined});
  const data=await r.json();if(!r.ok)throw Object.assign(new Error(data.message||'Não foi possível concluir.'),{status:r.status});return data;
};
const dialog=document.createElement('dialog');dialog.innerHTML='<button type="button" data-close>Fechar</button><div data-content></div><p data-message role="status"></p>';document.body.append(dialog);
const content=dialog.querySelector('[data-content]'),message=dialog.querySelector('[data-message]');
let current=null;
const labels={discordBans:'Publicar bans no Discord',discordVerified:'Publicar jogadores verificados no Discord',rustStarted:'Avisar início de telagem no chat do Rust',rustVerified:'Avisar jogador verificado no chat do Rust',rustBans:'Avisar banimento no chat do Rust'};
async function openConfig(id){
  current=id;message.textContent='';content.textContent='Carregando canais…';dialog.showModal();
  const data=await api('/servers/'+id+'/settings');
  const options=selected=>'<option value="">Desativado / nenhum canal</option>'+data.channels.map(c=>'<option value="'+esc(c.id)+'" '+(c.id===selected?'selected':'')+'>#'+esc(c.name)+'</option>').join('');
  content.innerHTML='<h2>Bot Vorken · '+esc(data.name)+'</h2><p>Escolha canais separados ou o mesmo canal para bans e verificações. Os tickets e alertas com provas continuam privados.</p><form data-settings><label>Canal de ban feed<select name="banChannelId">'+options(data.settings.banChannelId)+'</select></label><label>Canal de jogadores verificados<select name="verifiedChannelId">'+options(data.settings.verifiedChannelId)+'</select></label><button type="button" data-same>Usar o canal de bans também para verificados</button><h3>Avisos</h3>'+Object.entries(labels).map(([key,label])=>'<label><input type="checkbox" name="'+key+'" '+(data.settings[key]?'checked':'')+'>'+label+'</label>').join('')+'<button type="submit" class="primary">Salvar configuração</button></form>';
  if(!data.owned)content.querySelectorAll('input,select,button').forEach(e=>e.disabled=true);
}
async function openTeam(id,alreadyOpen=false){
  current=id;message.textContent='';content.textContent='Carregando equipe…';if(!alreadyOpen)dialog.showModal();
  const data=await api('/servers/'+id+'/team');
  content.innerHTML='<h2>Equipe de administração</h2><p>O acesso vale apenas para este servidor Rust. Para liberar outros servidores, convide a mesma conta em cada um. O convidado precisa administrar o Discord vinculado.</p><form data-invite><label>ID Discord do administrador<input name="discordId" required pattern="[0-9]{16,20}" placeholder="ID numérico da conta Discord"></label><p class="muted">No Discord, ative o modo desenvolvedor e use Copiar ID no perfil da pessoa. Cada convite é pessoal e expira em 7 dias.</p><button class="primary" type="submit">Gerar link de convite</button></form><div data-invite-link></div><h3>Membros</h3>'+data.members.map(m=>'<article class="audit-line"><span>'+esc(m.name)+'</span><span>'+esc(m.discord_id)+'</span><button data-remove="'+m.id+'">Remover acesso</button></article>').join('')+'<h3>Convites pendentes</h3>'+data.invites.map(i=>'<article class="audit-line"><span>'+esc(i.discord_id)+'</span><span>'+new Date(i.expires_at).toLocaleString('pt-BR')+'</span><button data-revoke="'+i.id+'">Revogar convite</button></article>').join('');
}
document.addEventListener('click',async e=>{
  const b=e.target.closest('button');if(!b)return;
  try{
    if(b.dataset.botconfig)await openConfig(b.dataset.botconfig);
    if(b.dataset.team)await openTeam(b.dataset.team);
    if(b.hasAttribute('data-close')&&dialog.contains(b))dialog.close();
    if(b.hasAttribute('data-same'))content.querySelector('[name="verifiedChannelId"]').value=content.querySelector('[name="banChannelId"]').value;
    if(b.dataset.remove){await api('/servers/'+current+'/team/'+b.dataset.remove,'DELETE');await openTeam(current,true);}
    if(b.dataset.revoke){await api('/servers/'+current+'/invites/'+b.dataset.revoke,'DELETE');await openTeam(current,true);}
  }catch(err){message.textContent=err.message;}
});
dialog.addEventListener('submit',async e=>{
  e.preventDefault();const button=e.target.querySelector('button[type="submit"]');button.disabled=true;
  try{
    if(e.target.hasAttribute('data-settings')){
      const settings={};for(const key of Object.keys(labels))settings[key]=e.target.elements[key].checked;
      for(const key of ['banChannelId','verifiedChannelId'])settings[key]=e.target.elements[key].value||null;
      await api('/servers/'+current+'/settings','PATCH',{settings});message.textContent='Configuração salva. O plugin recebe os avisos automaticamente.';
    }else if(e.target.hasAttribute('data-invite')){
      const r=await api('/servers/'+current+'/team/invites','POST',{discordId:e.target.elements.discordId.value.trim()});
      await openTeam(current,true);const box=content.querySelector('[data-invite-link]');
      box.innerHTML='<label>Envie este link ao administrador<input readonly value="'+esc(r.url)+'"></label>';box.querySelector('input').select();
    }
  }catch(err){message.textContent=err.message;}finally{button.disabled=false;}
});
const fragment=new URLSearchParams(location.hash.slice(1));
if(fragment.has('convite')){sessionStorage.setItem('vorken-invite',fragment.get('convite'));history.replaceState(null,'',location.pathname+location.search+'#workspace');}
async function acceptInvite(){
  const token=sessionStorage.getItem('vorken-invite');if(!token)return;
  content.textContent='Vinculando convite à sua conta Discord…';dialog.showModal();
  try{const r=await api('/team/accept','POST',{token});sessionStorage.removeItem('vorken-invite');content.textContent='Acesso liberado ao servidor '+r.name+'.';const a=document.createElement('a');a.href='/servidor#workspace';a.className='button primary';a.textContent='Abrir meu painel';content.append(a);}
  catch(err){content.textContent=err.message;if(err.status===401){const a=document.createElement('a');a.href='/api/vorken/auth/discord';a.className='button primary';a.textContent='Entrar com Discord para aceitar';content.append(a);}else sessionStorage.removeItem('vorken-invite');}
}
acceptInvite();
