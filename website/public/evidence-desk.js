/* Presentation and additive multi-server controls. Existing scanner/report handlers remain authoritative. */
(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  let clients = [], servers = [], selectedClientId = '', activeReport = null, loggedIn = false, busy = false;
  let timer;
  const pending = new WeakSet();
  async function request(url, body, method = 'POST') {
    const response = await fetch(url, {credentials:'same-origin', headers:{'Content-Type':'application/json'}, ...(body === undefined ? {} : {method,body:JSON.stringify(body)})});
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.message || data.error || 'Não foi possível concluir a operação.');
    return data;
  }
  function toast(message, error = false) {
    $('deskToast')?.remove();
    const el = document.createElement('div'); el.id='deskToast'; el.className='desk-toast';el.setAttribute('role',error?'alert':'status');el.dataset.error=String(error);el.textContent=message;document.body.append(el);setTimeout(()=>el.remove(),8000);
  }
  const selectedClient = () => clients.find(c=>String(c.id)===selectedClientId);
  const date = value => value ? new Date(value).toLocaleString('pt-BR') : '—';
  function applyPolicy() {
    const client = selectedClient();
    for (const form of [$('deskQuotaForm'), $('deskPolicyForm')]) for (const input of form.elements) input.disabled = !client;
    if (!client) {$('deskQuotaUsage').textContent='Selecione um cliente no topo.';return;}
    $('deskServerLimit').value=client.server_limit;
    $('deskAssociationDays').value=client.association_days;
    $('deskAssociationEnabled').checked=client.association_enabled;
    $('deskNotifyChat').checked=client.notify_chat;
    $('deskQuotaUsage').textContent=`${client.server_count} de ${client.server_limit} servidores registrados.`;
  }
  function renderFleet(preserveEdits = false) {
    if (selectedClientId && !selectedClient()) selectedClientId='';
    $('deskClientSelect').innerHTML='<option value="">Todos os servidores</option>'+clients.map(c=>`<option value="${escape(c.id)}">${escape(c.name)}</option>`).join('');
    $('deskClientSelect').value=selectedClientId;
    $('fleetServerClient').innerHTML='<option value="">Selecione o cliente</option>'+clients.map(c=>`<option value="${escape(c.id)}">${escape(c.name)} · ${c.server_count}/${c.server_limit}</option>`).join('');
    $('fleetServerClient').value=selectedClientId;
    const client=selectedClient();
    $('deskServerCount').textContent=client ? `${client.server_count} de ${client.server_limit} servidores` : `${servers.length} servidor(es) registrado(s)`;
    $('fleetClientsList').innerHTML=clients.length ? clients.map(c=>`<div class="fleet-item"><div><strong>${escape(c.name)}</strong><small>${c.server_count} de ${c.server_limit} servidores · Associação: ${c.association_enabled?`${c.association_days} dias`:'desativada'}</small></div><button class="button ghost" type="button" data-select-client="${escape(c.id)}">Gerenciar</button></div>`).join('') : '<p class="muted">Cadastre seu primeiro cliente para liberar servidores.</p>';
    const analysisServer=$('analysisServer'), previousServer=analysisServer.value;
    analysisServer.innerHTML='<option value="">Sem servidor · liberação manual</option>'+servers.map(s=>`<option value="${escape(s.id)}">${escape(s.name)} · ${s.report_visibility==='automatic'?'Relatório automático':'Liberação manual'}</option>`).join('');
    analysisServer.value=previousServer;
    const visible=servers.filter(s=>!selectedClientId||String(s.client_id)===selectedClientId);
    $('fleetServersList').innerHTML=visible.length ? visible.map(s=>`<div class="fleet-item"><div><strong>${escape(s.name)}</strong><small>${escape(clients.find(c=>String(c.id)===String(s.client_id))?.name||'')} · Última conexão: ${date(s.last_seen_at)}</small><small>${Number(s.applied_revision)>=Number(s.revision)?'Política sincronizada':'Decisões aguardando aplicação'}</small></div><label class="fleet-report-policy">Relatório para o jogador<select data-report-policy="${escape(s.id)}" aria-label="Disponibilidade do relatório de ${escape(s.name)}"><option value="manual" ${s.report_visibility==='automatic'?'':'selected'}>Somente após liberação</option><option value="automatic" ${s.report_visibility==='automatic'?'selected':''}>Automaticamente após a análise</option></select></label><span class="fleet-status ${s.online?'':'offline'}">● ${s.online?'Online':'Aguardando conexão'}</span></div>`).join(''):'<p class="muted">Nenhum servidor registrado neste grupo.</p>';
    if (!preserveEdits) applyPolicy();
  }
  async function refresh(preserveEdits = false) {
    if (!loggedIn || busy) return;
    busy=true;
    try {const data=await request('/api/admin/fleet');clients=data.clients;servers=data.servers;renderFleet(preserveEdits);}
    finally {busy=false;}
  }
  async function loadBans() {
    const {bans}=await request('/api/admin/fleet/bans'+(selectedClientId?'?clientId='+encodeURIComponent(selectedClientId):''));
    const active=bans.filter(b=>b.active), associates=active.filter(b=>b.kind==='association');
    $('fleetBansList').innerHTML=`<div class="desk-audit-summary"><div><strong>${active.length}</strong><span>Bloqueios ativos</span></div><div><strong>${associates.length}</strong><span>Por associação</span></div><div><strong>${bans.filter(b=>!b.active).length}</strong><span>Encerrados</span></div></div>`+(bans.length?`<table class="fleet-ban-table"><thead><tr><th>JOGADOR / CLIENTE</th><th>MOTIVO</th><th>TIPO</th><th>EXPIRAÇÃO</th><th>STATUS</th><th>AUDITORIA</th></tr></thead><tbody>${bans.map(b=>`<tr><td><strong>${escape(b.player_name||b.steam_id)}</strong><br><small>${escape(b.steam_id)} · ${escape(b.client_name)}</small></td><td>${escape(b.reason)}</td><td><span class="tag ${b.kind==='association'?'medium':'critical'}">${b.kind==='association'?'Associação':'Direto'}</span></td><td>${b.expires_at?date(b.expires_at):'Permanente'}</td><td><span class="tag ${b.active?'high':'info'}">${b.active?'Ativo':b.revoked_at?'Revogado':'Expirado'}</span></td><td><button class="button ghost" type="button" data-audit-ban="${escape(b.id)}">Ver provas</button>${b.active?` <button class="button ghost" type="button" data-unban-client="${escape(b.client_id)}" data-unban-steam="${escape(b.steam_id)}">Desbanir</button>`:''}</td></tr>`).join('')}</tbody></table>`:'<div class="desk-audit-empty"><div class="desk-empty-icon">⊘</div><h2>Nenhum banimento registrado</h2><p>As decisões e suas provas selecionadas aparecerão aqui.</p></div>');
  }
  function inspect(finding) {
    const panel=$('deskEvidenceInspector');
    panel.querySelector('.desk-empty-icon')?.remove();panel.querySelector('p')?.remove();
    const data=finding.evidence&&typeof finding.evidence==='object'?finding.evidence:{};
    $('deskEvidenceDetails').innerHTML=`<h3>${escape(finding.title||'Evidência')}</h3><p class="desk-inspect-value">${escape(finding.artifact_value||'')}</p><div class="desk-divider"></div><p>Tipo: <strong>${escape(finding.artifact_type||'Artefato')}</strong><br>Severidade: <strong>${escape(finding.severity||'info')}</strong></p><pre>${escape(JSON.stringify(data,null,2))}</pre><p class="desk-note">A classificação indica prioridade de revisão. A decisão continua sob responsabilidade da administração.</p><button class="button primary" type="button" id="deskLocateEvidence">Localizar na análise</button>`;
    $('deskLocateEvidence').onclick=()=>{
      const checkbox=document.querySelector(`.ban-evidence-checkbox[data-finding-id="${Number(finding.id)}"]`);
      const element=checkbox?.closest('.finding');
      if(element){for(const details of element.closest('details')?[element.closest('details')]:[])details.open=true;element.scrollIntoView({behavior:matchMedia('(prefers-reduced-motion: reduce)').matches?'auto':'smooth',block:'center'});}
    };
  }
  window.addEventListener('vorken:inspect',e=>inspect(e.detail));
  window.addEventListener('vorken:report',e=>{
    activeReport=e.detail;
    const rows=e.detail.findings.filter(f=>['critical','high','medium'].includes(f.severity));
    $('deskEvidenceTotal').textContent=`${rows.length} evidência(s)`;
    $('deskEvidenceRows').innerHTML=rows.length?rows.map(f=>`<tr data-desk-finding="${Number(f.id)}" tabindex="0"><td><input type="checkbox" data-desk-proof="${Number(f.id)}" aria-label="Selecionar ${escape(f.title)} como prova" ${e.detail.analysis.status==='completed'&&!e.detail.analysis.external_decision?'':'disabled'}></td><td><strong>${escape(f.title)}</strong><code>${escape(f.artifact_value)}</code></td><td>${escape(f.artifact_type)}</td><td><span class="tag ${escape(f.severity)}">${({critical:'Crítica',high:'Alta',medium:'Média'})[f.severity]}</span></td></tr>`).join(''):'<tr><td colspan="4" class="desk-note">Nenhuma evidência crítica ou para revisão nesta análise.</td></tr>';
    const a=e.detail.analysis;
    $('deskCaseTimeline').innerHTML=[['Sessão criada',a.created_at],['Coleta iniciada',a.started_at],['Relatório recebido',a.uploaded_at],['Processamento concluído',a.finished_at]].filter(([,time])=>time).map(([label,time])=>`<div class="desk-timeline-event"><i></i><time>${date(time)}</time><strong>${label}</strong></div>`).join('')||'<p class="desk-note">Esta sessão não contém datas de eventos disponíveis.</p>';
    $('deskEvidenceDetails').replaceChildren();
    if(e.detail.findings.length)inspect(e.detail.findings[0]);
    else $('deskEvidenceDetails').innerHTML='<p>Nenhum achado disponível nesta análise.</p>';
  });
  window.addEventListener('vorken:analyses',e=>{
    const rows=e.detail||[];
    $('deskPending').textContent=rows.filter(r=>r.status==='pending'||r.status==='created').length;
    $('deskProcessing').textContent=rows.filter(r=>['running','processing','started','uploaded'].includes(r.status)).length;
    $('deskCritical').textContent=rows.filter(r=>Number(r.critical_findings??r.high_findings??0)>0).length;
    $('deskCompleted').textContent=rows.filter(r=>r.status==='completed').length;
  });
  window.addEventListener('vorken:auth',e=>{
    loggedIn=e.detail.logged;clearInterval(timer);
    if(loggedIn){refresh().catch(e=>toast(e.message,true));timer=setInterval(()=>{if(!document.hidden)refresh(true).catch(()=>{});},15000);}
    else {clients=[];servers=[];selectedClientId='';activeReport=null;$('deskEvidenceDetails').replaceChildren();}
  });
  $('deskClientSelect').addEventListener('change',()=>{selectedClientId=$('deskClientSelect').value;renderFleet();loadBans().catch(e=>toast(e.message,true));});
  document.addEventListener('click',async e=>{
    const evidenceRow=e.target.closest('[data-desk-finding]');
    if(evidenceRow&&!e.target.matches('input')){const finding=activeReport?.findings.find(f=>Number(f.id)===Number(evidenceRow.dataset.deskFinding));if(finding){document.querySelectorAll('[data-desk-finding]').forEach(row=>row.classList.toggle('selected',row===evidenceRow));inspect(finding);}}
    const audit=e.target.closest('[data-audit-ban]');
    if(audit){
      audit.disabled=true;
      try{
        const {ban,evidence}=await request('/api/admin/fleet/bans/'+audit.dataset.auditBan+'/evidence');
        $('fleetAuditContent').innerHTML=`<div class="eyebrow">REGISTRO DE DECISÃO #${escape(ban.id)}</div><h2>Provas do banimento</h2><p class="muted">${escape(ban.reason)}</p>${ban.kind==='association'?`<p class="message">Associação com o jogador ${escape(ban.source_steam_id)}. As provas abaixo pertencem à decisão de origem.</p>`:''}<div class="desk-divider"></div>${evidence.length?evidence.map(f=>`<article class="desk-audit-proof"><span class="tag ${escape(f.severity)}">${escape(f.severity)}</span><h3>${escape(f.title)}</h3><code>${escape(f.artifact_value)}</code><p>Tipo: ${escape(f.artifact_type)}</p></article>`).join(''):'<p class="message">Este banimento foi recebido diretamente do servidor e não tem provas anexadas no Vorken.</p>'}<p class="desk-note">Somente as evidências selecionadas para esta decisão são exibidas.</p>`;
        $('fleetAuditDialog').showModal();
      }catch(error){toast(error.message,true);}finally{audit.disabled=false;}
    }
    const select=e.target.closest('[data-select-client]');
    if(select){selectedClientId=select.dataset.selectClient;renderFleet();document.querySelector('[data-admin-tab="sessions"]').click();}
    const unban=e.target.closest('[data-unban-steam]');
    if(unban && confirm(`Desbanir ${unban.dataset.unbanSteam} de todos os servidores deste cliente?`)){
      unban.disabled=true;
      try {const result=await request('/api/admin/fleet/unban',{clientId:Number(unban.dataset.unbanClient),steamId:unban.dataset.unbanSteam});toast(result.message);await loadBans();}
      catch(error){toast(error.message,true);unban.disabled=false;}
    }
    if(e.target.closest('[data-admin-tab="bans"]'))loadBans().catch(e=>toast(e.message,true));
  });
  document.addEventListener('keydown',e=>{if((e.key==='Enter'||e.key===' ')&&e.target.matches('[data-desk-finding]')){e.preventDefault();e.target.click();}});
  document.addEventListener('change',e=>{
    const proxy=e.target.closest('[data-desk-proof]');
    if(proxy){const original=document.querySelector('.ban-evidence-checkbox[data-finding-id="'+Number(proxy.dataset.deskProof)+'"]');if(original){original.checked=proxy.checked;original.dispatchEvent(new Event('change'));}else{proxy.checked=false;toast('Esta evidência não está disponível para uma nova decisão.',true);}}
    const original=e.target.closest('.ban-evidence-checkbox');
    if(original)document.querySelectorAll('[data-desk-proof="'+Number(original.dataset.findingId)+'"]').forEach(box=>box.checked=original.checked);
  });
  function form(id,action){$(id).addEventListener('submit',async e=>{
    e.preventDefault();const el=e.currentTarget;if(pending.has(el))return;pending.add(el);const button=el.querySelector('button[type=submit],button:not([type])');if(button)button.disabled=true;
    try{await action(el);}catch(error){toast(error.message,true);}finally{pending.delete(el);if(button)button.disabled=false;}
  });}
  $('fleetServersList').addEventListener('change',async e=>{
    const select=e.target.closest('[data-report-policy]');if(!select)return;
    const server=servers.find(s=>String(s.id)===select.dataset.reportPolicy);if(!server)return;
    const previous=server.report_visibility;select.disabled=true;
    try{await request('/api/admin/fleet/servers/'+server.id,{reportVisibility:select.value},'PATCH');server.report_visibility=select.value;toast('Disponibilidade do relatório atualizada.');}
    catch(error){select.value=previous;toast(error.message,true);}finally{select.disabled=false;}
  });
  form('fleetClientForm',async el=>{const {client}=await request('/api/admin/fleet/clients',{name:$('fleetClientName').value,serverLimit:Number($('fleetClientLimit').value)});selectedClientId=String(client.id);el.reset();await refresh();toast('Cliente cadastrado.');});
  form('fleetServerForm',async el=>{
    const clientId=Number($('fleetServerClient').value);if(!clientId)throw Error('Selecione um cliente.');
    const {server,token}=await request('/api/admin/fleet/servers',{clientId,name:$('fleetServerName').value});
    $('fleetServerToken').classList.remove('hidden');
    $('fleetServerToken').innerHTML=`<strong>Servidor ${escape(server.name)} registrado.</strong><p>Copie a chave agora. Ela só é exibida nesta resposta.</p><code class="fleet-token">${escape(token)}</code><p>URL: <code>${escape(location.origin)}</code></p><button type="button" class="button ghost" id="fleetCopyToken">Copiar chave</button>`;
    $('fleetCopyToken').onclick=()=>navigator.clipboard.writeText(token).then(()=>toast('Chave copiada.')).catch(()=>toast('Selecione a chave e copie manualmente.',true));
    selectedClientId=String(clientId);el.reset();await refresh();toast('Servidor registrado. Configure o plugin Rust para conectar.');
  });
  form('deskQuotaForm',async()=>{if(!selectedClientId)throw Error('Selecione um cliente.');await request('/api/admin/fleet/clients/'+selectedClientId,{serverLimit:Number($('deskServerLimit').value)},'PATCH');await refresh();toast('Limite de servidores atualizado.');});
  form('deskPolicyForm',async()=>{if(!selectedClientId)throw Error('Selecione um cliente.');await request('/api/admin/fleet/clients/'+selectedClientId,{associationEnabled:$('deskAssociationEnabled').checked,associationDays:Number($('deskAssociationDays').value),notifyChat:$('deskNotifyChat').checked},'PATCH');await refresh();toast('Política de associação atualizada.');});
  const dialog=document.createElement('dialog');dialog.id='fleetBanDialog';dialog.className='gf-ban-dialog';dialog.innerHTML=`<form class="gf-ban-dialog-card fleet-form" id="fleetBanForm"><div class="eyebrow">MODERAÇÃO MULTISSERVIDOR</div><h2>Banir jogador</h2><p id="fleetBanScope" class="muted"></p><label>Servidor de origem<select id="fleetBanServer" required></select></label><label>SteamID64 do jogador<input id="fleetBanSteam" pattern="7656119[0-9]{10}" maxlength="17" required></label><label>Motivo<textarea id="fleetBanReason" maxlength="500" required></textarea></label><p id="fleetBanSummary" class="desk-note"></p><div class="gf-ban-dialog-actions"><button class="button ghost" type="button" id="fleetBanCancel">Cancelar</button><button class="button gf-ban-button" type="submit">Confirmar banimento</button></div></form>`;document.body.append(dialog);
  const auditDialog=document.createElement('dialog');auditDialog.id='fleetAuditDialog';auditDialog.className='gf-ban-dialog';auditDialog.innerHTML='<div class="gf-ban-dialog-card"><div id="fleetAuditContent"></div><button class="button ghost" type="button" id="fleetAuditClose">Fechar auditoria</button></div>';document.body.append(auditDialog);$('fleetAuditClose').onclick=()=>auditDialog.close();
  let banContext=null;
  $('fleetBanCancel').onclick=()=>dialog.close();
  window.vorkenFleet={get selectedClientId(){return selectedClientId;},banAnalysis:async context=>{
    if(!context.evidenceIds.length){toast('Selecione pelo menos uma evidência para justificar o banimento.',true);return;}
    const client=selectedClient();const eligible=servers.filter(s=>String(s.client_id)===selectedClientId);
    if(!client||!eligible.length){toast('Cadastre um servidor para este cliente.',true);return;}
    banContext={...context,clientId:Number(selectedClientId)};
    $('fleetBanServer').innerHTML=eligible.map(s=>`<option value="${escape(s.id)}">${escape(s.name)} · ${s.online?'Online':'Sem conexão'}</option>`).join('');
    $('fleetBanSteam').value=activeReport?.analysis?.external_player_id||String(context.steamIds?.[0]?.steamId||context.steamIds?.[0]||'');
    $('fleetBanReason').value='';
    $('fleetBanScope').textContent=`Cliente: ${client.name}. O banimento valerá em ${eligible.length} servidor(es).`;
    $('fleetBanSummary').textContent=`${context.evidenceIds.length} evidência(s) selecionada(s). ${client.association_enabled?`Todos os integrantes do time receberão ${client.association_days} dia(s) por associação.`:'Associação desativada.'} ${client.notify_chat?'Os servidores notificarão no chat.':''}`;
    dialog.showModal();
  }};
  form('fleetBanForm',async()=>{
    const data=await request('/api/admin/fleet/bans',{clientId:banContext.clientId,analysisId:banContext.analysisId,evidenceIds:banContext.evidenceIds,serverId:Number($('fleetBanServer').value),steamId:$('fleetBanSteam').value,reason:$('fleetBanReason').value,playerName:activeReport?.analysis?.label||''});
    dialog.close();toast(data.message);await loadBans();
  });
  applyPolicy();
})();
