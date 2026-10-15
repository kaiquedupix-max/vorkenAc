(() => {
  const labels = {
    ok:'Consulta concluída nos dados acessíveis', partial:'Consulta parcial — confira as limitações',
    not_configured:'Integração aguardando configuração', unauthorized:'Token inválido ou expirado',
    forbidden:'Acesso negado: confira plano e permissões', rate_limited:'Limite de consultas atingido',
    unavailable:'BattleMetrics indisponível', missing_ip:'IP público indisponível',
    identifiers_unavailable:'Resultados sem identificador exato verificável — confira permissões',
    records_found:'Registros encontrados', no_accessible_records:'Nenhum ban retornado nas listas acessíveis',
    not_checked:'Consulta de bans não realizada', active:'Ativo', expired:'Expirado', no_expiry:'Sem expiração informada'
  };
  const esc = value => String(value ?? '').replace(/[&<>"']/g, x => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[x]));
  const date = value => { const d = new Date(value); return value && !Number.isNaN(d.getTime()) ? d.toLocaleString('pt-BR') : 'Não informado'; };
  const safeLink = (url,text) => {
    try { const u = new URL(url); if(u.protocol === 'https:' && u.hostname === 'www.battlemetrics.com') return '<a target="_blank" rel="noopener noreferrer" href="'+esc(u.href)+'">'+esc(text)+'</a>'; } catch {}
    return esc(text);
  };
  window.renderBattleMetrics = data => {
    const target = document.getElementById('battleMetricsResults'); if(!target) return;
    if(!data) { target.textContent = 'Esta análise ainda não possui consulta BattleMetrics. Reprocesse após configurar a integração.'; return; }
    const accounts = Array.isArray(data.accounts) ? data.accounts : [];
    const checks = Array.isArray(data.checks) ? data.checks : [];
    target.innerHTML = '<p><strong>'+esc(labels[data.status] || 'Estado desconhecido')+'</strong> · '+esc(date(data.checkedAt))+(data.cached?' · Resultado em cache':'')+'</p>'+
      '<p>IP compartilhado e pontuação de associação não comprovam uso da conta neste PC ou evasão. Uma consulta sem registros não garante ausência de bans.</p>'+
      (data.truncated?'<p><strong>Resultados limitados por paginação, quantidade de contas ou tempo de consulta.</strong></p>':'')+
      accounts.map(account => '<article class="info-card"><div><h3>'+safeLink(account.profileUrl,account.name || 'Perfil '+account.playerId)+'</h3><p>'+esc(account.foundOnPc?'SteamID também encontrado no PC':'Vínculo externo — uso neste PC não comprovado')+'</p><p>SteamIDs: '+esc((account.steamIds || []).join(', ') || 'Não disponibilizados pelas permissões')+'</p><ul>'+
        (account.associations || []).map(a => '<li>'+esc(a.kind === 'shared_ip' ? 'IP coincidente: '+a.value : a.kind === 'steam_id' ? 'SteamID exato: '+a.value : 'Player Query relacionada ao perfil '+a.value+' · pontuação '+a.score+' (não é porcentagem)')+(a.lastSeen?' · '+esc(date(a.lastSeen)):'')+'</li>').join('')+'</ul><p>'+esc(labels[account.banStatus] || account.banStatus)+'</p>'+
        (account.bans || []).map(b => '<p>'+safeLink(b.url,b.server || 'Registro de ban')+' · '+esc(labels[b.status] || b.status)+'<br>'+esc(b.reason || 'Motivo não informado')+'<br>Registro: '+esc(date(b.createdAt))+' · Expiração: '+esc(date(b.expiresAt))+'</p>').join('')+'</div></article>').join('')+
      (!accounts.length && data.status === 'ok'?'<p>Nenhum perfil com identificador exato foi retornado nas fontes acessíveis.</p>':'')+
      '<details><summary>Cobertura e diagnóstico das consultas</summary><ul>'+checks.map(c=>'<li>'+esc(c.kind)+': '+esc(labels[c.status] || c.status)+'</li>').join('')+'</ul><p>Player Queries exigem uma consulta salva e adesão ao Global Player Matching. Bans são limitados às listas acessíveis ao token.</p></details>';
  };
})();
