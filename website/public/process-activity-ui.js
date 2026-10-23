(() => {
  const state = {open:{items:[]},journal:{items:[]}}, limits={open:50,journal:50};
  const el=id=>document.getElementById(id);
  const date=value=>value && Number.isFinite(Date.parse(value)) ? new Date(value).toLocaleString('pt-BR') : 'indisponível';
  const line=(parent,label,value)=>{ if(!value)return; const p=document.createElement('p'); p.textContent=label+value;parent.append(p); };
  function render(kind) {
    const data=state[kind], host=el('activity-'+kind+'-list');if(!host)return;
    const query=el('activity-'+kind+'-search').value.toLocaleLowerCase();
    const rows=data.items.filter(r=>[r.name,r.path,r.pid,r.parentName,r.parentPath].join(' ').toLocaleLowerCase().includes(query));
    host.replaceChildren();
    for(const row of rows.slice(0,limits[kind])){
      const card=document.createElement('article');card.className='activity-card';
      const heading=document.createElement('h3');heading.textContent=row.name||'Processo sem nome';card.append(heading);
      line(card,'PID: ',String(row.pid||'indisponível'));line(card,'Caminho: ',row.path||'indisponível');
      line(card,kind==='journal'?'Executado em: ':'Iniciado em: ',date(row.timeUtc));
      line(card,'Origem: ',kind==='journal'?row.source+' · evento '+row.eventId:({scanned:'Arquivo analisado', 'metadata-only':'Somente metadados','file-excluded':'Arquivo fora do escopo',legacy:'Relatório anterior'})[row.inspectionStatus]||row.inspectionStatus);
      line(card,'Assinatura: ',row.signed ? row.signer||'confirmada' : 'não confirmada');
      line(card,'SHA-256: ',row.sha256);line(card,'Processo pai: ',[row.parentName,row.parentPath].filter(Boolean).join(' · '));
      line(card,'Contexto: ',(row.reasons||[]).join(' · '));host.append(card);
    }
    if(!rows.length)line(host,'',query?'Nenhum resultado para esta pesquisa.':'Nenhum item relevante disponível nesta coleta.');
    el('activity-'+kind+'-more').hidden=rows.length<=limits[kind];
  }
  for(const kind of ['open','journal']){
    el('activity-'+kind+'-search')?.addEventListener('input',()=>{limits[kind]=50;render(kind)});
    el('activity-'+kind+'-more')?.addEventListener('click',()=>{limits[kind]+=50;render(kind)});
  }
  window.addEventListener('vorken:report',event=>{
    const activity=event.detail?.report?.payload?.processActivity||{};
    for(const kind of ['open','journal']){
      state[kind]=activity[kind]||{items:[]};state[kind].items ||= [];limits[kind]=50;
      const data=state[kind];
      el(kind==='open'?'activityOpenCount':'activityJournalCount').textContent=data.items.length;
      const counts=data.items.length+' relevantes · '+(data.commonCount||0)+' comuns ocultos';
      let status=counts+' · Coletado em '+date(data.capturedAtUtc)+'.';
      if(kind==='journal'){
        status=counts+' · Inicialização: '+date(data.bootTimeUtc)+' · Fim da coleta: '+date(data.capturedAtUtc)+'. ';
        status+=data.legacy?'Este agente não enviou um Journal com limite de inicialização.': 'Mostra apenas execuções registradas pelo Windows (Security 4688 / Sysmon 1). Não é um histórico completo garantido. ';
        for(const s of data.sources||[])status+=' '+s.channel+': '+({available:'eventos disponíveis','no-events':'sem eventos no período',unavailable:'fonte indisponível'})[s.state]+(s.limitReached?' (limite de coleta atingido)':'')+'.';
      }
      el('activity-'+kind+'-status').textContent=status;render(kind);
    }
  });
})();
