(() => {
  const state = {open:{items:[]},journal:{items:[]}}, limits={open:50,journal:50};
  const el=id=>document.getElementById(id);
  const date=value=>value && Number.isFinite(Date.parse(value)) ? new Date(value).toLocaleString('pt-BR') : 'indisponível';
  const line=(parent,label,value,className='')=>{ if(!value)return; const p=document.createElement('p'); p.className=className;p.textContent=label+value;parent.append(p); };
  function render(kind) {
    const data=state[kind], host=el('activity-'+kind+'-list');if(!host)return;
    const query=el('activity-'+kind+'-search').value.toLocaleLowerCase();
    const full=el('activity-journal-mode')?.value==='full';
    const available=kind==='journal'?(data.sessions||data.items).filter(row=>full||row.sinceBoot!==false):data.items;
    const rows=available.filter(r=>[r.name,r.path,r.pid,r.parentName,r.parentPath].join(' ').toLocaleLowerCase().includes(query));
    if(kind==='journal'){
      el('activityJournalCount').textContent=available.length;
      let status=(full?'Histórico completo disponível':'Desde a inicialização do PC')+' · '+available.length+' processo(s) · Inicialização: '+date(data.bootTimeUtc)+' · Scan: '+date(data.capturedAtUtc)+'. ';
      if(full&&!data.fullHistory)status+='Este relatório antigo contém somente os eventos coletados desde a inicialização; execute um novo scan para coletar o histórico anterior. ';
      if(data.coverage==='limited')status+='Limite de coleta atingido; histórico parcial. ';
      status+='Os horários dependem dos registros retidos pelo Windows. ';
      for(const s of data.sources||[])status+=s.channel+': '+({available:'eventos disponíveis','no-events':'sem eventos no período',unavailable:'fonte indisponível'})[s.state]+(s.limitReached?' (limite atingido)':'')+'. ';
      el('activity-journal-status').textContent=status;
    }
    host.replaceChildren();
    for(const row of rows.slice(0,limits[kind])){
      const closed=kind==='journal' && Boolean(row.closedAtUtc);
      const card=document.createElement('article');card.className='activity-card '+(closed?'activity-closed':'activity-opened');
      const heading=document.createElement('h3');heading.textContent=row.name||'Processo sem nome';card.append(heading);
      line(card,'PID: ',String(row.pid||'indisponível'));line(card,'Caminho: ',row.path||'indisponível');
      if(kind==='open')line(card,'Estado: ','Aberto no momento do scan');
      line(card,'Aberto em: ',date(kind==='journal'?row.openedAtUtc:row.timeUtc),'activity-start-time');
      if(kind==='journal')line(card,'Fechado em: ',row.closedAtUtc?date(row.closedAtUtc):'Fechamento não registrado','activity-end-time');
      line(card,'Origem: ',kind==='journal'?row.source+' · evento '+row.eventId:({scanned:'Arquivo analisado', 'metadata-only':'Somente metadados','file-excluded':'Arquivo fora do escopo',legacy:'Relatório anterior'})[row.inspectionStatus]||row.inspectionStatus);
      line(card,'Assinatura: ',row.signed ? row.signer||'confirmada' : 'não confirmada');
      line(card,'SHA-256: ',row.sha256);line(card,'Processo pai: ',[row.parentName,row.parentPath].filter(Boolean).join(' · '));
      line(card,'Contexto: ',(row.reasons||[]).join(' · '));host.append(card);
    }
    if(!rows.length)line(host,'',query?'Nenhum resultado para esta pesquisa.':'Nenhum item relevante disponível nesta coleta.');
    el('activity-'+kind+'-more').hidden=rows.length<=limits[kind];
  }
  el('activity-journal-mode')?.addEventListener('change',()=>{limits.journal=50;render('journal')});
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
        status+=data.legacy?'Este agente não enviou um Journal com limite de inicialização.': 'Aberturas e fechamentos registrados desde a inicialização (Security 4688/4689 e Sysmon 1/5). Cada linha representa um evento; horários ausentes não são estimados. O histórico depende da auditoria disponível. ';
        for(const s of data.sources||[])status+=' '+s.channel+': '+({available:'eventos disponíveis','no-events':'sem eventos no período',unavailable:'fonte indisponível'})[s.state]+(s.limitReached?' (limite de coleta atingido)':'')+'.';
      }
      el('activity-'+kind+'-status').textContent=status;render(kind);
    }
  });
})();
