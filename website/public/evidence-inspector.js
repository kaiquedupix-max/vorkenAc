(() => {
  'use strict';
  function safeUrl(value) {
    try { const url=new URL(value);return ['http:','https:'].includes(url.protocol)?url.href:''; }
    catch { return ''; }
  }
  function origins(evidence={}) {
    return [evidence,...(Array.isArray(evidence.downloadOrigins)?evidence.downloadOrigins:[])].flatMap(item=>{
      const rows=[];
      for(const [key,label] of [['finalUrl','URL final do download'],['sourceUrl','Origem do download'],
        ['pageUrl','Página do download'],['referrerUrl','Página de referência'],['siteUrl','Site']]) {
        const url=safeUrl(item[key]);if(url)rows.push({label,url,browser:item.browser,profile:item.profile,path:item.targetPath||item.currentPath});
      }
      for(const value of Array.isArray(item.urlChain)?item.urlChain:[]) {
        const url=safeUrl(value);if(url)rows.push({label:'Cadeia de redirecionamento',url,browser:item.browser,profile:item.profile});
      }
      return rows;
    });
  }
  globalThis.VorkenEvidenceInspector={safeUrl,origins};
  if(typeof window==='undefined')return;
  const add=(parent,tag,text)=>{const node=document.createElement(tag);if(text!=null)node.textContent=text;parent.appendChild(node);return node;};
  window.addEventListener('vorken:inspect',event=>{
    const finding=event.detail;if(!finding)return;
    let dialog=document.getElementById('vorkenEvidenceDialog');
    if(!dialog){dialog=document.createElement('dialog');dialog.id='vorkenEvidenceDialog';dialog.setAttribute('aria-labelledby','vorkenEvidenceTitle');document.body.appendChild(dialog);}
    dialog.replaceChildren();
    const close=add(dialog,'button','Fechar evidência');close.type='button';close.addEventListener('click',()=>dialog.close());
    add(dialog,'h2',finding.title||'Inspecionar evidência').id='vorkenEvidenceTitle';
    add(dialog,'code',finding.artifact_value||'');
    add(dialog,'h3','De onde foi baixado');
    const evidence=finding.evidence||{},links=origins(evidence);
    if(!links.length)add(dialog,'p','A origem do download não foi registrada para este arquivo no relatório.');
    for(const item of links){
      const row=add(dialog,'div');add(row,'strong',item.label);
      const link=add(row,'a',item.url);link.href=item.url;link.target='_blank';link.rel='noopener noreferrer';
      if(item.browser)add(row,'small',[item.browser,item.profile].filter(Boolean).join(' · '));
      if(item.path)add(row,'code',item.path);
    }
    add(dialog,'h3','Detalhes técnicos da evidência');
    add(dialog,'pre',JSON.stringify(evidence,null,2));
    if(!dialog.open)dialog.showModal();
    close.focus();
  });
})();
