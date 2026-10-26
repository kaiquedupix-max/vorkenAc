const normalized = value => String(value || '').replaceAll('/', '\\').toLowerCase();
const pid = value => /^(?:0x[0-9a-f]+|\d+)$/i.test(String(value)) ? String(Number(value)) : String(value || '');
const time = value => Date.parse(value);

// The Journal describes recorded launches and exits, independently of the
// current-process snapshot shown in the separate Processes tab.
export function buildProcessSessions(events, bootTimeUtc) {
  const boot = time(bootTimeUtc), sessions = [], pending = new Map();
  const ordered = [...events].sort((a,b) => time(a.timeUtc)-time(b.timeUtc) || (a.action==='closed')-(b.action==='closed'));
  for (const row of ordered) {
    const identity = row.processGuid || (pid(row.pid) && normalized(row.path) + '|' + pid(row.pid));
    const key = identity ? [row.source, identity, time(row.timeUtc)>=boot].join('|') : null;
    if (row.action !== 'closed') {
      const session = {...row, openedAtUtc:row.timeUtc, closedAtUtc:null, state:'opened'};
      sessions.push(session);
      if(key)pending.set(key,session);
    } else {
      const session=key && pending.get(key);
      if(session){session.closedAtUtc=row.timeUtc;session.state='closed';pending.delete(key);}
      else sessions.push({...row,openedAtUtc:null,closedAtUtc:row.timeUtc,state:'closed'});
    }
  }
  // Security and Sysmon may report the same launch. Keep one row, preserving
  // distinct launches even when Windows later reuses the same PID.
  const merged=[],buckets=new Map();
  for(const row of sessions){
    const anchor=row.openedAtUtc||row.closedAtUtc;
    const second=Math.floor(time(anchor)/1000),identity=normalized(row.path)+'|'+pid(row.pid);
    const candidates=Number.isFinite(second)&&pid(row.pid)?[-1,0,1].flatMap(offset=>buckets.get(identity+'|'+(second+offset))||[]):[];
    const duplicate=candidates.find(other=>!other.source.split(' / ').includes(row.source) &&
      Boolean(row.openedAtUtc)===Boolean(other.openedAtUtc) && Math.abs(time(other.openedAtUtc||other.closedAtUtc)-time(anchor))<=1000 &&
      (!row.closedAtUtc || !other.closedAtUtc || Math.abs(time(other.closedAtUtc)-time(row.closedAtUtc))<=1000));
    if(duplicate){
      if(row.closedAtUtc){duplicate.closedAtUtc=row.closedAtUtc;duplicate.state='closed';}
      duplicate.source=[...new Set([duplicate.source,row.source])].join(' / ');
    } else {
      const entry={...row};merged.push(entry);
      const key=identity+'|'+second;
      if(!buckets.has(key))buckets.set(key,[]);
      buckets.get(key).push(entry);
    }
  }
  return merged.map(row=>({...row,pid:pid(row.pid),sinceBoot:time(row.openedAtUtc)>=boot||time(row.closedAtUtc)>=boot}))
    .sort((a,b)=>(time(b.closedAtUtc||b.openedAtUtc)||0)-(time(a.closedAtUtc||a.openedAtUtc)||0));
}
