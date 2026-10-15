import { isIP } from 'node:net';
import { createHash } from 'node:crypto';

const ORIGIN = 'https://api.battlemetrics.com';
const steamPattern = /^7656119\d{10}$/;
const list = value => Array.isArray(value) ? value : [];
const clean = (value, max = 300) => String(value ?? '').replace(/[\u0000-\u001f]/g, ' ').slice(0, max);

export function publicIp(value) {
  let ip = String(value || '').trim().replace(/^::ffff:/i, '');
  const version = isIP(ip);
  if (version === 4) {
    const [a,b] = ip.split('.').map(Number);
    if (a === 0 || a === 10 || a === 127 || a >= 224 || a === 169 && b === 254 || a === 172 && b >= 16 && b <= 31 || a === 192 && b === 168 || a === 100 && b >= 64 && b <= 127 || a === 198 && [18,19].includes(b)) return null;
    return ip;
  }
  // Only global unicast IPv6; exclude documentation space.
  if (version === 6 && /^[23]/i.test(ip) && !/^2001:db8:/i.test(ip)) return ip.toLowerCase();
  return null;
}

export function captureConnectionEvidence(req, proxyHops = 0) {
  const hops = Number(proxyHops);
  const forwarded = String(req.headers?.['x-forwarded-for'] || '').split(',').map(x => x.trim()).filter(Boolean);
  const chain = [...forwarded, req.socket?.remoteAddress || ''];
  const raw = Number.isInteger(hops) && hops > 0 && hops <= 5 && chain.length > hops
    ? chain[chain.length - 1 - hops] : req.socket?.remoteAddress;
  return { publicIp: publicIp(raw), source: 'report_upload_connection', observedAt: new Date().toISOString() };
}

export function playerIdentifiers(document, player) {
  const refs = list(player?.relationships?.identifiers?.data);
  const included = list(document?.included);
  return included.filter(x => x.type === 'identifier' && (
    String(x.relationships?.player?.data?.id || '') === String(player?.id || '') ||
    refs.some(ref => ref.type === 'identifier' && String(x.id) === String(ref.id))
  ))
    .map(x => ({ type: x.attributes?.type, value: String(x.attributes?.identifier || ''), lastSeen: x.attributes?.lastSeen || null }));
}

export function createBattleMetricsClient({ token = '', queryId = '', fetchImpl = fetch, now = Date.now, maxRequests = 35, deadlineMs = 25000, minIntervalMs = 1100 } = {}) {
  const cache = new Map();
  let blockedUntil = 0;
  let nextRequestAt = 0;
  async function analyze(report, linkedSteamId) {
    const base = { provider: 'BattleMetrics', status: token ? 'ok' : 'not_configured', checkedAt: new Date(now()).toISOString(), accounts: [], checks: [], truncated: false,
      note: 'Associação por IP não comprova uso da conta neste computador. Resultados limitados às permissões do token; ausência de registro não comprova ausência de bans.' };
    if (!token) return base;
    const local = new Set(list(report?.steamAccounts).map(x => String(x?.steamId64 || '')).filter(x => steamPattern.test(x)));
    const seeds = [...new Set([String(linkedSteamId || ''), ...local])].filter(x => steamPattern.test(x));
    const ip = publicIp(report?.connectionEvidence?.publicIp);
    const key = createHash('sha256').update(JSON.stringify([seeds,ip,queryId,[...local].sort()])).digest('hex');
    const cached = cache.get(key);
    if (cached && now() - cached.at < 15 * 60 * 1000) return { ...structuredClone(cached.value), cached: true };
    if (now() < blockedUntil) return { ...base, status: 'rate_limited', retryAt: new Date(blockedUntil).toISOString() };
    const started = now(); let requests = 0;
    const accounts = new Map();
    async function get(path, params = {}) {
      if (++requests > maxRequests || now() - started >= deadlineMs) { base.truncated = true; throw Object.assign(new Error('budget'), { status: 'partial' }); }
      const waitMs = Math.max(0, nextRequestAt - now());
      if (now() - started + waitMs >= deadlineMs) { base.truncated = true; throw Object.assign(new Error('budget'), {status:'partial'}); }
      nextRequestAt = now() + waitMs + minIntervalMs;
      if (waitMs) await new Promise(resolve => setTimeout(resolve, waitMs));
      if (now() < blockedUntil) throw Object.assign(new Error('rate_limited'), {status:'rate_limited'});
      const url = new URL(path, ORIGIN);
      if (url.origin !== ORIGIN) throw new Error('Invalid API origin');
      for (const [name,value] of Object.entries(params)) url.searchParams.set(name,value);
      const response = await fetchImpl(url, { headers: { Authorization: 'Bearer ' + token, Accept: 'application/json' }, redirect: 'error', signal: AbortSignal.timeout(Math.max(1, Math.min(6000, deadlineMs - (now() - started)))) });
      if (!response.ok) {
        const status = response.status === 401 ? 'unauthorized' : response.status === 403 ? 'forbidden' : response.status === 429 ? 'rate_limited' : 'unavailable';
        if (response.status === 429) {
          const retry = response.headers.get('retry-after');
          const seconds = Number(retry);
          blockedUntil = now() + Math.max(60000, Number.isFinite(seconds) ? seconds * 1000 : (Date.parse(retry) - now()) || 60000);
        }
        throw Object.assign(new Error(status), { status });
      }
      const json = await response.json();
      if (!json || typeof json !== 'object' || !('data' in json)) throw new Error('Invalid API response');
      return json;
    }
    async function check(kind, run) {
      if (base.checks.some(x => ['unauthorized','rate_limited'].includes(x.status))) return;
      try { await run(); base.checks.push({ kind, status: 'ok' }); }
      catch (error) { base.checks.push({ kind, status: error.status || 'unavailable' }); }
    }
    function add(player, document, evidence) {
      const id = String(player?.id || '');
      if (player?.type !== 'player' || !/^\d+$/.test(id)) return;
      const ids = playerIdentifiers(document,player);
      const steamIds = ids.filter(x => x.type === 'steamID' && steamPattern.test(x.value)).map(x => x.value);
      const previous = accounts.get(id);
      const row = previous || { playerId: id, name: clean(player.attributes?.name), steamIds, foundOnPc: steamIds.some(x => local.has(x)), profileUrl: 'https://www.battlemetrics.com/rcon/players/' + id, associations: [], bans: [], banStatus: 'not_checked' };
      if (!row.associations.some(x => x.kind === evidence.kind && x.value === evidence.value)) row.associations.push(evidence);
      accounts.set(id,row);
    }
    async function search(value, type) {
      let pagination = {};
      for (let page = 0; page < 3; page++) {
        const doc = await get('/players', { 'filter[search]': '"' + value + '"', include: 'identifier', 'filter[identifiers]':'steamID,ip', 'page[size]': '100', ...pagination });
        for (const player of list(doc.data)) {
          const match = playerIdentifiers(doc,player).find(x => x.type === type && (type === 'ip' ? publicIp(x.value) === value : x.value === value));
          // Search is not proof: require an exact identifier attached to this player.
          if (match) add(player,doc,{kind:type === 'ip' ? 'shared_ip' : 'steam_id', value, lastSeen:match.lastSeen});
        }
        if (list(doc.data).length && !list(doc.data).some(player => playerIdentifiers(doc,player).some(x => x.type === type && (type === 'ip' ? publicIp(x.value) === value : x.value === value)))) {
          throw Object.assign(new Error('unverified_results'), {status:'identifiers_unavailable'});
        }
        const next = doc.links?.next;
        if (!next) return;
        const nextUrl = new URL(next,ORIGIN);
        if (nextUrl.origin !== ORIGIN || nextUrl.pathname !== '/players') { base.truncated = true; return; }
        const cursor = nextUrl.searchParams.get('page[key]');
        const offset = nextUrl.searchParams.get('page[offset]');
        if (cursor) pagination = {'page[key]':cursor,'page[rel]':'next'};
        else if (offset !== null && /^\d+$/.test(offset) && Number(offset) <= 90 && Number(offset) > Number(pagination['page[offset]'] || 0)) pagination = {'page[offset]':offset};
        else { base.truncated = true; return; }
        if (page === 2) { base.truncated = true; return; }
      }
    }
    if (seeds.length > 10) base.truncated = true;
    for (const steamId of seeds.slice(0,10)) await check('steam:' + steamId, () => search(steamId,'steamID'));
    if (ip) await check('connection_ip', () => search(ip,'ip'));
    else base.checks.push({kind:'connection_ip',status:'missing_ip'});
    if (queryId) {
      // Saved queries run against known BM players, never an arbitrary injected IP.
      for (const seed of [...accounts.values()].filter(x => x.associations.some(a => a.kind === 'steam_id')).slice(0,3)) {
        await check('related:' + seed.playerId, async () => {
          const doc = await get('/players/' + seed.playerId + '/relationships/player-query/' + encodeURIComponent(queryId), {'page[size]':'20',include:'player,identifier','filter[identifiers]':'steamID,ip'});
          if (doc.links?.next) base.truncated = true;
          for (const result of list(doc.data)) {
            const ref = result.relationships?.player?.data;
            if (!ref || !/^\d+$/.test(String(ref.id))) continue;
            const included = list(doc.included).find(x => x.type === 'player' && String(x.id) === String(ref.id));
            // Global matches may intentionally hide unique identifiers. Keep that
            // distinction instead of inventing a SteamID or marking it as on-PC.
            add(included || {type:'player',id:ref.id},doc,{kind:'player_query',value:seed.playerId,score:Number(result.attributes?.score)||0});
          }
        });
      }
    } else base.checks.push({kind:'player_queries',status:'not_configured'});
    if (accounts.size > 20) base.truncated = true;
    for (const account of [...accounts.values()].slice(0,20)) {
      await check('bans:' + account.playerId, async () => {
        const doc = await get('/bans', {'filter[player]':account.playerId,'filter[expired]':'true',include:'server,organization,banList','page[size]':'100'});
        if (doc.links?.next) base.truncated = true;
        account.bans = list(doc.data).filter(x => x.type === 'ban' && String(x.relationships?.player?.data?.id) === account.playerId).slice(0,20).map(ban => {
          const attrs = ban.attributes || {};
          const serverId = ban.relationships?.server?.data?.id;
          const server = list(doc.included).find(x => x.type === 'server' && String(x.id) === String(serverId));
          return { id:clean(ban.id),reason:clean(attrs.reason,700),createdAt:attrs.timestamp || null,expiresAt:attrs.expires || null,
            status: attrs.expires ? (Date.parse(attrs.expires) > now() ? 'active' : 'expired') : 'no_expiry', server:clean(server?.attributes?.name || serverId || 'Organização / lista'),url:'https://www.battlemetrics.com/rcon/bans/' + encodeURIComponent(ban.id) };
        });
        account.banStatus = account.bans.length ? 'records_found' : 'no_accessible_records';
      });
      const outcome = base.checks.find(x => x.kind === 'bans:' + account.playerId);
      if (outcome && outcome.status !== 'ok') account.banStatus = outcome.status;
      base.accounts.push(account);
    }
    const failures = base.checks.filter(x => !['ok','not_configured','missing_ip'].includes(x.status));
    base.status = failures.length ? (base.accounts.length ? 'partial' : failures[0].status) : base.truncated ? 'partial' : 'ok';
    base.requests = requests;
    if (!failures.length && !base.truncated) {
      if (cache.size >= 500) cache.delete(cache.keys().next().value);
      cache.set(key,{at:now(),value:structuredClone(base)});
    }
    return base;
  }
  return { analyze };
}
