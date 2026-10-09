import crypto from 'node:crypto';

export const PERIODS = Object.freeze({ mensal: 1, trimestral: 3, semestral: 6, anual: 12 });
export const hash = value => crypto.createHash('sha256').update(String(value)).digest('hex');
export function serverSlug(name) {
  const slug=String(name||'').normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase().replace(/[^a-z0-9-]+/g,'').replace(/^-|-$/g,'').slice(0,40).replace(/-$/,'');
  const reserved=new Set(['www','api','admin','mail','smtp','portal','app','support','suporte','status','checkout']);
  return slug.length>=3&&!reserved.has(slug)?slug:'servidor';
}
export function addMonths(date, months) {
  const result = new Date(date), day = result.getUTCDate();
  result.setUTCDate(1); result.setUTCMonth(result.getUTCMonth() + months);
  const last = new Date(Date.UTC(result.getUTCFullYear(), result.getUTCMonth() + 1, 0)).getUTCDate();
  result.setUTCDate(Math.min(day, last)); return result;
}
export function licensed(customer, now = new Date()) {
  return customer?.status === 'active' && customer?.license_status === 'active' &&
    new Date(customer.license_until) > now;
}
export function managesGuild(guild) {
  try { return !!guild.owner || (BigInt(guild.permissions || '0') & 40n) !== 0n; }
  catch { return false; }
}
export function validDiscordInvite(input) {
  try { const url = new URL(input);
    if (url.protocol !== 'https:' || url.username || url.password) return false;
    return (url.hostname === 'discord.gg' && /^\/[\w-]+\/?$/.test(url.pathname)) ||
      (['discord.com', 'www.discord.com'].includes(url.hostname) && /^\/invite\/[\w-]+\/?$/.test(url.pathname));
  } catch { return false; }
}
export function validIds(values) {
  if (!Array.isArray(values) || values.length > 200) return null;
  const ids = [...new Set(values.map(Number))];
  return ids.every(x => Number.isSafeInteger(x) && x > 0) ? ids : null;
}
export function seal(value, secret) {
  const iv = crypto.randomBytes(12), cipher = crypto.createCipheriv('aes-256-gcm', crypto.createHash('sha256').update(secret).digest(), iv);
  const data = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), data]).toString('base64url');
}
export function unseal(value, secret) {
  const raw = Buffer.from(value, 'base64url'), decipher = crypto.createDecipheriv('aes-256-gcm', crypto.createHash('sha256').update(secret).digest(), raw.subarray(0,12));
  decipher.setAuthTag(raw.subarray(12,28));
  return Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]).toString('utf8');
}
