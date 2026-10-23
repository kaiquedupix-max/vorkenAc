const normalize = name => name.normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
const playerNames = new Set(['jogador verificado', 'jogadores verificados', 'verified player', 'verified players']);
const verifiedNames = new Set(['verificado', 'verificados', 'verified']);

export async function ensureVerifiedRole(guild, storedId) {
  const roles = [...guild.roles.cache.values()].filter(role => !role.managed && role.id !== guild.id);
  const stored = roles.find(role => role.id === storedId);
  // Prefer the community's established player role over an old bot-created duplicate.
  const existing = roles.find(role => playerNames.has(normalize(role.name)))
    || stored
    || roles.find(role => verifiedNames.has(normalize(role.name)));
  if (existing) return existing;
  return guild.roles.create({
    name: '✅ Jogador verificado', color: 0x2ecc71, permissions: [], mentionable: false,
    ...(guild.features.includes('ROLE_ICONS') ? { unicodeEmoji: '✅' } : {}),
    reason: 'Cargo de verificação Vorken'
  });
}
