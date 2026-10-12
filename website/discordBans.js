// Only resolve accounts linked by verification on this exact Rust server/guild.
export async function applyDiscordBan(db, guild, serverId, steamId, reason) {
  const {rows} = await db.query(`SELECT v.discord_user_id FROM vorken_sessions v
    JOIN vorken_servers s ON s.id=v.server_id
    WHERE v.server_id=$1 AND s.guild_id=$2 AND v.steam_id=$3
      AND v.discord_user_id IS NOT NULL
    ORDER BY v.created_at DESC LIMIT 1`, [serverId, guild.id, steamId]);
  const userId = rows[0]?.discord_user_id;
  if (!userId || !/^\d{17,20}$/.test(userId)) return false;
  await guild.members.ban(userId, {
    reason: `Vorken | Steam ${steamId} | ${String(reason || 'Banimento confirmado no Rust.')}`.slice(0, 500),
    deleteMessageSeconds: 0
  });
  return true;
}
