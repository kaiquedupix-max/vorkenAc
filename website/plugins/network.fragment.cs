        private class BridgeNetworkBan
        {
            public string id, steamId, playerName, reason, kind, expiresAt;
        }
        private void ApplyNetworkBan(BridgeNetworkBan ban)
        {
            ulong steamId;
            if (ban == null || !ulong.TryParse(ban.steamId, out steamId)) return;
            long expiry = -1;
            if (!string.IsNullOrWhiteSpace(ban.expiresAt))
            {
                DateTimeOffset expires;
                if (!DateTimeOffset.TryParse(ban.expiresAt, out expires)) return;
                expiry = expires.ToUnixTimeSeconds();
                if (expiry <= DateTimeOffset.UtcNow.ToUnixTimeSeconds()) return;
            }
            var existing = ServerUsers.Get(steamId);
            if (existing != null && existing.group == ServerUsers.UserGroup.Banned)
            {
                // Never replace a permanent or longer local punishment with a shorter one.
                if (existing.expiry <= 0 || (expiry > 0 && existing.expiry >= expiry)) return;
            }
            var target = BasePlayer.FindByID(steamId) ?? BasePlayer.FindSleeping(steamId);
            string name = string.IsNullOrWhiteSpace(ban.playerName) ? (target == null ? ban.steamId : target.displayName) : ban.playerName;
            if (sessions.ContainsKey(steamId)) End(steamId, null);
            // Do not call SetVorkenBan: a replicated ban must not punish a new team or echo back.
            ServerUsers.Set(steamId, ServerUsers.UserGroup.Banned, name, ban.reason, expiry);
            ServerUsers.Save();
            if (target != null && target.IsConnected) target.Kick(ban.reason);
        }

