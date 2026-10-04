        private const string ApiBase = "__VORKEN_API__";
        private const string Installation = "__VORKEN_INSTALLATION__";
        private bool bridgeActive;
        private BridgeNotifications bridgeNotifications = new BridgeNotifications();
        private BridgeVerification bridgeVerification = new BridgeVerification();
        private class BridgeVerification
        {
            public int timeoutSeconds = 300;
            public bool banOnTimeout = false, banOnRefusal = true, banOnDisconnect = true;
        }
        private class BridgeNotifications
        {
            public bool rustStarted = true, rustVerified = true, rustBans = true;
        }
        private string AdministratorDisplay(string administrator)
        {
            string value = (administrator ?? "").Trim();
            if (value.StartsWith("discord:", StringComparison.OrdinalIgnoreCase))
                value = value.Substring("discord:".Length).Trim();
            int separator = value.IndexOf('|');
            if (separator >= 0)
            {
                string display = value.Substring(separator + 1).Trim();
                if (!string.IsNullOrWhiteSpace(display)) return Clean(display);
                value = value.Substring(0, separator).Trim();
            }
            if (value.StartsWith("customer:", StringComparison.OrdinalIgnoreCase) || value == "owner" || value == "console")
                return "Administracao Vorken";
            ulong discordId;
            if (ulong.TryParse(value, out discordId)) return "Administracao Vorken";
            return string.IsNullOrWhiteSpace(value) ? "Administracao Vorken" : Clean(value);
        }
        private void AnnounceBridge(string kind, string playerName, string administrator = null)
        {
            string name = Clean(playerName);
            if (kind == "start" && bridgeNotifications.rustStarted)
                Server.Broadcast("<color=#FF2222>[VERIFICAÇÃO]</color> Foi iniciado um processo de verificação administrativa com o jogador <color=#FF5555>" + name + "</color>. Administrador responsável: <color=#FFD166>" + AdministratorDisplay(administrator) + "</color>.");
            else if (kind == "approve" && bridgeNotifications.rustVerified)
                Server.Broadcast("<color=#2bf0c9>[VERIFICAÇÃO]</color> O jogador <color=#2bf0c9>" + name + "</color> foi verificado e liberado pela administração. ✅");
            else if (kind == "deny" && bridgeNotifications.rustBans)
                Server.Broadcast("<color=#FF2222>[VORKEN SCANNER]</color> O jogador <color=#FF5555>" + name + "</color> foi banido após verificação administrativa.");
        }
        private bool syncPending;
        private DateTime lastBridgeResponse = DateTime.UtcNow;
        private BridgeData bridge = new BridgeData();
        private class BridgeData
        {
            public List<BridgeEvent> Events = new List<BridgeEvent>();
            public Dictionary<string, BridgeReceipt> Receipts = new Dictionary<string, BridgeReceipt>();
            public List<string> Completed = new List<string>();
        }
        private class BridgeEvent
        {
            public string id, eventType, steamId, playerName, sessionId, code, administrator, reason, expiresAt;
        }
        private class BridgeReceipt
        {
            public string id, result;
            public bool ok;
        }
        private class BridgePlayer
        {
            public string steamId, name;
        }
        private DateTime lastPlayersSent = DateTime.MinValue;
        private class BridgeCommand
        {
            public bool detachedSession;
            public string id, sessionId, action, steamId, actorId, reason;
        }
        private class BridgeResponse
        {
            public bool active;
            public BridgeNotifications notifications;
            public BridgeVerification verification;
            public string discord, channel;
            public List<string> accepted, acknowledged;
            public List<BridgeCommand> commands;
        }
        private void LoadBridge()
        {
            try { bridge = Interface.Oxide.DataFileSystem.ReadObject<BridgeData>(Name + ".Bridge") ?? new BridgeData(); }
            catch { bridge = new BridgeData(); }
        }
        private void SaveBridge()
        {
            Interface.Oxide.DataFileSystem.WriteObject(Name + ".Bridge", bridge);
        }
        private void QueueBridgeEvent(string type, ulong steamId, Session session, string reason)
        {
            bridge.Events.Add(new BridgeEvent {
                id = Guid.NewGuid().ToString(), eventType = type, steamId = steamId.ToString(),
                playerName = session.Nome, sessionId = session.Id, code = session.Codigo,
                administrator = session.Administrador, reason = reason,
                expiresAt = session.PrazoUtc.ToUniversalTime().ToString("o")
            });
            SaveBridge();
        }
        private void QueueJoin(BasePlayer player)
        {
            bridge.Events.Add(new BridgeEvent { id = Guid.NewGuid().ToString(),
                eventType = "player_join", steamId = player.UserIDString, playerName = player.displayName });
            SaveBridge();
        }
        private void ReleaseBridgeSessions()
        {
            foreach (var item in new Dictionary<ulong, Session>(sessions))
                End(item.Key, "Verificacao encerrada: conexao Vorken indisponivel.");
        }
        private void SyncBridge()
        {
            if (unloading) return;
            if ((DateTime.UtcNow - lastBridgeResponse).TotalSeconds > 90)
            {
                bridgeActive = false;
                ReleaseBridgeSessions();
            }
            if (syncPending || !ApiBase.StartsWith("https://", StringComparison.Ordinal) || Installation.StartsWith("__"))
                return;
            syncPending = true;
            var events = bridge.Events.GetRange(0, Math.Min(50, bridge.Events.Count));
            var receipts = new List<BridgeReceipt>(bridge.Receipts.Values);
            if (receipts.Count > 50) receipts = receipts.GetRange(0, 50);
            List<BridgePlayer> players = null;
            if ((DateTime.UtcNow - lastPlayersSent).TotalSeconds >= 10)
            {
                players = new List<BridgePlayer>();
                foreach (BasePlayer player in BasePlayer.activePlayerList)
                    if (player != null && player.IsConnected && !player.IsNpc)
                        players.Add(new BridgePlayer { steamId = player.UserIDString, name = player.displayName });
            }
            string payload = JsonConvert.SerializeObject(new { version = "2.0.7", events = events, receipts = receipts, players = players });
            webrequest.Enqueue(ApiBase + "/api/vorken/plugin/sync", payload, (status, response) => {
                syncPending = false;
                if (unloading) return;
                if (status == 401 || status == 403)
                {
                    bridgeActive = false;
                    ReleaseBridgeSessions();
                    return;
                }
                if (status != 200 || string.IsNullOrWhiteSpace(response)) return;
                try
                {
                    BridgeResponse data = JsonConvert.DeserializeObject<BridgeResponse>(response);
                    if (data == null) return;
                    lastBridgeResponse = DateTime.UtcNow;
                    if (players != null) lastPlayersSent = DateTime.UtcNow;
                    bridgeActive = data.active;
                    bridgeNotifications = data.notifications ?? bridgeNotifications;
                    bridgeVerification = data.verification ?? bridgeVerification;
                    settings.PrazoEmSegundos = Math.Max(60, Math.Min(3600, bridgeVerification.timeoutSeconds));
                    settings.BanirAutomaticamenteAoExpirar = bridgeVerification.banOnTimeout;
                    if (data.accepted != null) bridge.Events.RemoveAll(e => data.accepted.Contains(e.id));
                    if (data.acknowledged != null) foreach (string id in data.acknowledged) bridge.Receipts.Remove(id);
                    settings.Discord = data.discord ?? settings.Discord;
                    settings.CanalVerificacao = data.channel ?? "#verificacao";
                    SaveBridge();
                    if (!bridgeActive) { ReleaseBridgeSessions(); return; }
                    if (data.commands != null) foreach (BridgeCommand command in data.commands) ApplyBridgeCommand(command);
                }
                catch (Exception) { PrintWarning("Resposta Vorken invalida; aguardando reconexao."); }
            }, this, Oxide.Core.Libraries.RequestMethod.POST,
                new Dictionary<string, string> { { "Authorization", "Bearer " + Installation }, { "Content-Type", "application/json" } }, 15f);
        }
        private void ApplyBridgeCommand(BridgeCommand command)
        {
            Guid commandId;
            ulong steamId;
            if (command == null || !Guid.TryParse(command.id, out commandId) || !ulong.TryParse(command.steamId, out steamId)) return;
            if (bridge.Completed.Contains(command.id))
            {
                return;
            }
            if (bridge.Receipts.ContainsKey(command.id)) return;
            var receipt = new BridgeReceipt { id = command.id };
            try
            {
                Session session;
                if (command.action == "start")
                {
                    if (!sessions.TryGetValue(steamId, out session))
                        Execute(null, new[] { "iniciar", command.steamId }, "discord:" + command.actorId);
                    receipt.ok = sessions.TryGetValue(steamId, out session);
                    receipt.result = receipt.ok ? "Verificacao iniciada." : "Jogador precisa estar conectado, vivo, acordado e fora de veiculos.";
                }
                else if (command.action == "ban_prior")
                {
                    BasePlayer target = Find(steamId);
                    string name = target != null ? target.displayName : command.steamId;
                    string reason = Clean(command.reason);
                    if (string.IsNullOrWhiteSpace(reason)) throw new Exception("Motivo obrigatorio.");
                    if (sessions.ContainsKey(steamId)) End(steamId, null);
                    ServerUsers.Set(steamId, ServerUsers.UserGroup.Banned, name, reason);
                    ServerUsers.Save();
                    if (target != null && target.IsConnected) target.Kick(reason);
                    AnnounceBridge("deny", name);
                    receipt.ok = true; receipt.result = "Banimento anterior confirmado pela administracao deste servidor.";
                }
                else if (command.detachedSession && (command.action == "approve" || command.action == "deny"))
                {
                    if (sessions.TryGetValue(steamId, out session))
                        throw new Exception("Nova verificacao em andamento.");
                    BasePlayer target = Find(steamId);
                    string name = target != null ? target.displayName : command.steamId;
                    if (command.action == "deny")
                    {
                        string reason = Clean(command.reason);
                        if (string.IsNullOrWhiteSpace(reason)) throw new Exception("Motivo obrigatorio.");
                        ServerUsers.Set(steamId, ServerUsers.UserGroup.Banned, name, reason);
                        ServerUsers.Save();
                        if (target != null && target.IsConnected) target.Kick(reason);
                    }
                    else
                    {
                        var user = ServerUsers.Get(steamId);
                        if (user != null && user.group == ServerUsers.UserGroup.Banned)
                            throw new Exception("Jogador banido: revise o banimento antes de liberar.");
                        permission.CreateGroup("vorken.verificado", "Vorken Verificado", 0);
                        permission.AddUserGroup(command.steamId, "vorken.verificado");
                    }
                    AnnounceBridge(command.action, name);
                    receipt.ok = true; receipt.result = "Decisao do relatorio encerrado aplicada no Rust.";
                }
                else if (!sessions.TryGetValue(steamId, out session) || session.Id != command.sessionId)
                {
                    receipt.ok = false; receipt.result = "Sessao encerrada ou substituida. Nenhuma acao executada.";
                }
                else if (command.action == "attend")
                {
                    Execute(null, new[] { "atender", command.steamId });
                    receipt.ok = session.EmAtendimento; receipt.result = "Codigo validado.";
                }
                else if (command.action == "approve")
                {
                    permission.CreateGroup("vorken.verificado", "Vorken Verificado", 0);
                    permission.AddUserGroup(command.steamId, "vorken.verificado");
                    string verifiedName = session.Nome;
                    End(steamId, "Verificacao Vorken concluida. Voce esta liberado!");
                    AnnounceBridge("approve", verifiedName);
                    receipt.ok = true; receipt.result = "Jogador liberado e grupo Vorken Verificado aplicado.";
                }
                else if (command.action == "deny")
                {
                    string name = session.Nome;
                    End(steamId, null);
                    string reason = Clean(command.reason);
                    ServerUsers.Set(steamId, ServerUsers.UserGroup.Banned, name, reason);
                    ServerUsers.Save();
                    BasePlayer player = Find(steamId);
                    if (player != null && player.IsConnected) player.Kick(reason);
                    AnnounceBridge("deny", name);
                    receipt.ok = true; receipt.result = "Banimento aplicado pelo Vorken.";
                }
                else { receipt.ok = false; receipt.result = "Acao desconhecida."; }
            }
            catch (Exception) { receipt.ok = false; receipt.result = "Falha ao aplicar comando Vorken."; }
            bridge.Receipts[command.id] = receipt;
            bridge.Completed.Add(command.id);
            if (bridge.Completed.Count > 2000) bridge.Completed.RemoveAt(0);
            SaveBridge();
        }
