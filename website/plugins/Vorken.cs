using System;
using System.Collections.Generic;
using Newtonsoft.Json;
using Oxide.Core;
using Oxide.Core.Plugins;
using Oxide.Game.Rust.Cui;
using UnityEngine;

namespace Oxide.Plugins
{
    [Info("Vorken", "Kaique", "2.0.7")]
    [Description("Telagem administrativa integrada ao Vorken/Discord com codigo individual, conexao HTTPS independente, sem RCON.")]
    public class Vorken : RustPlugin
    {
        [PluginReference] private Plugin Vanish;

        private const string Perm = "vorken.admin";
        private const string Ui = "Verificacao.Panel";
        private const string DiscordUi = "Verificacao.DiscordPanel";
        private const string ConfirmUi = "Verificacao.RefuseConfirm";
        private const string EventPrefix = "[VORKEN]";

        private Settings settings;
        private Dictionary<ulong, Session> sessions = new Dictionary<ulong, Session>();
        private bool unloading;
        private bool dataLoaded;

        private class Settings
        {
            public string Discord = "";
            public string CanalVerificacao = "#vorken";
            public int PrazoEmSegundos = 300;
            public bool BanirAutomaticamenteAoExpirar = false;
            public string MotivoDoBan = "Nao compareceu a vorken no Discord dentro do prazo.";
            public string MotivoDaRecusa = "Recusou a vorken administrativa.";
            public string MotivoDaDesconexao = "Desconectou do servidor durante uma vorken administrativa.";
        }

        private class Session
        {
            public string Id = Guid.NewGuid().ToString();
            public string Nome;
            public string Administrador;
            public string Codigo;
            public float X, Y, Z;
            public DateTime PrazoUtc;
            public bool EmAtendimento;
            public bool AvisoEnviado;
            public bool JaEstavaInvisivel;

            [JsonIgnore] public bool DiscordAberto;
            [JsonIgnore] public bool ConfirmandoRecusa;

            [JsonIgnore]
            public Vector3 Position
            {
                get { return new Vector3(X, Y, Z); }
            }
        }

        protected override void LoadDefaultConfig()
        {
            settings = new Settings();
        }

        protected override void LoadConfig()
        {
            base.LoadConfig();
            settings = Config.ReadObject<Settings>() ?? new Settings();

            // Regra fixa da vorken: o jogador possui exatamente
            // cinco minutos para validar o codigo no Discord.
            settings.PrazoEmSegundos = Math.Max(60, Math.Min(3600, settings.PrazoEmSegundos));
            // Respeita a configuração do administrador.

            if (string.IsNullOrWhiteSpace(settings.CanalVerificacao))
                settings.CanalVerificacao = "#vorken";

            SaveConfig();
        }

        protected override void SaveConfig()
        {
            Config.WriteObject(settings, true);
        }

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
                Server.Broadcast("<color=#2bf0c9>[VERIFICAÇÃO]</color> O jogador <color=#2bf0c9>" + name + "</color> foi verificado e liberado pela administração.");
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

        private void Init()
        {
            permission.RegisterPermission(Perm, this);
            cmd.AddChatCommand("vorken", this, nameof(ChatCommand));
            cmd.AddChatCommand("verificação", this, nameof(ChatCommand));

            sessions = Interface.Oxide.DataFileSystem
                .ReadObject<Dictionary<ulong, Session>>(Name)
                ?? new Dictionary<ulong, Session>();

            dataLoaded = true;

            foreach (Session session in sessions.Values)
                EnsureCode(session);

            SaveData();
        }

        private void OnServerInitialized()
        {
            LoadBridge();
            timer.Every(3f, SyncBridge);
            SyncBridge();

            timer.Every(0.25f, FreezePlayers);
            timer.Every(1f, Tick);

            foreach (var pair in new Dictionary<ulong, Session>(sessions))
            {
                Session session = pair.Value;
                EnsureCode(session);

                BasePlayer player = Find(pair.Key);
                if (player != null && player.IsConnected)
                    ShowUi(player, session);

                EmitEvent("session_started", pair.Key, session);
            }
        }

        private bool IsFourDigitCode(string value)
        {
            if (string.IsNullOrWhiteSpace(value) ||
                value.Length != 4)
                return false;

            for (int i = 0; i < value.Length; i++)
            {
                if (value[i] < '0' ||
                    value[i] > '9')
                    return false;
            }

            return true;
        }

        private bool CodeInUse(string code)
        {
            foreach (Session existing in sessions.Values)
            {
                if (existing != null &&
                    existing.Codigo == code)
                    return true;
            }

            return false;
        }

        private string NewCode()
        {
            for (int attempt = 0; attempt < 100; attempt++)
            {
                string code =
                    UnityEngine.Random.Range(0, 10000)
                        .ToString("D4");

                if (!CodeInUse(code))
                    return code;
            }

            for (int number = 0; number <= 9999; number++)
            {
                string code =
                    number.ToString("D4");

                if (!CodeInUse(code))
                    return code;
            }

            throw new InvalidOperationException(
                "Nao existem codigos de vorken livres."
            );
        }

        private string EnsureCode(Session session)
        {
            if (session == null)
                return "";

            if (!IsFourDigitCode(session.Codigo))
            {
                session.Codigo = NewCode();
            }

            return session.Codigo;
        }

        private void SaveData()
        {
            if (dataLoaded)
                Interface.Oxide.DataFileSystem.WriteObject(Name, sessions);
        }

        private bool Allowed(BasePlayer player)
        {
            return player != null &&
                (player.IsAdmin ||
                 permission.UserHasPermission(player.UserIDString, Perm));
        }

        private bool Held(BasePlayer player)
        {
            return !unloading &&
                player != null &&
                sessions.ContainsKey(player.userID);
        }

        private bool IsSelfTest(BasePlayer player)
        {
            Session session;

            return Allowed(player) &&
                sessions.TryGetValue(player.userID, out session) &&
                session.Administrador == player.UserIDString;
        }

        private bool CanManageSelfTest(BasePlayer player, string[] args)
        {
            return IsSelfTest(player) &&
                args != null &&
                args.Length == 2 &&
                args[1] == player.UserIDString &&
                (
                    args[0].Equals("liberar", StringComparison.OrdinalIgnoreCase) ||
                    args[0].Equals("atender", StringComparison.OrdinalIgnoreCase)
                );
        }

        private bool Invisible(BasePlayer player)
        {
            return Vanish != null &&
                player != null &&
                Vanish.Call<bool>("IsInvisible", player);
        }

        private BasePlayer Find(ulong id)
        {
            return BasePlayer.FindByID(id) ??
                BasePlayer.FindSleeping(id);
        }

        private static string Clean(string value)
        {
            return (value ?? "")
                .Replace("<", "")
                .Replace(">", "")
                .Replace("\r", " ")
                .Replace("\n", " ");
        }

        private void Tell(BasePlayer player, string message)
        {
            if (player == null)
                Puts(message);
            else
                SendReply(
                    player,
                    "<color=#efba62>[Verificacao]</color> " + message
                );
        }

        private void Staff(string message)
        {
            // Evita mensagens duplicadas no chat: o bot controla os avisos
            // publicos de inicio/fim e o plugin mantém o detalhe no console.
            Puts(message);
        }

        private bool TryGetDiscordAdministrator(
            Session session,
            out string discordUserId)
        {
            discordUserId = null;

            if (session == null ||
                string.IsNullOrWhiteSpace(session.Administrador))
                return false;

            const string prefix = "discord:";

            if (!session.Administrador.StartsWith(
                    prefix,
                    StringComparison.OrdinalIgnoreCase))
                return false;

            string id =
                session.Administrador.Substring(prefix.Length).Trim();

            int separator = id.IndexOf('|');
            if (separator >= 0)
                id = id.Substring(0, separator).Trim();

            ulong parsed;

            if (id.Length < 16 ||
                id.Length > 20 ||
                !ulong.TryParse(id, out parsed))
                return false;

            discordUserId = id;
            return true;
        }

        private void EmitEvent(
            string eventType,
            ulong id,
            Session session,
            string reason = null)
        {
            if (session == null ||
                string.IsNullOrWhiteSpace(eventType))
                return;

            string payload =
                JsonConvert.SerializeObject(new
                {
                    eventType = eventType,
                    steamId = id.ToString(),
                    playerName = Clean(session.Nome),
                    reason = string.IsNullOrWhiteSpace(reason)
                        ? null
                        : Clean(reason),
                    administrator = session.Administrador,
                    code = EnsureCode(session),
                    ttlSeconds = settings.PrazoEmSegundos
                });

            QueueBridgeEvent(eventType, id, session, reason);
        }

        private void ChatCommand(
            BasePlayer player,
            string command,
            string[] args)
        {
            if (!Allowed(player))
            {
                Tell(player, "Voce nao tem permissao.");
                return;
            }

            Execute(player, args);
        }

        [ConsoleCommand("vorken")]
        private void ConsoleCommand(ConsoleSystem.Arg arg)
        {
            BasePlayer player = arg.Player();

            if (arg.Connection != null && !Allowed(player))
            {
                arg.ReplyWith("Sem permissao.");
                return;
            }

            var rawArgs = arg.Args;
            string[] arguments =
                new string[rawArgs == null ? 0 : rawArgs.Length];

            for (int i = 0; i < arguments.Length; i++)
                arguments[i] = rawArgs[i].ToString();

            Execute(player, arguments);
        }

        [ConsoleCommand("vorken.bot")]
        private void BotCommand(ConsoleSystem.Arg arg)
        {
            if (arg == null || arg.Connection != null)
                return;

            var rawArgs = arg.Args;

            if (rawArgs == null || rawArgs.Length != 2)
            {
                Puts("Uso: vorken.bot STEAMID64 DISCORD_USER_ID");
                return;
            }

            string steamId = rawArgs[0].ToString();
            string discordUserId = rawArgs[1].ToString();

            ulong discordId;

            if (string.IsNullOrWhiteSpace(discordUserId) ||
                discordUserId.Length < 16 ||
                discordUserId.Length > 20 ||
                !ulong.TryParse(discordUserId, out discordId))
            {
                Puts("Discord user id invalido.");
                return;
            }

            Execute(
                null,
                new[] { "iniciar", steamId },
                "discord:" + Clean(discordUserId)
            );

            ulong parsedSteamId;
            Session createdSession;

            if (ulong.TryParse(steamId, out parsedSteamId) &&
                sessions.TryGetValue(
                    parsedSteamId,
                    out createdSession))
            {
                string payload =
                    JsonConvert.SerializeObject(new
                    {
                        eventType = "session_started",
                        steamId = parsedSteamId.ToString(),
                        playerName = Clean(createdSession.Nome),
                        administrator = createdSession.Administrador,
                        code = EnsureCode(createdSession),
                        ttlSeconds = settings.PrazoEmSegundos
                    });

                arg.ReplyWith(
                    EventPrefix + " " +
                    payload
                );
            }
        }

        [ConsoleCommand("vorken.lookup")]
        private void LookupCommand(ConsoleSystem.Arg arg)
        {
            if (arg == null || arg.Connection != null)
                return;

            var rawArgs = arg.Args;

            if (rawArgs == null || rawArgs.Length != 1)
            {
                arg.ReplyWith("[VORKEN_LOOKUP] NOT_FOUND");
                return;
            }

            string code =
                rawArgs[0].ToString().Trim();

            if (!IsFourDigitCode(code))
            {
                arg.ReplyWith("[VORKEN_LOOKUP] NOT_FOUND");
                return;
            }

            foreach (var pair in sessions)
            {
                Session session = pair.Value;

                if (session == null ||
                    EnsureCode(session) != code)
                    continue;

                int remaining =
                    Math.Max(
                        120,
                        (int)Math.Ceiling(
                            (session.PrazoUtc - DateTime.UtcNow)
                            .TotalSeconds
                        )
                    );

                string payload =
                    JsonConvert.SerializeObject(new
                    {
                        eventType = "session_started",
                        steamId = pair.Key.ToString(),
                        playerName = Clean(session.Nome),
                        administrator = session.Administrador,
                        code = EnsureCode(session),
                        ttlSeconds = remaining
                    });

                arg.ReplyWith(
                    "[VORKEN_LOOKUP] " +
                    payload
                );

                return;
            }

            arg.ReplyWith("[VORKEN_LOOKUP] NOT_FOUND");
        }

        private void Execute(
            BasePlayer admin,
            string[] args,
            string administratorOverride = null)
        {
            if (args == null)
                args = new string[0];

            if (admin != null &&
                sessions.ContainsKey(admin.userID) &&
                !CanManageSelfTest(admin, args))
            {
                Tell(
                    admin,
                    "Voce esta em vorken e nao pode administrar verificacoes."
                );
                return;
            }

            if (args.Length == 1 &&
                args[0].Equals(
                    "listar",
                    StringComparison.OrdinalIgnoreCase))
            {
                if (sessions.Count == 0)
                    Tell(admin, "Nenhuma vorken ativa.");

                foreach (var pair in sessions)
                {
                    Tell(
                        admin,
                        pair.Key + " - " +
                        Clean(pair.Value.Nome) + " - " +
                        Status(pair.Value) +
                        " - codigo " +
                        EnsureCode(pair.Value)
                    );
                }

                return;
            }

            string action =
                args.Length == 1
                    ? "iniciar"
                    : args.Length == 2
                        ? args[0].ToLowerInvariant()
                        : "";

            string idText =
                args.Length == 1
                    ? args[0]
                    : args.Length == 2
                        ? args[1]
                        : "";

            ulong id;

            if (idText.Length != 17 ||
                !ulong.TryParse(idText, out id))
            {
                Tell(
                    admin,
                    "Uso: /vorken STEAMID64 | /vorken atender STEAMID64 | /vorken liberar STEAMID64 | /vorken listar"
                );
                return;
            }

            Session session;

            if (action == "liberar")
            {
                if (!sessions.ContainsKey(id))
                {
                    Tell(
                        admin,
                        "Esse jogador nao esta em vorken."
                    );
                    return;
                }

                End(
                    id,
                    "Verificacao encerrada. Voce esta liberado!"
                );

                Staff(
                    id + " liberado por " +
                    (admin == null
                        ? "console"
                        : Clean(admin.displayName)) +
                    "."
                );

                return;
            }

            if (action == "atender")
            {
                if (!sessions.TryGetValue(id, out session))
                {
                    Tell(
                        admin,
                        "Esse jogador nao esta em vorken."
                    );
                    return;
                }

                session.EmAtendimento = true;
                session.AvisoEnviado = false;
                SaveData();

                BasePlayer targetAtendimento =
                    BasePlayer.FindByID(id);

                if (targetAtendimento != null &&
                    targetAtendimento.IsConnected)
                {
                    ShowUi(
                        targetAtendimento,
                        session
                    );
                }

                Staff(
                    id +
                    " validou o codigo no Discord. " +
                    "Prazo cancelado; aguardando analise Vorken."
                );

                return;
            }

            if (action != "iniciar")
            {
                Tell(
                    admin,
                    "Acao desconhecida. Use iniciar, atender, liberar ou listar."
                );
                return;
            }



            if (!bridgeActive)
            {
                Tell(admin, "Vorken desconectado ou licenca inativa. Aguarde a conexao.");
                return;
            }

            if (sessions.ContainsKey(id))
            {
                Tell(
                    admin,
                    "Esse jogador ja esta em vorken. O prazo nao foi reiniciado."
                );
                return;
            }

            BasePlayer target =
                BasePlayer.FindByID(id);

            if (target == null ||
                !target.IsConnected ||
                target.IsDead() ||
                target.IsSleeping() ||
                target.IsReceivingSnapshot)
            {
                Tell(
                    admin,
                    "O jogador precisa estar conectado, vivo e acordado."
                );
                return;
            }

            if (target.GetMounted() != null ||
                target.GetParentEntity() != null ||
                target.IsWounded())
            {
                Tell(
                    admin,
                    "Aguarde o jogador sair do veiculo/plataforma e estar fora do estado ferido."
                );
                return;
            }

            Vector3 pos =
                target.transform.position;

            session = new Session
            {
                Nome = target.displayName,
                Administrador =
                    !string.IsNullOrWhiteSpace(administratorOverride)
                        ? administratorOverride
                        : (
                            admin == null
                                ? "console"
                                : admin.UserIDString
                          ),
                Codigo = NewCode(),
                X = pos.x,
                Y = pos.y,
                Z = pos.z,
                PrazoUtc =
                    DateTime.UtcNow.AddSeconds(
                        settings.PrazoEmSegundos
                    ),
                JaEstavaInvisivel =
                    Invisible(target)
            };

            sessions.Add(id, session);
            SaveData();

            target.EndLooting();
            if (Vanish != null) Vanish.Call("Disappear", target);

            if (Vanish != null && !Invisible(target))
            {
                End(
                    id,
                    "Verificacao cancelada: nao foi possivel aplicar invisibilidade."
                );

                Tell(
                    admin,
                    "O Vanish recusou a invisibilidade. Confira conflitos entre plugins."
                );

                return;
            }

            ShowUi(target, session);
            AnnounceBridge("start", session.Nome, session.Administrador);
            EmitEvent("session_started", id, session);

            Staff(
                "Verificacao iniciada: " +
                Clean(target.displayName) +
                " (" + id + ") por " +
                session.Administrador +
                " | codigo " +
                session.Codigo +
                "."
            );
        }

        private void FreezePlayers()
        {
            if (unloading)
                return;

            foreach (var pair in sessions)
            {
                BasePlayer player =
                    BasePlayer.FindByID(pair.Key);

                if (player == null ||
                    !player.IsConnected ||
                    player.IsReceivingSnapshot ||
                    player.IsSleeping() ||
                    player.IsDead())
                    continue;

                player.Teleport(pair.Value.Position);
            }
        }

        private void Tick()
        {
            if (unloading)
                return;

            foreach (var pair in
                     new Dictionary<ulong, Session>(sessions))
            {
                Session s = pair.Value;
                EnsureCode(s);

                if (!s.EmAtendimento &&
                    DateTime.UtcNow >= s.PrazoUtc &&
                    !s.AvisoEnviado)
                {
                    s.AvisoEnviado = true;
                    SaveData();

                    if (settings.BanirAutomaticamenteAoExpirar && bridgeActive)
                        BanForTimeout(pair.Key, s);
                    else End(pair.Key, "Prazo de verificacao expirado. Entre em contato com a administracao.");

                    continue;
                }

                BasePlayer player =
                    BasePlayer.FindByID(pair.Key);

                if (player == null ||
                    !player.IsConnected ||
                    player.IsReceivingSnapshot ||
                    player.IsSleeping() ||
                    player.IsDead())
                    continue;

                if (Vanish != null && !Invisible(player))
                    Vanish.Call("Disappear", player);

                ShowUi(player, s);
            }
        }

        private string Status(Session s)
        {
            if (s.EmAtendimento)
            {
                return "CODIGO VALIDADO NO DISCORD - ABRA O LINK DO VORKEN NO TICKET PRIVADO";
            }

            int remaining =
                Math.Max(
                    0,
                    (int)Math.Ceiling(
                        (s.PrazoUtc -
                         DateTime.UtcNow)
                        .TotalSeconds
                    )
                );

            return remaining == 0
                ? "PRAZO ENCERRADO - BANIMENTO AUTOMATICO"
                : "TEMPO RESTANTE PARA VALIDAR O CODIGO: " +
                  (remaining / 60).ToString("00") +
                  ":" +
                  (remaining % 60).ToString("00");
        }

        private void ShowUi(
            BasePlayer player,
            Session s)
        {
            if (s.DiscordAberto ||
                s.ConfirmandoRecusa)
                return;

            EnsureCode(s);

            CuiHelper.DestroyUi(player, Ui);
            CuiHelper.DestroyUi(player, DiscordUi);
            CuiHelper.DestroyUi(player, ConfirmUi);

            var ui =
                new CuiElementContainer();

            ui.Add(
                new CuiPanel
                {
                    Image =
                    {
                        Color = "0 0 0 0.995"
                    },
                    RectTransform =
                    {
                        AnchorMin = "0 0",
                        AnchorMax = "1 1"
                    },
                    CursorEnabled = true
                },
                "Overlay",
                Ui
            );

            ui.Add(
                new CuiLabel
                {
                    Text =
                    {
                        Text = "VERIFICACAO ADMINISTRATIVA - VORKEN",
                        FontSize = 32,
                        Align = TextAnchor.MiddleCenter,
                        Color = "1 0.12 0.12 1"
                    },
                    RectTransform =
                    {
                        AnchorMin = "0.08 0.84",
                        AnchorMax = "0.92 0.94"
                    }
                },
                Ui
            );

            ui.Add(
                new CuiLabel
                {
                    Text =
                    {
                        Text =
                            "VERIFICACAO OBRIGATORIA. NAO DESCONECTE.\n" +
                            "Entre no Discord, procure o canal VERIFICACAO VORKEN e envie os 4 digitos abaixo.\n" +
                            "RECUSAR, DESCONECTAR OU DEIXAR O TEMPO ACABAR PODE RESULTAR EM BANIMENTO.",
                        FontSize = 20,
                        Align = TextAnchor.MiddleCenter,
                        Color = "0.95 0.18 0.18 1"
                    },
                    RectTransform =
                    {
                        AnchorMin = "0.10 0.69",
                        AnchorMax = "0.90 0.83"
                    }
                },
                Ui
            );

            ui.Add(
                new CuiLabel
                {
                    Text =
                    {
                        Text = "SEU CODIGO DE VERIFICACAO · 4 DIGITOS",
                        FontSize = 18,
                        Align = TextAnchor.MiddleCenter,
                        Color = "0.55 0.95 0.95 1"
                    },
                    RectTransform =
                    {
                        AnchorMin = "0.20 0.61",
                        AnchorMax = "0.80 0.68"
                    }
                },
                Ui
            );

            ui.Add(
                new CuiLabel
                {
                    Text =
                    {
                        Text = s.Codigo,
                        FontSize = 46,
                        Align = TextAnchor.MiddleCenter,
                        Color = "0.10 1 0.80 1"
                    },
                    RectTransform =
                    {
                        AnchorMin = "0.25 0.49",
                        AnchorMax = "0.75 0.61"
                    }
                },
                Ui
            );

            string instructions =
                s.EmAtendimento
                    ? "CODIGO ACEITO!\n" +
                      "Volte ao Discord e abra a sala privada criada pelo bot.\n" +
                      "Clique no link do Vorken, baixe, execute como administrador e aguarde."
                    : "1. ENTRE NO DISCORD\n" +
                      "2. PROCURE O CANAL VERIFICACAO VORKEN\n" +
                      "3. ENVIE SOMENTE OS 4 DIGITOS ACIMA DIRETAMENTE NO CHAT\n" +
                      "4. AGUARDE A SALA PRIVADA SER CRIADA AUTOMATICAMENTE\n" +
                      "5. USE O BOTAO DE DOWNLOAD, EXECUTE O VORKEN E AGUARDE\n" +
                      "A VERIFICACAO E OBRIGATORIA. NAO DESCONECTE.";

            ui.Add(
                new CuiLabel
                {
                    Text =
                    {
                        Text = instructions,
                        FontSize = 18,
                        Align = TextAnchor.MiddleCenter,
                        Color = "0.92 0.92 0.92 1"
                    },
                    RectTransform =
                    {
                        AnchorMin = "0.10 0.29",
                        AnchorMax = "0.90 0.48"
                    }
                },
                Ui
            );

            ui.Add(
                new CuiLabel
                {
                    Text =
                    {
                        Text = Status(s),
                        FontSize = 18,
                        Align = TextAnchor.MiddleCenter,
                        Color = s.EmAtendimento
                            ? "0.10 1 0.80 1"
                            : "1 0.15 0.15 1"
                    },
                    RectTransform =
                    {
                        AnchorMin = "0.10 0.21",
                        AnchorMax = "0.90 0.28"
                    }
                },
                Ui
            );


            ui.Add(new CuiButton
            {
                Button = { Color = "0.10 0.35 0.34 1", Command = "vorken.discord" },
                Text = { Text = "VER CONVITE DO DISCORD", FontSize = 16, Align = TextAnchor.MiddleCenter, Color = "1 1 1 1" },
                RectTransform = { AnchorMin = "0.30 0.12", AnchorMax = "0.70 0.18" }
            }, Ui);

            ui.Add(
                new CuiButton
                {
                    Button =
                    {
                        Color = "0.65 0.02 0.02 1",
                        Command = "vorken.recusar"
                    },
                    Text =
                    {
                        Text = "RECUSAR E ACEITAR BAN",
                        FontSize = 15,
                        Align = TextAnchor.MiddleCenter,
                        Color = "1 1 1 1"
                    },
                    RectTransform =
                    {
                        AnchorMin = "0.36 0.045",
                        AnchorMax = "0.64 0.095"
                    }
                },
                Ui
            );

            CuiHelper.AddUi(player, ui);
        }

        private static bool TryDiscordInvite(
            string configured,
            out Uri invite)
        {
            string address =
                (configured ?? "").Trim();

            if (address.StartsWith(
                    "discord.gg/",
                    StringComparison.OrdinalIgnoreCase) ||
                address.StartsWith(
                    "discord.com/invite/",
                    StringComparison.OrdinalIgnoreCase) ||
                address.StartsWith(
                    "discordapp.com/invite/",
                    StringComparison.OrdinalIgnoreCase))
            {
                address = "https://" + address;
            }

            return Uri.TryCreate(
                       address,
                       UriKind.Absolute,
                       out invite) &&
                   invite.Scheme == Uri.UriSchemeHttps &&
                   !string.IsNullOrEmpty(invite.Host);
        }

        [ConsoleCommand("vorken.discord")]
        private void DiscordCommand(ConsoleSystem.Arg arg)
        {
            BasePlayer player = arg.Player();
            Session session;

            if (player == null ||
                !sessions.TryGetValue(
                    player.userID,
                    out session))
                return;

            Uri invite;

            if (!TryDiscordInvite(
                    settings.Discord,
                    out invite))
            {
                Tell(
                    player,
                    "O endereco do Discord esta vazio ou invalido."
                );
                return;
            }

            session.DiscordAberto = true;
            session.ConfirmandoRecusa = false;

            CuiHelper.DestroyUi(player, Ui);
            CuiHelper.DestroyUi(player, DiscordUi);
            CuiHelper.DestroyUi(player, ConfirmUi);

            var ui =
                new CuiElementContainer();

            ui.Add(
                new CuiPanel
                {
                    Image =
                    {
                        Color = "0 0 0 0.995"
                    },
                    RectTransform =
                    {
                        AnchorMin = "0 0",
                        AnchorMax = "1 1"
                    },
                    CursorEnabled = true
                },
                "Overlay",
                DiscordUi
            );

            ui.Add(
                new CuiLabel
                {
                    Text =
                    {
                        Text = "DISCORD DO SEU SERVIDOR",
                        FontSize = 30,
                        Align = TextAnchor.MiddleCenter,
                        Color = "0.10 1 0.80 1"
                    },
                    RectTransform =
                    {
                        AnchorMin = "0.08 0.75",
                        AnchorMax = "0.92 0.88"
                    }
                },
                DiscordUi
            );

            ui.Add(
                new CuiLabel
                {
                    Text =
                    {
                        Text =
                            "Clique no campo abaixo e use CTRL+A e CTRL+C para copiar o convite.\n" +
                            "Procure o canal " +
                            "VERIFICACAO VORKEN" +
                            " e envie SOMENTE o codigo " +
                            EnsureCode(session) +
                            ".\n" +
                            "Voce tem " + (settings.PrazoEmSegundos / 60) + " minutos. Consulte as regras de verificacao do seu servidor no Discord.",
                        FontSize = 19,
                        Align = TextAnchor.MiddleCenter,
                        Color = "0.95 0.95 0.95 1"
                    },
                    RectTransform =
                    {
                        AnchorMin = "0.10 0.58",
                        AnchorMax = "0.90 0.74"
                    }
                },
                DiscordUi
            );

            string field =
                ui.Add(
                    new CuiPanel
                    {
                        Image =
                        {
                            Color = "0.08 0.08 0.08 1"
                        },
                        RectTransform =
                        {
                            AnchorMin = "0.16 0.43",
                            AnchorMax = "0.84 0.52"
                        }
                    },
                    DiscordUi
                );

            ui.Add(
                new CuiElement
                {
                    Parent = field,
                    Components =
                    {
                        new CuiInputFieldComponent
                        {
                            Text = invite.AbsoluteUri,
                            FontSize = 20,
                            Align = TextAnchor.MiddleCenter,
                            Color = "0.10 1 0.80 1",
                            ReadOnly = true,
                            NeedsKeyboard = true
                        },
                        new CuiRectTransformComponent
                        {
                            AnchorMin = "0.02 0",
                            AnchorMax = "0.98 1"
                        }
                    }
                }
            );

            ui.Add(
                new CuiButton
                {
                    Button =
                    {
                        Color = "0.12 0.30 0.30 1",
                        Command = "vorken.voltar"
                    },
                    Text =
                    {
                        Text = "VOLTAR",
                        FontSize = 18,
                        Align = TextAnchor.MiddleCenter,
                        Color = "1 1 1 1"
                    },
                    RectTransform =
                    {
                        AnchorMin = "0.30 0.28",
                        AnchorMax = "0.70 0.36"
                    }
                },
                DiscordUi
            );

            CuiHelper.AddUi(player, ui);
        }

        [ConsoleCommand("vorken.voltar")]
        private void BackCommand(ConsoleSystem.Arg arg)
        {
            BasePlayer player = arg.Player();
            Session session;

            if (player == null ||
                !sessions.TryGetValue(
                    player.userID,
                    out session))
                return;

            session.DiscordAberto = false;
            session.ConfirmandoRecusa = false;

            CuiHelper.DestroyUi(player, DiscordUi);
            CuiHelper.DestroyUi(player, ConfirmUi);

            ShowUi(player, session);
        }

        [ConsoleCommand("vorken.recusar")]
        private void RefuseCommand(ConsoleSystem.Arg arg)
        {
            BasePlayer player = arg.Player();
            Session session;

            if (player == null ||
                !sessions.TryGetValue(
                    player.userID,
                    out session))
                return;

            session.DiscordAberto = false;
            session.ConfirmandoRecusa = true;

            CuiHelper.DestroyUi(player, Ui);
            CuiHelper.DestroyUi(player, DiscordUi);

            ShowRefuseConfirmation(player);
        }

        private void ShowRefuseConfirmation(BasePlayer player)
        {
            CuiHelper.DestroyUi(player, ConfirmUi);

            var ui =
                new CuiElementContainer();

            ui.Add(
                new CuiPanel
                {
                    Image =
                    {
                        Color = "0 0 0 0.998"
                    },
                    RectTransform =
                    {
                        AnchorMin = "0 0",
                        AnchorMax = "1 1"
                    },
                    CursorEnabled = true
                },
                "Overlay",
                ConfirmUi
            );

            ui.Add(
                new CuiLabel
                {
                    Text =
                    {
                        Text = "CONFIRMAR RECUSA",
                        FontSize = 34,
                        Align = TextAnchor.MiddleCenter,
                        Color = "1 0 0 1"
                    },
                    RectTransform =
                    {
                        AnchorMin = "0.08 0.67",
                        AnchorMax = "0.92 0.80"
                    }
                },
                ConfirmUi
            );

            ui.Add(
                new CuiLabel
                {
                    Text =
                    {
                        Text =
                            "AO CONFIRMAR, VOCE SERA BANIDO PERMANENTEMENTE\n" +
                            "POR RECUSAR A VERIFICACAO ADMINISTRATIVA.",
                        FontSize = 24,
                        Align = TextAnchor.MiddleCenter,
                        Color = "1 0.05 0.05 1"
                    },
                    RectTransform =
                    {
                        AnchorMin = "0.12 0.43",
                        AnchorMax = "0.88 0.66"
                    }
                },
                ConfirmUi
            );

            ui.Add(
                new CuiButton
                {
                    Button =
                    {
                        Color = "0.9 0 0 1",
                        Command = "vorken.recusar.confirmar"
                    },
                    Text =
                    {
                        Text = "SIM, RECUSAR E ACEITAR O BAN",
                        FontSize = 18,
                        Align = TextAnchor.MiddleCenter,
                        Color = "1 1 1 1"
                    },
                    RectTransform =
                    {
                        AnchorMin = "0.20 0.27",
                        AnchorMax = "0.80 0.36"
                    }
                },
                ConfirmUi
            );

            ui.Add(
                new CuiButton
                {
                    Button =
                    {
                        Color = "0.15 0.15 0.15 1",
                        Command = "vorken.recusar.cancelar"
                    },
                    Text =
                    {
                        Text = "CANCELAR E CONTINUAR",
                        FontSize = 18,
                        Align = TextAnchor.MiddleCenter,
                        Color = "1 0.2 0.2 1"
                    },
                    RectTransform =
                    {
                        AnchorMin = "0.20 0.16",
                        AnchorMax = "0.80 0.25"
                    }
                },
                ConfirmUi
            );

            CuiHelper.AddUi(player, ui);
        }

        [ConsoleCommand("vorken.recusar.cancelar")]
        private void RefuseCancelCommand(ConsoleSystem.Arg arg)
        {
            BasePlayer player = arg.Player();
            Session session;

            if (player == null ||
                !sessions.TryGetValue(
                    player.userID,
                    out session))
                return;

            session.ConfirmandoRecusa = false;
            CuiHelper.DestroyUi(player, ConfirmUi);
            ShowUi(player, session);
        }

        [ConsoleCommand("vorken.recusar.confirmar")]
        private void RefuseConfirmCommand(ConsoleSystem.Arg arg)
        {
            BasePlayer player = arg.Player();
            Session session;

            if (player == null ||
                !sessions.TryGetValue(
                    player.userID,
                    out session) ||
                !session.ConfirmandoRecusa)
                return;

            if (bridgeVerification.banOnRefusal) BanForRefusal(player, session);
            else End(player.userID, "Verificacao encerrada por recusa. Aguarde a administracao.");
        }

        private void BanForTimeout(
            ulong id,
            Session session)
        {
            string name =
                Clean(
                    string.IsNullOrWhiteSpace(session.Nome)
                        ? id.ToString()
                        : session.Nome
                );

            string reason =
                string.IsNullOrWhiteSpace(settings.MotivoDoBan)
                    ? "Nao enviou o codigo de vorken no Discord dentro do prazo."
                    : Clean(settings.MotivoDoBan);

            ServerUsers.Set(
                id,
                ServerUsers.UserGroup.Banned,
                name,
                reason
            );

            ServerUsers.Save();

            BasePlayer player = Find(id);

            sessions.Remove(id);
            SaveData();

            if (player != null)
            {
                CuiHelper.DestroyUi(player, Ui);
                CuiHelper.DestroyUi(player, DiscordUi);
                CuiHelper.DestroyUi(player, ConfirmUi);
            }

            if (player != null &&
                !session.JaEstavaInvisivel &&
                Invisible(player))
            {
                Vanish.Call("Reappear", player);
            }

            EmitEvent(
                "timeout_ban",
                id,
                session,
                reason
            );

            Staff(
                id +
                " banido automaticamente por nao validar o codigo dentro do prazo."
            );

            if (player != null &&
                player.IsConnected)
            {
                player.Kick(
                    reason +
                    " Banimento permanente."
                );
            }
        }

        private void BanForRefusal(
            BasePlayer player,
            Session session)
        {
            ulong id = player.userID;
            string name =
                Clean(player.displayName);

            string reason =
                string.IsNullOrWhiteSpace(
                    settings.MotivoDaRecusa)
                    ? "Recusou a vorken administrativa."
                    : Clean(settings.MotivoDaRecusa);

            ServerUsers.Set(
                id,
                ServerUsers.UserGroup.Banned,
                name,
                reason
            );

            ServerUsers.Save();

            sessions.Remove(id);
            SaveData();

            CuiHelper.DestroyUi(player, Ui);
            CuiHelper.DestroyUi(player, DiscordUi);
            CuiHelper.DestroyUi(player, ConfirmUi);

            if (!session.JaEstavaInvisivel &&
                Invisible(player))
            {
                Vanish.Call("Reappear", player);
            }

            EmitEvent(
                "refusal_ban",
                id,
                session,
                reason
            );

            Staff(
                id +
                " banido permanentemente por recusar a vorken."
            );

            if (player.IsConnected)
                player.Kick(
                    reason +
                    " Banimento permanente."
                );
        }

        private void Restore(
            BasePlayer player,
            Session session)
        {
            if (player == null)
                return;

            CuiHelper.DestroyUi(player, Ui);
            CuiHelper.DestroyUi(player, DiscordUi);
            CuiHelper.DestroyUi(player, ConfirmUi);

            if (!session.JaEstavaInvisivel &&
                Invisible(player))
            {
                Vanish.Call("Reappear", player);
            }
        }

        private void End(
            ulong id,
            string message)
        {
            Session session;

            if (!sessions.TryGetValue(
                    id,
                    out session))
                return;

            sessions.Remove(id);
            SaveData();

            BasePlayer player = Find(id);
            Restore(player, session);

            if (player != null &&
                player.IsConnected &&
                message != null)
            {
                Tell(player, message);
            }

            EmitEvent(
                "session_end",
                id,
                session
            );
        }

        private void OnPlayerConnected(BasePlayer player)
        {
            if (player != null) QueueJoin(player);
        }

        private void OnPlayerDisconnected(
            BasePlayer player,
            string disconnectReason)
        {
            if (player == null)
                return;

            Session session;

            if (!sessions.TryGetValue(
                    player.userID,
                    out session))
                return;

            if (!bridgeActive || !bridgeVerification.banOnDisconnect)
            {
                End(player.userID, null);
                return;
            }

            ulong id = player.userID;

            string name =
                Clean(
                    string.IsNullOrWhiteSpace(
                        session.Nome)
                        ? player.displayName
                        : session.Nome
                );

            string banReason =
                string.IsNullOrWhiteSpace(
                    settings.MotivoDaDesconexao)
                    ? "Desconectou do servidor durante uma vorken administrativa."
                    : Clean(
                        settings.MotivoDaDesconexao
                    );

            ServerUsers.Set(
                id,
                ServerUsers.UserGroup.Banned,
                name,
                banReason
            );

            ServerUsers.Save();

            sessions.Remove(id);
            SaveData();

            CuiHelper.DestroyUi(player, Ui);
            CuiHelper.DestroyUi(player, DiscordUi);
            CuiHelper.DestroyUi(player, ConfirmUi);

            EmitEvent(
                "refusal_ban",
                id,
                session,
                banReason
            );

            Staff(
                id +
                " banido permanentemente por desconectar durante a vorken."
            );
        }

        private void OnNewSave(string filename)
        {
            foreach (ulong id in
                     new List<ulong>(sessions.Keys))
            {
                End(id, null);
            }
        }

        private void Unload()
        {
            unloading = true;
            SaveBridge();
            SaveData();

            foreach (var pair in sessions)
                Restore(Find(pair.Key), pair.Value);
        }

        private object OnEntityTakeDamage(
            BaseCombatEntity entity,
            HitInfo hit)
        {
            if (hit == null ||
                (
                    !Held(entity as BasePlayer) &&
                    !Held(hit.InitiatorPlayer)
                ))
            {
                return null;
            }

            hit.damageTypes.Clear();
            hit.DoHitEffects = false;
            hit.HitMaterial = 0;

            return true;
        }

        private object OnRunPlayerMetabolism(
            PlayerMetabolism metabolism,
            BaseCombatEntity owner,
            float delta)
        {
            return Held(owner as BasePlayer)
                ? (object)true
                : null;
        }

        private object OnPlayerInput(
            BasePlayer player,
            InputState input)
        {
            if (!Held(player) ||
                player.IsReceivingSnapshot ||
                player.IsSleeping())
                return null;

            if (input != null &&
                input.current != null)
            {
                input.current.buttons = 0;
            }

            return true;
        }

        private object CanBeWounded(
            BasePlayer player,
            HitInfo hit)
        {
            return Held(player)
                ? (object)false
                : null;
        }

        private object CanMountEntity(
            BasePlayer player,
            BaseMountable mount)
        {
            return Held(player)
                ? (object)false
                : null;
        }

        private object CanLootEntity(
            BasePlayer player,
            BaseEntity entity)
        {
            return Held(player)
                ? (object)false
                : null;
        }

        private object CanLootPlayer(
            BasePlayer target,
            BasePlayer looter)
        {
            return Held(looter) ||
                   (Held(target) &&
                    !Allowed(looter))
                ? (object)false
                : null;
        }

        private object CanMoveItem(
            Item item,
            PlayerInventory inventory)
        {
            return inventory != null &&
                   Held(
                       inventory.baseEntity
                       as BasePlayer)
                ? (object)false
                : null;
        }

        private object OnItemAction(
            Item item,
            string action,
            BasePlayer player)
        {
            return Held(player)
                ? (object)true
                : null;
        }

        private object OnPlayerCommand(
            BasePlayer player,
            string command,
            string[] args)
        {
            if (!Held(player))
                return null;

            if (
                (
                    string.Equals(
                        command,
                        "vorken",
                        StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(
                        command,
                        "verificação",
                        StringComparison.OrdinalIgnoreCase)
                ) &&
                CanManageSelfTest(
                    player,
                    args)
            )
            {
                return null;
            }

            return true;
        }

        private object OnServerCommand(
            ConsoleSystem.Arg arg)
        {
            if (arg == null ||
                arg.cmd == null ||
                !Held(arg.Player()))
                return null;

            string name =
                arg.cmd.FullName;

            if (name == "global.wakeup" ||
                name == "vorken.discord" ||
                name == "vorken.voltar" ||
                name == "vorken.recusar" ||
                name == "vorken.recusar.cancelar" ||
                name == "vorken.recusar.confirmar" ||
                name == "vorken.lookup")
            {
                return null;
            }

            return false;
        }
    }
}
