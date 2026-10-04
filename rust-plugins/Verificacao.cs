using System;
using System.Collections.Generic;
using Newtonsoft.Json;
using Oxide.Core;
using Oxide.Core.Plugins;
using Oxide.Game.Rust.Cui;
using UnityEngine;

namespace Oxide.Plugins
{
    [Info("Verificacao", "Kaique", "1.6.4")]
    [Description("Telagem administrativa integrada ao Vorken/Discord com codigo individual, isolamento via Vanish e eventos RCON.")]
    public class Verificacao : RustPlugin
    {
        [PluginReference] private Plugin Vanish;

        private const string Perm = "verificacao.admin";
        private const string Ui = "Verificacao.Panel";
        private const string DiscordUi = "Verificacao.DiscordPanel";
        private const string ConfirmUi = "Verificacao.RefuseConfirm";
        private const string EventPrefix = "[GF_VERIFICACAO]";

        private Settings settings;
        private Dictionary<ulong, Session> sessions = new Dictionary<ulong, Session>();
        private bool unloading;
        private bool dataLoaded;

        private class Settings
        {
            public string Discord = "discord.gg/guerrafria";
            public string CanalVerificacao = "#verificacao";
            public int PrazoEmSegundos = 300;
            public bool BanirAutomaticamenteAoExpirar = false;
            public string MotivoDoBan = "Nao compareceu a verificacao no Discord dentro do prazo.";
            public string MotivoDaRecusa = "Recusou a verificacao administrativa.";
            public string MotivoDaDesconexao = "Desconectou do servidor durante uma verificacao administrativa.";
        }

        private class Session
        {
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

            // Regra fixa da verificacao: o jogador possui exatamente
            // cinco minutos para validar o codigo no Discord.
            settings.PrazoEmSegundos = 300;
            settings.BanirAutomaticamenteAoExpirar = true;

            if (string.IsNullOrWhiteSpace(settings.CanalVerificacao))
                settings.CanalVerificacao = "#verificacao";

            SaveConfig();
        }

        protected override void SaveConfig()
        {
            Config.WriteObject(settings, true);
        }

        private void Init()
        {
            permission.RegisterPermission(Perm, this);
            cmd.AddChatCommand("verificacao", this, nameof(ChatCommand));
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
            if (Vanish == null)
                PrintWarning("Instale Vanish: https://umod.org/plugins/vanish. Verificacoes ficam suspensas sem essa dependencia.");

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
                "Nao existem codigos de verificacao livres."
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
                Vanish != null &&
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

            Puts(EventPrefix + " " + payload);
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

        [ConsoleCommand("verificacao")]
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

        [ConsoleCommand("verificacao.bot")]
        private void BotCommand(ConsoleSystem.Arg arg)
        {
            if (arg == null || arg.Connection != null)
                return;

            var rawArgs = arg.Args;

            if (rawArgs == null || rawArgs.Length != 2)
            {
                Puts("Uso: verificacao.bot STEAMID64 DISCORD_USER_ID");
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

        [ConsoleCommand("verificacao.lookup")]
        private void LookupCommand(ConsoleSystem.Arg arg)
        {
            if (arg == null || arg.Connection != null)
                return;

            var rawArgs = arg.Args;

            if (rawArgs == null || rawArgs.Length != 1)
            {
                arg.ReplyWith("[GF_VERIFICACAO_LOOKUP] NOT_FOUND");
                return;
            }

            string code =
                rawArgs[0].ToString().Trim();

            if (!IsFourDigitCode(code))
            {
                arg.ReplyWith("[GF_VERIFICACAO_LOOKUP] NOT_FOUND");
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
                    "[GF_VERIFICACAO_LOOKUP] " +
                    payload
                );

                return;
            }

            arg.ReplyWith("[GF_VERIFICACAO_LOOKUP] NOT_FOUND");
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
                    "Voce esta em verificacao e nao pode administrar verificacoes."
                );
                return;
            }

            if (args.Length == 1 &&
                args[0].Equals(
                    "listar",
                    StringComparison.OrdinalIgnoreCase))
            {
                if (sessions.Count == 0)
                    Tell(admin, "Nenhuma verificacao ativa.");

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
                    "Uso: /verificacao STEAMID64 | /verificacao atender STEAMID64 | /verificacao liberar STEAMID64 | /verificacao listar"
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
                        "Esse jogador nao esta em verificacao."
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
                        "Esse jogador nao esta em verificacao."
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

            if (Vanish == null)
            {
                Tell(
                    admin,
                    "Instale/carregue o plugin Vanish primeiro."
                );
                return;
            }

            if (sessions.ContainsKey(id))
            {
                Tell(
                    admin,
                    "Esse jogador ja esta em verificacao. O prazo nao foi reiniciado."
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
            Vanish.Call("Disappear", target);

            if (!Invisible(target))
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
            if (unloading || Vanish == null)
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
            if (unloading || Vanish == null)
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

                    BanForTimeout(
                        pair.Key,
                        s
                    );

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

                if (!Invisible(player))
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
                            "Voce tem 5 MINUTOS para enviar o codigo no canal " +
                            Clean(settings.CanalVerificacao) +
                            " do Discord.\n" +
                            "RECUSAR, DESCONECTAR OU DEIXAR O TEMPO ACABAR RESULTA EM BAN PERMANENTE.",
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
                    : "1. ENTRE NO DISCORD GUERRA FRIA\n" +
                      "2. ABRA O CANAL " +
                      Clean(settings.CanalVerificacao) +
                      "\n" +
                      "3. ENVIE SOMENTE OS 4 DIGITOS ACIMA EM ATE 5 MINUTOS\n" +
                      "4. ENTRE NA SALA PRIVADA CRIADA PELO BOT\n" +
                      "5. BAIXE E EXECUTE O VORKEN E AGUARDE A DECISAO\n" +
                      "A VERIFICACAO E OBRIGATORIA. RECUSAR RESULTA EM BAN.";

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

            ui.Add(
                new CuiButton
                {
                    Button =
                    {
                        Color = "0.10 0.35 0.34 1",
                        Command = "verificacao.discord"
                    },
                    Text =
                    {
                        Text = "MOSTRAR CONVITE DO DISCORD",
                        FontSize = 16,
                        Align = TextAnchor.MiddleCenter,
                        Color = "1 1 1 1"
                    },
                    RectTransform =
                    {
                        AnchorMin = "0.30 0.12",
                        AnchorMax = "0.70 0.18"
                    }
                },
                Ui
            );

            ui.Add(
                new CuiButton
                {
                    Button =
                    {
                        Color = "0.65 0.02 0.02 1",
                        Command = "verificacao.recusar"
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

        [ConsoleCommand("verificacao.discord")]
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
                        Text = "DISCORD GUERRA FRIA",
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
                            "Copie o convite abaixo e entre no Discord.\n" +
                            "Abra " +
                            Clean(settings.CanalVerificacao) +
                            " e envie SOMENTE o codigo " +
                            EnsureCode(session) +
                            ".\n" +
                            "Voce tem 5 minutos. A verificacao e obrigatoria; recusar ou expirar gera ban permanente.",
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
                        Command = "verificacao.voltar"
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

        [ConsoleCommand("verificacao.voltar")]
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

        [ConsoleCommand("verificacao.recusar")]
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
                        Command = "verificacao.recusar.confirmar"
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
                        Command = "verificacao.recusar.cancelar"
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

        [ConsoleCommand("verificacao.recusar.cancelar")]
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

        [ConsoleCommand("verificacao.recusar.confirmar")]
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

            BanForRefusal(player, session);
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
                    ? "Nao enviou o codigo de verificacao no Discord dentro de 5 minutos."
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
                " banido automaticamente por nao validar o codigo em 5 minutos."
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
                    ? "Recusou a verificacao administrativa."
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
                " banido permanentemente por recusar a verificacao."
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
                    ? "Desconectou do servidor durante uma verificacao administrativa."
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
                " banido permanentemente por desconectar durante a verificacao."
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
                        "verificacao",
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
                name == "verificacao.discord" ||
                name == "verificacao.voltar" ||
                name == "verificacao.recusar" ||
                name == "verificacao.recusar.cancelar" ||
                name == "verificacao.recusar.confirmar" ||
                name == "verificacao.lookup")
            {
                return null;
            }

            return false;
        }
    }
}
