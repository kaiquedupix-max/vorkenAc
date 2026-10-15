import fs from 'node:fs';

const legacySourceUrl=new URL('../rust-plugins/Verificacao.cs',import.meta.url);
const generatedSourceUrl=new URL('./plugins/Vorken.cs',import.meta.url);
const forceGenerated=process.env.VORKEN_PLUGIN_SOURCE==='generated';
const hasLegacySource=!forceGenerated&&fs.existsSync(legacySourceUrl);
const original=fs.readFileSync(hasLegacySource?legacySourceUrl:generatedSourceUrl,'utf8').replace(/\r\n/g,'\n');
let source=original;

if(hasLegacySource){
  source=original
    .replace('[Info("Verificacao", "Kaique", "1.6.4")]','[Info("Vorken", "Kaique", "2.0.10")]')
    .replace('public class Verificacao : RustPlugin','public class Vorken : RustPlugin')
    .replace('isolamento via Vanish e eventos RCON.','conexao HTTPS independente, sem RCON.')
    .replaceAll('verificacao','vorken')
    .replaceAll('[GF_VERIFICACAO]','[VORKEN]')
    .replaceAll('[GF_VERIFICACAO_LOOKUP]','[VORKEN_LOOKUP]')
    .replaceAll('GUERRA FRIA','DO SEU SERVIDOR')
    .replace('public string Discord = "discord.gg/guerrafria";','public string Discord = "";')
    .replace('settings.BanirAutomaticamenteAoExpirar = true;','// Respeita a configuração do administrador.')
    .replace('settings.PrazoEmSegundos = 300;','settings.PrazoEmSegundos = Math.Max(60, Math.Min(3600, settings.PrazoEmSegundos));')
    .replace('                Vanish != null &&\n                player != null &&','                player != null &&')
    .replaceAll('if (unloading || Vanish == null)','if (unloading)')
    .replace('            if (Vanish == null)\n                PrintWarning("Instale Vanish: https://umod.org/plugins/vanish. Verificacoes ficam suspensas sem essa dependencia.");',
      '            LoadBridge();\n            timer.Every(3f, SyncBridge);\n            SyncBridge();')
    .replace('            if (Vanish == null)\n            {\n                Tell(\n                    admin,\n                    "Instale/carregue o plugin Vanish primeiro."\n                );\n                return;\n            }','')
    .replace('            Vanish.Call("Disappear", target);','            if (Vanish != null) Vanish.Call("Disappear", target);')
    .replace('            if (!Invisible(target))','            if (Vanish != null && !Invisible(target))')
    .replace('                if (!Invisible(player))','                if (Vanish != null && !Invisible(player))')
    .replace('            public string Nome;','            public string Id = Guid.NewGuid().ToString();\n            public string Nome;')
    .replace('            Puts(EventPrefix + " " + payload);','            QueueBridgeEvent(eventType, id, session, reason);')
    .replace('                    BanForTimeout(\n                        pair.Key,\n                        s\n                    );',
      '                    if (settings.BanirAutomaticamenteAoExpirar && bridgeActive)\n                        BanForTimeout(pair.Key, s);\n                    else End(pair.Key, "Prazo de verificacao expirado. Entre em contato com a administracao.");')
    .replace('            if (sessions.ContainsKey(id))\n            {','            if (!bridgeActive)\n            {\n                Tell(admin, "Vorken desconectado ou licenca inativa. Aguarde a conexao.");\n                return;\n            }\n\n            if (sessions.ContainsKey(id))\n            {');

  const bridge=fs.readFileSync(new URL('./plugins/bridge.fragment.cs',import.meta.url),'utf8');
  source=source.replace('        private void Init()\n',bridge+'\n        private void Init()\n');
  source=source.replace('        private void OnPlayerDisconnected(\n','        private void OnPlayerConnected(BasePlayer player)\n        {\n            if (player != null) QueueJoin(player);\n        }\n\n        private void OnPlayerDisconnected(\n');
  source=source.replace('            unloading = true;','            unloading = true;\n            SaveBridge();');
  source=source.replace('            ShowUi(target, session);\n            EmitEvent("session_started", id, session);','            ShowUi(target, session);\n            AnnounceBridge("start", session.Nome, session.Administrador);\n            EmitEvent("session_started", id, session);');
  source=source.replace('            BanForRefusal(player, session);','            if (bridgeVerification.banOnRefusal) BanForRefusal(player, session);\n            else End(player.userID, "Verificacao encerrada por recusa. Aguarde a administracao.");');
  source=source.replace('            ulong id = player.userID;\n\n            string name =','            if (!bridgeActive || !bridgeVerification.banOnDisconnect)\n            {\n                End(player.userID, null);\n                return;\n            }\n\n            ulong id = player.userID;\n\n            string name =');
  source=source.replace('"Voce tem 5 minutos. A vorken e obrigatoria; recusar ou expirar gera ban permanente."','"Voce tem " + (settings.PrazoEmSegundos / 60) + " minutos. Consulte as regras de verificacao do seu servidor no Discord."');
  source=source.replaceAll('dentro de 5 minutos.','dentro do prazo.').replaceAll('em 5 minutos.','dentro do prazo.');
}else{
  // O container de produção recebe apenas website/. Nesse cenário usamos o
  // template Vorken já versionado como base e aplicamos somente a migração 2.0.10.
  source=source
    .replace('[Info("Vorken", "Kaique", "2.0.3")]','[Info("Vorken", "Kaique", "2.0.10")]')
    .replace('version = "2.0.1"','version = "2.0.10"');

  if(!source.includes('private string AdministratorDisplay(string administrator)')){
    source=source.replace(
`        private void AnnounceBridge(string kind, string playerName, string administrator = null)
`,
`        private string AdministratorDisplay(string administrator)
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
`);
  }

  source=source.replace(
'Clean(administrator ?? "Equipe Vorken") + "</color>."',
'AdministratorDisplay(administrator) + "</color>."');
}

// Vorken 2.0.10: a tela do Rust não expõe URL, ID de canal ou convite bruto.
source=source.replace(
`                            "VERIFICACAO OBRIGATORIA. NAO DESCONECTE.\\n" +
                            "Voce tem 5 MINUTOS para enviar o codigo no canal " +
                            Clean(settings.CanalVerificacao) +
                            " do Discord.\\n" +
                            "RECUSAR, DESCONECTAR OU DEIXAR O TEMPO ACABAR RESULTA EM BAN PERMANENTE.",`,
`                            "VERIFICACAO OBRIGATORIA. NAO DESCONECTE.\\n" +
                            "Entre no Discord, procure o canal VERIFICACAO VORKEN e envie os 4 digitos abaixo.\\n" +
                            "RECUSAR, DESCONECTAR OU DEIXAR O TEMPO ACABAR PODE RESULTAR EM BANIMENTO.",`);

source=source.replace(
`                    : "1. ENTRE NO DISCORD DO SEU SERVIDOR\\n" +
                      "2. ABRA O CANAL " +
                      Clean(settings.CanalVerificacao) +
                      "\\n" +
                      "3. ENVIE SOMENTE OS 4 DIGITOS ACIMA EM ATE 5 MINUTOS\\n" +
                      "4. ENTRE NA SALA PRIVADA CRIADA PELO BOT\\n" +
                      "5. BAIXE E EXECUTE O VORKEN E AGUARDE A DECISAO\\n" +
                      "A VERIFICACAO E OBRIGATORIA. RECUSAR RESULTA EM BAN.";`,
`                    : "1. ENTRE NO DISCORD\\n" +
                      "2. PROCURE O CANAL VERIFICACAO VORKEN\\n" +
                      "3. ENVIE SOMENTE OS 4 DIGITOS ACIMA DIRETAMENTE NO CHAT\\n" +
                      "4. AGUARDE A SALA PRIVADA SER CRIADA AUTOMATICAMENTE\\n" +
                      "5. USE O BOTAO DE DOWNLOAD, EXECUTE O VORKEN E AGUARDE\\n" +
                      "A VERIFICACAO E OBRIGATORIA. NAO DESCONECTE.";`);

const oldDiscordButton=`
            ui.Add(
                new CuiButton
                {
                    Button =
                    {
                        Color = "0.10 0.35 0.34 1",
                        Command = "vorken.discord"
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
`;
source=source.replace(oldDiscordButton,'\n');

// Keep packaged-only installations on the current standalone bridge implementation.
if(!source.includes('Text = "VER CONVITE DO DISCORD"')){
  const refuse=source.indexOf('Text = "RECUSAR E ACEITAR BAN"');
  const position=source.lastIndexOf('            ui.Add(',refuse);
  if(refuse<0||position<0)throw new Error('Missing verification refusal button');
  source=source.slice(0,position)+`            ui.Add(new CuiButton
            {
                Button = { Color = "0.10 0.35 0.34 1", Command = "vorken.discord" },
                Text = { Text = "VER CONVITE DO DISCORD", FontSize = 16, Align = TextAnchor.MiddleCenter, Color = "1 1 1 1" },
                RectTransform = { AnchorMin = "0.30 0.12", AnchorMax = "0.70 0.18" }
            }, Ui);

`+source.slice(position);
}
source=source.replace('"Copie o convite abaixo e entre no Discord.\\n"','"Clique no campo abaixo e use CTRL+A e CTRL+C para copiar o convite.\\n"')
  .replace('"Abra " +\n                            Clean(settings.CanalVerificacao) +','"Procure o canal " +\n                            "VERIFICACAO VORKEN" +');
source=source.replace(/\[Info\("Vorken", "Kaique", "2\.0\.\d+"\)\]/,'[Info("Vorken", "Kaique", "2.0.10")]')
  .replace(/version = "2\.0\.\d+"/g,'version = "2.0.10"');
if(!source.includes('command.action == "ban_prior"')){
  const fragment=fs.readFileSync(new URL('./plugins/bridge.fragment.cs',import.meta.url),'utf8');
  const start=fragment.indexOf('                else if (command.action == "ban_prior")');
  const end=fragment.indexOf('                else if (!sessions.TryGetValue',start);
  if(start<0||end<0)throw new Error('Missing prior ban bridge implementation');
  source=source.replace('                else if (!sessions.TryGetValue',fragment.slice(start,end)+'                else if (!sessions.TryGetValue');
}

if(!source.includes('command.detachedSession')){
  const fragment=fs.readFileSync(new URL('./plugins/bridge.fragment.cs',import.meta.url),'utf8');
  const start=fragment.indexOf('                else if (command.detachedSession');
  const end=fragment.indexOf('                else if (!sessions.TryGetValue',start);
  source=source.replace('                else if (!sessions.TryGetValue',fragment.slice(start,end)+'                else if (!sessions.TryGetValue');
  source=source.replace(/(private class BridgeCommand\s*\{)/,'$1\n            public bool detachedSession;');
}
// O identificador continua interno, mas pode carregar "DiscordID|Nome do ADM".
source=source.replace(
`            string id =
                session.Administrador.Substring(prefix.Length).Trim();

            ulong parsed;`,
`            string id =
                session.Administrador.Substring(prefix.Length).Trim();

            int separator = id.IndexOf('|');
            if (separator >= 0)
                id = id.Substring(0, separator).Trim();

            ulong parsed;`);

if(!source.includes('[Info("Vorken", "Kaique", "2.0.10")]')||!source.includes('SyncBridge')||source.includes('[GF_VERIFICACAO]')||!source.includes('PROCURE O CANAL VERIFICACAO VORKEN')||source.includes('MOSTRAR CONVITE DO DISCORD')||!source.includes('AdministratorDisplay')||!source.includes('SEU CODIGO DE VERIFICACAO')||!source.includes('VER CONVITE DO DISCORD')||!source.includes('CTRL+A e CTRL+C'))throw new Error('Plugin generation failed');
// Keep Rust chat on one line, without glyphs that some chat plugins render as '?'.
source = source.replace(/Server\.Broadcast\("<color=#5AA7FF>[^\n]+VERIFICAÇÃO CONCLUÍDA[^\n]+\);/g,
  'Server.Broadcast("<color=#5AA7FF><b>[VORKEN]</b></color> <color=#38E0B0><b>VERIFICACAO CONCLUIDA</b></color> O jogador <color=#38E0B0>" + name + "</color> foi verificado e liberado pela administracao.");');

// Direct bans also apply the local association policy, without requiring Fleet.
if (!source.includes('public int DiasDoBanPorAssociacao')) {
  source = source.replace('        private class Settings\n        {', '        private class Settings\n        {\n            public bool BanirTimePorAssociacao = true;\n            public int DiasDoBanPorAssociacao = 7;\n            public bool NotificarAssociacaoNoChat = true;');
}
// Replace the earlier Fleet-only bridge when building from generated source.
const oldBridgeStart = source.indexOf('        private void SetVorkenBan(');
if (oldBridgeStart >= 0) {
  const oldBridgeEnd = source.indexOf('        private void Init()', oldBridgeStart);
  if (oldBridgeEnd < 0) throw new Error('Missing Init after ban bridge');
  source = source.slice(0, oldBridgeStart) + source.slice(oldBridgeEnd);
}
if (!source.includes('private void SetVorkenBan(')) {
  source = source.replaceAll('ServerUsers.Set(', 'SetVorkenBan(');
  source = source.replace('        private void Init()', `        private void SetVorkenBan(ulong steamId, ServerUsers.UserGroup group, string playerName, string reason)
        {
            var manager = RelationshipManager.ServerInstance;
            var team = manager == null ? null : manager.FindPlayersTeam(steamId);
            var members = team == null ? new List<ulong>() : new List<ulong>(team.members);
            ServerUsers.Set(steamId, group, playerName, reason);
            if (group != ServerUsers.UserGroup.Banned) return;
            if (bridgeNotifications.rustBans)
                Server.Broadcast("<color=#FF5555><b>[VORKEN] BANIMENTO APLICADO</b></color> Jogador: <color=#FFD166>" + Clean(playerName) + "</color> (" + steamId + ") | Duracao: permanente | Motivo: " + Clean(reason));
            if (settings.BanirTimePorAssociacao)
            {
                int days = Math.Max(1, Math.Min(365, settings.DiasDoBanPorAssociacao));
                long expiry = DateTimeOffset.UtcNow.AddDays(days).ToUnixTimeSeconds();
                foreach (ulong member in members)
                {
                    if (member == steamId) continue;
                    var existing = ServerUsers.Get(member);
                    if (existing != null && existing.group == ServerUsers.UserGroup.Banned &&
                        (existing.expiry <= 0 || existing.expiry > DateTimeOffset.UtcNow.ToUnixTimeSeconds())) continue;
                    var target = BasePlayer.FindByID(member) ?? BasePlayer.FindSleeping(member);
                    string memberName = target != null ? target.displayName : member.ToString();
                    string associationReason = "Associacao com " + steamId + ": " + reason;
                    ServerUsers.Set(member, ServerUsers.UserGroup.Banned, memberName, associationReason, expiry);
                    bridge.Events.Add(new BridgeEvent {
                        id = Guid.NewGuid().ToString(), eventType = "association_ban", steamId = member.ToString(),
                        playerName = memberName, reason = reason, sourceSteamId = steamId.ToString(),
                        sourcePlayerName = playerName, associationDays = days,
                        expiresAt = DateTimeOffset.FromUnixTimeSeconds(expiry).UtcDateTime.ToString("o")
                    });
                    SaveBridge();
                    if (settings.NotificarAssociacaoNoChat)
                        Server.Broadcast("<color=#FF9F43><b>[VORKEN] BANIMENTO POR ASSOCIACAO</b></color> Jogador: <color=#FFD166>" + Clean(memberName) + "</color> (" + member + ") | Associado a: " + Clean(playerName) + " (" + steamId + ") | Duracao: " + days + " dia(s) | Motivo de origem: " + Clean(reason));
                    if (target != null && target.IsConnected) target.Kick("VORKEN: " + associationReason);
                }
                ServerUsers.Save();
            }
            var fleet = plugins.Find("VorkenFleet");
            if (fleet != null) fleet.Call("RecordVorkenBan", playerName, steamId, reason);
        }

        private void Init()`);
}
if (!source.includes('public string sourceSteamId, sourcePlayerName;'))
  source = source.replace('        private class BridgeEvent\n        {', '        private class BridgeEvent\n        {\n            public string sourceSteamId, sourcePlayerName;\n            public int associationDays;');
// The central ban helper now announces all six direct-ban paths exactly once.
source = source.replaceAll('AnnounceBridge("deny", name);', '')
  .replace('AnnounceBridge(command.action, name);', 'if (command.action == "approve") AnnounceBridge("approve", name);');
fs.mkdirSync(new URL('./plugins/',import.meta.url),{recursive:true});
if (!source.includes('public int DiasDoBanPorAssociacao') || !source.includes('private void SetVorkenBan('))
  throw new Error('Plugin association configuration generation failed');
// Migrate both the legacy source and already-generated production template.
source=source.replace('"Associacao com " + steamId + ": " + reason','"Banimento por associação — " + Clean(playerName)');
source=source.replace(/Server\.Broadcast\("<color=#FF9F43>[^\n]+\);/g,
  'Server.Broadcast("<color=#FF9F43><b>[VORKEN] BANIMENTO POR ASSOCIACAO</b></color> " + Clean(memberName) + " - associado a " + Clean(playerName));');
if(!source.includes('private class BridgeNetworkBan')){
  source=source.replace(/^.*public List<BridgeNetworkBan> networkBans;\n/gm,'')
    .replace(/^.*if \(data.networkBans != null\).*\n/gm,'');
  const network=fs.readFileSync(new URL('./plugins/network.fragment.cs',import.meta.url),'utf8');
  source=source.replace('        private void Init()',network+'\n        private void Init()');
  source=source.replace('            public List<BridgeCommand> commands;',
    '            public List<BridgeCommand> commands;\n            public List<BridgeNetworkBan> networkBans;');
  source=source.replace('                    if (data.commands != null)',
    '                    if (data.networkBans != null) foreach (BridgeNetworkBan ban in data.networkBans) ApplyNetworkBan(ban);\n                    if (data.commands != null)');
}
if(!source.includes('eventType = "direct_ban"')){
  source=source.replace('            if (group != ServerUsers.UserGroup.Banned) return;',
    `            if (group != ServerUsers.UserGroup.Banned) return;
            bridge.Events.Add(new BridgeEvent { id = Guid.NewGuid().ToString(), eventType = "direct_ban",
                steamId = steamId.ToString(), playerName = playerName, reason = reason });
            SaveBridge();`);
}
fs.writeFileSync(generatedSourceUrl,source);
