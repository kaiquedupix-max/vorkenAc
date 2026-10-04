import fs from 'node:fs';

const original=fs.readFileSync(new URL('../rust-plugins/Verificacao.cs',import.meta.url),'utf8').replace(/\r\n/g,'\n');
let source=original
  .replace('[Info("Verificacao", "Kaique", "1.6.4")]','[Info("Vorken", "Kaique", "2.0.4")]')
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

// Vorken 2.0.4: a tela do Rust não expõe URL, ID de canal ou convite bruto.
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

// Remove o antigo botão que abria uma tela com o convite/URL cru do Discord.
source=source.replace(/\n\s*ui\.Add\(\s*\n\s*new CuiButton\s*\n\s*\{[\s\S]*?Command = "vorken\.discord"[\s\S]*?\n\s*Ui\s*\n\s*\);\n/, '\n');

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

if(source===original||!source.includes('SyncBridge')||source.includes('[GF_VERIFICACAO]')||!source.includes('VERIFICACAO VORKEN'))throw new Error('Plugin generation failed');
fs.mkdirSync(new URL('./plugins/',import.meta.url),{recursive:true});
fs.writeFileSync(new URL('./plugins/Vorken.cs',import.meta.url),source);
