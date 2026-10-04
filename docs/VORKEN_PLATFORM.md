# Plataforma independente Vorken

## O que foi implementado

- Cadastro e login com Discord (OAuth), sem senha adicional para o cliente.
- Licenças por cliente, com vencimento, limite de servidores, suspensão e revogação.
- Planos por período: mensal R$ 50, trimestral R$ 135 (10%), semestral R$ 255 (15%) e anual R$ 480 (20%).
- Compra no Checkout Pro do Mercado Pago: Pix/cartão conforme disponibilidade da conta, confirmação por webhook autenticado, reenvios sem duplicar a licença, suspensão por estorno/chargeback.
- Pagamento único por período; não há débito recorrente automático.
- Painel do cliente em /servidor e administração comercial em /admin/clientes, junto ao painel existente.
- Bot próprio cria Verificado, Em telagem, canal de instruções, categoria e alertas privados. /telagem inicia; /codigo valida; /verificar libera após a análise.
- Plugin personalizado Vorken.cs se conecta por HTTPS. Nenhum cliente informa IP, RCON ou credenciais do Rust.
- Comandos e eventos persistidos, confirmação no Rust antes de registrar aprovação/banimento, escopo por instalação e servidor.
- Banimento confirmado com provas selecionadas produz um registro de rede. Entrada em outro Rust conectado gera alerta privado com motivo, origem e provas JSON. Não aplica banimento no novo servidor.
- Falsos positivos selecionados no painel reutilizam o aprendizado global existente. Evidências protegidas continuam protegidas pelas regras existentes; o arquivo bruto do computador não é enviado no alerta.
- Subdomínios automáticos pelo nome: Guerra Fria → guerrafria.vorken.xyz, Xtreme → xtreme.vorken.xyz. Duplicidades recebem sufixo. O domínio não substitui a autorização por conta.

## Configuração única do operador no Coolify

Manter DATABASE_URL, DATABASE_SSL e ADMIN_PASSWORD existentes. Usar SESSION_SECRET aleatório com no mínimo 32 caracteres. Não enviar segredos ao GitHub.

Definir PUBLIC_URL=https://vorken.xyz e VORKEN_SUBDOMAINS=true.

Criar aplicação própria no Discord Developer Portal, habilitar instalação em servidores, cadastrar callback https://vorken.xyz/api/vorken/auth/callback. Configurar VORKEN_DISCORD_CLIENT_ID, VORKEN_DISCORD_CLIENT_SECRET e VORKEN_DISCORD_BOT_TOKEN no Coolify. O bot não precisa do intent privilegiado Message Content: usa comandos de barra.

Configurar MERCADO_PAGO_ACCESS_TOKEN e MERCADO_PAGO_WEBHOOK_SECRET no Coolify. Cadastrar webhook https://vorken.xyz/api/vorken/payments/webhook, tópico payment. Credenciais de teste primeiro; ativar credenciais de produção após validar uma compra. Não existe ativação confiando na URL de retorno do navegador.

No primeiro deploy, as tabelas vorken_* são criadas automaticamente no PostgreSQL já utilizado. As tabelas e a integração antigas do Guerra Fria são preservadas para a migração gradual. Backup do banco antes do deploy.

## Domínio Hostinger e subdomínios automáticos

Configuração uma única vez:

1. Na zona DNS da Hostinger, apontar os registros A @ e * para o IP público do servidor Coolify. Preservar registros de email e outros serviços. Não usar o endereço provisório de parking da Hostinger.
2. No aplicativo Coolify, usar https://vorken.xyz como domínio e porta 3000.
3. Configurar certificado para vorken.xyz e *.vorken.xyz por DNS challenge. O wildcard exige validação DNS, não HTTP challenge.
4. O provedor Hostinger do Lego usa HOSTINGER_API_TOKEN e existe a partir do Lego 4.27.0. Conferir se o Traefik instalado contém esse provedor. Se não, atualizar de forma controlada ou usar certificado wildcard renovado por um cliente compatível.
5. Em Dynamic Configurations do proxy, instalar deploy/vorken-wildcard.yml, substituindo apenas o nome do container uma vez. Todos os subdomínios apontam ao mesmo aplicativo.
6. Validar HTTPS no domínio principal e em um subdomínio cadastrado. Não criar um recurso Coolify ou registro DNS por cliente.

Referências: [Wildcard no Coolify](https://coolify.io/docs/core/networking/proxy/traefik/wildcard-certs), [DNS challenge](https://coolify.io/docs/core/networking/proxy/traefik/dns-challenge), [Hostinger no Lego](https://go-acme.github.io/lego/dns/hostinger/), [registros A na Hostinger](https://support.hostinger.com/en/articles/4468886-how-to-manage-a-records).

## Instalação de um cliente

1. Cadastrar com Discord e comprar plano ou receber licença manual.
2. Selecionar um Discord administrado, nomear o Rust e informar convite.
3. Adicionar bot pelo botão do painel. A posição do cargo do bot precisa estar acima dos cargos que ele gerencia.
4. Baixar plugin exclusivo e colocar Vorken.cs em oxide/plugins (servidor Rust com uMod/Oxide).
5. Descarregar/remover a versão antiga Verificacao.cs quando não houver telagem ativa. Não executar dois plugins de verificação sobre o mesmo jogador.
6. Aguardar status Conectado e testar /telagem, /codigo e /verificar em um jogador de teste com consentimento.

Vanish é opcional: se instalado é reutilizado para invisibilidade; sem ele o próprio plugin congela o jogador, bloqueia ações e protege de dano. Timeout automático não é forçado. A interface e as regras legadas de recusa/desconexão foram preservadas.

O download contém chave exclusiva apenas dessa instalação. Guardar como credencial do servidor. Novo download invalida a chave anterior; substituir o arquivo no Rust. Suspensão de licença impede novos comandos e encerra sessões no próximo sync. Sem comunicação por 90 segundos, o plugin libera sessões para evitar manter jogador preso por falha de rede.

## Validação e limites da entrega

- Suite Node existente e testes da plataforma com Postgres embutido PGlite.
- Testes de autorização entre clientes, eventos e confirmações entre instalações, idempotência de eventos/pagamentos, revogação de licença, provas de banimento e alerta de entrada em outro servidor.
- PGlite não valida locks distribuídos; os locks de Postgres são no-ops no harness local. Validar múltiplas réplicas em Postgres real antes de escalar.
- Painéis revisados em navegador desktop/mobile, em prévia isolada com dados explicitamente de demonstração.
- O plugin C# ainda precisa de compilação e teste dentro do Rust/uMod real, onde existem as assemblies do jogo. Não foi testado um banimento real.
- A sintaxe C# do plugin gerado foi validada com o parser Roslyn; isso não substitui a compilação com as assemblies de Rust/uMod.
- Discord e Mercado Pago precisam das credenciais reais e testes de integração antes de vender.
- DNS/HTTPS e deploy do Coolify não foram alterados nesta entrega.

Comandos locais em website: pnpm install --frozen-lockfile; node --test; node preview-platform.mjs. A prévia é somente localhost e não se conecta a cadastros ou pagamentos reais.
# Jogadores online e telagem no painel

## Hospedagem atual com nginx

No servidor atual, nginx atende as portas públicas e encaminha o Vorken para `127.0.0.1:18082`, mapeado pelo Coolify à porta 3000 do aplicativo. Não inicie Traefik nas mesmas portas. O domínio principal usa Certbot; o roteamento dos clientes usa `deploy/vorken-tenants.nginx.conf` e um certificado curinga emitido por Lego 4.28.0, que corrige a integração Hostinger da versão 4.27.0.

O token fica em `/etc/vorken/hostinger.token` com permissão 600, o e-mail ACME em `/etc/vorken/acme.email`, e os certificados em `/etc/vorken/acme`. Instale `deploy/vorken-certificate.sh` como `/usr/local/sbin/vorken-certificate` (700), e as unidades service/timer em `/etc/systemd/system`. Só habilite o roteamento após emitir o certificado e validar com `nginx -t`. A renovação diária usa `vorken-certificate.timer`. Não coloque o token da Hostinger no repositório nem nas variáveis do aplicativo.

Para implantar a versão em revisão, use a branch `codex/vorken-independent-platform` no Coolify, `PUBLIC_URL=https://vorken.xyz`, `VORKEN_SUBDOMAINS=true`, as três credenciais Discord e o callback `https://vorken.xyz/api/vorken/auth/callback`. Reinstale o plugin novo em cada Rust. O token da instalação é incluído apenas no download autenticado.

O admin central oferece a aba **Jogadores online**. O cliente tem os mesmos controles em `/servidor`, restritos aos seus servidores. Com mais de um servidor, selecione primeiro o Rust desejado; busque por nome ou SteamID e clique em **Iniciar telagem**. Revise o relatório para **Verificar e liberar jogador** ou banir com provas selecionadas. As ações aguardam confirmação do plugin e usam a mesma fila do bot, sem RCON.

O plugin Vorken 2.0.2 envia a lista de jogadores conectados a cada aproximadamente 10 segundos. O painel atualiza a cada 15 segundos e oculta listas com mais de 30 segundos. Uma lista vazia remove os jogadores que saíram. Instalações existentes precisam baixar e instalar a versão nova do plugin.

O bot mantém os cargos **✅ Verificado** (verde) e **🔎 Em telagem** (laranja), a categoria **Verificação Vorken**, instruções e tickets privados. O selo como ícone adicional é aplicado quando o Discord informa suporte a `ROLE_ICONS`; nos demais servidores o selo permanece no nome do cargo. A presença alterna números reais de jogadores/máquinas verificados, banidos e o link dos planos.

Em **Configurar bot e avisos**, após adicionar o bot, o cliente escolhe os canais de ban feed e jogadores verificados. Pode escolher o mesmo canal, canais separados ou nenhum. Só são aceitos canais de texto/anúncios do Discord vinculado com permissões de leitura, envio, embeds e histórico. Cada aviso no Discord e os avisos de início de telagem, verificação e banimento no Rust têm interruptores próprios. O plugin recebe as opções automaticamente por HTTPS; não usa RCON. Os avisos seguem as cores e o estilo do Guerra Fria com a identidade Vorken. Avisos públicos não incluem códigos, relatórios ou provas privadas e só confirmam bans/verificações após execução no Rust.

Em **Equipe e convites**, o dono informa o ID Discord do administrador e gera um link pessoal válido por sete dias. O administrador entra com Discord e aceita o convite; a conta deve administrar o Discord vinculado. O acesso é limitado ao Rust convidado, inclusive nos endpoints de jogadores, relatórios, telagem e decisões. Para vários servidores, convide a mesma pessoa em cada servidor necessário. A equipe usa a licença do dono e não precisa comprar uma licença própria. Somente o dono pode alterar instalação, canais, convites e membros. Remover um membro revoga imediatamente seu acesso e os convites ainda pendentes para aquela conta nesse Rust. Convites podem ser revogados individualmente. O dono central do Vorken mantém sua administração separada.

