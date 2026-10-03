# Vorken Anti Cheat

O **Vorken Anti Cheat** é um scanner forense para Windows, baseado em consentimento, desenvolvido para investigações de integridade em servidores competitivos de jogos.

O Vorken é um software **proprietário**. Novas versões não são distribuídas como software livre ou open source. O código-fonte, os componentes originais, as regras internas, a identidade visual e os materiais proprietários são protegidos pela [licença do Vorken](LICENSE).

Versões que já tenham sido validamente distribuídas anteriormente sob a GNU AGPL v3.0 continuam regidas pelos termos aplicáveis àquelas cópias. A mudança de licença não revoga retroativamente direitos já concedidos sobre versões anteriores.

- [Política de privacidade](docs/PRIVACY.md)
- [Política de segurança](SECURITY.md)
- [Diretrizes internas de contribuição](CONTRIBUTING.md)
- [Avisos de terceiros](THIRD_PARTY_NOTICES.md)
- [Política de marca](TRADEMARKS.md)
- [Política de assinatura de código](docs/CODE_SIGNING_POLICY.md)

## Vorken Agent 1.0

A página de análise disponibiliza um **único executável do Windows**. O token da análise é incorporado ao nome do arquivo baixado, portanto não existe ZIP nem arquivo de configuração separado para extrair.

O agente coleta evidências técnicas defensivas, incluindo:

- dispositivos USB atuais e históricos, Arduino, CH34x, CP210x, FTDI e linha do tempo de mídias removíveis;
- Prefetch, BAM/DAM, UserAssist, MUICache, PCA, Amcache, ShimCache e Evento 4688;
- exclusões no USN Journal do NTFS e eventos no estilo JournalTrace, como criação, exclusão, renomeação e alteração;
- histórico de downloads do navegador, indicadores de risco, histórico de buscas e sites suspeitos, recuperação SQLite/WAL e origem via Zone.Identifier;
- Lixeira, atalhos, metadados do Windows Error Reporting, falhas e correlações com arquivos excluídos;
- SHA-256, validação Authenticode real via WinVerifyTrust, timestamps PE, entropia, seções e indicadores de empacotamento;
- histórico e eventos suspeitos do PowerShell, inicializações automáticas, tarefas agendadas e Alternate Data Streams do NTFS;
- integridade de módulos de processos de alto valor, incluindo Rust, além de janelas com exclusão de captura e comportamento do tipo streamproof;
- histórico e exclusões do Defender, produtos antivírus e firewall registrados, Secure Boot, BCD, alterações de serviços, estado do SRUM e integridade do Prefetch;
- indicadores DNS e conexões TCP atuais correlacionadas com processo e assinatura;
- contexto de máquina virtual, disco virtual, horário do sistema, limpeza de logs e integridade;
- catálogo de IOC de cheats e scripts de Rust, além de regras personalizadas do administrador.

O agente **não coleta** senhas, cookies de autenticação do navegador, mensagens privadas, fotos, conteúdo de documentos pessoais nem dumps arbitrários de memória RAM.

## Site

```bash
cd website
npm install
npm start
```

Variáveis de ambiente:

```text
DATABASE_URL=postgresql://...
SESSION_SECRET=change-me
ADMIN_PASSWORD=change-me
PUBLIC_URL=https://your-domain.example
AGENT_BINARY_PATH=/absolute/path/to/Vorken.Agent.exe
PORT=3000

# Opcional: consultas de reputação apenas por hash. O Vorken não envia arquivos.
VIRUSTOTAL_API_KEY=
```

## Suporte remoto

O agente possui uma aba **Suporte** com dois modos autorizados pelo jogador: somente transmissão da tela ou transmissão com controle temporário de mouse e teclado. O aplicativo administrativo separado fica em `admin-app/`:

```bash
cd admin-app
dotnet publish -c Release -r win-x64 --self-contained true
```

Cada administrador entra com seu próprio usuário e só aparece para o jogador enquanto estiver marcado como disponível. Não há acesso não assistido, transferência de arquivos, transferência da área de transferência ou persistência após o encerramento. Consulte [docs/REMOTE_SUPPORT.md](docs/REMOTE_SUPPORT.md) para ver a configuração e as proteções.

## Revisão por Gemini

O Vorken usa o filtro técnico normal como primeira camada e pode usar o **Gemini** como segunda camada para reduzir falsos positivos. A integração utiliza a Gemini Developer API diretamente por HTTPS, sem SDK adicional.

Variáveis recomendadas:

```text
AI_REVIEW_ENABLED=true
GEMINI_API_KEY=sua-chave-do-google-ai-studio
GEMINI_BASE_URL=https://generativelanguage.googleapis.com/v1beta
GEMINI_MODEL=gemini-3.5-flash-lite
AI_TIMEOUT_MS=60000
AI_REVIEW_BATCH_SIZE=20
AI_FALSE_POSITIVE_THRESHOLD=0.85
AI_REVIEW_MAX_FINDINGS=0
```

A chave deve permanecer somente no servidor ou no Coolify. Ela nunca é enviada ao agente Windows nem ao navegador. Se o Gemini falhar, ficar sem cota ou atingir limite de requisições, o Vorken mantém o resultado do filtro técnico normal e deixa os lotes não revisados disponíveis para uma tentativa posterior.

## Agente

```bash
cd agent
dotnet publish -c Release -r win-x64 --self-contained true
```

O `Dockerfile` de produção na raiz compila o agente Windows e posiciona o executável no caminho configurado em `AGENT_BINARY_PATH`.

## Verificação do EXE e assinatura de código

Cada download direto expõe o SHA-256 do executável exato na página da análise e também pelo cabeçalho `X-Vorken-SHA256`.

A assinatura de produção deve utilizar um certificado de assinatura de código válido pertencente ao projeto ou um serviço comercial compatível. O programa gratuito da SignPath Foundation voltado a projetos open source não deve ser apresentado como método oficial para novas versões proprietárias do Vorken.

Consulte a [política de assinatura de código](docs/CODE_SIGNING_POLICY.md).

O fluxo suporta, quando configurado, um certificado PFX por meio de:

```text
VORKEN_SIGNING_PFX_BASE64
VORKEN_SIGNING_PFX_PASSWORD
```

O PFX deve conter um certificado de assinatura de código válido e confiável. Sem um certificado confiável, o Windows SmartScreen ou produtos antivírus ainda podem exibir avisos para um executável recém-distribuído, mesmo quando o build for legítimo. Metadados do produto e checksum ajudam na verificação, mas não substituem reputação de assinatura.

## Governança proprietária

- Licença atual: proprietária, conforme [LICENSE](LICENSE).
- O código-fonte e os componentes internos não podem ser copiados, redistribuídos ou modificados sem autorização expressa.
- A marca, o nome e a identidade visual do Vorken são protegidos separadamente; consulte [TRADEMARKS.md](TRADEMARKS.md).
- Vulnerabilidades devem ser reportadas de forma privada conforme [SECURITY.md](SECURITY.md).
- Relatórios reais de jogadores, tokens de acesso, credenciais, assinaturas proprietárias e bancos de dados comerciais nunca devem ser enviados ao repositório.

## Filosofia de detecção

Contexto e inventário não são automaticamente uma detecção. Achados de alta severidade exigem sinais mais fortes, como evidência de execução, correlação com exclusão, IOC conhecido, binário suspeito sem assinatura, origem de risco, correspondência de catálogo ou múltiplos artefatos independentes.

Regras e correspondências heurísticas servem como evidência para revisão humana e não constituem, isoladamente, prova automática de trapaça.

### Motor de confiança V4

- Visitas diretas no navegador a um domínio ou convite exato presente no catálogo são críticas e aparecem na área dedicada de **Histórico suspeito**.
- Resultados de pesquisa e fragmentos recuperados de SQLite/WAL permanecem como evidência de revisão; apenas mencionar um domínio catalogado não equivale a uma visita direta.
- Correspondências exatas de nome de executável ou SHA-256 com execução histórica são críticas, mesmo fora da sessão atual de Rust.
- Executáveis desconhecidos com nomes aleatórios precisam de corroboração técnica independente, por exemplo exclusão associada a empacotamento, mídia removível ou APIs fortes de injeção, antes de serem classificados como críticos.
- Caminho gravável pelo usuário, ausência de assinatura, nome aparentemente aleatório ou palavra suspeita nunca são suficientes isoladamente para um veredito crítico.

## Camada de compatibilidade forense

O Vorken implementa equivalentes defensivos próprios de recursos publicamente documentados usados em screenshare e análise forense, como origem de arquivos, downloads e histórico do navegador, Prefetch, BAM, Amcache, USB, PowerShell, autoruns, USN/JournalTrace, ADS, WER/falhas, inspeção PE/packer, verificações de integridade e correlação de rede/DNS.

O Vorken não copia assinaturas proprietárias, bancos de dados privados nem código-fonte de scanners de terceiros.
