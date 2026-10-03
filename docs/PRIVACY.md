# Política de privacidade do Vorken

Última atualização: 3 de outubro de 2026

O Vorken é um scanner forense sob demanda e baseado em consentimento, desenvolvido para investigações de integridade em ambientes competitivos de jogos. Esta política descreve o funcionamento das versões proprietárias atuais do Vorken Anti Cheat. O operador de uma implantação do Vorken é responsável por seus próprios controles de acesso, prazos de retenção e obrigações legais aplicáveis.

## Antes da coleta

O agente Windows apresenta seus termos e esta política antes do início da análise. O jogador pode recusar e fechar o aplicativo. O Vorken não instala serviço de acesso não assistido nem executa silenciosamente uma análise em segundo plano.

## Dados técnicos coletados

Após consentimento explícito, o agente pode coletar indicadores técnicos necessários para uma revisão de integridade, incluindo:

- metadados do sistema operacional, máquina, produtos de segurança e hardware;
- processos em execução, módulos, assinaturas de executáveis e metadados de integridade;
- artefatos de execução do Windows, como Prefetch, Amcache, ShimCache, BAM/DAM, UserAssist, MUICache, PCA, logs de eventos, metadados de falha e atividade USN;
- nomes de executáveis, caminhos, hashes, correlações com exclusão, origem de download e indicadores de execução em mídia removível;
- dispositivos removíveis, USB e seriais relevantes, atuais e históricos;
- registros de download do navegador e indicadores de navegação restritos ao necessário para regras de ameaça definidas pelo sistema ou pelo administrador;
- indicadores filtrados de PowerShell, inicialização automática, tarefas agendadas, DNS e conexões relevantes à investigação;
- identificadores Steam e identificadores de caso fornecidos pelo administrador; e
- erros da análise, timestamps, versão do agente e status da análise.

O Vorken não foi projetado para coletar senhas, cookies de autenticação, conteúdo de mensagens privadas, fotografias, vídeos pessoais, conteúdo de documentos pessoais, dados de pagamento ou dumps arbitrários de memória RAM. Os coletores devem minimizar conteúdo não relacionado e a interface administrativa deve separar inventário técnico de achados efetivos.

## Transferência e acesso

O agente envia o relatório com transporte criptografado ao servidor Vorken associado ao link de análise. Administradores autorizados daquela implantação podem revisar o relatório e registrar uma decisão.

Relatórios não devem ser tornados públicos por padrão. Caso uma violação confirmada seja documentada publicamente conforme os termos aplicáveis ao servidor, a divulgação deve ser limitada ao necessário para demonstrar a infração. Dados pessoais não relacionados, comunicações privadas, credenciais, endereços IP, localização, dados de terceiros, rostos, vozes e notificações devem ser removidos ou ocultados, salvo quando estritamente necessários e legalmente permitidos.

Uma revisão opcional por IA pode enviar resumos normalizados de achados à API do Google Gemini quando o operador do servidor habilitar esse recurso. A integração com VirusTotal utiliza apenas hashes de executáveis e não envia arquivos. O operador é responsável por revisar os termos de privacidade dos serviços opcionais que decidir ativar.

## Suporte remoto

O suporte remoto fica desativado por padrão. O jogador deve escolher entre visualização da tela ou visualização com controle temporário de mouse e teclado, confirmar a solicitação e aguardar que um administrador disponível aceite a sessão.

O jogador pode encerrar a sessão a qualquer momento. O Vorken não oferece acesso não assistido, transferência de arquivos, transferência de área de transferência, captura de credenciais ou controle remoto persistente. Os frames da tela são utilizados para a sessão ao vivo e não são intencionalmente armazenados pelo servidor Vorken.

## Retenção e decisões aprendidas

Um link de análise ainda não iniciado pode expirar conforme o período selecionado pelo administrador. A retenção de relatórios concluídos é controlada pelo operador da implantação. Relatórios devem ser mantidos somente pelo período necessário à finalidade documentada da investigação e de acordo com as obrigações legais aplicáveis.

Decisões administrativas podem gerar registros técnicos normalizados de confiança ou detecção para evitar a repetição de falsos positivos conhecidos em análises futuras. Esses registros devem utilizar identidade técnica, como hashes, informações de assinatura, metadados do produto e características normalizadas de executáveis, em vez de conteúdo pessoal de arquivos.

## Segurança e escolhas do usuário

O acesso aos relatórios exige autenticação administrativa. Tokens, senhas, chaves de API e relatórios privados nunca devem ser inseridos em repositórios públicos ou em locais acessíveis sem autorização.

O jogador pode recusar a análise, fechar o agente antes da coleta, recusar o suporte remoto ou encerrar uma sessão remota ativa.

Para relatar uma questão de privacidade ou segurança relacionada ao projeto, utilize o canal privado do GitHub enquanto ele estiver disponível para o repositório:

<https://github.com/kaiquedupix-max/vorkenAc/security/advisories/new>

Quando o Vorken estiver implantado por uma comunidade ou servidor específico, questões operacionais de retenção, acesso e administração devem ser direcionadas ao respectivo operador.
