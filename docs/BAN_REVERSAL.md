# Reversão de bans Vorken

Na auditoria administrativa de banimentos, use **Reverter ban**, confirme o SteamID e informe o motivo. A operação exige a sessão do administrador principal e proteção de origem. Ela reverte os registros desse SteamID na rede do mesmo cliente; registros e punições de outros clientes são preservados. Bans de associados com outro SteamID exigem revisão própria.

Os registros saem da lista ativa imediatamente, interrompendo a replicação. O histórico, as provas e o motivo da reversão ficam preservados. O painel mostra separadamente cada comando aguardando plugin, confirmado ou com falha. Somente a confirmação do plugin significa que a remoção foi aplicada no Rust. Falhas podem ser reenviadas com um novo identificador de comando.

Todos os servidores envolvidos precisam instalar o plugin **Vorken 2.0.11**, disponível no download habitual do painel. A atualização do site não instala plugins nos servidores Rust. A reversão é bloqueada enquanto uma instalação envolvida estiver desatualizada. Servidores offline mantêm o comando pendente até reconectar, inclusive com licença inativa.

O plugin confere se o motivo do ban atual corresponde a um dos registros revertidos. Um ban diferente exige revisão manual. O backend bloqueia a entrega de reversões quando existe uma nova punição ativa. Não há reversão automática de bans do Discord, de serviços externos ou de Steam/VAC.

“Remover da lista” continua sendo apenas uma alteração de visibilidade; não é um desbanimento. Um registro revertido não pode ser restaurado pelo botão de visibilidade: uma nova punição exige nova decisão.
