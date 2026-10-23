# Limites do agente

O agente não lê memória de processos, não enumera módulos e não captura ou transmite a tela. Não há controle remoto de mouse/teclado. Os contratos antigos correspondentes recebem listas vazias.

Rust, RustClient, RustDedicated e EasyAntiCheat são excluídos por nome antes de consultar caminho ou outros detalhes. Caminhos de Steam/steamapps, AppId 252490, Facepunch Studios, diretórios de Rust/EAC, locais registrados de instalação, caminhos de dispositivo/rede, aliases DOS e reparse points são bloqueados antes da leitura. O caminho dos outros processos vem de WMI, sem MainModule.

## Processos abertos

Inventário pontual dos processos permitidos; o relatório informa o horário e se houve análise do arquivo ou somente metadados. A interface oculta componentes comuns apenas com assinatura e localização compatíveis. Nome de Windows em pasta temporária não é ocultado. Correlação com achados relevantes mantém o item visível.

## Journal

Execuções registradas nos logs Security (4688) e Sysmon (1), do início desta inicialização até a coleta. Não usa o USN como prova de execução. Logs podem estar indisponíveis, desabilitados, incompletos ou rotacionados. São lidos até 5.000 eventos e 15 segundos por fonte; os limites são informados. A assinatura é verificada para até 1.000 caminhos distintos permitidos. Não envia linha de comando nem XML bruto de eventos. Relatórios antigos não são apresentados como histórico desde o boot.

## Build

Releases single-file passam pelo Obfuscar.GlobalTool 2.2.50 antes de empacotar, tanto no CI como no Docker. Nomes de propriedades, campos, interoperabilidade nativa, tipos gerados e formulário principal são preservados. Não há proteção contra depuração, packer ou driver. Mapeamentos ficam em obj e não são distribuídos. A ofuscação dificulta a leitura do executável, mas não impede engenharia reversa e não substitui manter segredos no servidor.

A validação usa diretórios temporários e eventos sintéticos: não inicia coleta no computador nem abre o jogo. As exclusões não constituem promessa de ausência de banimento por qualquer anticheat.
