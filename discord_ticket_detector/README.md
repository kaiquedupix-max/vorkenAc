# Discord Ticket Detector — módulo inicial

Classificador independente para evidências **voluntariamente fornecidas** de notificações de tickets. Detecta abertura, fechamento e indícios de pedido em PT/EN/ES, sem exigir que o servidor esteja no catálogo.

## Entrada

`classify(record, known_cheat_servers)` recebe um dicionário com:
- `consent: true` (obrigatório)
- `source: "user_submitted_notification" | "authorized_windows_notification"`
- `notification_text`: texto de uma notificação disponibilizada pelo usuário
- `server_name`, `server_id`, `bot_name`, `occurred_at`: metadados opcionais

## Saída e decisões

Retorna `TicketFinding` ou `None`. As classificações são `inventory`, `manual_review` e `inconclusive`. Nenhuma gera banimento automático. O identificador do servidor só é registrado se vier na evidência; **não é inferido do nome do bot**.

## Limitações e privacidade

Este módulo **não coleta notificações automaticamente**, não acessa bancos de dados privados do Discord, DMs, tokens ou sessões, e não promete recuperar tickets antigos. Uma notificação pode não informar o servidor; nesse caso o resultado é inconclusivo. Para integração com scanner/painel, adicionar uma origem autorizada de notificações, consentimento granular e visualização para revisão humana. Não transmitir chaves de licença nem conteúdo de mensagens privadas.

Teste: `python -m unittest discover -s discord_ticket_detector -p 'test_*.py'`.
