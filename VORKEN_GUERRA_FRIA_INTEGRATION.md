# Integração Vorken ↔ Guerra Fria

O Vorken aceita sessões criadas automaticamente pelo fluxo de verificação do Guerra Fria e permite aplicar a decisão diretamente no painel administrativo.

## Variáveis no Vorken / Coolify

Obrigatórias:

- `VORKEN_GF_INTEGRATION_KEY`: segredo compartilhado com o projeto Guerra Fria.
- `GUERRA_FRIA_INTEGRATION_URL`: URL pública do projeto Guerra Fria, sem barra final.

Exemplo de formato:

```
GUERRA_FRIA_INTEGRATION_URL=https://SEU-DOMINIO-DO-GUERRA-FRIA
VORKEN_GF_INTEGRATION_KEY=use-um-segredo-longo-e-aleatorio
```

Não salve o valor real do segredo no GitHub.

## Fluxo

- Guerra Fria registra o código temporário no Vorken.
- Ao jogador enviar o código no Discord, o Vorken cria a análise e devolve o link exclusivo.
- O ID do Discord, SteamID, código e canal privado ficam vinculados à análise.
- Depois da conclusão, os botões **Liberar jogador** e **Banir jogador** aparecem no relatório integrado.
- A decisão é enviada ao endpoint interno do Guerra Fria e só é persistida no Vorken depois que o Guerra Fria confirma a ação.
