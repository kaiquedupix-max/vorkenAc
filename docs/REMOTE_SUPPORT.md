# Suporte remoto Vorken

O suporte remoto é uma sessão temporária iniciada pelo jogador e aceita por um administrador específico. Ele oferece dois níveis de permissão:

- **Somente tela:** transmite imagens comprimidas da área de trabalho.
- **Tela + controle:** além da imagem, aceita mouse e teclado enquanto a sessão permanece ativa.

Não há acesso não assistido, serviço persistente, transferência de arquivos, sincronização de área de transferência ou reconexão automática. O jogador vê um indicador vermelho durante toda a sessão e pode encerrá-la pelo próprio Vorken.

## Cadastro de administradores

Depois do deploy, entre em `/admin` com a senha administrativa do site e abra a aba **Administradores**. Por ali é possível criar contas individuais, acompanhar quem está online, ativar ou desativar acessos e redefinir senhas.

Ao desativar uma conta ou redefinir sua senha, o servidor encerra as sessões remotas daquele administrador e exige um novo login. O painel impede que a última conta ativa seja desativada.

## Configuração inicial alternativa

Opcionalmente, o primeiro administrador também pode ser criado no início da aplicação por variáveis de ambiente. A senha precisa ter pelo menos 12 caracteres.

```text
REMOTE_ADMIN_BOOTSTRAP_USER=administrador
REMOTE_ADMIN_BOOTSTRAP_NAME=Nome exibido
REMOTE_ADMIN_BOOTSTRAP_PASSWORD=uma-senha-longa-e-exclusiva
```

Depois do primeiro início, remova a senha do ambiente. O cadastro já estará armazenado com `scrypt`, salt individual e hash. Não existe senha padrão.

O endereço público configurado em `PUBLIC_URL` precisa usar HTTPS em produção. A mesma conexão segura é convertida para WSS para transportar os quadros da tela e eventos de controle.

## Aplicativo administrativo

Compile `admin-app/Vorken.RemoteAdmin.csproj` e abra `Vorken.RemoteAdmin.exe`. Cada administrador entra com seu próprio usuário, marca-se como disponível e recebe apenas as solicitações destinadas à sua conta.

O administrador ainda precisa aceitar cada solicitação. O modo autorizado pelo jogador não pode ser elevado pelo administrador: uma sessão de visualização nunca encaminha eventos de controle.

## Auditoria e limites

O servidor registra solicitação, aceite, conexão e encerramento em `remote_support_events`. Credenciais de sessão expiram, quadros têm limite de 2 MiB e as sessões duram no máximo 30 minutos. Para continuar depois disso, o jogador deve iniciar e autorizar uma nova sessão.
