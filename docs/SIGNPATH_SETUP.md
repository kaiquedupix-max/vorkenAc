# Configuração de assinatura de código

Este documento existia originalmente para a integração do Vorken com o programa gratuito da SignPath Foundation destinado a projetos open source.

Como as novas versões do Vorken Anti Cheat passam a ser distribuídas como software proprietário, **o programa gratuito para projetos open source não deve ser utilizado nem apresentado como método oficial de assinatura das novas versões**.

## Opções suportadas para novas versões

O projeto pode utilizar:

1. um certificado próprio de assinatura de código, armazenado de forma segura e utilizado pelo fluxo de CI/CD; ou
2. um plano comercial de um provedor de assinatura compatível com Microsoft Authenticode, incluindo SignPath comercial quando aplicável.

## Configuração com certificado próprio

O workflow atual possui suporte a credenciais PFX por meio dos seguintes segredos do GitHub:

```text
VORKEN_SIGNING_PFX_BASE64
VORKEN_SIGNING_PFX_PASSWORD
```

O arquivo PFX deve conter um certificado válido de assinatura de código. A chave privada e a senha não podem ser gravadas no repositório, em arquivos de configuração versionados ou em logs públicos.

## Configuração com serviço comercial

Caso o projeto utilize SignPath ou outro provedor comercial, configure os identificadores e tokens exigidos pelo plano contratado somente após a criação do projeto no provedor.

Quando a integração utilizar os campos abaixo, eles devem permanecer exclusivamente como segredos do repositório:

```text
SIGNPATH_API_TOKEN
SIGNPATH_ORGANIZATION_ID
SIGNPATH_PROJECT_SLUG
SIGNPATH_SIGNING_POLICY_SLUG
SIGNPATH_ARTIFACT_CONFIGURATION_SLUG
```

Os nomes das variáveis podem ser mantidos por compatibilidade com o workflow existente, mas a utilização efetiva depende de uma conta e política de assinatura compatíveis com a distribuição proprietária do Vorken.

## Requisitos de segurança

- Ative autenticação multifator nas contas administrativas do GitHub e do provedor de assinatura.
- Exija aprovação manual para assinaturas de produção quando o provedor oferecer esse recurso.
- Restrinja tokens de API ao projeto e à política de assinatura necessários.
- Gere o SHA-256 somente depois que o executável final estiver pronto para distribuição.
- Não modifique os bytes do executável depois da assinatura.
- Não use segredos de exemplo ou valores fictícios em produção.

Consulte [CODE_SIGNING_POLICY.md](CODE_SIGNING_POLICY.md) para a política completa de assinatura do Vorken.
