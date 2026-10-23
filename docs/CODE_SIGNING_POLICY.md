# Política de assinatura de código

O Vorken publica seu agente Windows por meio de um fluxo de build controlado pelo projeto. Downloads personalizados por jogador alteram apenas o nome do arquivo baixado; os bytes do executável permanecem idênticos ao binário oficial correspondente, preservando o hash e a assinatura Authenticode.

## Modelo de assinatura

As versões proprietárias do Vorken devem utilizar uma destas opções:

- certificado de assinatura de código pertencente ao projeto, armazenado e utilizado por um fluxo seguro de CI/CD; ou
- serviço comercial de assinatura de código compatível com Authenticode e com a política interna do projeto.

O programa gratuito da SignPath Foundation voltado a projetos open source não é tratado como método oficial para novas versões proprietárias do Vorken.

## Responsabilidades da equipe

- Committers e revisores: proprietário do repositório e mantenedores autorizados.
- Aprovadores de produção: proprietário do projeto ou pessoa expressamente autorizada.

Contas administrativas utilizadas no GitHub, no provedor de assinatura e nos serviços de produção devem utilizar autenticação multifator sempre que disponível.

## Garantias do processo de build e publicação

- Artefatos de produção devem ser compilados a partir de um commit identificável.
- A assinatura deve ser aplicada ao mesmo artefato produzido pelo fluxo de build aprovado.
- Metadados de produto e versão devem ser definidos nos arquivos do projeto e validados antes da publicação.
- O SHA-256 deve ser gerado sobre o executável final que será distribuído.
- O executável não deve ser alterado depois da assinatura para inserir token de jogador.
- O token da análise é lido a partir do nome personalizado do arquivo, preservando os bytes do binário oficial.
- Releases oficiais devem disponibilizar o SHA-256 do executável correspondente.

## Uso de certificado PFX

Quando o fluxo utilizar certificado próprio, as credenciais podem ser fornecidas ao ambiente de CI por meio de segredos como:

```text
VORKEN_SIGNING_PFX_BASE64
VORKEN_SIGNING_PFX_PASSWORD
```

O PFX deve conter um certificado de assinatura de código válido e sua chave privada deve permanecer protegida. Segredos nunca devem ser incluídos no código-fonte, logs públicos ou artefatos de build.

## Verificação

No Windows, a assinatura pode ser verificada pelas propriedades do arquivo em **Assinaturas Digitais** ou por PowerShell:

```powershell
Get-AuthenticodeSignature .\Vorken.Agent.exe
Get-FileHash .\Vorken.Agent.exe -Algorithm SHA256
```

A assinatura deve aparecer como válida quando houver certificado configurado, e o hash deve corresponder ao checksum publicado junto da versão.

Consulte também a [política de privacidade](PRIVACY.md), a [política de segurança](../SECURITY.md) e a [política de marca](../TRADEMARKS.md).
