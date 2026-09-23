$ErrorActionPreference = "Stop"

$Project = Join-Path $PSScriptRoot "Vorken.Agent.csproj"
$Output = Join-Path $PSScriptRoot "publish"

if (Test-Path $Output) {
    Remove-Item $Output -Recurse -Force
}

dotnet restore $Project
dotnet publish $Project -c Release -r win-x64 --self-contained false -o $Output

$Exe = Join-Path $Output "Vorken.Agent.exe"

if (-not (Test-Path $Exe)) {
    throw "Vorken.Agent.exe não foi gerado."
}

Write-Host ""
Write-Host "Vorken Agent publicado:"
Write-Host $Exe
Write-Host ""
Write-Host "Copie esse executável para o caminho definido em AGENT_BINARY_PATH no servidor."
