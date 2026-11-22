[CmdletBinding()]
param(
    [string]$ProfileId = 'appsec-triage',
    [string]$ConfigDirectory = '',
    [switch]$EnableTelegram,
    [string]$TelegramChatId = '',
    [switch]$SkipBuild
)
$ErrorActionPreference = 'Stop'
$workspace = Split-Path -Parent $PSScriptRoot
if (-not $ConfigDirectory) { $ConfigDirectory = Join-Path $workspace '.local/config' }
[void](New-Item -ItemType Directory -Force -Path $ConfigDirectory)
$configPath = (Resolve-Path -LiteralPath $ConfigDirectory).Path.Replace('\', '/')
$serverFile = Join-Path $configPath 'server.json'
if (Test-Path -LiteralPath $serverFile -PathType Leaf) {
    $previousEntry = Get-Content -LiteralPath $serverFile -Raw | ConvertFrom-Json
    if (-not $PSBoundParameters.ContainsKey('TelegramChatId')) {
        $chatSetting = @($previousEntry.env | Where-Object { $_.name -eq 'APPSEC_MCP_TELEGRAM_CHAT_ID' })
        if ($chatSetting.Count) { $TelegramChatId = [string]$chatSetting[0].value }
    }
    if (-not $PSBoundParameters.ContainsKey('EnableTelegram')) {
        $EnableTelegram = @($previousEntry.secrets | Where-Object { $_.env -eq 'APPSEC_MCP_TELEGRAM_BOT_TOKEN' }).Count -gt 0
    }
}
if (-not $SkipBuild) {
    Push-Location $workspace
    try {
        & docker build -t 'appsec-triage-mcp:local' .
        if ($LASTEXITCODE -ne 0) { throw 'Docker build failed' }
    } finally { Pop-Location }
}
$entry = [ordered]@{
    name = 'appsec-triage'
    title = 'AppSec Triage Tools'
    type = 'server'
    image = 'appsec-triage-mcp:local'
    description = 'Clone 1 to 3 Git projects, scan, return HTML and remove temporary sources.'
    longLived = $true
    env = @(
        @{name = 'APPSEC_MCP_SCP_TARGETS_FILE'; value = '/run/appsec-mcp/scp-targets.json'},
        @{name = 'APPSEC_MCP_TELEGRAM_CHAT_ID'; value = $TelegramChatId}
    )
    volumes = @('appsec-mcp-results:/out', "${configPath}:/run/appsec-mcp:ro")
}
if ($EnableTelegram) {
    $entry.secrets = @(@{
        name = 'appsec-triage.telegram_bot_token'
        env = 'APPSEC_MCP_TELEGRAM_BOT_TOKEN'
        example = 'Configure in Docker Desktop secret store'
    })
}
[IO.File]::WriteAllText($serverFile, ($entry | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
$profilesRaw = & docker mcp profile list --format json
if ($LASTEXITCODE -ne 0) { throw 'Cannot list Docker MCP profiles' }
$profiles = @($profilesRaw | ConvertFrom-Json)
$reference = 'file://' + $serverFile.Replace('\', '/')
if (@($profiles | Where-Object { $_.id -eq $ProfileId }).Count) {
    & docker mcp profile server add $ProfileId --server $reference
} else {
    & docker mcp profile create --name $ProfileId --id $ProfileId --server $reference
}
if ($LASTEXITCODE -ne 0) { throw 'Docker MCP profile setup failed' }
Write-Host "Ready: docker mcp gateway run --profile $ProfileId --long-lived --cpus 3 --memory 8Gb"
Write-Host 'Pass Git URLs to appsec-scan-projects or scripts/scan_projects.py; no source mount is needed.'
