[CmdletBinding()]
param([string]$Python = '')

$ErrorActionPreference = 'Stop'
$repository = Split-Path -Parent $PSScriptRoot
if (-not $Python) { $Python = Join-Path $repository '.venv/Scripts/python.exe' }
$previousBytecodeSetting = $env:PYTHONDONTWRITEBYTECODE
$env:PYTHONDONTWRITEBYTECODE = '1'
Push-Location $repository
try {
    & $Python -m ruff check src tests --no-cache
    if ($LASTEXITCODE -ne 0) { throw 'Lint failed' }
    & $Python -m pytest -q -p no:cacheprovider
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
} finally {
    Pop-Location
    $env:PYTHONDONTWRITEBYTECODE = $previousBytecodeSetting
}
