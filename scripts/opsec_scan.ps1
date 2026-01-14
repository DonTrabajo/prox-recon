$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$scanner = Join-Path $PSScriptRoot "opsec_scan.py"

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Error "python not found in PATH."
    exit 1
}

& python $scanner --root $repoRoot
exit $LASTEXITCODE