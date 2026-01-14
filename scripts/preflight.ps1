$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")

Push-Location $repoRoot
try {
    if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
        Write-Error "python not found in PATH."
        exit 1
    }

    & python -m tools.demo
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }

    & (Join-Path $PSScriptRoot "opsec_scan.ps1")
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}