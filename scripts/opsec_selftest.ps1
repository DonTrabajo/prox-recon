$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$scanner = Join-Path $PSScriptRoot "opsec_scan.py"
$testdata = Join-Path $PSScriptRoot "opsec_testdata"

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Error "python not found in PATH."
    exit 1
}

# Expect failure when scanning testdata directly
& python $scanner --root $testdata
if ($LASTEXITCODE -eq 0) {
    Write-Error "Self-test failed: scanner did not flag test data."
    exit 1
}

# Expect success when excluding testdata from repo scan
& python $scanner --root $repoRoot --exclude scripts/opsec_testdata
if ($LASTEXITCODE -ne 0) {
    Write-Error "Self-test failed: scanner failed with exclusions."
    exit 1
}

Write-Output "OPSEC self-test passed."