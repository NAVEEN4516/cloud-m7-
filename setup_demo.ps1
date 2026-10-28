param([switch]$SkipTests)
$ErrorActionPreference = 'Stop'
function Invoke-Checked {
    param([string]$Program, [string[]]$Arguments)
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Command failed: $Program $($Arguments -join ' ')" }
}
Push-Location $PSScriptRoot
try {
    Get-Command python, node, npm.cmd -ErrorAction Stop | Out-Null
    Invoke-Checked -Program python -Arguments @('-c', 'import sys; assert sys.version_info[:2] == (3,12)')
    Invoke-Checked -Program node -Arguments @('-e', 'if(parseInt(process.versions.node)<18)process.exit(1)')
    if (!(Test-Path -LiteralPath '.venv\Scripts\python.exe')) {
        Invoke-Checked -Program python -Arguments @('-m', 'venv', '.venv')
    }
    Invoke-Checked -Program '.\.venv\Scripts\python.exe' -Arguments @('-m', 'pip', 'install', '-r', 'requirements-demo.lock.txt')
    Invoke-Checked -Program npm.cmd -Arguments @('ci', '--prefix', 'web_dashboard', '--no-audit', '--no-fund')
    Invoke-Checked -Program '.\.venv\Scripts\python.exe' -Arguments @('scripts/check_demo.py')
    if (!$SkipTests) { Invoke-Checked -Program '.\.venv\Scripts\python.exe' -Arguments @('-m', 'pytest', '-q') }
    Write-Host 'Setup complete. Run .\start_demo.ps1. Internet is not required after setup.'
} finally { Pop-Location }
