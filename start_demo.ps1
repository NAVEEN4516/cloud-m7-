param([switch]$NoBrowser)
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    if (!(Test-Path -LiteralPath '.venv\Scripts\python.exe')) { throw 'Run .\setup_demo.ps1 first.' }
    & '.\.venv\Scripts\python.exe' scripts/check_demo.py
    if ($LASTEXITCODE -ne 0) { throw 'Prerequisite check failed. Run .\setup_demo.ps1.' }
    $nodeCommand = (Get-Command node -ErrorAction Stop).Source
    & $nodeCommand -e "require('./web_dashboard/node_modules/express'); require('./web_dashboard/node_modules/multer'); require.resolve('./web_dashboard/node_modules/vis-network/standalone/umd/vis-network.min.js')"
    if ($LASTEXITCODE -ne 0) { throw 'Node dependencies missing. Run .\setup_demo.ps1.' }
    $health = $null
    try { $health = Invoke-RestMethod 'http://127.0.0.1:3001/api/health' -TimeoutSec 2 } catch { }
    if ($health -and ($health.version -ne 'review2')) { throw 'Port 3001 belongs to another service. Stop that service first.' }
    if (!$health) {
        $logDir = Join-Path $PSScriptRoot 'output'
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        $server = Start-Process -FilePath $nodeCommand -ArgumentList @('web_dashboard/server.js') -WorkingDirectory $PSScriptRoot -WindowStyle Hidden -RedirectStandardOutput (Join-Path $logDir 'demo-server.log') -RedirectStandardError (Join-Path $logDir 'demo-server-error.log') -PassThru
        Set-Content -LiteralPath (Join-Path $logDir 'demo-server.pid') -Value $server.Id
        for ($attempt = 0; $attempt -lt 20; $attempt++) {
            try { $health = Invoke-RestMethod 'http://127.0.0.1:3001/api/health' -TimeoutSec 1; break } catch { Start-Sleep -Milliseconds 500 }
        }
        if (!$health) { throw 'Server failed to start. Check output/demo-server-error.log.' }
    }
    if ($health.version -ne 'review2') { throw 'Unexpected service on port 3001.' }
    Write-Host 'CLOUD-M7 ready: http://localhost:3001'
    if (!$NoBrowser) { Start-Process 'http://localhost:3001' }
} finally { Pop-Location }
