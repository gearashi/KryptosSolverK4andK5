[CmdletBinding()]
param(
    [ValidateRange(0,65535)][int]$Port = 8767,
    [switch]$NoBrowser,
    [switch]$SkipGpuProbe,
    [switch]$StrictPort,
    [string]$StateDir = "",
    [string]$Python = "",
    [switch]$Help
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
if ($Help) {
    Write-Output "Usage: .\OpenDashboard.ps1 [-Port 8767] [-NoBrowser] [-SkipGpuProbe] [-StrictPort] [-StateDir path] [-Python path] [-Help]"
    Write-Output "Reopens an existing dashboard, or selects a free port if the preferred port is occupied."
    Write-Output "Open the local dashboard. No search starts on launch; Ctrl+C closes the server."
    Write-Output "Uses .venv when available, otherwise Python 3.10+. Installs nothing."
    exit 0
}
Push-Location -LiteralPath $PSScriptRoot
try {
    $choices = @()
    $venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
    if ($Python) {
        $choices = @(@{ Command = $Python; Prefix = @() })
    } elseif (Test-Path -LiteralPath $venvPython) {
        $choices = @(@{ Command = $venvPython; Prefix = @() })
    } else {
        $pyLauncher = Get-Command py.exe -ErrorAction SilentlyContinue
        if ($pyLauncher) { $choices += @{ Command = $pyLauncher.Source; Prefix = @("-3") } }
        $plainPython = Get-Command python.exe -ErrorAction SilentlyContinue
        if ($plainPython) { $choices += @{ Command = $plainPython.Source; Prefix = @() } }
    }
    $selected = $null
    foreach ($choice in $choices) {
        $prefix = $choice.Prefix
        try {
            & $choice.Command @prefix -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)" 2>$null
            if ($LASTEXITCODE -eq 0) { $selected = $choice; break }
        } catch { }
    }
    if (-not $selected) { throw "Python 3.10+ is required. Run Setup.cmd or supply -Python." }
    $launchArgs = @("-B", "-m", "kryptos.app", "--port", "$Port")
    if ($NoBrowser) { $launchArgs += "--no-browser" }
    if ($SkipGpuProbe) { $launchArgs += "--skip-gpu-probe" }
    if ($StrictPort) { $launchArgs += "--strict-port" }
    if ($StateDir) { $launchArgs += @("--state-dir", $StateDir) }
    $prefix = $selected.Prefix
    & $selected.Command @prefix @launchArgs
    if ($LASTEXITCODE -ne 0) { throw "The local application exited with code $LASTEXITCODE." }
} finally {
    Pop-Location
}
