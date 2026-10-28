[CmdletBinding()]
param(
    [switch]$Gpu,
    [switch]$Sat,
    [string]$Python = "",
    [switch]$Help
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
if ($Help) {
    Write-Output "Usage: .\Setup.ps1 [-Gpu] [-Sat] [-Python path-to-python] [-Help]"
    Write-Output "Create/reuse .venv and verify CPU imports. Only -Gpu installs pinned CUDA packages."
    Write-Output "Existing .venv is preserved; -Python selects the interpreter only when creating it."
    Write-Output "-Sat installs the optional pinned Z3 backend for finite constraint experiments."
    exit 0
}
Push-Location -LiteralPath $PSScriptRoot
try {
    $venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
    if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot ".venv"))) {
        $choices = @()
        if ($Python) {
            $choices = @(@{ Command = $Python; Prefix = @() })
        } else {
            $pyLauncher = Get-Command py.exe -ErrorAction SilentlyContinue
            if ($pyLauncher) {
                $choices += @{ Command = $pyLauncher.Source; Prefix = @("-3.12") }
                $choices += @{ Command = $pyLauncher.Source; Prefix = @("-3") }
            }
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
        if (-not $selected) { throw "Python 3.10+ is required. Install Python or supply -Python with its executable path." }
        $prefix = $selected.Prefix
        & $selected.Command @prefix -m venv (Join-Path $PSScriptRoot ".venv")
        if ($LASTEXITCODE -ne 0) { throw "Creating .venv failed. No existing environment was replaced." }
    }
    if (-not (Test-Path -LiteralPath $venvPython)) {
        throw "Existing .venv has no Windows Python interpreter. It was preserved; repair it or use a compatible environment manually."
    }
    & $venvPython -c "import sys; assert sys.version_info >= (3,10), 'Python 3.10+ required'; import kryptos.app; print('CPU application ready on Python ' + sys.version.split()[0])"
    if ($LASTEXITCODE -ne 0) { throw "CPU application import check failed." }
    if ($Gpu) {
        & $venvPython -c "import struct; assert struct.calcsize('P') == 8, 'CUDA setup requires a 64-bit Python interpreter'"
        if ($LASTEXITCODE -ne 0) { throw "GPU interpreter check failed." }
        & $venvPython -m pip install --requirement (Join-Path $PSScriptRoot "requirements-gpu.txt")
        if ($LASTEXITCODE -ne 0) { throw "GPU dependency installation failed. CPU use remains available." }
        Write-Output "GPU packages installed. The dashboard checks a compiled CUDA kernel on launch; a compatible NVIDIA driver is required."
    }
    if ($Sat) {
        & $venvPython -m pip install --requirement (Join-Path $PSScriptRoot "requirements-sat.txt")
        if ($LASTEXITCODE -ne 0) { throw "Optional SMT dependency installation failed. Other CPU methods remain available." }
        & $venvPython -c "import z3; print('Optional SMT backend ready: Z3 ' + z3.get_version_string())"
        if ($LASTEXITCODE -ne 0) { throw "Optional SMT import check failed." }
    }
    Write-Output "Run .\OpenDashboard.cmd to open the idle local application."
} finally {
    Pop-Location
}
