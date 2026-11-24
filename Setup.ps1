[CmdletBinding()]
param(
    [switch]$Gpu,
    [switch]$Cpu,
    [switch]$Sat,
    [string]$Python = "",
    [switch]$Help
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
if ($Help) {
    Write-Output "Usage: .\Setup.ps1 [-Gpu | -Cpu] [-Sat] [-Python path-to-python]"
    Write-Output "Default: set up CUDA on an NVIDIA PC, or a standard-library CPU environment otherwise."
    Write-Output "-Cpu skips GPU installation. -Gpu finds or installs 64-bit Python 3.12 and verifies an actual CUDA kernel."
    Write-Output "-Sat also installs the Z3 backend in the selected profile."
    exit 0
}
if ($Gpu -and $Cpu) { throw "Choose one profile: -Cpu or -Gpu." }

function Find-Python([string]$Executable, [string[]]$Prefix, [string]$Condition) {
    if (-not $Executable) { return }
    foreach ($program in (Get-Command $Executable -CommandType Application -ErrorAction SilentlyContinue)) {
        try {
            $result = & $program.Source @Prefix -c "import sys, sysconfig; print(sys.executable) if ($Condition) else sys.exit(1)" 2>$null
            if ($LASTEXITCODE -eq 0 -and $result) { return $result.Trim() }
        } catch { }
    }
}

Push-Location -LiteralPath $PSScriptRoot
try {
    $cpuCondition = "sys.version_info >= (3, 10)"
    $gpuCondition = "sys.implementation.name == 'cpython' and sys.version_info[:2] == (3, 12) and sysconfig.get_platform() == 'win-amd64'"
    $gpuMarker = Join-Path $PSScriptRoot ".venv-gpu\use-for-dashboard"
    if (-not ($Gpu -or $Cpu)) {
        # PCI display class 03 can identify a graphics card before its driver is installed.
        $devices = & pnputil.exe /enum-devices /connected
        if ($LASTEXITCODE -eq 0) {
            foreach ($match in [regex]::Matches(($devices -join " "), '(?i)PCI\\VEN_10DE[^\s]+')) {
                $device = Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Enum\$($match.Value)" -ErrorAction SilentlyContinue
                if ($device -and ($device.PSObject.Properties['CompatibleIDs']) -and ($device.CompatibleIDs -match '^PCI\\CC_03')) {
                    $Gpu = $true
                    break
                }
            }
        } else {
            $Gpu = Test-Path -LiteralPath "$env:SystemRoot\System32\nvcuda.dll"
            Write-Output "Windows could not enumerate display adapters. To request CUDA explicitly, run .\Setup.cmd -Gpu."
        }
    }
    $profile = if ($Gpu) { ".venv-gpu" } else { ".venv" }
    $condition = if ($Gpu) { $gpuCondition } else { $cpuCondition }
    $venvPython = Join-Path $PSScriptRoot "$profile\Scripts\python.exe"
    $retry = if ($Gpu) { ".\Setup.cmd -Gpu" } else { ".\Setup.cmd -Cpu" }
    if ($Sat) { $retry += " -Sat" }

    if ($Gpu) { Write-Output "NVIDIA profile: the pinned CuPy wheel needs a supported interpreter. Using 64-bit Python 3.12." }
    if (-not (Test-Path -LiteralPath $venvPython)) {
        $selected = Find-Python $Python @() $condition
        if ($Python -and -not $selected) {
            if (-not $Gpu) { throw "Could not use $Python for CPU setup. Run .\Setup.cmd -Cpu with a Python 3.10+ interpreter." }
            Write-Output "The requested interpreter cannot run this GPU profile. Looking for 64-bit Python 3.12."
        }
        if ($Gpu) {
            $private = Join-Path $PSScriptRoot ".python312"
            if (-not $selected) { $selected = Find-Python (Join-Path $private "python.exe") @() $condition }
            if (-not $selected) { $selected = Find-Python "py.exe" @("-3.12") $condition }
            if (-not $selected) { $selected = Find-Python "python.exe" @() $condition }
            if (-not $selected) {
                # Full x64 Windows runtime selected by the official Python install manager.
                # Its published SHA-256 binds the portable archive before extraction.
                $url = "https://www.python.org/ftp/python/3.12.10/python-3.12.10-amd64.zip"
                $sha256 = "8649692de846c56a7189d6dae5c322ab20deb1b5908b6f39426b62a36f39415d"
                $stage = Join-Path $PSScriptRoot (".python312-" + [guid]::NewGuid().ToString("N"))
                $archive = "$stage.zip"
                Write-Output "Downloading private 64-bit Python 3.12.10 from python.org."
                try {
                    $ProgressPreference = "SilentlyContinue"
                    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $archive
                    $sha = [Security.Cryptography.SHA256]::Create()
                    $stream = [IO.File]::OpenRead($archive)
                    try { $actual = [BitConverter]::ToString($sha.ComputeHash($stream)).Replace("-", "") }
                    finally { $stream.Dispose(); $sha.Dispose() }
                    if ($actual -ne $sha256) {
                        throw "The downloaded Python runtime has an unexpected SHA-256."
                    }
                    Add-Type -AssemblyName System.IO.Compression.FileSystem
                    [IO.Compression.ZipFile]::ExtractToDirectory($archive, $stage)
                    if (-not (Find-Python (Join-Path $stage "python.exe") @() $condition)) {
                        throw "The downloaded Python runtime failed the interpreter check."
                    }
                    [IO.Directory]::Move($stage, $private)
                } catch {
                    # A concurrent setup can finish the same verified installation.
                    if (-not (Find-Python (Join-Path $private "python.exe") @() $condition)) {
                        throw "Missing 64-bit Python 3.12. $($_.Exception.Message) To retry run $retry."
                    }
                } finally {
                    if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive -Force }
                    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
                }
                $selected = Find-Python (Join-Path $private "python.exe") @() $condition
            }
            if (-not $selected) { throw "Missing 64-bit Python 3.12. Restore access to the Python package source and run $retry." }
        } else {
            if (-not $selected) { $selected = Find-Python "py.exe" @("-3") $condition }
            if (-not $selected) { $selected = Find-Python "python.exe" @() $condition }
            if (-not $selected) { throw "CPU setup requires Python 3.10 or later. Use .\Setup.cmd -Cpu -Python path-to-python.exe." }
        }
        Write-Output "Creating $profile with $selected"
        & $selected -m venv --without-pip (Join-Path $PSScriptRoot $profile)
        if ($LASTEXITCODE -ne 0) { throw "Could not create $profile. Check the folder permissions and run $retry." }
    }
    if (-not (Find-Python $venvPython @() $condition)) {
        throw "The interpreter in $profile is unusable. Extract a fresh copy of the workbench and run $retry."
    }
    & $venvPython -B -c "import sys, kryptos.app; print('CPU application ready on Python ' + sys.version.split()[0])"
    if ($LASTEXITCODE -ne 0) { throw "CPU application import failed. Check the extracted source and run $retry." }
    if ($Gpu -or $Sat) {
        & $venvPython -c "import importlib.util, sys; sys.exit(importlib.util.find_spec('pip') is None)"
        if ($LASTEXITCODE -ne 0) {
            & $venvPython -m ensurepip --default-pip
            if ($LASTEXITCODE -ne 0) { throw "The profile is missing pip. Check access to your temporary folder and run $retry." }
        }
        $requirements = @()
        if ($Gpu) { $requirements += @("-r", "requirements-gpu.txt") }
        if ($Sat) { $requirements += @("-r", "requirements-sat.txt") }
        & $venvPython -m pip install --only-binary=:all: --disable-pip-version-check @requirements
        if ($LASTEXITCODE -ne 0) { throw "A required wheel could not be installed (see pip output above). Restore access to the wheel source and run $retry." }
    }
    if ($Sat) {
        & $venvPython -c "import z3; print('Optional SMT backend ready: Z3 ' + z3.get_version_string())"
        if ($LASTEXITCODE -ne 0) { throw "The Z3 backend failed to load. Run $retry." }
    }
    if ($Gpu) {
        & $venvPython -B scripts/check_windows_setup.py --gpu
        if ($LASTEXITCODE -eq 2) {
            Write-Output "Repairing the installed CUDA wheels and checking them again."
            & $venvPython -m pip install --only-binary=:all: --force-reinstall -r requirements-gpu.txt
            if ($LASTEXITCODE -ne 0) { throw "CUDA wheel repair failed. Restore access to the wheel source and run $retry." }
            & $venvPython -B scripts/check_windows_setup.py --gpu
        }
        if ($LASTEXITCODE -ne 0) { exit 1 }
        [IO.File]::WriteAllText($gpuMarker, "verified")
    } elseif (Test-Path -LiteralPath $gpuMarker) {
        Remove-Item -LiteralPath $gpuMarker
    }
    Write-Output "Close any running dashboard, then run .\OpenDashboard.cmd to open this profile."
} finally {
    Pop-Location
}
