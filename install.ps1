# Installer of DigitalCertiAnalytics for Windows (Windows PowerShell 5.1 or newer). No administrator rights needed.
#
# Easiest: double-click install.bat in the project folder.
# Without a copy of the project, paste this line in PowerShell (it downloads the project into
# %USERPROFILE%\DigitalCertiAnalytics first; run inside a copy of the project, it updates that copy):
#   powershell -ExecutionPolicy Bypass -c "irm https://raw.githubusercontent.com/MagliariElio/DigitalCertiAnalytics/main/install.ps1 | iex"
# (-ExecutionPolicy Bypass holds for that command only. The short form "irm ... | iex" works where PowerShell already
# allows scripts.)
#
# Everything is installed inside the project folder (.tools, .venv): nothing is changed elsewhere on the
# computer. To uninstall, delete the folder. Running it again is safe: it repairs what is broken and skips what is
# already installed.
#
# Options (install.bat passes them on):
#   --check            only show the status of every component
#   --only zlint       install only these components (zlint, log_list)
#   --skip zlint       leave out these components (e.g. when DCA_ZLINT_PATH names your own ZLint)
#   --force            reinstall ZLint even if it is already installed (the CT log list is kept)
#
# Advanced environment variables:
#   DCA_INSTALL_DIR    where "irm | iex" puts the project (default: %USERPROFILE%\DigitalCertiAnalytics)
#   DCA_ARCHIVE_URL    the project archive "irm | iex" downloads (default: the main branch on GitHub)
#   DCA_KEEP_UV=1      keep uv in .tools\uv after the installation (for developers who install more packages)
#
# This file must stay pure ASCII: Windows PowerShell 5.1 reads files without a BOM in the local code page.
# Under "irm | iex" there is no script file and "exit" would close the window, so everything is in functions.

$DcaScriptDir = $PSScriptRoot

function Write-DcaStep([string]$Text) { Write-Host ""; Write-Host "==> $Text" -ForegroundColor White }
function Write-DcaOk([string]$Text) { Write-Host "    [ OK ] " -ForegroundColor Green -NoNewline; Write-Host $Text }
function Write-DcaInfo([string]$Text) { Write-Host "           $Text" }
function Write-DcaWarn([string]$Text, [string]$Hint) {
    Write-Host "    [WARN] " -ForegroundColor Yellow -NoNewline; Write-Host $Text
    if ($Hint) { Write-Host "           What to do: $Hint" }
}

# Stops the installation with a message that says what to do
function Stop-Dca([string]$Text, [string]$Hint) {
    if ($Hint) { throw "$Text`n           What to do: $Hint" }
    throw $Text
}

function Test-DcaProject([string]$Dir) {
    if (-not $Dir) { return $false }
    foreach ($file in @('requirements.txt', 'src\analysis\main.py', 'scripts\install_tools.py')) {
        if (-not (Test-Path -LiteralPath (Join-Path $Dir $file) -PathType Leaf)) { return $false }
    }
    return $true
}

function Get-DcaArchitecture {
    $arch = $null
    try { $arch = [string][System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture } catch { $arch = $null }
    if (-not $arch) {
        $arch = $env:PROCESSOR_ARCHITEW6432
        if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
    }
    switch -Regex ($arch) {
        '^(X64|AMD64)$' { return 'x86_64' }
        '^ARM64$' { return 'aarch64' }
        default { return $null }
    }
}

# Not Get-FileHash: it is a script function of PowerShell 5.1, which is not loaded where scripts are not allowed
function Get-DcaSha256([string]$Path) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $stream = [System.IO.File]::OpenRead($Path)
    try { return (-join ($sha.ComputeHash($stream) | ForEach-Object { $_.ToString('x2') })) }
    finally { $stream.Dispose(); $sha.Dispose() }
}

function Save-DcaDownload([string]$Url, [string]$OutFile) {
    if ($Url -match '^file:///?(.+)$') {
        Copy-Item -LiteralPath ([Uri]$Url).LocalPath -Destination $OutFile -Force -ErrorAction Stop
        return
    }
    $request = @{ Uri = $Url; OutFile = $OutFile; UseBasicParsing = $true; ErrorAction = 'Stop' }
    if ($env:HTTPS_PROXY) {
        # Without it, PowerShell 5.1 uses only the proxy of the Windows settings
        $request['Proxy'] = $env:HTTPS_PROXY
        $request['ProxyUseDefaultCredentials'] = $true
    }
    $lastError = ''
    for ($attempt = 1; $attempt -le 4; $attempt++) {
        try {
            Invoke-WebRequest @request
            return
        } catch {
            $lastError = $_.Exception.Message
            if ($attempt -lt 4) { Start-Sleep -Seconds (3 * $attempt) }
        }
    }
    Stop-Dca "Could not download $Url ($lastError)." `
        'Check your internet connection (and the proxy settings of Windows), then run the installer again.'
}

function Expand-DcaZip([string]$Zip, [string]$Destination) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($Zip, $Destination)
}

# Download the newest version of the project for "irm | iex" into $Target (by default DCA_INSTALL_DIR, else
# %USERPROFILE%\DigitalCertiAnalytics); returns the project folder
function Get-DcaProject([string]$Target) {
    # PowerShell variable names ignore case: $target is the parameter
    if (-not $target) { $target = $env:DCA_INSTALL_DIR }
    if (-not $target) { $target = Join-Path $env:USERPROFILE 'DigitalCertiAnalytics' }
    $url = $env:DCA_ARCHIVE_URL
    if (-not $url) { $url = 'https://github.com/MagliariElio/DigitalCertiAnalytics/archive/refs/heads/main.zip' }
    if ((Test-Path -LiteralPath $target) -and -not (Test-DcaProject $target)) {
        if (@(Get-ChildItem -LiteralPath $target -Force -ErrorAction SilentlyContinue).Count -gt 0) {
            Stop-Dca "The folder $target already exists and does not contain DigitalCertiAnalytics." `
                'Rename or move that folder, or choose another one by setting DCA_INSTALL_DIR, then run the command again.'
        }
    }
    if (Test-Path -LiteralPath (Join-Path $target '.git')) {
        Write-DcaInfo "Found a git copy of the project in $target`: it is used as it is (update it with 'git pull')."
        return $target
    }
    Write-DcaStep "Downloading DigitalCertiAnalytics into $target"
    Write-DcaInfo 'Your data in that folder (data, res\certs_polito.json, the analysis results) is kept.'
    $work = Join-Path $target '.tools\cache\bootstrap'
    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
    New-Item -ItemType Directory -Path (Join-Path $work 'files') -Force | Out-Null
    $zip = Join-Path $work 'project.zip'
    Save-DcaDownload $url $zip
    try { Expand-DcaZip $zip (Join-Path $work 'files') } catch {
        Stop-Dca "The downloaded project archive is damaged ($($_.Exception.Message))." 'Run the command again.'
    }
    $top = Get-ChildItem -LiteralPath (Join-Path $work 'files') -Directory | Select-Object -First 1
    if (-not $top -or -not (Test-DcaProject $top.FullName)) {
        Stop-Dca 'The downloaded archive does not contain DigitalCertiAnalytics.' 'Run the command again.'
    }
    # Only the project's own files are replaced: data, .tools, .venv and res\certs_polito.json are not in the archive
    # /R:2 /W:2: a file held open by another program fails after a few seconds instead of a million retries
    & robocopy.exe $top.FullName $target /E /R:2 /W:2 /NFL /NDL /NJH /NJS /NP | Out-Null
    if ($LASTEXITCODE -ge 8) {
        Stop-Dca "Could not copy the project into $target." 'Close the programs that use files of that folder (for example the program itself, or an editor), check the free disk space and run the command again.'
    }
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    Write-DcaOk "Project downloaded into $target"
    return $target
}

# Files extracted from a downloaded ZIP carry the "Mark of the Web", which makes Windows warn before running them
function Unblock-DcaProject([string]$Project) {
    $skip = @('.venv', '.tools', 'data')
    foreach ($item in Get-ChildItem -LiteralPath $Project -Force -ErrorAction SilentlyContinue) {
        if ($skip -contains $item.Name) { continue }
        if ($item.PSIsContainer) {
            Get-ChildItem -LiteralPath $item.FullName -Recurse -File -Force -ErrorAction SilentlyContinue |
                Unblock-File -ErrorAction SilentlyContinue
        } else {
            Unblock-File -LiteralPath $item.FullName -ErrorAction SilentlyContinue
        }
    }
}

function Test-DcaLocation([string]$Project) {
    $longPaths = $null
    try {
        $longPaths = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name LongPathsEnabled `
            -ErrorAction Stop).LongPathsEnabled
    } catch { $longPaths = $null }
    if ($Project.Length -gt 80 -and $longPaths -ne 1) {
        Write-DcaWarn "The project folder has a long path ($($Project.Length) characters), and Windows limits paths to 260 characters." `
            'If the installation fails, move the project to a short path such as C:\DCA or %USERPROFILE%\DigitalCertiAnalytics.'
    }
    foreach ($cloud in @($env:OneDrive, $env:OneDriveCommercial, $env:OneDriveConsumer)) {
        if ($cloud -and $Project.StartsWith($cloud, [StringComparison]::OrdinalIgnoreCase)) {
            Write-DcaWarn 'The project is inside OneDrive, which synchronises it with the cloud.' `
                'Syncing the large databases slows everything down and can damage them: move the project to a folder outside OneDrive, such as C:\DCA.'
            break
        }
    }
    if ($Project -match '[^\x20-\x7E]') {
        Write-DcaWarn 'The project path contains letters outside the English alphabet.' `
            'If a tool fails, move the project to a simple path such as C:\DCA.'
    }
    try {
        $free = (New-Object System.IO.DriveInfo ([System.IO.Path]::GetPathRoot($Project))).AvailableFreeSpace
        if ($free -lt 2GB) {
            Write-DcaWarn ("Only {0:N1} GB of disk space are free: the installation needs about 0.5 GB (1.5 GB while ZLint is built from its source code)." -f ($free / 1GB)) `
                'Free some disk space if the installation fails.'
        }
    } catch { }
}

function Test-DcaUv([string]$Path, [string]$Version) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    try { $reported = (& $Path --version 2>$null) | Select-Object -First 1 } catch { return $false }
    return ($LASTEXITCODE -eq 0 -and "$reported" -match ('^uv ' + [regex]::Escape($Version) + '( |$)'))
}

function Install-DcaUv([string]$Project, [string]$Arch, [string]$Version) {
    Write-DcaStep "uv $Version (installs Python and the Python packages)"
    $uvDir = Join-Path $Project '.tools\uv'
    $uv = Join-Path $uvDir 'uv.exe'
    if (Test-DcaUv $uv $Version) { Write-DcaOk "uv $Version is already installed"; return $uv }
    $systemUv = Get-Command uv.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($systemUv -and (Test-DcaUv $systemUv.Source $Version)) {
        Write-DcaOk "Using uv $Version already installed in $($systemUv.Source)"
        return $systemUv.Source
    }
    $hashes = @{
        'x86_64' = @('uv-x86_64-pc-windows-msvc.zip', '7c38608c8a18ee137d748a1773053b07ec8f3a30fab49aebaa6f4e4efeceb019')
        'aarch64' = @('uv-aarch64-pc-windows-msvc.zip', '4b783bda5cc44bbae0651a837223873a7acee31152381aef5fc86ef6bef25997')
    }
    $file = $hashes[$Arch][0]
    $expected = $hashes[$Arch][1]
    $work = Join-Path $Project '.tools\cache\uv-download'
    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
    New-Item -ItemType Directory -Path $work -Force | Out-Null
    $zip = Join-Path $work $file
    $downloaded = $false
    foreach ($mirror in @('https://releases.astral.sh/github/uv/releases/download', 'https://github.com/astral-sh/uv/releases/download')) {
        Write-DcaInfo "Downloading $file (about 17 MB) from $(([Uri]$mirror).Host)..."
        try { Save-DcaDownload "$mirror/$Version/$file" $zip } catch { Write-DcaWarn $_.Exception.Message; continue }
        if ((Get-DcaSha256 $zip) -eq $expected) { $downloaded = $true; break }
        Write-DcaWarn "The file downloaded from $mirror does not match its expected SHA-256 checksum, so it was deleted."
        Remove-Item -LiteralPath $zip -Force
    }
    if (-not $downloaded) {
        Stop-Dca "Could not download uv $Version." 'Check your internet connection (and the proxy settings of Windows), then run the installer again.'
    }
    Expand-DcaZip $zip $work
    New-Item -ItemType Directory -Path $uvDir -Force | Out-Null
    foreach ($exe in @('uv.exe', 'uvx.exe', 'uvw.exe')) {
        $source = Join-Path $work $exe
        if (Test-Path -LiteralPath $source) { Move-Item -LiteralPath $source -Destination (Join-Path $uvDir $exe) -Force }
    }
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    if (-not (Test-DcaUv $uv $Version)) {
        Stop-Dca "uv was downloaded but cannot run ($uv)." 'An antivirus may have blocked it: allow it, or move the project to another folder, then run the installer again.'
    }
    Write-DcaOk "uv $Version installed in .tools\uv"
    return $uv
}

# Environment variables that keep uv, Python and the temporary files inside the project; the old values are returned
# so that they can be restored (under "irm | iex" this is the user's own PowerShell session)
function Set-DcaEnvironment([string]$Project) {
    $values = @{
        'UV_PYTHON_INSTALL_DIR' = (Join-Path $Project '.tools\python')
        'UV_CACHE_DIR' = (Join-Path $Project '.tools\cache\uv')
        'PYTHONPYCACHEPREFIX' = (Join-Path $Project '.tools\cache\pycache')
        'UV_PYTHON_INSTALL_BIN' = '0'
        'UV_PYTHON_INSTALL_REGISTRY' = '0'
        'UV_NO_CONFIG' = '1'
        'UV_MANAGED_PYTHON' = '1'
        'UV_PYTHON_DOWNLOADS' = 'automatic'
        'TEMP' = (Join-Path $Project '.tools\cache\tmp')
        'TMP' = (Join-Path $Project '.tools\cache\tmp')
        'PYTHONUTF8' = '1'
        'PYTHONHOME' = $null
        'PYTHONPATH' = $null
        'VIRTUAL_ENV' = $null
        'CONDA_PREFIX' = $null
        'UV_PYTHON' = $null
        'UV_SYSTEM_PYTHON' = $null
    }
    if (-not $env:UV_HTTP_TIMEOUT) { $values['UV_HTTP_TIMEOUT'] = '300' }
    $saved = @{}
    foreach ($name in $values.Keys) {
        $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
        [Environment]::SetEnvironmentVariable($name, $values[$name], 'Process')
    }
    New-Item -ItemType Directory -Path (Join-Path $Project '.tools\cache\tmp') -Force | Out-Null
    return $saved
}

function Restore-DcaEnvironment($Saved) {
    if (-not $Saved) { return }
    foreach ($name in $Saved.Keys) { [Environment]::SetEnvironmentVariable($name, $Saved[$name], 'Process') }
}

# The .venv works and uses the project's own Python 3.12 (it breaks when the project folder is moved)
function Test-DcaVenv([string]$Project) {
    $python = Join-Path $Project '.venv\Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $python -PathType Leaf)) { return $false }
    $code = 'import os, sys; root = os.path.normcase(os.path.realpath(sys.argv[1])) + os.sep; ' +
            'base = os.path.normcase(os.path.realpath(sys.base_prefix)); ' +
            'sys.exit(0 if sys.version_info[:2] == (3, 12) and base.startswith(root) else 1)'
    try { & $python -c $code (Join-Path $Project '.tools\python') 2>$null | Out-Null } catch { return $false }
    return ($LASTEXITCODE -eq 0)
}

# Not called for its value: the output of uv goes straight to the console
function Install-DcaPython([string]$Project, [string]$Uv, [string]$PythonRequest, [string]$ExcludeNewer) {
    Write-DcaStep 'Python 3.12 and the Python packages'
    & $Uv python install $PythonRequest
    if ($LASTEXITCODE -ne 0) { Stop-Dca 'Could not install Python 3.12.' 'Check your internet connection and run the installer again.' }
    $venv = Join-Path $Project '.venv'
    if (Test-DcaVenv $Project) {
        Write-DcaOk 'The project environment .venv is ready'
    } else {
        if (Test-Path -LiteralPath $venv) { Write-DcaInfo 'The project environment .venv is outdated or was moved: it is recreated.' }
        # Quiet: its "Activate with: .venv\Scripts\activate" is not needed, the dca.bat launcher does that
        & $Uv venv --quiet --clear --python $PythonRequest --prompt DigitalCertiAnalytics $venv
        if ($LASTEXITCODE -ne 0) {
            Stop-Dca "Could not create the project environment in $venv." 'An antivirus may have blocked it, or the path is too long: try a short folder such as C:\DCA.'
        }
        Write-DcaOk 'Project environment created in .venv'
    }
    $python = Join-Path $venv 'Scripts\python.exe'
    & $Uv pip install --python $python -r (Join-Path $Project 'requirements.txt') --only-binary ':all:' --no-binary sslyze `
        --exclude-newer $ExcludeNewer
    if ($LASTEXITCODE -ne 0) {
        Stop-Dca 'Could not install the Python packages.' 'If the messages above are about the network, check your internet connection (behind a proxy, set HTTPS_PROXY), then run the installer again.'
    }
    Write-DcaOk 'Python packages installed'
    # The downloaded packages are no longer needed: the .venv has its own copy of every file (about 150 MB)
    $cleaned = $false
    try { & $Uv cache clean --quiet 2>$null | Out-Null; $cleaned = ($LASTEXITCODE -eq 0) } catch { $cleaned = $false }
    if (-not $cleaned) { Remove-Item -LiteralPath $env:UV_CACHE_DIR -Recurse -Force -ErrorAction SilentlyContinue }
}

# uv is needed only while installing: the bundled one is removed (it is downloaded again, checked, when the installer
# runs again), unless DCA_KEEP_UV=1. A uv found on the computer is left alone.
function Remove-DcaBundledUv([string]$Project, [string]$Uv) {
    $bundled = Join-Path $Project '.tools\uv\uv.exe'
    if ($Uv -ne $bundled -or $env:DCA_KEEP_UV -eq '1') { return }
    Remove-Item -LiteralPath (Join-Path $Project '.tools\uv') -Recurse -Force -ErrorAction SilentlyContinue
}

# Runs the installation and sets $script:DcaExitCode. It is not called for a value, so that the programs it runs
# (uv, Python) write straight to the console, with their colors and progress bars.
function Invoke-DcaInstall([string[]]$Arguments, [string]$ScriptDir) {
    $UvVersion = '0.12.24'
    $ExcludeNewer = '2026-10-01T00:00:00Z'  # Newest upload date of the Python packages: same versions everywhere
    $ProgressPreference = 'SilentlyContinue'  # The progress bar makes downloads many times slower in PowerShell 5.1
    $script:DcaExitCode = 1
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        [Net.WebRequest]::DefaultWebProxy.Credentials = [Net.CredentialCache]::DefaultNetworkCredentials
    } catch { }
    if (-not $Arguments) { $Arguments = @() }
    if ($Arguments -contains '--help' -or $Arguments -contains '-h') {
        Write-Host 'Usage: install.bat [--check] [--only zlint,log_list] [--skip zlint] [--force]'
        $script:DcaExitCode = 0
        return
    }
    $saved = $null
    $project = $null
    try {
        $arch = Get-DcaArchitecture
        if (-not $arch) { Stop-Dca 'This is a 32-bit Windows, which is not supported.' 'A 64-bit Windows 10 or 11 is needed.' }
        $build = [Environment]::OSVersion.Version.Build
        $pythonRequest = '3.12'
        if ($arch -eq 'aarch64') {
            # Some Python packages (sslyze's nassl) have no ARM build: the x64 ones run emulated on Windows 11
            if ($build -lt 22000) { Stop-Dca 'Windows 10 on ARM cannot run the programs this project needs.' 'Windows 11 is needed on ARM computers.' }
            $pythonRequest = 'cpython-3.12-windows-x86_64-none'
        }

        $here = (Get-Location).ProviderPath
        if (Test-DcaProject $ScriptDir) { $project = (Resolve-Path -LiteralPath $ScriptDir).Path }
        elseif ($ScriptDir -and (Test-DcaProject $here)) { $project = $here }
        elseif ((-not $env:DCA_INSTALL_DIR) -and (Test-DcaProject $here)) {
            # "irm | iex" (no script folder) inside a copy of the project updates that copy
            $project = Get-DcaProject $here
        }
        else { $project = Get-DcaProject '' }
        Unblock-DcaProject $project

        $python = Join-Path $project '.venv\Scripts\python.exe'
        $tools = Join-Path $project 'scripts\install_tools.py'
        if ($Arguments -contains '--check') {
            $saved = Set-DcaEnvironment $project
            if (Test-DcaVenv $project) {
                & $python $tools @Arguments
                $script:DcaExitCode = $LASTEXITCODE
            } else {
                Write-Host '    [FAIL] ' -ForegroundColor Red -NoNewline
                Write-Host "DigitalCertiAnalytics is not installed in $project (or the folder was moved)."
                Write-DcaInfo 'What to do: run install.bat in the project folder.'
            }
            return
        }

        Write-Host 'DigitalCertiAnalytics installer' -ForegroundColor White
        Write-Host "Everything is installed inside $project"
        Write-Host '(no administrator rights needed; to uninstall, delete the folder).'
        Test-DcaLocation $project
        $uv = Install-DcaUv $project $arch $UvVersion
        $saved = Set-DcaEnvironment $project
        Install-DcaPython $project $uv $pythonRequest $ExcludeNewer
        $env:DCA_UV_VERSION = "$((& $uv --version) | Select-Object -First 1)"
        # Tells install_tools.py that .tools\uv is removed afterwards, so that the size it shows leaves it out
        if ($uv -eq (Join-Path $project '.tools\uv\uv.exe') -and $env:DCA_KEEP_UV -ne '1') { $env:DCA_UV_TEMPORARY = '1' }
        & $python $tools @Arguments
        $script:DcaExitCode = $LASTEXITCODE
        if ($script:DcaExitCode -eq 0) { Remove-DcaBundledUv $project $uv }
    } catch {
        Write-Host ''
        Write-Host '    [FAIL] ' -ForegroundColor Red -NoNewline
        Write-Host $_.Exception.Message
        $script:DcaExitCode = 1
    } finally {
        # The temporary files of this run (TEMP and TMP point there); --check leaves nothing behind either
        if ($project) {
            Remove-Item -LiteralPath (Join-Path $project '.tools\cache\tmp') -Recurse -Force -ErrorAction SilentlyContinue
        }
        Restore-DcaEnvironment $saved
        Remove-Item Env:DCA_UV_VERSION -ErrorAction SilentlyContinue
        Remove-Item Env:DCA_UV_TEMPORARY -ErrorAction SilentlyContinue
    }
}

$DcaExitCode = 1
Invoke-DcaInstall -Arguments $args -ScriptDir $DcaScriptDir
if ($PSCommandPath) { exit $DcaExitCode }
