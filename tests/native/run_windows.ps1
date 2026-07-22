param(
    [string]$ServerHost = "127.0.0.1",
    [string]$ListenAddress = "127.0.0.1:0",
    [string]$PortmapperAddress = "127.0.0.1:111",
    [string]$Drive = "Z:"
)

$ErrorActionPreference = "Stop"
$repository = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$client = Join-Path $PSScriptRoot "client_windows.ps1"
$probe = Join-Path $PSScriptRoot "procedure_probe.py"

function Wait-Ready([string]$ReadyFile, [System.Diagnostics.Process]$Process) {
    $deadline = [DateTime]::UtcNow.AddMinutes(10)
    while ([DateTime]::UtcNow -lt $deadline) {
        if (Test-Path -LiteralPath $ReadyFile) {
            $value = (Get-Content -LiteralPath $ReadyFile -Raw).Trim()
            if ($value) {
                return [int]$value
            }
        }
        if ($Process.HasExited) {
            throw "certification server exited before becoming ready (exit $($Process.ExitCode))"
        }
        Start-Sleep -Milliseconds 100
    }
    throw "timed out waiting for certification server readiness"
}

function Stop-CertificationServer([System.Diagnostics.Process]$Process, [string]$ShutdownFile, [string]$LogFile) {
    New-Item -ItemType File -Path $ShutdownFile -Force | Out-Null
    if (-not $Process.WaitForExit(30000)) {
        $Process.Kill()
        throw "certification server did not stop within 30 seconds"
    }
    $Process.WaitForExit()
    $Process.Refresh()
    if (-not $Process.HasExited) {
        throw "certification server exit state is unavailable"
    }
    $exitCode = $Process.ExitCode
    if ($null -eq $exitCode) {
        Get-Content -LiteralPath $LogFile -ErrorAction SilentlyContinue | Write-Error
        throw "certification server exit code is unavailable"
    }
    if ($exitCode -ne 0) {
        Get-Content -LiteralPath $LogFile -ErrorAction SilentlyContinue | Write-Error
        throw "certification server exited with code $exitCode"
    }
}

function Reset-NfsClient {
    & "$env:SystemRoot\System32\nfsadmin.exe" client stop | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "failed to stop Client for NFS"
    }
    & "$env:SystemRoot\System32\nfsadmin.exe" client start | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "failed to start Client for NFS"
    }
}

function Ensure-TcpNfsClient {
    $clientService = Get-Service -Name "NfsClnt" -ErrorAction Stop
    $redirectorService = Get-Service -Name "NfsRdr" -ErrorAction Stop
    if ($clientService.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
        & "$env:SystemRoot\System32\nfsadmin.exe" client stop | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "failed to stop Client for NFS before setting TCP transport"
        }
        $clientService.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
        $redirectorService.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
    } elseif ($redirectorService.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
        & "$env:SystemRoot\System32\sc.exe" stop "NfsRdr" | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "failed to stop the Client for NFS redirector before setting TCP transport"
        }
        $redirectorService.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
    }

    $configurationPath = "HKLM:\SOFTWARE\Microsoft\ClientForNFS\CurrentVersion\Default"
    $tcpOnlyProtocols = 0x455455
    Set-ItemProperty -LiteralPath $configurationPath -Name "Protocols" -Type DWord -Value $tcpOnlyProtocols -ErrorAction Stop
    $configuredProtocols = Get-ItemPropertyValue -LiteralPath $configurationPath -Name "Protocols" -ErrorAction Stop
    if ($configuredProtocols -ne $tcpOnlyProtocols) {
        throw "failed to configure Client for NFS for TCP transport"
    }

    & "$env:SystemRoot\System32\nfsadmin.exe" client start | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "failed to start Client for NFS after setting TCP transport"
    }
    $clientService.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
    $redirectorService.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
}

function Run-Profile([string]$Profile, [string]$ClientProfile) {
    $state = Join-Path $env:TEMP ("nfsserve-windows-" + [Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $state | Out-Null
    $ready = Join-Path $state "ready"
    $shutdown = Join-Path $state "shutdown"
    $restart = Join-Path $state "restart"
    $stdout = Join-Path $state "server.stdout.log"
    $stderr = Join-Path $state "server.stderr.log"
    $backendRoot = Join-Path $state "mirror-root"
    if ($Profile -eq "mirror") {
        New-Item -ItemType Directory -Path $backendRoot | Out-Null
        [System.IO.File]::WriteAllText((Join-Path $backendRoot "HostMiXeD.txt"), "host-case-preserved")
    }
    $cargo = (Get-Command cargo.exe -ErrorAction Stop).Source
    $arguments = @(
        "run", "--quiet", "--example", "certification_server", "--",
        $ListenAddress, $ready, $shutdown, $Profile, $restart, $PortmapperAddress
    )
    if ($Profile -eq "mirror") {
        $arguments += $backendRoot
    }
    $process = Start-Process -FilePath $cargo -ArgumentList $arguments -WorkingDirectory $repository -NoNewWindow -PassThru `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    # Windows PowerShell can discard the process handle for redirected child
    # processes, which leaves ExitCode unavailable after termination. Accessing
    # Handle here keeps it available for Stop-CertificationServer.
    $null = $process.Handle

    try {
        $serverPort = Wait-Ready $ready $process
        Reset-NfsClient
        & powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $client -ServerHost $ServerHost -Profile $ClientProfile -Drive $Drive
        if ($LASTEXITCODE -ne 0) {
            throw "Windows native client failed in $ClientProfile"
        }

        if ($Profile -eq "read-write") {
            & python.exe $probe $ServerHost $serverPort
            if ($LASTEXITCODE -ne 0) {
                throw "NFS procedure probe failed"
            }
            & powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $client -ServerHost $ServerHost -Profile restart-prepare -Drive $Drive
            if ($LASTEXITCODE -ne 0) {
                throw "restart preparation failed"
            }
            Remove-Item -LiteralPath $ready -Force
            New-Item -ItemType File -Path $restart -Force | Out-Null
            $null = Wait-Ready $ready $process
            Reset-NfsClient
            & powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $client -ServerHost $ServerHost -Profile restart-verify -Drive $Drive
            if ($LASTEXITCODE -ne 0) {
                throw "restart verification failed"
            }
        } elseif ($Profile -eq "read-only") {
            & python.exe $probe $ServerHost $serverPort read-only
            if ($LASTEXITCODE -ne 0) {
                throw "read-only procedure probe failed"
            }
        }

        Stop-CertificationServer $process $shutdown $stderr
    } catch {
        if (-not $process.HasExited) {
            New-Item -ItemType File -Path $shutdown -Force | Out-Null
            if (-not $process.WaitForExit(5000)) {
                $process.Kill()
            }
        }
        Write-Host "Windows native certification artifacts: $state" -ForegroundColor Yellow
        Get-Content -LiteralPath $stderr -ErrorAction SilentlyContinue
        throw
    }
    Remove-Item -LiteralPath $state -Recurse -Force
}

foreach ($command in @("mount.exe", "umount.exe", "nfsadmin.exe")) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "$command is unavailable; install the Windows Client for NFS feature"
    }
}

Ensure-TcpNfsClient
Run-Profile "read-write" "read-write"
Run-Profile "lost-reply" "lost-reply"
Run-Profile "read-only" "read-only"
Run-Profile "case-insensitive" "case-insensitive"
Run-Profile "mirror" "mirror"
Write-Host "Windows Client for NFS certification passed" -ForegroundColor Green
