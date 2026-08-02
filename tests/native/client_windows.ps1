param(
    [Parameter(Mandatory = $true)]
    [string]$ServerHost,
    [Parameter(Mandatory = $true)]
    [ValidateSet("read-write", "restart-prepare", "restart-verify", "lost-reply", "read-only", "case-insensitive", "mirror")]
    [string]$Profile,
    [string]$Drive = "Z:"
)

$ErrorActionPreference = "Stop"
$mountPath = "$Drive\"
$mounted = $false

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Invoke-Native([string]$Command, [string[]]$Arguments) {
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Command failed with exit code $LASTEXITCODE"
    }
}

function Mount-CertificationExport {
    $options = "sec=sys,nolock,mtype=soft,fileaccess=777,lang=ansi,rsize=32,wsize=32,timeout=3,retry=2"
    if ($Profile -notin @("case-insensitive", "mirror")) {
        $options += ",casesensitive"
    }
    # Windows encodes the NFS root export as an empty UNC share followed by
    # one additional separator, hence the two trailing backslashes.
    $share = "\\$ServerHost\\"
    Invoke-Native "$env:SystemRoot\System32\mount.exe" @("-o", $options, $share, $Drive)
    $script:mounted = $true
}

function Dismount-CertificationExport {
    if ($script:mounted) {
        Invoke-Native "$env:SystemRoot\System32\umount.exe" @("-f", $Drive)
        $script:mounted = $false
    }
}

try {
    Mount-CertificationExport

    switch ($Profile) {
        "read-only" {
            Assert-True (Test-Path -LiteralPath "$mountPath\file" -PathType Leaf) "read-only file is missing"
            $original = [System.IO.File]::ReadAllBytes("$mountPath\file")
            $writeFailed = $false
            try {
                [System.IO.File]::WriteAllText("$mountPath\read-only-attempt", "must-fail")
            } catch {
                $writeFailed = $true
            }
            Assert-True $writeFailed "read-only export accepted a file creation"
            Dismount-CertificationExport
            Mount-CertificationExport
            Assert-True (-not (Test-Path -LiteralPath "$mountPath\read-only-attempt")) "read-only mutation persisted"
            $after = [System.IO.File]::ReadAllBytes("$mountPath\file")
            Assert-True ([Convert]::ToBase64String($original) -eq [Convert]::ToBase64String($after)) "read-only file contents changed"
        }
        "case-insensitive" {
            Assert-True (Test-Path -LiteralPath "$mountPath\FiLe" -PathType Leaf) "case-insensitive lookup failed"
            [System.IO.File]::WriteAllText("$mountPath\MixedCase", "case-policy")
            Assert-True ([System.IO.File]::ReadAllText("$mountPath\mixedcase") -eq "case-policy") "case-folded read failed"
            Remove-Item -LiteralPath "$mountPath\MIXEDCASE" -Force
        }
        "mirror" {
            $hostEntry = Get-ChildItem -LiteralPath $mountPath -Force | Where-Object { $_.Name -ceq "HostMiXeD.txt" }
            Assert-True ($null -ne $hostEntry) "MirrorFS did not preserve an existing NTFS name"
            Assert-True ([System.IO.File]::ReadAllText("$mountPath\hostmixed.TXT") -eq "host-case-preserved") "case-folded host-file lookup failed"

            [System.IO.File]::WriteAllText("$mountPath\ClientMiXeD.txt", "client-case-preserved")
            $clientEntry = Get-ChildItem -LiteralPath $mountPath -Force | Where-Object { $_.Name -ceq "ClientMiXeD.txt" }
            Assert-True ($null -ne $clientEntry) "MirrorFS lowercased a client-created name"
            Rename-Item -LiteralPath "$mountPath\ClientMiXeD.txt" -NewName "case-rename-temporary"
            Rename-Item -LiteralPath "$mountPath\case-rename-temporary" -NewName "CLIENTmixed.Txt"
            $renamedEntry = Get-ChildItem -LiteralPath $mountPath -Force | Where-Object { $_.Name -ceq "CLIENTmixed.Txt" }
            Assert-True ($null -ne $renamedEntry) "MirrorFS did not preserve rename spelling"

            $expectedTime = [DateTime]::SpecifyKind([DateTime]"2020-01-02T03:04:06", [DateTimeKind]::Utc)
            $renamedEntry.LastWriteTimeUtc = $expectedTime
            $renamedEntry.Refresh()
            $timestampDelta = [Math]::Abs(($renamedEntry.LastWriteTimeUtc - $expectedTime).TotalSeconds)
            Assert-True ($timestampDelta -le 2) "MirrorFS did not persist the requested write timestamp"

            $renamedEntry.IsReadOnly = $true
            $renamedEntry.Refresh()
            Assert-True $renamedEntry.IsReadOnly "MirrorFS did not map a read-only mode to NTFS"
            $renamedEntry.IsReadOnly = $false

            $reservedFailed = $false
            try {
                [System.IO.File]::WriteAllText("$mountPath\CON.txt", "must-fail")
            } catch {
                $reservedFailed = $true
            }
            Assert-True $reservedFailed "MirrorFS accepted a reserved Win32 device name"

            New-Item -ItemType Directory -Path "$mountPath\non-empty" | Out-Null
            [System.IO.File]::WriteAllText("$mountPath\non-empty\child", "child")
            $notEmptyFailed = $false
            try {
                [System.IO.Directory]::Delete("$mountPath\non-empty", $false)
            } catch {
                $notEmptyFailed = $true
            }
            Assert-True $notEmptyFailed "MirrorFS removed a non-empty directory"

            foreach ($index in 0..511) {
                [System.IO.File]::WriteAllText("$mountPath\mirror-page-$index", [string]$index)
            }
            $pageCount = @(Get-ChildItem -LiteralPath $mountPath -Filter "mirror-page-*" -Force).Count
            Assert-True ($pageCount -eq 512) "MirrorFS pagination returned $pageCount of 512 entries"

            Dismount-CertificationExport
            Mount-CertificationExport
            Assert-True ([System.IO.File]::ReadAllText("$mountPath\clientmixed.txt") -eq "client-case-preserved") "MirrorFS state was lost after reconnect"

            Remove-Item -Path "$mountPath\mirror-page-*" -Force
            Remove-Item -LiteralPath "$mountPath\CLIENTmixed.Txt" -Force
            Remove-Item -LiteralPath "$mountPath\non-empty\child" -Force
            Remove-Item -LiteralPath "$mountPath\non-empty" -Force
        }
        "restart-prepare" {
            [System.IO.File]::WriteAllText("$mountPath\restart-persist", "survives-server-restart")
        }
        "restart-verify" {
            Assert-True ([System.IO.File]::ReadAllText("$mountPath\restart-persist") -eq "survives-server-restart") "restart state was lost"
            Remove-Item -LiteralPath "$mountPath\restart-persist" -Force
        }
        "lost-reply" {
            [System.IO.File]::WriteAllText("$mountPath\lost-reply-write", "windows-retransmission-survived")
            Assert-True ([System.IO.File]::ReadAllText("$mountPath\lost-reply-write") -eq "windows-retransmission-survived") "lost-reply write did not persist"
            Remove-Item -LiteralPath "$mountPath\lost-reply-write" -Force
        }
        "read-write" {
            Assert-True (Test-Path -LiteralPath "$mountPath\file" -PathType Leaf) "initial file is missing"
            Assert-True (Test-Path -LiteralPath "$mountPath\dir" -PathType Container) "initial directory is missing"
            Assert-True ((Get-Item -LiteralPath "$mountPath\file").Length -eq 2097152) "large file has the wrong size"
            $largeRead = [System.IO.File]::ReadAllBytes("$mountPath\file")
            Assert-True ($largeRead.Length -eq 2097152) "large read was truncated"

            $payload = "native-write-persisted-" + ("x" * 131072)
            [System.IO.File]::WriteAllText("$mountPath\file", $payload)
            Assert-True ([System.IO.File]::ReadAllText("$mountPath\file") -eq $payload) "stable write did not persist"
            [System.IO.File]::WriteAllText("$mountPath\new-native", "created-content")
            New-Item -ItemType Directory -Path "$mountPath\native-dir" | Out-Null
            [System.IO.File]::WriteAllText("$mountPath\native-dir\child", "nested-content")
            Rename-Item -LiteralPath "$mountPath\new-native" -NewName "renamed-native"
            Assert-True ([System.IO.File]::ReadAllText("$mountPath\renamed-native") -eq "created-content") "rename failed"

            foreach ($index in 0..511) {
                [System.IO.File]::WriteAllText("$mountPath\page-$index", [string]$index)
            }
            $pageCount = @(Get-ChildItem -LiteralPath $mountPath -Filter "page-*" -Force).Count
            Assert-True ($pageCount -eq 512) "directory pagination returned $pageCount of 512 entries"

            Dismount-CertificationExport
            Mount-CertificationExport
            Assert-True ([System.IO.File]::ReadAllText("$mountPath\file") -eq $payload) "write was lost after reconnect"
            Assert-True ([System.IO.File]::ReadAllText("$mountPath\native-dir\child") -eq "nested-content") "nested state was lost after reconnect"

            Remove-Item -Path "$mountPath\page-*" -Force
            Remove-Item -LiteralPath "$mountPath\renamed-native" -Force
            Remove-Item -LiteralPath "$mountPath\native-dir\child" -Force
            Remove-Item -LiteralPath "$mountPath\native-dir" -Force
            Remove-Item -LiteralPath "$mountPath\dir" -Force
        }
    }
} finally {
    if ($mounted) {
        & "$env:SystemRoot\System32\umount.exe" -f $Drive | Out-Null
    }
}
