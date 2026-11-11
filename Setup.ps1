#requires -Version 5.1
[CmdletBinding()]
param([ValidateSet('Install','Uninstall','Verify')][string]$Action='Install')
$ErrorActionPreference='Stop'
$Root=[IO.Path]::GetFullPath($PSScriptRoot)
$Target=[IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'Programs\InitioDvdBridge'))
$Marker='initio-dvd-bridge/0.1.0-alpha.2'
$Reg='HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\InitioDvdBridge'
$Links=Join-Path ([Environment]::GetFolderPath('Programs')) 'Initio DVD Bridge'
function Assert-NoRuntime {
    foreach ($name in @('Local\CodexInitioDvdRuntime','Local\CodexInitioDvdReader')) {
        try { $m=[Threading.Mutex]::OpenExisting($name); $m.Dispose(); throw 'Close VLC, Stop the DVD utility, and wait for cleanup before installing or removing.' }
        catch [Threading.WaitHandleCannotBeOpenedException] { }
    }
}
function Read-Manifest([string]$Directory) {
    $m=Get-Content -LiteralPath (Join-Path $Directory 'install-manifest.json') -Raw | ConvertFrom-Json
    if ($m.product -cne $Marker) { throw 'Installer manifest identity mismatch.' }
    foreach ($entry in $m.files) {
        $path=[IO.Path]::GetFullPath((Join-Path $Directory $entry.path))
        if (-not $path.StartsWith($Directory.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Manifest path escapes the installation.' }
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ine $entry.sha256) { throw ('Package file changed: '+$entry.path) }
    }
    return $m
}
if ($Action -eq 'Verify') {
    $m=Read-Manifest $Root
    Write-Output ('Verified '+$m.files.Count+' package files; no installation or device access performed.')
    exit 0
}
$id=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=New-Object Security.Principal.WindowsPrincipal($id)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Encode the fixed action/path, preserving spaces without shell interpolation.
    $script="& '"+$PSCommandPath.Replace("'","''")+"' -Action '"+$Action+"'"
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
    $p=Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Verb RunAs -WindowStyle Hidden -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand',$encoded) -PassThru -Wait
    exit $p.ExitCode
}
try {
    Assert-NoRuntime
    if ($Action -eq 'Install') {
        try { $watcher=[Threading.Mutex]::OpenExisting('Local\CodexInitioDvdAutostart'); $watcher.Dispose(); throw 'Disable the existing DVD autostart watcher before installing this separate package.' }
        catch [Threading.WaitHandleCannotBeOpenedException] { }
        $m=Read-Manifest $Root
        if (Test-Path -LiteralPath $Target) { throw 'An installation already exists. Uninstall it before installing this experimental version.' }
        if (-not [Environment]::Is64BitOperatingSystem) { throw 'Windows x64 is required.' }
        New-Item -ItemType Directory -Path $Target | Out-Null
        foreach ($entry in $m.files) {
            $dest=Join-Path $Target $entry.path
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dest) | Out-Null
            Copy-Item -LiteralPath (Join-Path $Root $entry.path) -Destination $dest
        }
        Copy-Item -LiteralPath (Join-Path $Root 'install-manifest.json') -Destination $Target
        New-Item -ItemType Directory -Force -Path (Join-Path $Target 'outputs\initio') | Out-Null
        New-Item -ItemType Directory -Force -Path $Links | Out-Null
        $shell=New-Object -ComObject WScript.Shell
        foreach ($name in @('DVD Controls','Start DVD','Stop DVD','Enable Autostart','Disable Autostart','Uninstall')) {
            $link=$shell.CreateShortcut((Join-Path $Links ($name+'.lnk')))
            $link.TargetPath=Join-Path $Target ($name+'.cmd'); $link.WorkingDirectory=$Target; $link.Save()
        }
        New-Item -Path $Reg -Force | Out-Null
        New-ItemProperty -Path $Reg -Name DisplayName -Value 'Initio DVD Bridge (experimental)' -Force | Out-Null
        New-ItemProperty -Path $Reg -Name DisplayVersion -Value '0.1.0-alpha.2' -Force | Out-Null
        New-ItemProperty -Path $Reg -Name InstallLocation -Value $Target -Force | Out-Null
        New-ItemProperty -Path $Reg -Name UninstallString -Value ('"'+(Join-Path $Target 'Uninstall.cmd')+'"') -Force | Out-Null
        & (Join-Path $Target 'work\initio\manage_dvd_autostart.ps1') -Action Enable
        $run='HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
        New-Item -Path $run -Force | Out-Null
        $trayCommand='"'+(Join-Path $Target 'DVD Controls.exe')+'" --hidden'
        New-ItemProperty -Path $run -Name InitioDvdBridgeTray -Value $trayCommand -Force | Out-Null
        Write-Output 'Installed. Autostart is enabled for the signed-in user.'
    } else {
        if ($Root -ine $Target) { throw 'Run Uninstall from the installed copy.' }
        $m=Read-Manifest $Root
        [IO.File]::WriteAllText((Join-Path $Root 'outputs\initio\tray-exit.request'),'Uninstall requested')
        $trayDeadline=[DateTime]::UtcNow.AddSeconds(10)
        do {
            $trayRunning=$false
            try { $tm=[Threading.Mutex]::OpenExisting('Local\InitioDvdBridgeTray');$tm.Dispose();$trayRunning=$true }
            catch [Threading.WaitHandleCannotBeOpenedException] { }
            if($trayRunning){Start-Sleep -Milliseconds 250}
        } while($trayRunning -and [DateTime]::UtcNow -lt $trayDeadline)
        if($trayRunning){throw 'Close DVD Controls before uninstalling. No application files were removed.'}
        & (Join-Path $Root 'work\initio\manage_dvd_autostart.ps1') -Action Disable
        $deadline=[DateTime]::UtcNow.AddSeconds(10)
        do {
            $watching=$false
            try { $mx=[Threading.Mutex]::OpenExisting('Local\CodexInitioDvdAutostart'); $mx.Dispose(); $watching=$true }
            catch [Threading.WaitHandleCannotBeOpenedException] { }
            if ($watching) { Start-Sleep -Milliseconds 250 }
        } while ($watching -and [DateTime]::UtcNow -lt $deadline)
        if ($watching) { throw 'Watcher has not exited. Files retained; retry removal after it exits.' }
        Assert-NoRuntime
        # Remove only verified manifest files. Keep logs, unknown files, and folders.
        foreach ($entry in $m.files) { Remove-Item -LiteralPath (Join-Path $Root $entry.path) -ErrorAction Stop }
        Remove-Item -LiteralPath (Join-Path $Root 'install-manifest.json')
        foreach ($name in @('DVD Controls','Start DVD','Stop DVD','Enable Autostart','Disable Autostart','Uninstall')) {
            $link=Join-Path $Links ($name+'.lnk')
            if (Test-Path -LiteralPath $link) { Remove-Item -LiteralPath $link }
        }
        if ((Get-ItemProperty -Path $Reg).InstallLocation -ieq $Target) { Remove-Item -LiteralPath $Reg }
        $run='HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
        $entry=(Get-ItemProperty -Path $run -Name InitioDvdBridgeTray -ErrorAction SilentlyContinue).InitioDvdBridgeTray
        if($entry -and $entry.Contains((Join-Path $Target 'DVD Controls.exe'))){Remove-ItemProperty -Path $run -Name InitioDvdBridgeTray}
        Write-Output 'Removed application and startup task. Diagnostic logs and empty folders are retained.'
    }
} catch {
    $message=[string]$_
    [IO.File]::WriteAllText((Join-Path $env:TEMP 'InitioDvdBridge-setup-error.txt'),$message)
    Add-Type -AssemblyName System.Windows.Forms
    [Windows.Forms.MessageBox]::Show($message,'Initio DVD Bridge setup') | Out-Null
    exit 1
}
