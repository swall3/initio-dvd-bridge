#requires -Version 5.1
#requires -RunAsAdministrator
<#
One-time installation of the current user's exact-device DVD watcher.
No running DVD is stopped. No device, service, network, or USB setting changes.
Task schema: https://learn.microsoft.com/windows/win32/taskschd/task-scheduler-schema
Registration: https://learn.microsoft.com/powershell/module/scheduledtasks/register-scheduledtask
#>
[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidateSet('Enable','Disable')][string]$Action)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$Out = Join-Path $Root 'outputs\initio'
$Report = Join-Path $Out 'dvd-autostart-install.json'
$StopRequest = Join-Path $Out 'dvd-autostart-stop.request'
$TaskName = 'Initio DVD Bridge Autostart'
$TaskPath = '\'
$Python = (Join-Path $Root 'runtime\pythonw.exe')
$Watcher = Join-Path $PSScriptRoot 'dvd_autostart.py'
$Arguments = '"' + $Watcher + '"'
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Sid = $Identity.User.Value
$Description = 'Codex exact Initio DVD arrival watcher v1; workspace=' + $Root
$Utf8 = New-Object Text.UTF8Encoding($false)

function Write-Result([string]$Status, [string]$Message) {
    $record = [ordered]@{ status=$Status; action=$Action; time=[DateTime]::UtcNow.ToString('o');
        task_name=$TaskName; task_path=$TaskPath; user=$Identity.Name; user_sid=$Sid;
        executable=$Python; arguments=$Arguments; working_directory=$Root; message=$Message }
    [IO.File]::WriteAllText($Report, ($record | ConvertTo-Json -Depth 5), $Utf8)
    $record | ConvertTo-Json -Depth 5
}
function Assert-OwnedTask($Task) {
    if ($Task.TaskName -cne $TaskName -or $Task.TaskPath -cne $TaskPath -or
        $Task.Description -cne $Description) { throw 'The existing task is not this workspace''s DVD task.' }
    $actions = @($Task.Actions)
    if ($actions.Count -ne 1 -or $actions[0].Execute -ine $Python -or
        $actions[0].Arguments -cne $Arguments -or $actions[0].WorkingDirectory -ine $Root) {
        throw 'The existing task action differs; no task was changed.'
    }
    $registeredSid = [string]$Task.Principal.UserId
    if ($registeredSid -notmatch '^S-1-') {
        $account = New-Object Security.Principal.NTAccount($registeredSid)
        $registeredSid = $account.Translate([Security.Principal.SecurityIdentifier]).Value
    }
    if ($registeredSid -cne $Sid -or [string]$Task.Principal.LogonType -cne 'Interactive' -or
        [string]$Task.Principal.RunLevel -cne 'Highest') {
        throw 'The existing task principal differs; no task was changed.'
    }
}
function Escape-Xml([string]$Value) { return [Security.SecurityElement]::Escape($Value) }

try {
    if (-not (Test-Path -LiteralPath $Out -PathType Container)) { throw 'Workspace output directory is absent.' }
    Import-Module ScheduledTasks -ErrorAction Stop
    # Scheduler names are case-insensitive. Detect case-only foreign collisions
    # too; Assert-OwnedTask then requires our exact registered spelling.
    $existing = @(Get-ScheduledTask -TaskPath $TaskPath -ErrorAction Stop | Where-Object { $_.TaskName -eq $TaskName })
    if ($existing.Count -gt 1) { throw 'Ambiguous scheduled task identity.' }
    if ($existing.Count -eq 1) { Assert-OwnedTask $existing[0] }
    if ($Action -eq 'Disable') {
        if ($existing.Count -eq 1) {
            Disable-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop | Out-Null
        }
        # Cooperatively exit only the watcher. The active DVD runtime is left alone.
        [IO.File]::WriteAllText($StopRequest, [DateTime]::UtcNow.ToString('o'), $Utf8)
        if ($existing.Count -eq 1) {
            Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false -ErrorAction Stop
        }
        Write-Result 'disabled' 'Autostart removed; watcher exit requested. Any playing DVD remains running.'
        exit 0
    }
    if (-not (Test-Path -LiteralPath $Python -PathType Leaf) -or
        -not (Test-Path -LiteralPath $Watcher -PathType Leaf)) { throw 'Python or the DVD watcher is absent.' }
    # Registration can update this exact owned task, but never terminates an instance.
    $xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>$(Escape-Xml $Identity.Name)</Author><Description>$(Escape-Xml $Description)</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>$Sid</UserId><Delay>PT10S</Delay></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>$Sid</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>false</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>7</Priority>
  </Settings>
  <Actions Context="Author"><Exec><Command>$(Escape-Xml $Python)</Command><Arguments>$(Escape-Xml $Arguments)</Arguments><WorkingDirectory>$(Escape-Xml $Root)</WorkingDirectory></Exec></Actions>
</Task>
"@
    Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Xml $xml -Force -ErrorAction Stop | Out-Null
    $registered = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop
    Assert-OwnedTask $registered
    if (Test-Path -LiteralPath $StopRequest) { Remove-Item -LiteralPath $StopRequest -ErrorAction Stop }
    Start-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop
    Write-Result 'enabled' 'Autostart registered for this user and watcher start requested. Existing playback is untouched.'
} catch {
    Write-Result 'error' ([string]$_)
    throw
}
