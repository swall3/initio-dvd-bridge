#requires -Version 5.1
#requires -RunAsAdministrator
<#
Prepared local-only lifecycle helper. This file is NOT run by the inventory.
Default action is Inventory. Connect/Cleanup must be invoked deliberately in an
already elevated process. No self-elevation, startup-type changes, firewall,
routing, USB, controller, disk, volume, or drive-letter operations are present.

Official API references:
https://learn.microsoft.com/powershell/module/iscsi/connect-iscsitarget
https://learn.microsoft.com/powershell/module/iscsi/disconnect-iscsitarget
https://learn.microsoft.com/powershell/module/iscsi/remove-iscsitargetportal

Keep the target/backend alive until Cleanup completes. A Windows login call can
take its native timeout; do not kill the helper and assume cleanup has happened.
#>
[CmdletBinding()]
param(
    [ValidateSet('Inventory', 'Connect', 'Cleanup')][string]$Action = 'Inventory',
    [string]$PythonPath = (Join-Path $PSScriptRoot '..\..\runtime\python.exe')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$TargetHost = '127.0.0.1'
$TargetPort = 32610
$TargetIqn = 'iqn.2026-11.local.codex:initio-dvd'
$OutputRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\outputs\initio'))
$StatePath = Join-Path $OutputRoot 'iscsi-windows-session.json'
$LogPath = Join-Path $OutputRoot 'iscsi-windows-session.jsonl'
$InventoryPath = Join-Path $PSScriptRoot 'iscsi_windows_inventory.py'
$OwnedPortalPath = Join-Path $PSScriptRoot 'iscsi_owned_portal.py'
$Utf8 = New-Object Text.UTF8Encoding($false)
$script:State = $null

function Write-Log([string]$Event, $Data) {
    $record = [ordered]@{ time_utc = [DateTime]::UtcNow.ToString('o'); event = $Event; data = $Data }
    [IO.File]::AppendAllText($LogPath, (($record | ConvertTo-Json -Depth 20 -Compress) + [Environment]::NewLine), $Utf8)
}
function Save-State {
    $script:State.updated_utc = [DateTime]::UtcNow.ToString('o')
    $temp = $StatePath + '.tmp'
    [IO.File]::WriteAllText($temp, ($script:State | ConvertTo-Json -Depth 25), $Utf8)
    Move-Item -LiteralPath $temp -Destination $StatePath -Force
}
function Read-Inventory {
    $text = & $PythonPath $InventoryPath
    if ($LASTEXITCODE -ne 0) { throw 'Read-only iSCSI inventory failed.' }
    $value = ($text -join [Environment]::NewLine) | ConvertFrom-Json
    if ($value.schema -ne 1 -or -not $value.read_only -or $value.target.host -cne $TargetHost -or
        $value.target.port -ne $TargetPort -or $value.target.iqn -cne $TargetIqn) {
        throw 'Inventory schema or fixed endpoint mismatch.'
    }
    return $value
}
function Get-LiveSessions { return @(Get-IscsiSession -ErrorAction Stop) }
function Assert-NativeSessionsEmpty {
    $text = & $PythonPath $InventoryPath --native sessions
    if ($LASTEXITCODE -ne 0) { throw 'Native session inventory failed; stale CIM session cannot be ignored.' }
    $report = ($text -join [Environment]::NewLine) | ConvertFrom-Json
    if ($report.api -cne 'GetIScsiSessionListW' -or $report.ok -ne $true -or
        $report.status -ne 0 -or $report.count -ne 0) {
        throw 'Native session inventory does not prove zero sessions.'
    }
    return $report
}
function Get-CleanupBlockingSessions {
    $sessions = @(Get-LiveSessions)
    if ($script:VerifiedStaleIds.Count -gt 0) { Assert-NativeSessionsEmpty | Out-Null }
    return @($sessions | Where-Object {
        -not ($script:VerifiedStaleIds.ContainsKey([string]$_.SessionIdentifier) -and
              $_.TargetNodeAddress -ceq $TargetIqn -and
              $_.IsConnected -is [bool] -and $_.IsConnected -eq $false)
    })
}
function Get-OwnedPortals {
    return @(Get-IscsiTargetPortal -ErrorAction Stop | Where-Object {
        $_.TargetPortalAddress -ceq $TargetHost -and $_.TargetPortalPortNumber -eq $TargetPort
    })
}
function Read-NativePortalInventory {
    $text = & $PythonPath $OwnedPortalPath
    if ($LASTEXITCODE -ne 0) { throw 'Native portal inventory failed.' }
    $report = ($text -join [Environment]::NewLine) | ConvertFrom-Json
    if ($report.schema -ne 1 -or $report.ok -ne $true -or $report.read_only -ne $true) {
        throw 'Invalid native portal inventory.'
    }
    return $report
}
function Get-ServiceIdentity {
    $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='MSiSCSI'" -ErrorAction Stop
    if ($null -eq $svc) { throw 'MSiSCSI service not found.' }
    $started = $null
    if ($svc.ProcessId -gt 0) {
        $started = (Get-Process -Id $svc.ProcessId -ErrorAction Stop).StartTime.ToUniversalTime().ToString('o')
    }
    return [pscustomobject]@{ status = $svc.State; pid = [int]$svc.ProcessId; process_started_utc = $started; start_mode = $svc.StartMode }
}
function Assert-LoopbackConnection($Session, [switch]$AllowOwnedDisconnected) {
    try {
        $connections = @(Get-IscsiConnection -IscsiSession $Session -ErrorAction Stop)
    } catch {
        if (-not $AllowOwnedDisconnected -or $_.FullyQualifiedErrorId -notlike 'CmdletizationQuery_NotFound,*') { throw }
        $connections = @()
    }
    # After our target shuts down, an owned disconnected session can remain
    # without a TCP connection. Its journaled ID and target IQN still identify
    # exactly what Cleanup may log out; Connect never uses this exception.
    if ($AllowOwnedDisconnected -and $connections.Count -eq 0 -and
        $Session.IsConnected -is [bool] -and $Session.IsConnected -eq $false -and
        $Session.TargetNodeAddress -ceq $TargetIqn -and
        @($script:State.session_ids | Where-Object { $_ -ceq $Session.SessionIdentifier }).Count -eq 1) {
        return @()
    }
    if ($connections.Count -ne 1) { throw 'Expected exactly one owned iSCSI connection.' }
    if ($connections[0].TargetAddress -cne $TargetHost -or $connections[0].TargetPortNumber -ne $TargetPort) {
        throw 'Owned session endpoint differs from the fixed loopback address/port.'
    }
    return @($connections | Select-Object ConnectionIdentifier, TargetAddress, TargetPortNumber, InitiatorAddress, InitiatorPortNumber)
}
function Invoke-OwnedCleanup {
    if ($null -eq $script:State) { throw 'No ownership journal is loaded.' }
    if ($script:State.schema -ne 1 -or $script:State.iqn -cne $TargetIqn -or
        $script:State.host -cne $TargetHost -or $script:State.port -ne $TargetPort) {
        throw 'Ownership journal endpoint/schema mismatch; no cleanup performed.'
    }
    $script:VerifiedStaleIds = @{}
    if (-not $script:State.PSObject.Properties['stale_session_ids']) {
        $script:State | Add-Member -NotePropertyName stale_session_ids -NotePropertyValue @()
    }
    $svc = Get-ServiceIdentity
    if ($svc.status -ne 'Running') {
        if ($svc.status -ne 'Stopped') {
            throw 'Service state is transitional or unknown; cleanup will not change it.'
        }
        # Reboot can remove the nonpersistent session while leaving our old
        # journal. Never start a service just to clear that journal: require a
        # stable stopped service and verified empty discovery/target inventory.
        $empty = Read-Inventory
        $nativeSessions = $empty.native_reports.sessions
        if ($empty.start_guard.allowed -ne $true -or
            $empty.service_before.state -cne 'Stopped' -or $empty.service_after.state -cne 'Stopped' -or
            ($nativeSessions.PSObject.Properties['count'] -and $nativeSessions.count -gt 0) -or
            ($nativeSessions.PSObject.Properties['reported_count'] -and $nativeSessions.reported_count -gt 0) -or
            (Get-ServiceIdentity).status -cne 'Stopped') {
            throw 'Stopped service does not have a stable verified empty iSCSI configuration; ownership retained.'
        }
        Write-Log 'owned_resources_already_absent_service_stopped' @{ service = $svc; inventory = $empty }
        $script:State.session_ids = @()
        $script:State.portal_created = $false
        $script:State.service_started = $false
        $script:State.status = 'cleaned'
        Save-State
        return
    }
    foreach ($id in @($script:State.session_ids)) {
        $found = @(Get-LiveSessions | Where-Object { $_.SessionIdentifier -ceq $id })
        if ($found.Count -gt 1) { throw 'Ambiguous owned session ID.' }
        if ($found.Count -eq 1) {
            if ($found[0].TargetNodeAddress -cne $TargetIqn) { throw 'Owned session ID now belongs to a different target.' }
            $connectionLog = @(Assert-LoopbackConnection $found[0] -AllowOwnedDisconnected)
            Write-Log 'disconnect_owned_session' @{ session_id = $id; connections = $connectionLog }
            try {
                Disconnect-IscsiTarget -NodeAddress $TargetIqn -SessionIdentifier $id -Confirm:$false -ErrorAction Stop | Out-Null
            } catch {
                if ($_.FullyQualifiedErrorId -cne 'HRESULT 0xefff001c,Disconnect-IscsiTarget' -or
                    $connectionLog.Count -ne 0 -or $found[0].IsConnected -isnot [bool] -or
                    $found[0].IsConnected -ne $false -or $found[0].TargetNodeAddress -cne $TargetIqn -or
                    $found[0].SessionIdentifier -cne $id) { throw }
                $native = Assert-NativeSessionsEmpty
                $script:VerifiedStaleIds[$id] = $true
                if (@($script:State.stale_session_ids | Where-Object { $_ -ceq $id }).Count -eq 0) {
                    $script:State.stale_session_ids = @($script:State.stale_session_ids) + @($id)
                }
                Write-Log 'owned_session_native_gone_cim_stale' @{ session_id = $id; iqn = $TargetIqn; native = $native }
                Save-State
            }
            if (-not $script:VerifiedStaleIds.ContainsKey($id) -and
                @(Get-LiveSessions | Where-Object { $_.SessionIdentifier -ceq $id }).Count) {
                throw 'Owned session remains present after disconnect.'
            }
        }
        # Retain ownership through partial cleanup so a retry can reverify this
        # exact stale record. The historical stale_session_ids remain afterward.
        if ($script:VerifiedStaleIds.ContainsKey($id)) { continue }
        $script:State.session_ids = @($script:State.session_ids | Where-Object { $_ -cne $id })
        Save-State
    }
    if ($script:State.portal_created) {
        # Do not remove discovery configuration if anybody has since reused it.
        foreach ($session in Get-CleanupBlockingSessions) {
            $connections = @(Get-IscsiConnection -IscsiSession $session -ErrorAction Stop)
            if (@($connections | Where-Object { $_.TargetAddress -ceq $TargetHost -and $_.TargetPortNumber -eq $TargetPort }).Count) {
                throw 'Another session uses the owned portal; leaving portal/service intact.'
            }
        }
        # CIM can retain a deleted portal or fail removal with TypeMismatch.
        # The native helper verifies ownership/source binding, zero native
        # sessions, exact removal, and preservation of every other portal.
        $text = & $PythonPath $OwnedPortalPath --remove
        if ($LASTEXITCODE -ne 0) { throw 'Exact native owned-portal cleanup failed.' }
        $portalResult = ($text -join [Environment]::NewLine) | ConvertFrom-Json
        if ($portalResult.schema -ne 1 -or $portalResult.ok -ne $true -or $portalResult.absent -ne $true -or
            $portalResult.owner -cne $script:State.owner -or $portalResult.host -cne $TargetHost -or
            $portalResult.port -ne $TargetPort -or $portalResult.iqn -cne $TargetIqn) {
            throw 'Native portal cleanup returned an unexpected ownership result.'
        }
        Write-Log 'native_owned_portal_cleanup' $portalResult
        $script:State.portal_created = $false
        Save-State
    }
    if ($script:State.service_started) {
        $current = Get-ServiceIdentity
        if ($current.pid -ne $script:State.service_identity.pid -or
            $current.process_started_utc -cne $script:State.service_identity.process_started_utc) {
            # Exact owned sessions/portal are already removed above. A new
            # service generation is not ours to stop, but is not leftover DVD
            # ownership either. Relinquish only that stop permission.
            Write-Log 'service_ownership_relinquished_generation_changed' @{
                previous = $script:State.service_identity; current = $current; service_unchanged = $true
            }
            $script:State.service_started = $false
            Save-State
        } else {
            if (@(Get-CleanupBlockingSessions).Count -gt 0 -or (Read-NativePortalInventory).count -gt 0) {
                throw 'Other iSCSI sessions or portals now exist; leaving service running.'
            }
            $endInventory = Read-Inventory
            Write-Log 'before_owned_service_stop' $endInventory
            if (-not $endInventory.start_guard.allowed) { throw 'New or unreadable iSCSI configuration; leaving service running.' }
            $dependents = @((Get-Service -Name MSiSCSI -ErrorAction Stop).DependentServices | Where-Object { $_.Status -ne 'Stopped' })
            if ($dependents.Count) { throw 'Running dependent services exist; leaving MSiSCSI running.' }
            Write-Log 'stop_owned_service' $current
            Stop-Service -Name MSiSCSI -ErrorAction Stop
            (Get-Service -Name MSiSCSI).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(10))
            $script:State.service_started = $false
            Save-State
        }
    }
    $script:State.session_ids = @($script:State.session_ids | Where-Object { -not $script:VerifiedStaleIds.ContainsKey($_) })
    $script:State.status = 'cleaned'
    Save-State
    Write-Log 'cleanup_complete' $script:State
}

if (-not (Test-Path -LiteralPath $OutputRoot -PathType Container)) { throw 'Expected workspace output directory is absent.' }
if ($Action -eq 'Inventory') {
    Read-Inventory | ConvertTo-Json -Depth 25
    exit 0
}
# Serialize only our helper processes. This cannot lock out unrelated administrators.
$mutex = New-Object Threading.Mutex($false, 'Local\CodexInitioDvdIscsiLifecycle')
$locked = $false
try {
    $locked = $mutex.WaitOne(0)
    if (-not $locked) { throw 'Another Initio iSCSI lifecycle helper is running.' }
    Import-Module iSCSI -ErrorAction Stop
    if ($Action -eq 'Cleanup') {
        if (-not (Test-Path -LiteralPath $StatePath)) { throw 'No ownership journal exists; nothing will be removed.' }
        $script:State = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
        Invoke-OwnedCleanup
        $script:State | ConvertTo-Json -Depth 25
        exit 0
    }
    if (Test-Path -LiteralPath $StatePath) {
        $old = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
        if ($old.status -ne 'cleaned') { throw 'Prior ownership journal still needs Cleanup; refusing another connection.' }
    }
    $before = Read-Inventory
    Write-Log 'pre_start_inventory' $before
    if (-not $before.start_guard.allowed) { throw ('Pre-start guard refused: ' + ($before.start_guard.reasons -join '; ')) }
    $service = Get-ServiceIdentity
    if ($service.status -notin @('Stopped', 'Running')) { throw 'Service state is transitional.' }
    $script:State = [pscustomobject][ordered]@{
        schema = 1; owner = [Guid]::NewGuid().ToString(); host = $TargetHost; port = $TargetPort; iqn = $TargetIqn
        status = 'preparing'; updated_utc = ''; original_service = $service; service_started = $false
        service_identity = $null; portal_created = $false; portal_initiator_instance = $null
        portal_initiator_address = $null; session_ids = @(); connection_ids = @(); last_error = $null
    }
    Save-State
    try {
        if ($service.status -eq 'Stopped') {
            # Fresh guard immediately before the only service-start operation.
            $fresh = Read-Inventory
            if (-not $fresh.start_guard.allowed -or $fresh.service_after.state -ne 'Stopped') { throw 'Pre-start state changed.' }
            Write-Log 'start_service' @{ evidence = $fresh.start_guard.evidence; startup_type_unchanged = $true }
            Start-Service -Name MSiSCSI -ErrorAction Stop
            $script:State.service_started = $true
            $script:State.service_identity = Get-ServiceIdentity
            Save-State
            (Get-Service -Name MSiSCSI).WaitForStatus('Running', [TimeSpan]::FromSeconds(10))
        }
        $afterStart = Read-Inventory
        Write-Log 'before_loopback_connection' $afterStart
        if (-not $afterStart.start_guard.allowed -or $afterStart.service_after.state -ne 'Running') {
            throw 'Live iSCSI configuration is not empty and stable.'
        }
        if (@(Get-LiveSessions).Count -or @(Get-IscsiTargetPortal -ErrorAction Stop).Count) { throw 'Existing sessions/portals detected.' }
        Write-Log 'create_loopback_portal' @{ host = $TargetHost; port = $TargetPort }
        $created = @(New-IscsiTargetPortal -TargetPortalAddress $TargetHost -TargetPortalPortNumber $TargetPort -ErrorAction Stop)
        if ($created.Count -ne 1) { throw 'Portal creation did not return one ownership object.' }
        $script:State.portal_created = $true
        $script:State.portal_initiator_instance = [string]$created[0].InitiatorInstanceName
        $script:State.portal_initiator_address = [string]$created[0].InitiatorPortalAddress
        Save-State
        $targets = @(Get-IscsiTarget -ErrorAction Stop)
        if ($targets.Count -ne 1 -or $targets[0].NodeAddress -cne $TargetIqn -or $targets[0].IsConnected) {
            throw 'Loopback discovery returned unexpected or already-connected target identity.'
        }
        Write-Log 'connect_loopback_target' @{ iqn = $TargetIqn; host = $TargetHost; port = $TargetPort; persistent = $false; report_to_pnp = $true }
        $connected = @(Connect-IscsiTarget -NodeAddress $TargetIqn -TargetPortalAddress $TargetHost -TargetPortalPortNumber $TargetPort -IsPersistent:$false -ReportToPnP:$true -IsMultipathEnabled:$false -IsHeaderDigest:$false -IsDataDigest:$false -AuthenticationType NONE -ErrorAction Stop)
        # Journal returned IDs before any further validation or queries.
        $script:State.session_ids = @($connected | ForEach-Object { [string]$_.SessionIdentifier })
        Save-State
        if ($connected.Count -ne 1 -or $connected[0].TargetNodeAddress -cne $TargetIqn -or $connected[0].IsPersistent -or -not $connected[0].IsConnected) {
            throw 'Unexpected connected-session identity, persistence, or state.'
        }
        $connections = Assert-LoopbackConnection $connected[0]
        $script:State.connection_ids = @($connections | ForEach-Object { [string]$_.ConnectionIdentifier })
        $script:State.status = 'connected'
        Save-State
        Write-Log 'connected' @{ session_ids = $script:State.session_ids; connections = $connections }
        $script:State | ConvertTo-Json -Depth 25
    } catch {
        $script:State.last_error = $_.Exception.Message
        $script:State.status = 'failed'
        Save-State
        Write-Log 'connect_failed' $script:State.last_error
        try { Invoke-OwnedCleanup } catch { Write-Log 'cleanup_incomplete' $_.Exception.Message }
        throw
    }
} finally {
    if ($locked) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}
