# Read-only verification of this utility's virtual optical device.
$ErrorActionPreference = 'Stop'
$devices = @(Get-CimInstance -ClassName Win32_CDROMDrive | Where-Object {
    $_.Name -like '*CODEX*USB DVD Bridge*'
})
$result = [ordered]@{ time_utc=[DateTime]::UtcNow.ToString('o'); devices=@(); verification_complete=$true }
foreach ($device in $devices) {
    $item = [ordered]@{ name=$device.Name; id=$device.PNPDeviceID; drive=$device.Drive; media_loaded=$device.MediaLoaded; root_entries=@(); readable=$false; error=$null }
    if ($device.Drive -match '^[A-Z]:$') {
        try {
            $entries = @(Get-ChildItem -LiteralPath ($device.Drive+'\') -Force -ErrorAction Stop)
            $item.root_entries = @($entries | Select-Object -First 20 Name,Length,Mode)
            $item.readable = $true
        } catch { $item.error=$_.Exception.Message }
    }
    $result.devices += [pscustomobject]$item
}
$result | ConvertTo-Json -Depth 10
