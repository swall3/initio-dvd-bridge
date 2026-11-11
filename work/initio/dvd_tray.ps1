#requires -Version 5.1
# Native Windows Forms tray UI. No elevated player or device operations here.
# https://learn.microsoft.com/dotnet/api/system.windows.forms.notifyicon
param([string]$Python='', [switch]$Hidden)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()
$Root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
if (-not $Python) { $Python=Join-Path $Root 'runtime\python.exe' }
if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) { throw 'Bundled Python is missing.' }
$created=$false
$mutex=New-Object Threading.Mutex($true,'Local\InitioDvdBridgeTray',([ref]$created))
if (-not $created) {
    if(-not $Hidden){[IO.File]::WriteAllText((Join-Path $Root 'outputs\initio\tray-show.request'),'Show controls')}
    $mutex.Dispose(); exit
}
$script:Jobs=New-Object Collections.ArrayList
$script:NextStatus=[DateTime]::MinValue
$script:Exiting=$false
$script:Current=$null
$script:FirstTick=$true
$form=New-Object Windows.Forms.Form
$form.Text='Initio DVD Bridge'
$form.ClientSize=New-Object Drawing.Size(490,450)
$form.StartPosition='CenterScreen'
$form.FormBorderStyle='FixedDialog';$form.MaximizeBox=$false
$form.Font=New-Object Drawing.Font('Segoe UI',10)
$form.BackColor=[Drawing.Color]::FromArgb(245,247,250)
$title=New-Object Windows.Forms.Label
$title.Text='Your DVD, ready when you are.';$title.Location=New-Object Drawing.Point(22,20)
$title.Size=New-Object Drawing.Size(450,32);$title.Font=New-Object Drawing.Font('Segoe UI Semibold',16)
$form.Controls.Add($title)
$state=New-Object Windows.Forms.Label
$state.Text='Checking drive...';$state.Location=New-Object Drawing.Point(24,65)
$state.Size=New-Object Drawing.Size(440,27);$state.Font=New-Object Drawing.Font('Segoe UI Semibold',12)
$form.Controls.Add($state)
$detail=New-Object Windows.Forms.Label
$detail.Location=New-Object Drawing.Point(24,98);$detail.Size=New-Object Drawing.Size(440,43)
$form.Controls.Add($detail)
$feedback=New-Object Windows.Forms.Label
$feedback.Location=New-Object Drawing.Point(24,338);$feedback.Size=New-Object Drawing.Size(440,52)
$feedback.ForeColor=[Drawing.Color]::FromArgb(65,78,95)
$feedback.Text='DVD sound and music files play in VLC.'
$form.Controls.Add($feedback)
$foot=New-Object Windows.Forms.Label
$foot.Location=New-Object Drawing.Point(24,397);$foot.Size=New-Object Drawing.Size(440,38)
$foot.Font=New-Object Drawing.Font('Segoe UI',9)
$foot.Text='Audio CDs are not supported by this bridge yet. Closing this window keeps the tray and DVD utility running.'
$form.Controls.Add($foot)
$auto=New-Object Windows.Forms.CheckBox
$auto.Text='Start DVD utility when this drive is connected'
$auto.Location=New-Object Drawing.Point(24,298);$auto.Size=New-Object Drawing.Size(440,28)
$form.Controls.Add($auto)
$tray=New-Object Windows.Forms.NotifyIcon
$tray.Icon=[Drawing.SystemIcons]::Information;$tray.Text='Initio DVD Bridge';$tray.Visible=$true
$menu=New-Object Windows.Forms.ContextMenuStrip
$tray.ContextMenuStrip=$menu
function Show-Window { $form.Show();$form.WindowState='Normal';$form.Activate() }
function Run-Command([hashtable]$Request) {
    if ($script:Jobs.Count -ge 4) { return }
    $json=$Request | ConvertTo-Json -Compress -Depth 5
    $encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
    $start=New-Object Diagnostics.ProcessStartInfo
    $start.FileName=$Python
    $start.Arguments='"'+(Join-Path $PSScriptRoot 'tray_backend.py')+'" --request '+$encoded
    $start.WorkingDirectory=$Root;$start.UseShellExecute=$false;$start.CreateNoWindow=$true
    $start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    $p=New-Object Diagnostics.Process;$p.StartInfo=$start
    [void]$p.Start()
    [void]$script:Jobs.Add([pscustomobject]@{Process=$p;Output=$p.StandardOutput.ReadToEndAsync();Error=$p.StandardError.ReadToEndAsync();Action=$Request.action;Started=[DateTime]::UtcNow})
}
function Choose-Media {
    $dialog=New-Object Windows.Forms.OpenFileDialog
    $dialog.Title='Play audio or video in VLC';$dialog.Multiselect=$true
    $dialog.Filter='Audio and video|*.mp3;*.flac;*.wav;*.m4a;*.aac;*.ogg;*.opus;*.wma;*.mp4;*.mkv;*.avi;*.mov;*.webm;*.vob|All files|*.*'
    if ($dialog.ShowDialog($form) -eq 'OK') { Run-Command @{action='play-files';files=@($dialog.FileNames)} }
    $dialog.Dispose()
}
function Choose-Vlc {
    $dialog=New-Object Windows.Forms.OpenFileDialog
    $dialog.Title='Choose VLC (vlc.exe)';$dialog.Filter='VLC media player|vlc.exe'
    if ($dialog.ShowDialog($form) -eq 'OK') { Run-Command @{action='set-vlc';path=$dialog.FileName} }
    $dialog.Dispose()
}
function Stop-Dvd {
    $answer=[Windows.Forms.MessageBox]::Show($form,'Close VLC first. Stop the DVD utility and begin cleanup?','Stop DVD','YesNo','Question')
    if ($answer -eq 'Yes') { Run-Command @{action='stop'} }
}
function Show-Details {
    $text='Waiting for status.'
    if($script:Current){
        $s=$script:Current
        $text="DVD: $($state.Text)`r`nDrive: $($s.drive)`r`nAutomatic startup: $($s.autostart)`r`nStartup watcher running: $($s.watcher_alive)`r`n`r`nVLC: $($s.vlc)`r`n`r`nLast error: $(if($s.error){$s.error}else{'None'})`r`n`r`n$($s.audio)"
    }
    [Windows.Forms.MessageBox]::Show($form,$text,'DVD status and troubleshooting','OK','Information') | Out-Null
}
function Add-Button([string]$Text,[int]$X,[int]$Y,[scriptblock]$Click) {
    $b=New-Object Windows.Forms.Button;$b.Text=$Text
    $b.Location=New-Object Drawing.Point($X,$Y);$b.Size=New-Object Drawing.Size(212,40)
    $b.FlatStyle='Flat';$b.BackColor=[Drawing.Color]::White;$b.Add_Click($Click)
    $form.Controls.Add($b);return $b
}
$play=Add-Button 'Play DVD in VLC' 24 148 {Run-Command @{action='play-disc'}}
$files=Add-Button 'Play audio / video files...' 252 148 {Choose-Media}
$startButton=Add-Button 'Start DVD utility' 24 196 {Run-Command @{action='start'}}
$stopButton=Add-Button 'Stop DVD utility' 252 196 {Stop-Dvd}
$vlcButton=Add-Button 'Choose VLC...' 24 244 {Choose-Vlc}
$infoButton=Add-Button 'Status / troubleshooting' 252 244 {Show-Details}
$auto.Add_Click({Run-Command @{action=$(if($auto.Checked){'enable'}else{'disable'})}})
function Add-Menu([string]$Text,[scriptblock]$Click) {
    $item=New-Object Windows.Forms.ToolStripMenuItem($Text);$item.Add_Click($Click);[void]$menu.Items.Add($item);return $item
}
$openItem=Add-Menu 'Open DVD controls' {Show-Window}
$menuPlay=Add-Menu 'Play DVD in VLC' {Run-Command @{action='play-disc'}}
$mediaItem=Add-Menu 'Play audio / video files...' {Choose-Media}
[void]$menu.Items.Add((New-Object Windows.Forms.ToolStripSeparator))
$menuStart=Add-Menu 'Start DVD utility' {Run-Command @{action='start'}}
$menuStop=Add-Menu 'Stop DVD utility' {Stop-Dvd}
$exitItem=Add-Menu 'Exit tray (leave DVD running)' {$script:Exiting=$true;$form.Close()}
$tray.Add_DoubleClick({Show-Window})
$form.Add_FormClosing({param($sender,$eventArgs) if(-not $script:Exiting){$eventArgs.Cancel=$true;$form.Hide()}})
$form.Add_Resize({if($form.WindowState -eq 'Minimized'){$form.Hide()}})
$timer=New-Object Windows.Forms.Timer;$timer.Interval=300
$timer.Add_Tick({
    if($script:FirstTick){
        $script:FirstTick=$false
        if(-not $Hidden){$form.Hide();$form.Show();$form.Activate()}
    }
    foreach($job in @($script:Jobs.ToArray())) {
        if(-not $job.Process.HasExited){
            if($job.Action -eq 'status' -and ([DateTime]::UtcNow-$job.Started).TotalSeconds -gt 15){
                # Only terminate our own unprivileged status subprocess.
                $job.Process.Kill();$job.Process.Dispose();$script:Jobs.Remove($job)
                $state.Text='Status timed out';$play.Enabled=$false;$menuPlay.Enabled=$false
                $startButton.Enabled=$false;$menuStart.Enabled=$false
                $stopButton.Enabled=$false;$menuStop.Enabled=$false
            }
            continue
        }
        try {
            $result=$job.Output.Result | ConvertFrom-Json
            if(-not $result.ok){throw $result.error}
            if($job.Action -eq 'status') {
                $script:Current=$result
                $labels=@{ready='Ready to play';disconnected='Drive disconnected';stopped='DVD utility stopped';initializing='Starting DVD...';connecting='Connecting DVD...';connected='Reading disc...';stopping='Stopping and cleaning up...';stopping_after_error='Cleaning up after an error';cleanup_incomplete='Cleanup needs attention';error='DVD needs attention'}
                $label=$labels[$result.phase];if(-not $label){$label=$result.phase}
                $state.Text=$label+$(if($result.drive){'  '+$result.drive}else{''})
                $tray.Text=('Initio DVD Bridge - '+$label).Substring(0,[Math]::Min(63,('Initio DVD Bridge - '+$label).Length))
                $play.Enabled=$result.phase -eq 'ready';$menuPlay.Enabled=$play.Enabled
                $startButton.Enabled=$result.device_present -and -not $result.runtime_alive;$menuStart.Enabled=$startButton.Enabled
                $stopButton.Enabled=$result.runtime_alive;$menuStop.Enabled=$stopButton.Enabled
                $auto.Checked=$result.autostart
                $detail.Text=if($result.error){$result.error}elseif(-not $result.vlc){'Choose VLC once to enable DVD, music and video playback.'}elseif($result.autostart -and -not $result.watcher_alive){'Automatic startup is configured, but its watcher is not running.'}else{'VLC is available. Playback controls and volume are in VLC.'}
            } else { $feedback.Text=$result.message;$script:NextStatus=[DateTime]::MinValue }
        } catch {
            $feedback.Text=[string]$_
            if($job.Action -eq 'status'){
                $state.Text='Status unavailable';$play.Enabled=$false;$menuPlay.Enabled=$false
                $startButton.Enabled=$false;$menuStart.Enabled=$false
                $stopButton.Enabled=$false;$menuStop.Enabled=$false
            }
        }
        $job.Process.Dispose();$script:Jobs.Remove($job)
    }
    if([DateTime]::UtcNow -ge $script:NextStatus -and -not @($script:Jobs | Where-Object {$_.Action -eq 'status'}).Count){
        Run-Command @{action='status'};$script:NextStatus=[DateTime]::UtcNow.AddSeconds(3)
    }
    if(Test-Path -LiteralPath (Join-Path $Root 'outputs\initio\tray-exit.request')){$script:Exiting=$true;$form.Close()}
    $showRequest=Join-Path $Root 'outputs\initio\tray-show.request'
    if(Test-Path -LiteralPath $showRequest){Remove-Item -LiteralPath $showRequest;Show-Window}
})
$exitRequest=Join-Path $Root 'outputs\initio\tray-exit.request'
if(Test-Path -LiteralPath $exitRequest){Remove-Item -LiteralPath $exitRequest}
$form.Add_Shown({if($Hidden){$form.Hide()}})
$timer.Start()
try { [Windows.Forms.Application]::Run($form) }
finally { $timer.Stop();$timer.Dispose();$tray.Visible=$false;$tray.Dispose();$menu.Dispose();$mutex.ReleaseMutex();$mutex.Dispose() }
