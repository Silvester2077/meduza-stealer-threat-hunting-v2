<#
 Exports Sysmon (EID 1,3,11,12,13,22) and PowerShell 4104 events to CSV for Splunk upload.
 Usage: powershell -ExecutionPolicy Bypass -File .\export_sysmon_csv.ps1 -Minutes 60
#>
param([int]$Minutes = 60)
$start = (Get-Date).AddMinutes(-$Minutes)
$out = Join-Path $PSScriptRoot ("sysmon_week9_{0:yyyyMMdd_HHmm}.csv" -f (Get-Date))

function Flatten($e){
  $x = [xml]$e.ToXml(); $o = [ordered]@{ EventCode=$e.Id; TimeCreated=$e.TimeCreated.ToUniversalTime().ToString("o"); Computer=$e.MachineName; LogName=$e.LogName }
  foreach($d in $x.Event.EventData.Data){ if($d.Name){ $o[$d.Name] = $d.'#text' } }
  [pscustomobject]$o
}

$ev  = @(Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; Id=1,3,11,12,13,22; StartTime=$start} -ErrorAction SilentlyContinue)
$ev += @(Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-PowerShell/Operational"; Id=4104; StartTime=$start} -ErrorAction SilentlyContinue)
$ev | ForEach-Object { Flatten $_ } | Export-Csv $out -NoTypeInformation -Encoding UTF8
Write-Host "Exported $($ev.Count) events -> $out"
