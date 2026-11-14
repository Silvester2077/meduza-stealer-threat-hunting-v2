<#
 Collects EXACT versions of the Windows lab VM for the report (section 9.4).
 Run as Administrator:  powershell -ExecutionPolicy Bypass -File .\collect_lab_info.ps1 -SysmonConfig C:\Sysmon\sysmonconfig-export.xml
 Output: lab_info_windows.md (paste values into notes.md, redact user names if needed)
#>
param([string]$SysmonConfig = "")
$out = Join-Path $PSScriptRoot "lab_info_windows.md"
$L = New-Object System.Collections.Generic.List[string]
function Add($k,$v){ $L.Add("| $k | $v |") }
$L.Add("# Windows lab VM - collected $((Get-Date).ToString('yyyy-MM-dd HH:mm')) (local time)"); $L.Add("")
$L.Add("| Item | Value |"); $L.Add("|---|---|")

$os = Get-CimInstance Win32_OperatingSystem
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
Add "OS" "$($os.Caption) $($os.OSArchitecture)"
Add "OS version (DisplayVersion)" "$($cv.DisplayVersion)"
Add "OS build" "$($os.Version).$($cv.UBR)"

$cs = Get-CimInstance Win32_ComputerSystem
Add "Virtual hardware (manufacturer / model)" "$($cs.Manufacturer) / $($cs.Model)"
Add "vCPU / RAM" "$($cs.NumberOfLogicalProcessors) vCPU / $([math]::Round($cs.TotalPhysicalMemory/1GB,1)) GB"

Add "PowerShell" "$($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"
$sbl = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockLogging
Add "PowerShell Script Block Logging (4104)" ($(if($sbl -eq 1){"enabled"}else{"NOT enabled"}))

$sysExe = @("C:\Windows\Sysmon64.exe","C:\Windows\Sysmon.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if($sysExe){
  Add "Sysmon binary" "$sysExe, version $((Get-Item $sysExe).VersionInfo.FileVersion)"
  $svc = Get-Service Sysmon64,Sysmon -ErrorAction SilentlyContinue | Select-Object -First 1
  Add "Sysmon service" "$($svc.Name): $($svc.Status)"
  $schema = (& $sysExe -c 2>&1 | Select-String -Pattern "schema" | Select-Object -First 1)
  Add "Sysmon config schema" "$schema"
} else { Add "Sysmon" "NOT FOUND" }
if($SysmonConfig -and (Test-Path $SysmonConfig)){
  Add "Sysmon config file" "$SysmonConfig"
  Add "Sysmon config SHA-256" "$((Get-FileHash $SysmonConfig -Algorithm SHA256).Hash)"
  Add "Sysmon config last modified" "$((Get-Item $SysmonConfig).LastWriteTime.ToString('yyyy-MM-dd'))"
}

$mod = Get-Module -ListAvailable Invoke-AtomicRedTeam -ErrorAction SilentlyContinue | Sort-Object Version -Descending | Select-Object -First 1
if(-not $mod -and (Test-Path "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1")){
  $mod = Import-PowerShellDataFile "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1"
  Add "Invoke-AtomicRedTeam module" "$($mod.ModuleVersion)"
} elseif($mod){ Add "Invoke-AtomicRedTeam module" "$($mod.Version)" } else { Add "Invoke-AtomicRedTeam" "NOT FOUND" }
if(Test-Path "C:\AtomicRedTeam\atomics"){
  Add "Atomics folder downloaded" "$((Get-Item C:\AtomicRedTeam\atomics).CreationTime.ToString('yyyy-MM-dd'))"
  Add "Number of technique folders" "$((Get-ChildItem C:\AtomicRedTeam\atomics -Directory -Filter 'T*').Count)"
}

$mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
if($mp){ Add "Microsoft Defender" "engine $($mp.AMEngineVersion), product $($mp.AMProductVersion), real-time protection: $($mp.RealTimeProtectionEnabled)" }
$excl = (Get-MpPreference -ErrorAction SilentlyContinue).ExclusionPath -join ", "
Add "Defender exclusions" "$excl"

Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -ne "127.0.0.1" } | ForEach-Object { Add "IPv4 ($($_.InterfaceAlias))" "$($_.IPAddress)/$($_.PrefixLength)" }

$L | Set-Content $out -Encoding UTF8
Write-Host "Saved: $out" -ForegroundColor Green
Get-Content $out
