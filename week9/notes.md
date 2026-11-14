# Week 9 — Atomic Red Team: Introduction to Atomic Tests

Topic: Meduza Stealer, running selected Atomic Red Team tests and analyzing the results in Splunk.

> **Status:** test selection, commands and queries are prepared. Results in 9.6 must be filled in **only** after the tests are actually run in the lab. Nothing is claimed in advance.

## 9.1 Key terminology

Terms from previous weeks (ATT&CK, tactic, technique, emulation, CAR analytic, emulation plan) are not repeated here.

| Term | Definition |
|---|---|
| **Atomic Red Team** | Open-source library (Red Canary) of small, ATT&CK-mapped tests that reproduce one technique each. |
| **Atomic test** | A single test inside a technique file (e.g. `T1547.001` → test "Reg Key Run"), with an executor, input arguments and cleanup command. |
| **Invoke-AtomicRedTeam** | PowerShell module that runs atomic tests (`Invoke-AtomicTest`). |
| **Prerequisites (`-GetPrereqs`)** | Files or tools a test needs before it can run. |
| **Cleanup (`-Cleanup`)** | Command that reverts the changes made by a test. |
| **Detection validation** | Checking whether a planned detection actually fires on the telemetry produced by a test. |

## 9.2 Why Atomic Red Team after Week 8

In Week 8 we wrote an emulation plan. Phases 1–4 were executed in Week 6 with our own script. Phases 5 (persistence), 7 (collection) and 8 (exfiltration) were only **planned**. This week we use Atomic Red Team to:

1. run standard, repeatable tests for the planned phases;
2. re-run Phase 2–3 behaviors with standard tests instead of our own script;
3. check in Splunk which tests are visible and which detections from Weeks 5–7 fire.

## 9.3 Test selection

| # | Week 8 phase | Technique | Atomic test (verify name/number) | Why for Meduza |
|---|---|---|---|---|
| A1 | 2 Execution | T1059.003 Windows Command Shell | "Create and Execute Batch Script" | Meduza uses `cmd.exe /C ...` (Splunk analysis, Week 6) |
| A2 | 2 Execution | T1059.001 PowerShell | an offline test without downloads (choose with `-ShowDetailsBrief`) | syllabus example; our emulation chain starts from PowerShell |
| A3 | 3 Discovery | T1082 System Information Discovery | "System Information Discovery" | stealers collect host info for the victim log |
| A4 | 3 Discovery | T1016 System Network Configuration Discovery | "System Network Configuration Discovery on Windows" | public-IP / network checks (Week 6, S4) |
| A5 | 3 Discovery | T1012 Query Registry | "Query Registry" | installed-software registry query (Week 6, S3) |
| A6 | 3 Discovery | T1614.001 System Language Discovery | "Discover System Language by Registry Query" | region/language check (documented by Splunk) |
| A7 | **5 Persistence** | T1547.001 Registry Run Keys | "Reg Key Run" | Week 8 Phase 5 (generic technique, **not confirmed** for Meduza) |
| C1 | **7 Collection** | T1005 Data from Local System | custom step (dummy file), see script | no safe Windows atomic that reads only one dummy file |
| C2 | **8 Exfiltration** | T1132.001 + T1041 | custom step: Base64 + TCP to lab listener | Windows atomics for T1132.001 are not available; T1041 atomic sends to an external URL by default |

**Not selected:**

- **T1003 OS Credential Dumping** (syllabus example). Meduza steals browser data, not LSASS memory, and the T1003 atomics download or run credential-dumping tools. Out of scope for safety; mentioned for completeness.
- **T1555.003 Credentials from Web Browsers**: excluded, as in Week 8 Phase 6 (touches real browser credential stores).

> Verify every test name and number with `Invoke-AtomicTest <TID> -ShowDetailsBrief` before running — names and numbers can change between Atomic Red Team versions.

## 9.4 Lab setup

### 9.4.1 Lab environment (exact versions)

All values below were collected automatically with `collect_lab_info.ps1` (Windows VM) and `collect_lab_info.sh` (Linux VM) on <YYYY-MM-DD>. Raw output: `lab_info_windows.md`, `lab_info_linux.md`.

| Component | Role in the lab | Exact version / value |
|---|---|---|
| Host OS | physical machine running the VMs | <e.g. Windows 11 Pro 23H2, build 22631.xxxx> |
| Hypervisor | runs both VMs | <e.g. Oracle VirtualBox 7.1.x / VMware Workstation 17.x> (Help → About) |
| Network mode | isolation between VMs | <Host-only adapter, network 192.168.56.0/24, no NAT/internet during the run> |
| **Windows VM — OS** | target (victim) machine | <Windows 10/11 edition, DisplayVersion, build> |
| Windows VM — resources | | <vCPU / RAM> |
| Windows VM — IP | | <IPv4> |
| PowerShell | runs Atomic tests | <e.g. 5.1.xxxxx Desktop> |
| PowerShell Script Block Logging | EID 4104 | enabled |
| Sysmon | endpoint telemetry | <e.g. Sysmon64 v15.x>, schema <x.xx> |
| Sysmon configuration | which events are logged | SwiftOnSecurity sysmon-config, file `sysmonconfig-export.xml`, downloaded <date>, SHA-256 <hash> |
| Sysmon events exported | sent to Splunk | EID 1, 3, 11, 12, 13, 22 + PowerShell 4104 (`export_sysmon_csv.ps1`) |
| Microsoft Defender | AV on the VM | engine <x>, real-time protection <off / on + exclusion C:\AtomicRedTeam> |
| Invoke-AtomicRedTeam | test runner module | <version> |
| Atomic Red Team atomics | test definitions | downloaded <date> with `Install-AtomicRedTeam -getAtomics` |
| **Linux VM — distribution** | SIEM + listener | <e.g. Ubuntu 22.04.4 LTS> |
| Linux VM — kernel | | <e.g. 6.5.0-xx-generic x86_64> |
| Linux VM — resources / IP | | <vCPU / RAM / IPv4> |
| Splunk | SIEM | <e.g. Splunk Enterprise 9.x.x (build xxxx), Free/Trial license> |
| Splunk index / sourcetype | where data is stored | index `sysmon`, sourcetype <csv> (Add Data → Upload) |
| netcat | TCP listener for step C2 | <package and version, e.g. netcat-openbsd 1.218> |

> Rule for this report: every tool is given with its exact version, its role, and where/when it was obtained. Values in `< >` must be replaced with the real output — do not leave guesses.

### 9.4.2 Setup steps

- Snapshot of the Windows VM taken before the run (snapshot name: before-week9, date 2026-11-14).
- Windows VM network switched to host-only before the tests (internet used only for the Atomic Red Team download).
- Change compared to Week 6: the CSV export now includes Sysmon **EID 11** (file create) and **EID 12/13** (registry), needed for Phase 5 (see Week 8, 8.6 note). PowerShell Script Block Logging (EID 4104) enabled.
- Scripts in this folder:

| Script | Purpose |
|---|---|
| `collect_lab_info.ps1` / `collect_lab_info.sh` | collect exact versions for 9.4.1 |
| `meduza_atomic_run.ps1` | runs tests A1–A7, custom steps C1–C2, writes `run_log.csv`, cleanup |
| `export_sysmon_csv.ps1` | exports events to CSV for the Splunk upload |

```powershell
# one-time install (run as admin, internet needed only for this step)
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force

# check a test before running it
Invoke-AtomicTest T1547.001 -ShowDetailsBrief
Invoke-AtomicTest T1547.001 -TestNames "Reg Key Run" -ShowDetails
```

*Figure 36. Invoke-AtomicRedTeam installed, `-ShowDetailsBrief` output for T1547.001.*

## 9.5 Running the tests

```powershell
powershell -ExecutionPolicy Bypass -File .\meduza_atomic_run.ps1 -ListenerIp <lab-linux-ip>
powershell -ExecutionPolicy Bypass -File .\export_sysmon_csv.ps1 -Minutes 60
# then: Splunk → Settings → Add Data → Upload → index=sysmon (same as Week 6)
```

For C2 start a listener on the Linux VM first: `nc -lvnp 15666 > received.txt` (port reused from our IOC only as a label; the target is our lab IP).

*Figure 37. PowerShell output of `meduza_atomic_run.ps1` (user name redacted).*

*Figure 38. Linux listener received the Base64 dummy data.*

### Splunk queries

Same data note as Week 7: on CSV-uploaded data, field filters in the base search did not work, so we select with keywords first and filter with `where`.

**Overview of produced events**

```spl
index=sysmon
| stats count by EventCode
```

**A1 / A2 — CAR-2013-02-003 (Week 7) on Atomic output**

```spl
index=sysmon cmd.exe
| where EventCode=1 AND like(Image,"%cmd.exe") AND NOT match(ParentImage,"(?i)(explorer|cmd)\\.exe$")
| table _time Computer ParentImage Image CommandLine
```

**A3–A6 — discovery burst (several discovery tools from one parent in a short window)**

```spl
index=sysmon
| where EventCode=1 AND match(Image,"(?i)\\(systeminfo|ipconfig|reg|netsh|chcp|hostname|whoami)\\.exe$")
| bin _time span=5m
| stats dc(Image) as tools values(Image) as images values(CommandLine) as cmd by _time Computer ParentImage
| where tools>=3
```

**A7 — Run-key persistence (needs EID 13)**

```spl
index=sysmon CurrentVersion Run
| where EventCode=13 AND like(TargetObject,"%\\CurrentVersion\\Run%")
| table _time Computer Image TargetObject Details
```

**C1 — dummy file read (EID 1 command line; EID 11 for the copy)**

```spl
index=sysmon meduza_sim
| where (EventCode=1 OR EventCode=11) AND like(_raw,"%meduza_sim%")
| table _time EventCode Image CommandLine TargetFilename
```

**C2 — Hunt 2 (Week 5) adapted to the lab listener**

```spl
index=sysmon 15666
| where EventCode=3 AND DestinationPort=15666
| stats count min(_time) as first_seen by Computer Image DestinationIp DestinationPort
```

*Figure 39. Splunk: `stats count by EventCode` after the Atomic run.*\
*Figure 40. Splunk: Run-key event (EID 13) for test A7.*\
*Figure 41. Splunk: `powershell.exe` → lab IP:15666 (EID 3) for step C2.*

## 9.6 Results

Fill in after the run. If a query returns nothing, write "No matching events in the available dataset" (as in Week 5) — do not assume.

| # | Technique | Ran? | Event in Splunk? | Event ID | Detection that fired | Notes |
|---|---|---|---|---|---|---|
| A1 | T1059.003 | TODO | TODO | 1 | CAR-2013-02-003 (Week 7)? | |
| A2 | T1059.001 | TODO | TODO | 1 / 4104 | — | |
| A3 | T1082 | TODO | TODO | 1 | discovery burst? | |
| A4 | T1016 | TODO | TODO | 1 | discovery burst? | |
| A5 | T1012 | TODO | TODO | 1 | discovery burst? | |
| A6 | T1614.001 | TODO | TODO | 1 | discovery burst? | |
| A7 | T1547.001 | TODO | TODO | 13 | Run-key query | Week 8 Phase 5 |
| C1 | T1005 | TODO | TODO | 1 / 11 | — | Week 8 Phase 7 |
| C2 | T1132.001, T1041 | TODO | TODO | 3 | Hunt 2 (Week 5) | Week 8 Phase 8 |

### Update of the Week 8 plan status

| Week 8 phase | Status before | Status after Week 9 |
|---|---|---|
| 5 Persistence | planned | TODO (executed / not executed) |
| 7 Collection | planned | TODO |
| 8 Exfiltration | planned | TODO |

## 9.7 Detection coverage (gaps)

| Area | Covered by | Gap / tuning |
|---|---|---|
| Shell from unusual parent | CAR-2013-02-003 | Atomic framework itself runs from PowerShell → expected hit; allowlist needed in production |
| Discovery | discovery burst query | Admin scripts also run systeminfo/ipconfig; use as a hunting lead only |
| Persistence | Run-key query (EID 13) | Needs registry events in the export; only HKCU/HKLM Run covered |
| Exfiltration | Hunt 2 | Works only for a known IP:port; behavior-based detection still missing |
| Browser credentials | Hunt 4 (Week 5) | Not tested (safety), coverage unknown |

## 9.8 Limitations

- Atomic tests reproduce single techniques, not the full Meduza Stealer chain or the real malware.
- Phase 5 uses a generic technique; persistence is not confirmed for Meduza in our sources (Week 8).
- Logs are uploaded to Splunk as CSV in batches; `_time` may reflect upload time, use `UtcTime` (Week 7).
- One lab host, no baseline of normal activity → false-positive rate unknown.
- Atomic test names/numbers depend on the installed version.

## 9.9 Conclusion

We selected Atomic Red Team tests that match Meduza-like behaviors and the open phases of our Week 8 plan, prepared a run script, extended the Sysmon export with registry and file events, and wrote Splunk queries to check which detections fire. After the run, 9.6 shows which phases moved from "planned" to "executed" and which detection gaps remain. In Week 10 we compare these techniques with the TTPs of an APT group.

> **Note on AI use:** Test selection, scripts and query templates were prepared with the help of an AI tool. Lab execution, observed results and screenshots are the team's own.

## References

1. Red Canary — Atomic Red Team (GitHub repository and Wiki)
2. Red Canary — Invoke-AtomicRedTeam Wiki
3. MITRE ATT&CK — T1059.001, T1059.003, T1082, T1016, T1012, T1614.001, T1547.001, T1005, T1132.001, T1041
4. MITRE CAR — CAR-2013-02-003 Processes Spawning cmd.exe
5. Splunk Threat Research Team — Meduza Stealer Analysis
