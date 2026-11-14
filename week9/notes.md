# Week 9 — Atomic Red Team: Introduction to Atomic Tests

Topic: Meduza Stealer, running selected Atomic Red Team tests and analyzing the results in Splunk.

> **Status:** the tests were run in the lab on 2026-11-14 (UTC 08:46–08:50). Results in 9.6 contain only what is confirmed by the run log, the console output, the Linux listener and the exported CSV.

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
3. check which tests produce telemetry and which detections from Weeks 5–7 can be applied to it.

## 9.3 Test selection

| # | Week 8 phase | Technique | Atomic test | Why for Meduza | Run status |
|---|---|---|---|---|---|
| A1 | 2 Execution | T1059.003 Windows Command Shell | T1059.003-1 "Create and Execute Batch Script" | Meduza uses `cmd.exe /C ...` (Splunk analysis, Week 6) | executed |
| A2 | 2 Execution | T1059.001 PowerShell | an offline test without downloads | syllabus example; our emulation chain starts from PowerShell | **not executed** (see 9.8) |
| A3 | 3 Discovery | T1082 System Information Discovery | T1082-1 and T1082-28 "System Information Discovery" | stealers collect host info for the victim log | executed |
| A4 | 3 Discovery | T1016 System Network Configuration Discovery | T1016-1 "System Network Configuration Discovery on Windows" | public-IP / network checks (Week 6, S4) | executed |
| A5 | 3 Discovery | T1012 Query Registry | T1012-1 "Query Registry" | installed-software registry query (Week 6, S3) | executed |
| A6 | 3 Discovery | T1614.001 System Language Discovery | T1614.001-1 "Discover System Language by Registry Query" | region/language check (documented by Splunk) | executed |
| A7 | **5 Persistence** | T1547.001 Registry Run Keys | T1547.001-1 "Reg Key Run" | Week 8 Phase 5 (generic technique, **not confirmed** for Meduza) | executed |
| C1 | **7 Collection** | T1005 Data from Local System | custom step (dummy file), see script | no safe Windows atomic that reads only one dummy file | executed |
| C2 | **8 Exfiltration** | T1132.001 + T1041 | custom step: Base64 + TCP to lab listener | Windows atomics for T1132.001 are not available; T1041 atomic sends to an external URL by default | executed |

**Not selected:**

- **T1003 OS Credential Dumping** (syllabus example). Meduza steals browser data, not LSASS memory, and the T1003 atomics download or run credential-dumping tools. Out of scope for safety; mentioned for completeness.
- **T1555.003 Credentials from Web Browsers**: excluded, as in Week 8 Phase 6 (touches real browser credential stores).

> Test names and numbers were verified with `Invoke-AtomicTest <TID> -ShowDetailsBrief` before the run (for example T1547.001-1 "Reg Key Run", Figure 36); they can change between Atomic Red Team versions.

## 9.4 Lab setup

### 9.4.1 Lab environment (exact versions)

Values below were collected with `collect_lab_info.ps1` (Windows VM) and `collect_lab_info.sh` (Linux VM) on 2026-11-14. Raw output: `lab_info_windows.md`, `lab_info_linux.md`. Values marked `<...>` must be copied from these two files.

| Component | Role in the lab | Exact version / value |
|---|---|---|
| Host OS | physical machine running the VMs | <copy from lab_info_windows.md, e.g. Windows 11 Pro 23H2, build 22631.xxxx> |
| Hypervisor | runs both VMs | <e.g. Oracle VirtualBox 7.1.x / VMware Workstation 17.x> |
| Network mode | isolation between VMs | Host-only network 192.168.56.0/24; internet used only for the Atomic Red Team download |
| **Windows VM — OS** | target (victim) machine | Windows Server 2022 Datacenter Evaluation, version 10.0.20348, build 20348 (from `systeminfo`, Figure 37a) |
| Windows VM — host name / role | | WIN-IBSOJSQ127Q; OS configuration "Primary Domain Controller"; DNS suffix ws.local (Figures 37a, 37b) |
| Windows VM — resources / IP | | <vCPU / RAM / IPv4 from lab_info_windows.md> |
| PowerShell | runs Atomic tests | <e.g. 5.1.xxxxx Desktop> |
| PowerShell Script Block Logging | EID 4104 | enabled (670 EID 4104 events in the export, Figure 40) |
| Sysmon | endpoint telemetry | <e.g. Sysmon64 v15.x>, schema <x.xx> |
| Sysmon configuration | which events are logged | SwiftOnSecurity sysmon-config, file `sysmonconfig-export.xml`, downloaded <date>, SHA-256 <hash> |
| Sysmon events exported | sent to Splunk | EID 1, 3, 11, 12, 13, 22 + PowerShell 4104 (`export_sysmon_csv.ps1`) |
| Microsoft Defender | AV on the VM | <engine version; real-time protection off / on + exclusion C:\AtomicRedTeam> |
| Invoke-AtomicRedTeam | test runner module | <version>; atomics folder `C:\AtomicRedTeam\atomics` |
| Atomic Red Team atomics | test definitions | downloaded <date> with `Install-AtomicRedTeam -getAtomics` |
| **Linux VM — host name / user** | SIEM + listener | labvm, user `cisco` (Figure 39); IPv4 192.168.56.103 |
| Linux VM — distribution / kernel / resources | | <e.g. Ubuntu 22.04.4 LTS, kernel 6.5.0-xx-generic, vCPU / RAM> |
| Splunk | SIEM | <e.g. Splunk Enterprise 9.x.x (build xxxx)>; not available during the run (see 9.5) |
| Splunk index / sourcetype | where data is stored | index `sysmon`, sourcetype csv (Add Data → Upload) |
| netcat | TCP listener for step C2 | <package and version, e.g. netcat-openbsd 1.218>; port 15666 |

### 9.4.2 Setup steps

- Snapshot of the Windows VM taken before the run (snapshot name: before-week9, date 2026-11-14).
- Windows VM network switched to host-only before the tests (internet used only for the Atomic Red Team download).
- Change compared to Week 6: the CSV export now includes Sysmon **EID 11** (file create) and **EID 12/13** (registry), needed for Phase 5 (see Week 8, 8.6 note). PowerShell Script Block Logging (EID 4104) enabled.
- Scripts in this folder:

| Script | Purpose |
|---|---|
| `collect_lab_info.ps1` / `collect_lab_info.sh` | collect exact versions for 9.4.1 |
| `meduza_atomic_run.ps1` | runs tests A1, A3–A7, custom steps C1–C2, writes `run_log.csv`, cleanup |
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

<img width="825" height="400" alt="image" src="https://github.com/user-attachments/assets/a8fb80d8-cf15-4a1c-9727-e0b1f09a5986" />


*Figure 36. Invoke-AtomicRedTeam installed, `-ShowDetailsBrief` output for T1547.001 (T1547.001-1 "Reg Key Run" is the test used for A7).*

## 9.5 Running the tests

```powershell
powershell -ExecutionPolicy Bypass -File .\meduza_atomic_run.ps1 -ListenerIp 192.168.56.103
powershell -ExecutionPolicy Bypass -File .\export_sysmon_csv.ps1 -Minutes 60
# then: Splunk → Settings → Add Data → Upload → index=sysmon (same as Week 6)
```

For C2 a listener was started on the Linux VM first: `nc -lvnp 15666 > received.txt` (port 15666 is reused from our IOC only as a label; the target is our lab IP 192.168.56.103).

The script ran the tests in sequence and wrote one line per step to `run_log.csv`. The whole run took about three minutes (08:46:46Z – 08:49:56Z). For A1 the prerequisite (the batch file `T1059.003_script.bat`) was created automatically and the test finished with exit code 0. For A3 two tests with the same name were run (T1082-1 and T1082-28). A4 printed the Windows IP configuration, A6 returned the system language `0409` (English, US), and A7 reported "The operation completed successfully." After the last step the script ran `-Cleanup` for all atomic tests and reminded us to export the logs before reverting the snapshot.

<img width="960" height="487" alt="image" src="https://github.com/user-attachments/assets/e0208e7e-c90a-4a25-9e8f-050b961a3b4a" />


*Figure 37a. Output of `meduza_atomic_run.ps1`: A1 (prerequisite met, test executed) and the start of A3 (T1082 System Information Discovery).*

<img width="636" height="341" alt="image" src="https://github.com/user-attachments/assets/a07a1b88-3c54-412a-b533-949266889087" />


*Figure 37b. Output of `meduza_atomic_run.ps1`: end of A3 (T1082-1 and T1082-28) and A4 (T1016 System Network Configuration Discovery).*

<img width="652" height="409" alt="image" src="https://github.com/user-attachments/assets/545f3bd7-4734-4788-b29b-267d66e8915b" />


*Figure 37c. Output of `meduza_atomic_run.ps1`: end of A5 (T1012), A6 (T1614.001, language 0409) and A7 (T1547.001-1 Reg Key Run).*

<img width="757" height="500" alt="image" src="https://github.com/user-attachments/assets/14f1b952-b82e-4f4a-9288-aedb4176ee79" />


*Figure 37d. Output of `meduza_atomic_run.ps1`: custom steps C1 and C2, path of `run_log.csv` and cleanup of all atomic tests.*

<img width="535" height="253" alt="image" src="https://github.com/user-attachments/assets/4ea1bce4-3775-45e1-9f78-14965bf7dd0a" />


*Figure 38. `run_log.csv`: eight steps with status "executed" (A1, A3, A4, A5, A6, A7, C1, C2); A2 is not in the log.*

<img width="816" height="91" alt="image" src="https://github.com/user-attachments/assets/b0d44436-b2a8-429d-a7bd-20408f1d64d6" />


*Figure 39. Linux listener (`labvm`) received the Base64 dummy data; decoded text: "DUMMY DATA - not a real secret - 2026-11-14T00:49:56.4038187-08:00".*

The decoded timestamp (00:49:56 at UTC−8) is the same moment as the C2 entry in the run log (08:49:56Z), so the data on the listener comes from this run. The `base64: invalid input` message appears after the full text was already printed; it is most likely caused by the missing trailing newline/padding in the received file and does not change the decoded content.

### Splunk queries

Splunk VM was unavailable during the run; the same logic was applied to the exported CSV in PowerShell. The SPL below is the query form prepared for Splunk.

**Overview of produced events**

```spl
index=sysmon
| stats count by EventCode
```

<img width="1000" height="233" alt="image" src="https://github.com/user-attachments/assets/e602065d-502d-470c-80a8-061258c34805" />


*Figure 40. PowerShell (exported CSV): event count by EventCode (EID 1 – 352, EID 3 – 1, EID 11 – 39, EID 13 – 3, EID 22 – 40, EID 4104 – 670).*

**A1 — CAR-2013-02-003 (Week 7) on Atomic output**

```spl
index=sysmon cmd.exe
| where EventCode=1 AND like(Image,"%cmd.exe") AND NOT match(ParentImage,"(?i)(explorer|cmd)\\.exe$")
| table _time Computer ParentImage Image CommandLine
```

**A3–A6 — discovery burst (several discovery tools from one parent in a short window)**

```spl
index=sysmon
| where EventCode=1 AND match(Image,"(?i)\\\\(systeminfo|ipconfig|reg|netsh|chcp|hostname|whoami)\\.exe$")
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

## 9.6 Results

Sources: `run_log.csv` (Figure 38), console output (Figure 37), Linux listener (Figure 39) and the CSV event counts (Figure 40). Queries per test were not captured, so a detection is not marked as "fired" unless it was checked.

| # | Technique | Ran? | Events in exported CSV | Event ID | Detection that fired | Notes |
|---|---|---|---|---|---|---|
| A1 | T1059.003 | yes (08:46:46Z, exit code 0) | EID 1 present in the export (352 in total); per-test match not checked | 1 | CAR-2013-02-003: not verified | Prerequisite batch file created automatically; the runner itself starts from PowerShell, so a hit is expected |
| A2 | T1059.001 | **no** | — | 1 / 4104 | — | Not in `run_log.csv`; 670 EID 4104 events in the export come from the whole session, not from A2 |
| A3 | T1082 | yes (08:47:57Z) | per-test match not checked | 1 | discovery burst: not verified | Two tests ran: T1082-1 and T1082-28 |
| A4 | T1016 | yes (08:48:05Z) | per-test match not checked | 1 | discovery burst: not verified | `ipconfig /all`-type output shown in console |
| A5 | T1012 | yes (08:49:31Z) | per-test match not checked | 1 | discovery burst: not verified | Test T1012-1 Query Registry |
| A6 | T1614.001 | yes (08:49:39Z) | per-test match not checked | 1 | discovery burst: not verified | Language registry value `0409` returned |
| A7 | T1547.001 | yes (08:49:48Z) | 3 EID 13 events in the export; TargetObject not checked | 13 | Run-key query: not verified | "The operation completed successfully"; cleanup executed; EID 12 not present in the export |
| C1 | T1005 | yes (08:49:56Z) | EID 11: 39 in the export; match on `meduza_sim` not checked | 1 / 11 | — | Week 8 Phase 7 |
| C2 | T1132.001, T1041 | yes (08:49:56Z) | 1 EID 3 event in the whole export (consistent with the C2 connection; port not checked) | 3 | Hunt 2 (Week 5): not verified | Data confirmed on the Linux listener (Figure 39) |

### Update of the Week 8 plan status

| Week 8 phase | Status before | Status after Week 9 |
|---|---|---|
| 2 Execution | executed (Week 6, own script) | repeated with Atomic: T1059.003 executed; T1059.001 not executed |
| 3 Discovery | executed (Week 6, own script) | repeated with Atomic: T1082, T1016, T1012, T1614.001 executed |
| 5 Persistence | planned | executed (T1547.001-1 Reg Key Run, cleaned up afterwards) |
| 7 Collection | planned | executed (custom step C1 with a dummy file) |
| 8 Exfiltration | planned | executed (custom step C2: Base64 dummy data sent to the lab listener and received) |

## 9.7 Detection coverage (gaps)

| Area | Covered by | Gap / tuning |
|---|---|---|
| Shell from unusual parent | CAR-2013-02-003 | Atomic framework itself runs from PowerShell → expected hit; allowlist needed in production |
| Discovery | discovery burst query | Admin scripts also run systeminfo/ipconfig; use as a hunting lead only |
| Persistence | Run-key query (EID 13) | Needs registry events in the export (3 EID 13 events were exported); only HKCU/HKLM Run covered |
| Exfiltration | Hunt 2 | Works only for a known IP:port; behavior-based detection still missing |
| Browser credentials | Hunt 4 (Week 5) | Not tested (safety), coverage unknown |

## 9.8 Limitations

- Atomic tests reproduce single techniques, not the full Meduza Stealer chain or the real malware.
- A2 (T1059.001) was not executed in this run, so the PowerShell execution behavior was not re-tested with Atomic.
- Phase 5 uses a generic technique; persistence is not confirmed for Meduza in our sources (Week 8).
- Splunk was unavailable during the run; only event counts from the exported CSV were captured, so matching each test to its events and detections was not completed.
- Logs are uploaded to Splunk as CSV in batches; `_time` may reflect upload time, use `UtcTime` (Week 7).
- The Windows VM is Windows Server 2022 (evaluation) configured as a domain controller, not a typical user workstation.
- One lab host, no baseline of normal activity → false-positive rate unknown.
- Atomic test names/numbers depend on the installed version.

## 9.9 Conclusion

We selected Atomic Red Team tests that match Meduza-like behaviors and the open phases of our Week 8 plan, prepared a run script, extended the Sysmon export with registry and file events, and ran the tests on 2026-11-14. Eight of nine steps were executed (A1, A3–A7, C1, C2); A2 was not. Phases 5 (persistence), 7 (collection) and 8 (exfiltration) moved from "planned" to "executed", and the exfiltration step was confirmed on the Linux listener. The exported CSV contains the expected event types (EID 1, 3, 11, 13, 22 and 4104), but the per-test detection check is still open because Splunk was not available. In Week 10 we compare these techniques with the TTPs of an APT group.

> **Note on AI use:** Test selection, scripts and query templates were prepared with the help of an AI tool. Lab execution, observed results and screenshots are the team's own.

## References

1. Red Canary — Atomic Red Team (GitHub repository and Wiki)
2. Red Canary — Invoke-AtomicRedTeam Wiki
3. MITRE ATT&CK — T1059.001, T1059.003, T1082, T1016, T1012, T1614.001, T1547.001, T1005, T1132.001, T1041
4. MITRE CAR — CAR-2013-02-003 Processes Spawning cmd.exe
5. Splunk Threat Research Team — Meduza Stealer Analysis
