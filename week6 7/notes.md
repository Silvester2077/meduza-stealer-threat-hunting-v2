# Assignment 4: ATT&CK Framework (Week 6) and MITRE CAR (Week 7)

Topic: Meduza Stealer, behavior emulation and detection (Sysmon + Splunk).

---

# Week 6: ATT&CK Framework

## 6.1 Key terminology

| Term | Definition |
|---|---|
| **MITRE ATT&CK** | Knowledge base of adversary tactics and techniques based on real-world observations. |
| **Tactic** | The adversary's goal at a given step (the "why"), e.g. Execution. |
| **Technique / Sub-technique** | How a tactic is achieved (the "how"), e.g. T1059 and T1059.003. |
| **Procedure** | A concrete, observed implementation of a technique by specific malware or a group. |
| **Emulation / simulation** | Safely reproducing attacker *behavior* in a lab, without running the real malware. |

## 6.2 Selected technique: T1059.003 Command and Scripting Interpreter: Windows Command Shell

| Item | Description |
|---|---|
| **Tactic** | Execution |
| **Platform** | Windows |
| **Idea** | Adversaries use `cmd.exe` to run commands, batch scripts and built-in utilities. |
| **Why we chose it** | The public Splunk analysis of Meduza Stealer shows a `CMD.EXE /C ping ... & Del ...` command used as a delay and clean-up step. It is visible in process-creation telemetry (Sysmon Event ID 1). |
| **Data sources** | Process creation, command execution |
| **Reference** | https://attack.mitre.org/techniques/T1059/003/ |

`cmd.exe` is used constantly by administrators, installers and logon scripts, so the technique alone is not malicious. Context (parent process, path, command line) makes it suspicious.

## 6.3 The technique in Meduza Stealer

The Splunk Threat Research Team documents this command string in Meduza Stealer, used as a sleep (ping timeout) before removing files:

```text
CMD.EXE /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q *
```

Source: Splunk Threat Research Team, [Meduza Stealer Analysis](https://www.splunk.com/en_us/blog/security/meduza-stealer-analysis.html).

| Observation | Status |
|---|---|
| Splunk labels the ping-sleep behavior as T1497.003 (Time Based Evasion). | Documented by Splunk |
| The command runs through `cmd.exe /C`, so T1059.003 applies to *how* it is executed. | Our mapping, based on the command string |
| `Del /f /q *` removes files, which resembles T1070.004 (File Deletion). | Possible mapping, not confirmed by the source |

We did not observe this command in our own ANY.RUN session (Week 4); it comes from public reporting.

## 6.4 Simulation plan

We do **not** run Meduza Stealer. We emulate selected *behaviors* with harmless commands in an isolated Windows VM.

**Lab setup**

- Windows host with Sysmon (SwiftOnSecurity config; Event IDs 1, 3, 22).
- Splunk runs on a separate Linux VM. Sysmon events were exported from Windows to CSV with PowerShell (`Get-WinEvent`) and uploaded through the Splunk web interface (Settings → Add Data → Upload) into the index `sysmon`.
- Script: [`meduza_behavior_sim.ps1`](./meduza_behavior_sim.ps1), run with `powershell -ExecutionPolicy Bypass -File .\meduza_behavior_sim.ps1`.

<img width="965" height="672" alt="image" src="https://github.com/user-attachments/assets/d3f24d21-fa98-4755-885a-7d08b2b15747" />


*Figure 29. Event Viewer, Microsoft-Windows-Sysmon/Operational: the Sysmon log is working and collecting events.*

<img width="1181" height="656" alt="image" src="https://github.com/user-attachments/assets/a865d993-512d-4602-a8ce-37c031e6b7b4" />


*Figure 30. Splunk confirms the CSV file was uploaded successfully (Add Data → Upload).*

| Step | Emulated behavior | Harmless emulation | ATT&CK technique | Expected telemetry |
|---|---|---|---|---|
| S1 | Execution from a user-writable path | Run the script from `Downloads\sim\` | T1204.002 | Sysmon EID 1 |
| S2 | Region check | Read the current region code; print only | T1614 | PowerShell logs (if enabled) |
| S3 | Installed-software query | Count entries under the `Uninstall` registry keys | T1012 | Sysmon EID 1 |
| S4 | Public-IP lookup | DNS resolution of `api.ipify.org` | T1016 | Sysmon EID 22 |
| S5 | Command shell ping-sleep and delete | `cmd.exe /c ping 127.0.0.1 -n 3 > nul & del /f /q <dummy file>` | T1059.003, T1497.003 | Sysmon EID 1 |
| S6 | Browser credential store access (optional) | Read-only copy of `Login Data` from a test profile | T1555.003 | Security EID 4663 |

**Safety notes**

- The original command ends with `Del /f /q *`, which deletes everything in the current folder. Our version deletes only one named dummy file in a scratch folder.
- The ping target is `127.0.0.1` instead of `1.1.1.1`, so the delay generates no external traffic.
- Step S6 was **not run**, because it touches a real browser credential file.

## 6.5 Simulation results

| Step | Ran? | Event found in Splunk? | Event ID | Notes |
|---|---|---|---|---|
| S1 | Yes | Yes (indirect) | 1 | In the S5 event, `CurrentDirectory` is `...\Downloads\sim\` and `ParentCommandLine` is `powershell.exe -ExecutionPolicy Bypass -File .\meduza_behavior_sim.ps1`, so the script ran from a user-writable path |
| S2 | Yes | No (none expected) | n/a | Script printed `Current region code: US`; only Sysmon EIDs 1, 3 and 22 were exported to Splunk |
| S3 | Yes | TODO | 1 | Script printed `Installed software entries found: 401`; no dedicated Sysmon event identified yet |
| S4 | Yes | **Yes** | 22 | `powershell.exe` resolved `api.ipify.org` (Figure 33) |
| S5 | Yes | **Yes** | 1 | `ParentImage` = `powershell.exe`, `Image` = `cmd.exe`, command line contains `ping 127.0.0.1 -n 3` and `del /f /q ...\dummy.txt`; a separate `PING.EXE` process-creation event also exists (Figure 32) |
| S6 | No | n/a | 4663 | Deliberately not run (safety) |

<img width="1378" height="485" alt="image" src="https://github.com/user-attachments/assets/6fcf8d0f-8d19-40ae-a4e9-38db371267ac" />


*Figure 31. PowerShell output of the simulation script, steps [S1]...[S5] (user name redacted).*

<img width="707" height="187" alt="image" src="https://github.com/user-attachments/assets/2a75c0b1-613a-4fbb-b9fa-a38f0abd234d" />


*Figure 32. Sysmon Process Create event (Event ID 1) for `PING.EXE` in Event Viewer, produced by the S5 command.*

<img width="1542" height="287" alt="image" src="https://github.com/user-attachments/assets/c73f4783-6473-41fd-999e-387f97716af3" />

*Figure 33. Splunk: `index=sysmon ipify | where EventCode=22 | table _time Image QueryName` returns the S4 DNS query for `api.ipify.org` made by `powershell.exe`.*

The S5 event as seen in Splunk is shown in Figure 35 (Week 7).

## 6.6 Mapping results to ATT&CK

| Observed / documented behavior | Tactic | Technique | Evidence |
|---|---|---|---|
| Script started from `Downloads\sim\` | Execution | T1204.002 User Execution: Malicious File | Lab emulation (S1) |
| `cmd.exe /C` command string | Execution | T1059.003 Windows Command Shell | Splunk article + lab emulation (S5, observed) |
| PowerShell launching the script and `cmd.exe` | Execution | T1059.001 PowerShell | Lab emulation (parent process in S5) |
| Ping-based delay | Defense Evasion | T1497.003 Time Based Evasion | Splunk article + lab emulation (S5) |
| File deletion with `del` | Defense Evasion | T1070.004 File Deletion | Possible mapping only |
| Region check | Discovery | T1614 System Location Discovery | Splunk article |
| Installed-software registry query | Discovery | T1012 Query Registry | Splunk article |
| Public-IP lookup via `api.ipify.org` | Discovery | T1016 System Network Configuration Discovery | Splunk article |
| Browser credentials and cookies | Credential Access | T1555.003, T1539 | Week 4 + Splunk article |
| Encrypted configuration / C2 traffic | Command and Control | T1573 Encrypted Channel | Splunk article |
| Data sent to C2 | Exfiltration | T1041 Exfiltration Over C2 Channel | Splunk article |

*Verify all technique IDs on attack.mitre.org before submission.*

## 6.7 Limitations (Week 6)

- The simulation reproduces **behaviors**, not the real malware. It validates telemetry and mapping, not detection of real Meduza samples.
- Technique mappings taken from the Splunk article are the authors' analysis; we did not reverse-engineer the malware ourselves.
- T1070.004 is a possible mapping only.
- Results depend on the Sysmon configuration in our VM.

---

# Week 7: Using MITRE CAR

## 7.1 Key terminology

| Term | Definition |
|---|---|
| **MITRE CAR** | Knowledge base of analytics based on the ATT&CK model. Each analytic has a hypothesis, required data and pseudocode or tool-specific implementations. |
| **Analytic** | A description of observable behavior that can identify a technique (hypothesis + logic). |
| **Detection** | A tuned, deployed implementation of an analytic (thresholds, allowlists, response). |
| **Data model** | Standard objects, actions and fields used by CAR (e.g. `process / create / exe`). |

An analytic explains *what behavior to look for and why*. A detection is what we deploy after adapting it to our data schema and testing it against legitimate activity.

## 7.2 Selected analytic

| Item | Description |
|---|---|
| **Analytic** | [CAR-2013-02-003: Processes Spawning cmd.exe](https://car.mitre.org/analytics/CAR-2013-02-003/) |
| **Supporting analytic** | [CAR-2014-11-002: Outlier Parents of Cmd](https://car.mitre.org/analytics/CAR-2014-11-002/) |
| **ATT&CK coverage** | T1059.003 (Execution), coverage level Moderate according to CAR |
| **CAR data model** | `process / create / exe` |
| **Hypothesis (CAR)** | `cmd.exe` is normally started by `explorer.exe` or another command prompt. Other parents may indicate malice (e.g. a document reader or mail client launching a shell). |

*Verify the analytic IDs and coverage level on car.mitre.org before submission.*

**Why this analytic.** In Week 6 we emulated the `cmd.exe /C ping ... & del ...` pattern documented for Meduza Stealer. This analytic detects the shell launch itself, so it connects directly to that work.

## 7.3 Mapping to ATT&CK and Meduza Stealer

| Meduza-related behavior | ATT&CK technique | Covered by CAR-2013-02-003? | Comment |
|---|---|---|---|
| `cmd.exe /C ping ... & Del ...` | T1059.003 | Yes (partially) | Detects the shell launch; does not judge the command content by itself. |
| Ping-based delay | T1497.003 | Indirect | The command line can be inspected as an extra filter. |
| Execution from a user-writable path | T1204.002 | No | Covered by Hunt 3 (Week 5). |
| Browser credential/cookie access | T1555.003, T1539 | No | Covered by Hunt 4 (Week 5). |
| C2 communication | T1573, T1041 | No | Covered by Hunt 2 (Week 5). |

A single CAR analytic covers one technique. For Meduza Stealer several detections must work together; this analytic closes the *command shell* gap.

## 7.4 SIEM implementation (Splunk)

**Data note.** Sysmon events were uploaded to Splunk as CSV. On this data, field filters in the base search (for example `Image="*cmd.exe"` or `CommandLine="*ping*"`) returned no results, although a plain keyword search found the events. The queries therefore select events with keywords first and filter fields afterwards with `where` and `like()`. The exact cause was not investigated.

### Implementation A: cmd.exe from unusual parents (CAR-2013-02-003)

```spl
index=sysmon cmd.exe
| where EventCode=1 AND like(Image,"%cmd.exe") AND NOT match(ParentImage,"(?i)(explorer|cmd)\\.exe$")
| stats count min(_time) as first_seen max(_time) as last_seen values(CommandLine) as cmd by Computer ParentImage
| sort - count
```

Logic: find `cmd.exe` process creations whose parent is not `explorer.exe` or `cmd.exe` (the normal parents in the CAR hypothesis). In our lab, the emulation script should show `ParentImage = powershell.exe`.

### Behavior-specific refinement (Meduza-like command line)

This is the query that was run and produced the result below. It is narrower than the CAR analytic and easy for an attacker to change.

```spl
index=sysmon ping del
| where EventCode=1 AND like(Image,"%cmd.exe") AND like(CommandLine,"%ping%") AND like(CommandLine,"%del%")
| table _time Computer ParentImage Image CommandLine
```

### Implementation B: outlier parents (CAR-2014-11-002 idea)

Not run. Our lab has no 30-day baseline of `cmd.exe` parents, so every parent would look "new". The idea is documented in CAR; applying it needs historical data.

## 7.5 Test plan and results

| Test | Action | Expected | Actual result |
|---|---|---|---|
| T1 | Run `meduza_behavior_sim.ps1` (step S5), then run the refinement query (All time) | `cmd.exe` with parent `powershell.exe` | **Observed: 1 event**, `ParentImage` = `...\WindowsPowerShell\v1.0\powershell.exe`, `Image` = `...\System32\cmd.exe`, `CommandLine` = `cmd.exe /c ping 127.0.0.1 -n 3 > nul & del /f /q "...\meduza_sim\dummy.txt"`. See Figure 35 |
| T2 | Open `cmd.exe` from the Start menu | Not returned (parent `explorer.exe`) | Not performed |
| T3 | Run a harmless batch file from an installer-like tool | Possible false positive | Not performed |
| T4 | Implementation B right after the simulation | Needs a baseline | Not performed (no baseline) |

<img width="1541" height="310" alt="image" src="https://github.com/user-attachments/assets/2c2dd4f4-c740-4742-abc8-cdd7192722bf" />


*Figure 34. `index=sysmon | stats count by EventCode` (All time): 305 events in total (EventCode 1: 83, EventCode 22: 77, EventCode 3: 145).*

<img width="1550" height="293" alt="image" src="https://github.com/user-attachments/assets/c38523d4-e96c-45e7-a804-0a61695113c8" />


*Figure 35. Splunk result for the refinement query: `powershell.exe` → `cmd.exe` with `ping` and `del` in the command line (user name redacted).*

## 7.6 From analytic to detection (tuning)

| Issue | Example | Tuning idea |
|---|---|---|
| Legitimate admin scripts | PowerShell or management tools launching `cmd.exe` | Allowlist known parent + path combinations |
| Installers and updaters | Installers spawn `cmd.exe` | Allowlist signed installers; require extra signals |
| Too many alerts | Many hosts show the same parent | Raise priority only when combined with a user-writable image path or network activity |
| Easy to evade | Attacker renames or uses another interpreter | Add related analytics (PowerShell, irregular parents) |

Combined detection idea: raise severity when (1) `cmd.exe` has an unusual parent, (2) the parent runs from a user-writable folder (Hunt 3), and (3) the same host connects to the investigated IP (Hunt 2) within a short time window. This is a correlation procedure that must be validated before production use.

## 7.7 Limitations (Week 7)

- Logs were exported to CSV and uploaded in a batch. They were not forwarded in real time by a Splunk forwarder.
- The result is a single event on a single lab host.
- The Splunk `_time` of the uploaded events (07:16:18) differs from the Sysmon event time seen in Event Viewer for the same run (07:03:44 UTC), so `_time` appears to reflect the export or upload time. The `UtcTime` field holds the real event time.
- Field filters in the base search did not work on the CSV data, so queries use `where` with `like()`. The cause was not investigated.
- CAR-2013-02-003 rates its coverage of T1059.003 as moderate; it detects the shell launch, not every malicious use.
- Legitimate software also launches `cmd.exe` from many parents, and `cmd /c` with ping and del occurs in legitimate scripts, so false positives are possible. The result is a hunting lead, not a verdict.
- Baseline-based analytics need historical data that a new lab does not have.
- Results come from emulation of behaviors, not from real Meduza Stealer execution.

## 7.8 Conclusion

In Weeks 6 and 7 we studied T1059.003, linked it to a documented Meduza Stealer command string, emulated Meduza-like behaviors safely, and mapped them to ATT&CK. We selected the CAR analytic *Processes Spawning cmd.exe*, implemented it in Splunk and confirmed that the emulated chain `powershell.exe → cmd.exe (ping + del)` is captured by Sysmon Event ID 1. We also listed which Meduza behaviors this analytic does not cover.

> **Note on AI use:** The simulation script and the query templates were prepared with the help of an AI tool (Claude Sonnet 5.5), including debugging the Splunk queries. Lab execution, observed results and screenshots are the author's own.

## References

1. [MITRE ATT&CK: T1059.003](https://attack.mitre.org/techniques/T1059/003/)
2. [MITRE CAR: CAR-2013-02-003 Processes Spawning cmd.exe](https://car.mitre.org/analytics/CAR-2013-02-003/)
3. [MITRE CAR: CAR-2014-11-002 Outlier Parents of Cmd](https://car.mitre.org/analytics/CAR-2014-11-002/)
4. [Splunk Threat Research Team: Meduza Stealer Analysis](https://www.splunk.com/en_us/blog/security/meduza-stealer-analysis.html)
5. [SwiftOnSecurity sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)
