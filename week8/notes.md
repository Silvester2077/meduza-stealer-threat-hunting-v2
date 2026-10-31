# Week 8: Creating a Plan to Emulate an Attacker's Actions

Topic: Meduza Stealer, adversary emulation plan (initial access → persistence → data exfiltration).

> **Status:** this is a *plan*. Steps marked "done" were executed in Week 6 and observed in Sysmon/Splunk. Steps marked "planned" have **not** been executed yet, and no results are claimed for them.

## 8.1 Key terminology

| Term | Definition |
|---|---|
| **Adversary emulation** | Reproducing the *behavior* of a real threat actor or malware, step by step, to test whether defenses see it. |
| **Emulation plan** | A written scenario: objective, scope, ordered steps mapped to ATT&CK, expected telemetry, success criteria, cleanup. |
| **Phase** | A group of steps with one goal (e.g. persistence). |
| **Ability (CALDERA)** | A single ATT&CK-mapped action in MITRE CALDERA; abilities are chained into an adversary profile. We use the same idea, written by hand. |
| **Rules of engagement** | Limits that keep the emulation safe (isolated VM, harmless data, cleanup). |

## 8.2 Objective and scope

**Objective.** Describe a simple, safe emulation of Meduza Stealer-like behavior, from first execution to data leaving the host, and check which steps our current detections (Sysmon, Splunk, CAR analytic from Week 7) can see.

**Scope.**

- One isolated Windows VM with Sysmon; Splunk on a separate Linux VM (host-only network).
- Harmless commands and dummy data only. No real malware, no real credentials, no internet exfiltration.
- Meduza is the *model* of behavior. Where our sources do not document a step for Meduza, the plan says so.

## 8.3 Threat profile (what we emulate)

Sources: Splunk Threat Research Team analysis of Meduza Stealer, our Week 4 sandbox analysis, and Weeks 6-7.

| Behavior | Source status |
|---|---|
| Runs from a user-writable path (Downloads/Temp) | Week 4 sandbox + Week 6 emulation |
| Region check, installed-software query, public-IP lookup | Documented by Splunk |
| `cmd /c ping ... & del ...` sleep and clean-up | Documented by Splunk |
| Browser credentials and cookies | Documented by Splunk |
| Base64-encoded data sent over TCP to a C2 server | Documented by Splunk |
| **Persistence** | **Not confirmed in our sources.** Included only because the scenario requires a persistence phase; labeled as a generic technique, not a Meduza claim. |
| Delivery / initial access vector | Not confirmed in our sources; out of scope (see Phase 1). |

## 8.4 Emulation plan

| # | Phase | ATT&CK tactic | Technique | Emulated action (harmless) | Expected telemetry | Status |
|---|---|---|---|---|---|---|
| 1 | Initial access / first execution | Execution | T1204.002 User Execution: Malicious File | User runs a file from `Downloads\sim\` (we assume the file is already on disk; delivery, e.g. phishing, is out of scope) | Sysmon EID 1 (`CurrentDirectory` = `Downloads\sim\`) | done (Week 6, S1) |
| 2 | Execution | Execution | T1059.001 PowerShell, T1059.003 Windows Command Shell | PowerShell script starts `cmd.exe /c ...` | Sysmon EID 1 (`ParentImage` = powershell.exe) | done (S5) |
| 3 | Discovery | Discovery | T1614, T1012, T1016 | Read region code, count `Uninstall` registry entries, DNS lookup of `api.ipify.org` | EID 22 for the DNS lookup; others print-only | done (S2-S4) |
| 4 | Defense evasion | Defense Evasion | T1497.003 Time Based Evasion; T1070.004 File Deletion (possible mapping) | `ping 127.0.0.1 -n 3` as delay, then delete one dummy file | EID 1 for `cmd.exe` and `PING.EXE` | done (S5) |
| 5 | **Persistence** | Persistence | T1547.001 Registry Run Keys / Startup Folder | Create a Run-key value that starts a harmless command (e.g. `cmd.exe /c echo test`), then remove it | Sysmon registry events (EID 13) if enabled in the config; EID 1 at next logon | planned |
| 6 | Credential access (optional) | Credential Access | T1555.003, T1539 | Only against a test profile with dummy files; **not planned for execution** | Security EID 4663 | excluded (safety) |
| 7 | **Collection** | Collection | T1005 Data from Local System | Read a dummy text file created for the test | EID 1 (command line), EID 11 if enabled | planned |
| 8 | **Exfiltration** | Exfiltration / C2 | T1132.001 Standard Encoding (Base64), T1041 Exfiltration Over C2 Channel | Base64-encode the dummy content and send it over TCP to a listener on the lab Linux VM (host-only network, no internet) | Sysmon EID 3 (`powershell.exe` → lab IP:port); detected by Hunt 2 (Week 5) | planned |
| 9 | Cleanup | n/a | n/a | Remove the Run-key value and dummy files, stop the listener, revert the VM snapshot | n/a | planned |

*Verify all technique IDs on attack.mitre.org before submission.*

## 8.5 Attack flow

```text
Phase 1-2: user runs script from Downloads  ->  powershell.exe  ->  cmd.exe
Phase 3:   region / software / public-IP checks (DNS lookup of api.ipify.org)
Phase 4:   ping delay  ->  delete dummy file
Phase 5:   persistence (harmless Run-key value)
Phase 7-8: read dummy data  ->  Base64  ->  TCP to lab listener
Phase 9:   cleanup, snapshot revert
```

ATT&CK Navigator layer

We visualized the plan as an ATT&CK Navigator layer ([`week8_meduza_layer.json`](./images/week8_meduza_layer.json)). Green techniques were executed in Week 6, yellow techniques are planned (Phases 5, 7, 8), and grey techniques are excluded for safety.

Open the layer in ATT&CK Navigator: [Meduza emulation plan layer](https://mitre-attack.github.io/attack-navigator/#layerURL=https%3A%2F%2Fraw.githubusercontent.com%2FSilvester2077%2Fmeduza-stealer-threat-hunting-v2%2Fmain%2Fweek8%2Fimages%2Fweek8_meduza_layer.json)

## 8.6 Detection coverage (what we expect to see)

| Phase | Detection we already have | Gap |
|---|---|---|
| 1 | Hunt 3 (user-writable path), Week 5 | none expected |
| 2, 4 | CAR-2013-02-003 Processes Spawning cmd.exe (Week 7) + `ping`/`del` refinement | depends on the parent being unusual |
| 3 | DNS query in Sysmon EID 22 (seen in Splunk, Week 6) | no analytic yet; a single DNS lookup is weak evidence on its own |
| 5 | none | needs registry events exported to Splunk (EID 12/13) and a persistence analytic; the analytic is still to be chosen from CAR |
| 8 | Hunt 2 (IP:port, EID 3), Week 5 | the lab IP/port must be added to the hunt |

**Note.** Our Week 6 CSV export contained only Sysmon Event IDs 1, 3 and 22. Persistence (Phase 5) needs registry events, so the export must include EID 12/13 (and EID 11 for file creation) before that phase can be validated.

## 8.7 Success criteria

- Every executed step has a Sysmon event in Splunk (or is recorded as "not found").
- Each step is mapped to an ATT&CK technique.
- For each phase we state whether an existing detection fires, and list the gaps.

## 8.8 Rules of engagement and safety

- Isolated Windows VM, snapshot taken before the run, host-only network.
- Dummy data only; the listener is on our own lab VM; nothing leaves the lab network.
- Persistence value is harmless and removed in cleanup.
- Browser credential steps (Phase 6) are not executed.

## 8.9 Results

This week's deliverable is the plan. Phases 1-4 were executed in Week 6 and observed in Sysmon and Splunk (see the Week 6-7 report: S1 and S5 as `EventCode=1`, S4 as `EventCode=22`). Phases 5, 7 and 8 were **not executed**; they are planned for a later run (for example together with Atomic Red Team tests in Week 9), and no results are claimed for them.

| Phase | Executed? | Evidence |
|---|---|---|
| 1-4 | Yes (Week 6) | Week 6-7 report, Figures 31-35 |
| 5 | No (planned) | n/a |
| 7 | No (planned) | n/a |
| 8 | No (planned) | n/a |

## 8.10 Limitations

- This is a simplified plan. It is not a full adversary emulation (no C2 framework, no real malware).
- Persistence and the initial-access delivery vector are not confirmed for Meduza in our sources.
- Phases 1-4 reuse Week 6 results; Phases 5, 7, 8 are planned and not executed, so their detection coverage in 8.6 is an expectation, not a measured result.
- Logs are exported to CSV and uploaded to Splunk in batches, not in real time.

## 8.11 Conclusion and next step

We turned the Week 6-7 findings into an ordered emulation plan with ATT&CK mappings, expected telemetry and detection coverage, and identified gaps (persistence and exfiltration visibility). In Week 9 we can run selected steps as Atomic Red Team tests and record the results in Splunk.


## References

1. [MITRE ATT&CK](https://attack.mitre.org/)
2. [MITRE CALDERA documentation](https://caldera.readthedocs.io/)
3. [MITRE CAR: CAR-2013-02-003 Processes Spawning cmd.exe](https://car.mitre.org/analytics/CAR-2013-02-003/)
4. [Splunk Threat Research Team: Meduza Stealer Analysis](https://www.splunk.com/en_us/blog/security/meduza-stealer-analysis.html)
