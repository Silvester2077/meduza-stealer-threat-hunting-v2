# Week 5 — Threat Hunting Concept

## 5.1 Key Terminology

Terms from previous weeks, such as CTI, IOC, TTP, C2, Cyber Kill Chain, and MITRE ATT&CK techniques, are not repeated here.

| Term | Definition |
|---|---|
| **Threat Hunting** | Proactive investigation to find potentially malicious activity that existing alerts may have missed. |
| **Hunting Hypothesis** | A testable statement describing possible attacker behavior and the evidence it may produce. |
| **Intel-driven Hunting** | Hunting that starts from threat intelligence, such as known indicators or public reports. |
| **Hypothesis-driven Hunting** | Hunting that starts from an assumption about suspicious behavior. |
| **Telemetry** | Data collected from systems and networks, such as process, file, authentication, and network events. |
| **Hunt Query** | A search used to investigate collected telemetry in a security analysis platform. |
| **False Positive** | A legitimate activity incorrectly identified as suspicious. |

## 5.2 Threat Hunting Models

Two hunting models are relevant to our Meduza Stealer project.

| Model | Starting point | Example for Meduza Stealer |
|---|---|---|
| **Intel-driven** | Known indicators and threat reports | Search available logs for the SHA-256 hash and the IP address `62.60.244.198`, port `15666`. |
| **Hypothesis-driven** | A hypothesis about attacker behavior | Investigate whether a suspicious process accesses browser credential files and then makes an external network connection. |

Intel-driven hunting can quickly find known indicators, but it may miss modified samples or new infrastructure. Hypothesis-driven hunting focuses on behavior and may identify suspicious activity even when the exact hash or IP address has changed.

For our project, we use both approaches. The indicators collected in Weeks 2–3 support intel-driven hunting, while the behavior investigated in Week 4 provides a basis for a hypothesis-driven hunt.

<img width="721" height="414" alt="image" src="https://github.com/user-attachments/assets/7f757772-2525-4806-b03f-965a7f24c2dd" />

>  **Note on AI use:** The diagram in Figure 25 was generated with the help of an AI tool (Claude) to visualize our own comparison of the two hunting models.

*Figure 25. Comparison of intel-driven and hypothesis-driven threat hunting.*

**Figure 25 source links:**
- [SANS — The Who, What, Where, When, Why and How of Effective Threat Hunting](https://www.sans.org/white-papers/who-what-where-when-why-how-effective-threat-hunting)
- [Microsoft — Conduct end-to-end proactive threat hunting](https://learn.microsoft.com/azure/sentinel/hunts)

*Note: Figure 25 is a team-created diagram based on these references, not an image copied from either website.*

## 5.3 Hunting Scenario — Hypothesis-driven

The scenario is based on our Week 4 analysis and the related MITRE ATT&CK techniques.

| Item | Description |
|---|---|
| **Hypothesis** | A suspicious executable may be launched from a user-writable directory, access browser credential or cookie files, and communicate with external infrastructure. |
| **Related ATT&CK techniques** | [T1204.002 — User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/), [T1555.003 — Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/), [T1539 — Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/), [T1005 — Data from Local System](https://attack.mitre.org/techniques/T1005/), and [T1071.001 — Web Protocols](https://attack.mitre.org/techniques/T1071/001/). |
| **Expected evidence** | 1. An executable starts from a user-writable directory. 2. A suspicious process accesses browser profile files. 3. The process makes an external network connection around the same time. |
| **Data sources** | Sysmon process creation (Event ID 1), Sysmon network connection (Event ID 3), and Windows Security file access auditing (Event ID 4663), if configured. |
| **Scope** | Windows endpoints in the lab where the required telemetry is available. |
| **Success criteria** | Determine whether the expected activity is present in the available logs and document the evidence or the limitations that prevent verification. |

The scenario describes behavior to investigate; it does not claim that these actions were observed on a real infected endpoint.

### Hunting workflow

1. Build the hypothesis.
2. Map the hypothesis to MITRE ATT&CK techniques.
3. Collect the required telemetry.
4. Hunt and investigate: run the hunt queries, review the results, and confirm, reject, or leave the hypothesis unresolved if the evidence is insufficient.
5. Document the findings.
6. Improve detections.

<img width="914" height="749" alt="image" src="https://github.com/user-attachments/assets/2e01d6d9-0119-48e2-9bc6-9edddc1b0117" />


*Figure 26. Threat hunting workflow designed for the Meduza Stealer investigation.*

**Figure 26 source links:**
- https://srql.com/knowledge/threat-hunting-mitre-attack-mapping/

## 5.4 Hunt Queries

The following queries are templates for environments that collect the required events. Field names and index names may need to be adjusted to match the actual Splunk or ELK configuration.

### Hunt 1 — Intel-driven: Known SHA-256 hash

**Splunk SPL**

```spl
index=sysmon EventCode=1
Hashes="*8844D41002892739EE42DB2B481E67D6EDBAAA0A9B9DF5E314C2C083F2900BEE*"
| table _time Computer User Image CommandLine ParentImage Hashes
```

**ELK — KQL**

```text
winlog.event_id: 1 and
process.hash.sha256: "8844d41002892739ee42db2b481e67d6edbaaa0a9b9df5e314c2c083f2900bee"
```

These queries search for process creation events containing the known hash. They require Sysmon process events with the hash field populated and correctly mapped.

### Hunt 2 — Intel-driven: Investigate the IP address

**Splunk SPL**

```spl
index=sysmon EventCode=3 DestinationIp="62.60.244.198" DestinationPort=15666
| stats count min(_time) as first_seen max(_time) as last_seen
  by Computer Image User DestinationIp DestinationPort
```

**ELK — KQL**

```text
winlog.event_id: 3 and
destination.ip: "62.60.244.198" and
destination.port: 15666
```

These queries look for network connection events involving the investigated IP address and port. The IP is an indicator collected from public threat intelligence sources; its presence in the dataset does not prove that a lab endpoint is infected.

### Hunt 3 — Hypothesis-driven: Executables launched from user-writable folders

**Splunk SPL**

```spl
index=sysmon EventCode=1
(Image="*\\Downloads\\*" OR
 Image="*\\AppData\\Local\\Temp\\*" OR
 Image="*\\AppData\\Roaming\\*")
| stats count values(CommandLine) as cmd
  by Computer User Image ParentImage
| sort - count
```

This query searches for process creation events where the executable path contains common user-writable directories. Such paths are not malicious by themselves; legitimate installers and portable applications may also run from these locations.

### Hunt 4 — Hypothesis-driven: Access to browser credential files

**Splunk SPL**

```spl
index=wineventlog EventCode=4663
(ObjectName="*\\Google\\Chrome\\User Data\\*\\Login Data" OR
 ObjectName="*\\Google\\Chrome\\User Data\\*\\Cookies" OR
 ObjectName="*\\Microsoft\\Edge\\User Data\\*\\Login Data" OR
 ObjectName="*\\Microsoft\\Edge\\User Data\\*\\Cookies")
| table _time Computer SubjectUserName ProcessName ObjectName
```

This query searches for Windows Security file access events involving selected browser profile files. It requires the appropriate file-system auditing policy and SACLs to be configured. Without this configuration, Event ID 4663 may not be generated for the files being investigated.

Review the process name and user context to identify unexpected access. Do not assume that every access to browser data is malicious.

### Hunt 5 — Correlation: File access and network activity

The purpose of this hunt is to investigate whether a suspicious process accesses browser files and makes an external network connection around the same time.

First, run Hunt 4 to identify relevant file access events. Then run Hunt 2 or review Sysmon Event ID 3 records for network activity.

Compare the events using the available fields, such as computer name, process identity, timestamp, and destination. Check whether the events occur within a relevant time window.

**Important:** this is a correlation procedure, not a single validated correlation query. Process IDs can be reused, and the Security log and Sysmon may represent process information differently. Strong correlation requires matching the same process reliably and checking the event timestamps.

### Screenshot for the queries

<img width="1283" height="776" alt="image" src="https://github.com/user-attachments/assets/477722a0-a82a-40d5-a5d8-0118a3099aa3" />


*Figure 27. Example of a Splunk search query for detecting suspicious access to Chrome browser credential data.*

**Figure 27 source links:**
- https://research.splunk.com/endpoint/0d32ba37-80fc-4429-809c-0ba15801aeaf/

*Screenshot note: Capture the actual query in your Splunk or Kibana interface. If the query was only prepared in the report and has not been executed, label the screenshot as a query example, not as an executed hunt.*

## 5.5 Hunt Results

Results must be completed after the queries have been run against available lab telemetry. Do not enter assumed matches or conclusions.

| Hunt | Query | Required data source | Result | Conclusion |
|---|---|---|---|---|
| 1 | Known SHA-256 hash | Sysmon Event ID 1 | To be recorded after execution | To be determined from evidence |
| 2 | IP address and port | Sysmon Event ID 3 | To be recorded after execution | To be determined from evidence |
| 3 | Executables from user-writable folders | Sysmon Event ID 1 | To be recorded after execution | Investigate suspicious paths and processes |
| 4 | Access to browser credential files | Windows Security Event ID 4663 | To be recorded after execution | Investigate unexpected file access |
| 5 | File access and network correlation | Sysmon and Windows Security logs | To be recorded after execution | Requires reliable process and time correlation |

If the query returns no matching events, record **"No matching events in the available dataset"**. Do not conclude that the system is clean: the relevant activity may not have occurred, or the required telemetry may be missing.

### Screenshot of the results

<img width="1168" height="291" alt="image" src="https://github.com/user-attachments/assets/d7023648-37b0-4bb8-baf6-2e48a27765e5" />



*Figure 28. Example result of the published Splunk detection "Windows Credentials from Password Stores Chrome Login Data Access" in a Splunk Attack Range lab, where a simulated Meduza Stealer payload (`C:\Temp\meduza_payload.exe`) accesses the Chrome "Login Data" file*

**Figure 28 source:** 
- https://www.splunk.com/en_us/blog/security/meduza-stealer-analysis.html


## 5.6 Detection Improvement

If the hunt identifies suspicious behavior, the logic can be reviewed for use as a permanent detection. Any detection should be tested against legitimate activity to reduce false positives.

| Detection idea | Related ATT&CK technique | Notes |
|---|---|---|
| Unexpected process access to browser credential files | [T1555.003](https://attack.mitre.org/techniques/T1555/003/), [T1539](https://attack.mitre.org/techniques/T1539/) | Requires file-access telemetry and an allowlist for legitimate applications. |
| Suspicious executable launch followed by an external connection | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Correlate process and network events; a user-writable path alone is insufficient. |
| Connection to the investigated IP and port | IOC-based detection | Useful for the known indicator, but infrastructure may change. |
| Suspicious process accessing local files before network activity | [T1005](https://attack.mitre.org/techniques/T1005/) | Requires appropriate file and process telemetry. |

T1071.001 should only be treated as a supported mapping if evidence confirms that the communication uses a relevant web protocol. An IP address and port alone do not establish the protocol.

## 5.7 Limitations

- The hunt depends on the logs and fields available in the lab.
- Sysmon Event IDs 1 and 3 require the relevant events to be collected.
- Windows Security Event ID 4663 requires appropriate file-access auditing configuration.
- IOC-based hunting may miss modified malware or new infrastructure.
- Public indicators do not prove that a real endpoint in our environment is infected.
- Passive DNS relationships do not prove that every related domain belongs to Meduza Stealer.
- No-match results do not prove that malicious activity is absent.
- The queries are templates and must be validated against the actual data schema before being used as production detections.

## 5.8 Conclusion

During Week 5, we moved from analyzing Meduza Stealer to planning a threat hunting investigation.

We compared intel-driven and hypothesis-driven hunting, developed a scenario based on our Week 4 analysis, and prepared queries for searching process creation, network connections, and browser file access.

The next step is to execute these queries against available lab telemetry, document the actual results, investigate possible false positives, and improve the detection logic where appropriate.

This work provides a basis for more detailed investigation using MITRE ATT&CK in the following week.

## References

1. [SANS — The Who, What, Where, When, Why and How of Effective Threat Hunting](https://www.sans.org/white-papers/who-what-where-when-why-how-effective-threat-hunting)
2. [Microsoft — Conduct end-to-end proactive threat hunting](https://learn.microsoft.com/azure/sentinel/hunts)
3. [Microsoft — The art and science of threat hunting](https://www.microsoft.com/en-us/security/blog/2022/09/08/part-1-the-art-and-science-of-threat-hunting/)
4. [MITRE ATT&CK](https://attack.mitre.org/)
5. [Splunk Search Tutorial](https://docs.splunk.com/Documentation/Splunk/latest/SearchTutorial/WelcometotheSearchTutorial)
6. [Elastic — Kibana Query Language](https://www.elastic.co/guide/en/kibana/current/kuery-query.html)

**Project evidence:** Query screenshots and hunt results should be captured from the team's actual lab environment. Any conclusions about detections must be based on the recorded evidence.
