# Week 10 — Learning APT Techniques: APT29 vs Meduza Stealer

Topic: analysis of APT29 TTPs, mapping to MITRE ATT&CK, and comparison with Meduza Stealer.

## 10.1 Key terminology

| Term | Definition |
|---|---|
| **APT (Advanced Persistent Threat)** | A well-resourced, usually state-linked group running long-term, targeted operations. |
| **APT29** | Group attributed to Russia's Foreign Intelligence Service (SVR); also tracked as Cozy Bear, NOBELIUM, Midnight Blizzard. MITRE ATT&CK ID **G0016**. |
| **Case study** | Analysis of one documented campaign (here: SolarWinds 2020, Microsoft corporate email 2024). |
| **Commodity malware** | Malware sold or rented to many criminals (e.g. Meduza Stealer, MaaS). |
| **Initial access broker** | Actor who sells access (e.g. stolen credentials/cookies) to other attackers. |
| **ATT&CK Navigator layer** | A JSON file that colors ATT&CK techniques, used here to compare two actors. |

## 10.2 Why APT29

- Meduza Stealer steals browser credentials and **session cookies** (Week 4, T1555.003 / T1539).
- APT29 is documented to abuse **stolen sessions, tokens and valid accounts** to access cloud and email (T1078, T1550).
- This gives a clear overlap: what a stealer collects is exactly what a targeted actor can use. APT41 is mainly known for exploitation of public-facing apps and supply chain, with less overlap.

## 10.3 APT29 case studies

| Campaign | What happened (short) | Source |
|---|---|---|
| **SolarWinds / SUNBURST (2020)** | Trojanized Orion update (supply chain), long dormancy, C2 over HTTP mimicking Orion traffic, then lateral movement and SAML token forging to access cloud email. | Mandiant (FireEye) SUNBURST report; MITRE ATT&CK C0024 |
| **Microsoft corporate email (2023–2024)** | Password spraying against a legacy test tenant account without MFA, then abuse of an OAuth application to read executives' mailboxes. | Microsoft MSRC blog, Jan 2024 |
| **Phishing campaigns** | Spearphishing with links/attachments (e.g. HTML smuggling, ISO/LNK) delivering loaders. | MITRE ATT&CK G0016; CrowdStrike Global Threat Report |

## 10.4 APT29 TTP mapping to MITRE ATT&CK

| Tactic | Technique | APT29 procedure (short) |
|---|---|---|
| Initial Access | T1195.002 Compromise Software Supply Chain | SolarWinds Orion update |
| Initial Access | T1566.001 / T1566.002 Spearphishing Attachment / Link | phishing with loaders |
| Execution | T1204.002 User Execution: Malicious File | victim opens the delivered file |
| Credential Access | T1110.003 Password Spraying | Microsoft 2024 incident |
| Initial Access / Persistence | T1078.004 Valid Accounts: Cloud Accounts | use of compromised accounts |
| Execution | T1059.001 PowerShell | post-exploitation scripting |
| Persistence | T1547.001 Registry Run Keys | persistence on hosts |
| Defense Evasion | T1027 Obfuscated Files or Information | obfuscated payloads |
| Defense Evasion | T1070.004 File Deletion | removing tools after use |
| Discovery | T1082 / T1016 System / Network Discovery | host and network reconnaissance |
| Credential Access | T1003.006 DCSync | domain credential theft |
| Credential Access | T1606.002 Forge Web Credentials: SAML Tokens | "Golden SAML" (SolarWinds) |
| Lateral Movement | T1021.006 Windows Remote Management | movement inside the network |
| Defense Evasion | T1550.001 / T1550.004 Use Alternate Authentication Material | application tokens / web session cookies |
| Command and Control | T1071.001 Web Protocols | HTTP(S) C2 |
| Exfiltration | T1041 Exfiltration Over C2 Channel | data sent over the existing C2 channel |
| Collection | T1114.002 Remote Email Collection | reading mailboxes via Exchange/Graph |

*All technique IDs were checked against the ATT&CK page of group G0016 (see 10.6 for the access date).*

## 10.5 Comparison: APT29 vs Meduza Stealer

| Technique | Meduza Stealer (our Weeks 4–9) | APT29 | Overlap |
|---|---|---|---|
| T1204.002 User Execution | yes (Week 4, sandbox) | yes (phishing payloads) | ✓ |
| T1059.001 / .003 PowerShell / cmd | yes (Weeks 6–7); T1059.003 re-run with Atomic in Week 9 | yes | ✓ |
| T1082 / T1016 Discovery | yes (Splunk article; re-run with Atomic in Week 9) | yes | ✓ |
| T1012 Query Registry, T1614.001 System Language Discovery | yes (Week 6, Week 9) | — | Meduza only |
| T1547.001 Run Keys | not confirmed (Week 8); run only as a generic Atomic test in Week 9 | yes | ? |
| T1070.004 File Deletion | possible (Week 6) | yes | ✓ (possible) |
| T1555.003 Browser credentials | yes (core function) | — | Meduza only |
| T1539 Steal Web Session Cookie | yes (core function) | — (uses stolen sessions through T1550.004) | **key link**: T1539 → T1550.004 |
| T1005 Data from Local System, T1132.001 Standard Encoding | yes (Week 9, custom steps C1 and C2) | — | Meduza only |
| T1041 Exfiltration over C2 | yes | yes | ✓ |
| T1195.002 Supply chain | — | yes | APT29 only |
| T1003.006 DCSync, T1606.002 Golden SAML | — | yes | APT29 only |
| T1021.006 Lateral movement | — | yes | APT29 only |

| Aspect | Meduza Stealer | APT29 |
|---|---|---|
| Motivation | financial (selling stolen data, MaaS) | espionage |
| Targeting | mass, opportunistic (gamers, "cheats", cracks) | selected government, IT, think tanks |
| Dwell time | seconds–minutes (steal and exit) | months |
| Kill chain coverage | ends at Actions on Objectives on one host | full chain incl. lateral movement and cloud |

## 10.6 ATT&CK Navigator layer

| Tool / data | Exact version / value |
|---|---|
| MITRE ATT&CK (Enterprise) | [FILL: version shown on attack.mitre.org], accessed [FILL: date] |
| ATT&CK Navigator | web version [FILL: version from the ⓘ / about window], https://mitre-attack.github.io/attack-navigator/ |
| Browser used | [FILL: browser and version] |
| APT29 group page | https://attack.mitre.org/groups/G0016/ , accessed [FILL: date] |

File: `week10_apt29_meduza_layer.json` (open in ATT&CK Navigator → Open Existing Layer → Upload from local). Colors: **red** = Meduza only, **blue** = APT29 only, **purple** = both. The layer has 27 techniques: 7 in both, 6 Meduza only, 14 APT29 only.

[INSERT Navigator screenshot HERE]

*Figure 42. ATT&CK Navigator layer: APT29 vs Meduza Stealer.*

## 10.7 Threat hunting hypotheses from the comparison

| # | Hypothesis | ATT&CK | Data source |
|---|---|---|---|
| H1 | A stealer infection on an employee's PC can be followed by a login with the stolen session from a new IP/ASN (cookie replay). | T1539 → T1550.004 / T1078 | IdP / cloud sign-in logs |
| H2 | PowerShell launching `cmd.exe` and discovery tools within minutes (Weeks 7, 9) is a shared early-stage pattern for both commodity and APT activity. | T1059, T1082, T1016 | Sysmon EID 1 |
| H3 | A new Run-key value created by a process from a user-writable folder indicates persistence regardless of actor. | T1547.001 | Sysmon EID 13 |

## 10.8 Limitations

- APT29 TTPs come from public reports (Mandiant, Microsoft, CrowdStrike, MITRE); we did not observe APT29 activity ourselves.
- Overlap of techniques does **not** mean a link between Meduza Stealer and APT29. Attribution is out of scope.
- Meduza techniques are limited to what our sources and lab work support (Weeks 4–9); T1547.001 is not confirmed for Meduza.
- The comparison is at technique level only, without procedures or detection data from a real APT29 intrusion.

## 10.9 Conclusion

APT29 covers the full attack lifecycle with supply chain, cloud identity abuse and lateral movement, while Meduza Stealer is a short, single-host operation. The key link is credential and session theft: data collected by stealers (T1539) is the type of access material APT actors reuse (T1550.004). Early-stage behavior such as PowerShell/cmd execution and discovery, which we re-ran with Atomic Red Team in Week 9, is shared by both. Detections for Meduza (browser file access, session reuse) therefore also help against targeted attacks.

> **Note on AI use:** The comparison tables and the Navigator layer were prepared with the help of an AI tool. Sources were checked and the analysis was reviewed by the team.

## References

All sources accessed on [FILL: date].

1. MITRE ATT&CK — APT29 (G0016), SolarWinds Compromise (C0024)
2. Mandiant (FireEye) — SUNBURST / SolarWinds supply chain analysis
3. CrowdStrike — Global Threat Report
4. Microsoft MSRC — Microsoft Actions Following Attack by Nation State Actor Midnight Blizzard (Jan 2024)
5. Splunk Threat Research Team — Meduza Stealer Analysis
6. Mandiant — APT1: Exposing One of China's Cyber Espionage Units (recommended reading in the syllabus, used as a model for the structure of an APT report)
