# Week 4 — The Cyber Kill Chain

## 4.1 Key Terminology

Terms already defined in `week1/notes.md` (CTI, IOC, TTP, Threat Actor, Malware, C2)
are not repeated here. This table covers only the terms introduced this week.

| Term | Definition |
|---|---|
| **Cyber Kill Chain** | A model used to describe the different stages of a cyberattack. |
| **Reconnaissance** | Collecting information about a target before an attack. |
| **Weaponization** | Preparing a malicious file or payload for an attack. |
| **Delivery** | Sending the malicious payload to the target. |
| **Exploitation** | Using a vulnerability or user interaction to start malicious activity. |
| **Installation** | Placing or executing malware on the victim's system. |
| **Actions on Objectives** | Activities performed after compromise, such as stealing information. |

---

## 4.2 Cyber Kill Chain

The Cyber Kill Chain is a model developed by Lockheed Martin to describe the stages of a cyberattack.

The model contains seven stages:

1. Reconnaissance
2. Weaponization
3. Delivery
4. Exploitation
5. Installation
6. Command and Control
7. Actions on Objectives

For this week, we applied the Cyber Kill Chain model to Meduza Stealer activity. The goal was to understand how different parts of a malware attack can be organized into separate stages.

![Cyber Kill Chain](cyber-kill-chain.png)

*Figure 20. The seven stages of the Cyber Kill Chain.*
**Source:** Lockheed Martin — [The Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)

---

## 4.3 Meduza Stealer Attack Analysis

Meduza Stealer is an information-stealing malware family targeting Windows systems. It is designed to collect sensitive information such as browser credentials, cookies, browsing history, cryptocurrency wallet information, and password manager data.

For our analysis, we used publicly available malware intelligence and sandbox information to identify activities related to Meduza Stealer.

The available evidence does not provide direct evidence for every Kill Chain stage. Stages that were not directly observed are marked as possible or not directly observed, rather than assumed.

---

### Stage 1 — Reconnaissance

Reconnaissance is the stage where an attacker collects information about a potential target.

For Meduza Stealer, the exact reconnaissance activity of the threat actor was not directly observed in our available sandbox evidence.

**Evidence:** No direct reconnaissance evidence was available in our collected sandbox data.
**Status:** Not directly observed.

---

### Stage 2 — Weaponization

Weaponization is the preparation of a malicious payload for delivery.

In the case of Meduza Stealer, the malware itself is prepared as a malicious executable that is later delivered to a victim.

Our available evidence confirms the presence and execution of a Meduza Stealer sample, but it does not show the preparation process performed by the threat actor.

**Evidence:** Meduza Stealer malware sample and sandbox analysis.
**Status:** Partially supported by the malware sample.

---

### Stage 3 — Delivery

Delivery is the stage where the malicious payload reaches the victim.

Meduza Stealer can be distributed through methods such as malicious links and phishing-related activity, and is commonly disguised as game cheats or cracked software.

The exact delivery method was not directly confirmed in our specific sandbox session.

**Evidence:** Public malware intelligence describes phishing and malicious links as distribution methods.
**Status:** Possible delivery method; not directly observed in our sandbox session.

---

### Stage 4 — Exploitation

Exploitation is the stage where malicious activity is started on the victim's system.

For an information stealer, this happens when the victim executes the malicious file. In our analysis, the Meduza Stealer sample was executed in a sandbox environment and malicious behavior was observed, including detection of Meduza Stealer and actions related to collecting system and user information.

**Evidence:** Sandbox analysis of the Meduza Stealer sample.

![Meduza Stealer sandbox](meduza-info.png)

*Figure 21. Meduza Stealer sample and information from the sandbox analysis.*
**Source:** ANY.RUN — [https://any.run/](https://any.run/)

**Status:** Observed in the sandbox analysis.

---

### Stage 5 — Installation

Installation is the stage where malware becomes active on the compromised system.

During the sandbox session, the Meduza Stealer executable was dropped and executed after the sample started. `[add here any specific detail visible in Figure 21, e.g. file path, registry key, or autorun entry, if the sandbox report shows one]`

Without a confirmed persistence mechanism (such as a registry run key or scheduled task) in our available evidence, we cannot confirm whether the malware was designed to survive a reboot, only that it became active during the session.

**Evidence:** Sandbox activity showing executable creation and execution (Figure 21).
**Status:** Partially observed — execution confirmed, persistence mechanism not confirmed.

---

### Stage 6 — Command and Control

Command and Control (C2) is communication between malware and attacker-controlled infrastructure.

During the investigation, we identified an IP address and port:

`62.60.244.198:15666`

The IP address was investigated using threat intelligence sources.

![IOC enrichment](ioc-enrichment.png)

*Figure 22. Additional information obtained for the collected IP address.*
**Source:** VirusTotal — [https://www.virustotal.com/](https://www.virustotal.com/)

The IP address was also investigated using Passive DNS information to identify related domains.

![IOC correlation](ioc-correlation.png)

*Figure 23. Passive DNS relationships associated with the collected IP address.*
**Source:** VirusTotal — [https://www.virustotal.com/](https://www.virustotal.com/)

**Status:** The IP and related infrastructure were investigated as possible threat intelligence indicators. The available evidence should not be interpreted as proof that every related domain belongs to Meduza Stealer.

---

### Stage 7 — Actions on Objectives

Actions on Objectives are the final activities performed by an attacker after gaining access to a system.

For Meduza Stealer, the main objective is information theft. The malware is designed to collect:

- browser credentials
- cookies
- browsing history
- cryptocurrency wallet information
- password manager data
- system information

The sandbox analysis showed behavior consistent with information stealing and data exfiltration.

**Evidence:** Meduza Stealer sandbox analysis (Figure 21).
**Status:** Observed behavior related to information collection and possible exfiltration.

---

## 4.4 Cyber Kill Chain Summary

| Kill Chain Stage | Meduza Stealer Analysis | Evidence |
|---|---|---|
| **Reconnaissance** | Not directly observed | No direct evidence |
| **Weaponization** | Malicious sample prepared as an executable | Malware sample |
| **Delivery** | Possible phishing or malicious link | Public malware intelligence |
| **Exploitation** | Malicious sample executed | Sandbox (Figure 21) |
| **Installation** | Executable became active; persistence not confirmed | Sandbox (Figure 21) |
| **Command and Control** | IP and infrastructure indicators investigated | VirusTotal / Passive DNS (Figures 22–23) |
| **Actions on Objectives** | Sensitive information collection and possible exfiltration | Sandbox (Figure 21) |

---

## 4.5 MITRE ATT&CK Mapping

The Cyber Kill Chain describes the general stages of an attack, while MITRE ATT&CK provides a more detailed description of attacker behavior through tactics and techniques.

| Kill Chain Stage | MITRE ATT&CK Technique | Description |
|---|---|---|
| **Reconnaissance** | Not directly mapped | Reconnaissance was not directly observed in our evidence. |
| **Weaponization** | Not directly mapped | The exact malware preparation process was not observed. |
| **Delivery** | **T1566 – Phishing** | Phishing can be used to deliver malicious content to a victim. |
| **Exploitation** | **T1204.002 – User Execution: Malicious File** | The victim executes the malicious file, starting the infection. |
| **Installation** | **T1204.002 – User Execution: Malicious File** | The same execution event is also what installs the malware; we observed no separate installation mechanism (e.g. a dropper or loader) distinct from this execution. |
| **Command and Control** | **T1071.001 – Web Protocols** | Malware can use web protocols for communication with external infrastructure. |
| **Actions on Objectives** | **T1555.003 – Credentials from Web Browsers** | Malware can attempt to obtain credentials stored by web browsers. |
| **Actions on Objectives** | **T1539 – Steal Web Session Cookie** | Malware may attempt to obtain web session cookies. |
| **Actions on Objectives** | **T1005 – Data from Local System** | Malware can collect information stored on the local system. |

Techniques are only assigned where they reasonably correspond to observed or documented behavior. Exploitation and Installation share the same technique ID because, in our evidence, both stages correspond to the single observed event of the file being executed — we found no sign of a separate installer or loader stage.

---

## 4.6 IOC and Kill Chain Relationship

The IOCs collected in Week 2 and processed in Week 3 can be placed directly onto the Kill Chain stages they relate to:

```text
Kill Chain Stage                Related IOC
─────────────────────────────   ─────────────────────────────────
Weaponization / Exploitation →  File Hash (SHA-256)
                                 8844d41002892739ee42db2b481e67d
                                 6edbaaa0a9b9df5e314c2c083f2900bee

Installation                 →  Same file hash — executable
                                 dropped and run in the sandbox

Command and Control          →  IP Address : Port
                                 62.60.244.198:15666

Actions on Objectives        →  Data collected by the sample
                                 (credentials, cookies, wallet data)
```

*Figure 24. Mapping of collected IOCs onto Kill Chain stages.*

This shows how the two IOCs identified in Weeks 2–3 are not isolated values: the file hash anchors the Weaponization, Exploitation, and Installation stages, while the IP:port anchors the Command and Control stage. The later stages (Actions on Objectives) are supported by behavioral evidence rather than a specific IOC, since no exfiltration domain or URL was confirmed in our dataset.

## 4.7 Conclusion

Applying the Cyber Kill Chain to Meduza Stealer showed which stages our current evidence supports directly (Exploitation, Installation, Actions on Objectives, through sandbox data) and which remain inferred from public reporting (Reconnaissance, Weaponization, Delivery). Mapping these stages to MITRE ATT&CK techniques connects our Week 1–3 findings to a standard framework, and prepares the project for Week 5, where we will apply the threat hunting concept itself.
