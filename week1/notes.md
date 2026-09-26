# Week 1 — Cyber Threat Intelligence Fundamentals

## 1.1 Project Topic

Meduza Stealer is an information-stealing malware family. For this project, we focus
on threat intelligence that can help identify and investigate indicators associated
with the malware.

The main types of information that can be useful for our research include:

- file hashes
- domains
- IP addresses
- URLs
- malware samples
- detection information
- relationships between different indicators

<img width="1794" height="852" alt="image" src="https://github.com/user-attachments/assets/5484831e-44a3-4c16-a199-910731e26416" />


*Figure 1. Public information about Meduza Stealer.*

## 1.2 CTI Glossary

During Week 1, we created a small glossary of important Cyber Threat Intelligence terms.

| Term | Definition |
|---|---|
| **CTI** | Cyber Threat Intelligence is information about cyber threats that can support security investigations and decision-making. |
| **IOC** | Indicator of Compromise is an artifact that may indicate malicious activity. |
| **TTP** | Tactics, Techniques and Procedures describe how an attacker operates. |
| **Malware** | Software designed to perform malicious actions. |
| **Threat Actor** | A person or group responsible for malicious cyber activity. |
| **OSINT** | Open-Source Intelligence collected from publicly available sources. |
| **Enrichment** | Adding additional information to an existing indicator. |
| **Correlation** | Connecting different pieces of information to identify relationships. |
| **Hash** | A value used to identify a file or other digital object. |
| **C2** | Command and Control infrastructure used for communication with compromised systems. |

![CTI glossary source](cti-glossary-source.png)

*Figure 2. Source used to study CTI terminology.*

## 1.3 Types of Cyber Threat Intelligence

CTI can be organized into different types depending on its purpose and level of detail.

**Strategic Intelligence** — provides a high-level view of cyber threats. It can be used
to understand general trends, risks, and the possible impact of threats.

**Operational Intelligence** — focuses on information about attacks, campaigns, and
threat activity.

**Tactical Intelligence** — describes attacker behavior and techniques. It can help
security teams understand how attacks are performed.

**Technical Intelligence** — contains technical indicators such as hashes, domains, IP
addresses, URLs, and other artifacts.

For our Meduza Stealer project, technical intelligence is particularly useful because
our research requires working with concrete indicators.

![Types of CTI](cti-types.png)

*Figure 3. Classification of Cyber Threat Intelligence.*

## 1.4 CTI Sources

For the project, we identified several types of sources that can provide threat
intelligence.

| Source type | Example | Information |
|---|---|---|
| OSINT | OSINT Framework | Publicly available information |
| Malware analysis | VirusTotal | File and URL information |
| Security research | SANS resources | Research and security reports |
| Threat intelligence platform | MISP | Indicators and threat intelligence |
| Public reports | Security blogs/reports | Malware and campaign information |

![Example of a CTI source](cti-source-example.png)

*Figure 4. Example of a publicly available threat intelligence source.*
