# Week 2 — Data Collection Process

## 2.1 Open-Source and Closed-Source Intelligence

Threat intelligence can be collected from open and closed sources.

**Open-source intelligence (OSINT)** is obtained from publicly available information.
Examples include public websites, security reports, public databases, and open threat
intelligence platforms.

**Closed-source intelligence** can contain information that is not publicly available
and may require access to a private service, subscription, organization, or internal
security system.

For this project, we mainly use open-source information because it is accessible for
research and can be documented in our GitHub repository.

<img width="1109" height="764" alt="image" src="https://github.com/user-attachments/assets/1ed55f84-6100-45f2-aa5c-24cd39cfc52d" />


*Figure 5. Example of an open-source threat intelligence resource.*

## 2.2 OSINT Framework

The OSINT Framework provides a structured collection of resources that can be used to
search for publicly available information.

We used it as a reference for identifying possible sources that could provide
information related to malware and threat intelligence.


*Figure 6. OSINT Framework used for identifying information sources.*

## 2.3 SANS Resources

SANS provides cybersecurity education and security research resources. Security
publications can be used to understand malware, attacks, and defensive techniques.

For our project, SANS resources can be used as a supporting source when researching
the threat intelligence concepts and malware-related information.

![SANS resource](sans-resource.png)

*Figure 7. SANS resource used during the research.*

## 2.4 VirusTotal

VirusTotal can be used to investigate files, hashes, URLs, domains, and other
indicators.

For our Meduza Stealer research, VirusTotal can be used to examine indicators and
collect additional information about suspicious files or infrastructure.

The collected information can include:

- SHA-256 hashes
- file names
- detection results
- related URLs
- domains
- IP addresses

![VirusTotal result](virustotal-result.png)

*Figure 8. VirusTotal result related to one of the collected indicators.*

## 2.5 MISP

MISP is a platform used for collecting, storing, sharing, and correlating threat
intelligence.

It can help organize indicators and connect related pieces of information.

For our project, MISP is relevant because it demonstrates how indicators can be
structured and correlated as part of a threat intelligence workflow.

![MISP interface](misp-interface.png)

*Figure 9. MISP interface or relevant threat intelligence data.*

## 2.6 Data Source Mapping

After identifying the sources, we created a data source mapping for the project.

| Source | Type | Possible Data | Purpose |
|---|---|---|---|
| OSINT Framework | Open | Websites and public resources | Find relevant sources |
| SANS | Open | Reports and research | Background information |
| VirusTotal | Open/Service | Hashes, files, domains, URLs | Indicator investigation |
| MISP | Threat intelligence platform | IOCs and relationships | Organization and correlation |

![Data source mapping](data-source-mapping.png)

*Figure 10. Data source mapping for the Meduza Stealer project.*

## 2.7 Initial IOC Collection

Based on the selected sources, we collected indicators related to the research topic.

The initial dataset can contain several IOC types:

| IOC Type | Value | Source | Description |
|---|---|---|---|
| SHA-256 | 8844D41002892739EE42DB2B481E67D6EDBAAA0A9B9DF5E314C2C083F2900BEE | any.run | File indicator |
| IP:Port | 62.60.244.198:15666 | ThreatFox (abuse.ch) | Infrastructure indicator (C2) |
| Domain | [ADD DOMAIN] | [SOURCE] | Network indicator |
| URL | [ADD URL] | [SOURCE] | Web indicator |

*Values above marked `[ADD ...]` still need to be filled in with indicators found
during our own OSINT session; the hash and IP were taken from public reporting as a
starting reference point.*

![Collected indicators](collected-indicators.png)

*Figure 11. Initial IOC collection.*
