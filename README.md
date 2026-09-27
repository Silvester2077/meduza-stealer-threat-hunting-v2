# Threat Hunting Project — Meduza Stealer (Malware Disguised as Game Cheats)

**Course:** Introduction to Threat Hunting (ITH), Astana IT University
**Team:** Meiram, Alikhan, Ulan
**Target malware family:** Meduza Stealer
**Repository:** Silvester2077/meduza-stealer-threat-hunting

## Repository Structure

```
README.md          ← this file — project overview, results, conclusion
week1/notes.md      ← CTI Fundamentals: glossary, CTI types, sources
week2/notes.md      ← Data Collection: OSINT, VirusTotal, MISP, data source mapping
week3/notes.md      ← Data Processing: filtering, normalization, enrichment, correlation
```

Each week's folder holds a `notes.md` write-up plus the screenshots referenced in it,
kept side by side so everything for a given week is in one place.

## 4. Results

During Weeks 1–3, we applied the course topics to the Meduza Stealer threat hunting
project.

**Week 1** — We:
- studied basic CTI concepts
- created a CTI glossary
- identified different CTI types
- identified relevant intelligence sources

**Week 2** — We:
- studied open-source and closed-source intelligence
- examined OSINT Framework, SANS, VirusTotal, and MISP
- created a data source mapping
- collected initial indicators

**Week 3** — We:
- filtered the collected information
- normalized the indicators
- enriched the data with additional information
- correlated different IOC types

![GitHub repository progress](repo-progress.png)

*Figure 18. GitHub repository showing the project progress.*

## 5. Conclusion

During the first three weeks, we developed a basic threat intelligence workflow for
Meduza Stealer:

```
CTI Fundamentals
       ↓
Data Collection
       ↓
IOC Collection
       ↓
Filtering
       ↓
Normalization
       ↓
Enrichment
       ↓
Correlation
       ↓
Threat Hunting Analysis
```

The project demonstrates how theoretical CTI concepts from the course can be applied
to a specific malware-related research topic.

## 6. References

- Astana IT University — Introduction to Threat Hunting, Syllabus 2026–2027.
- OSINT Framework.
- SANS cybersecurity resources.
- VirusTotal.
- MISP.
- Public threat intelligence and security research related to Meduza Stealer
  (Wazuh, SOC Prime, Security Affairs, ThreatFox/abuse.ch, any.run).
- Project GitHub repository: Silvester2077/meduza-stealer-threat-hunting-v2

## Weekly Commit Log

| Week | Date | Contributor | Summary of commit |
|---|---|---|---|
| 1 |08.09.2026 - 13.09.2026|Meiram | Glossary + CTI types + sources added |
| 2 |13.09.2026 - 18.09.2026|Alikhan | OSINT collection + data source mapping + initial IOCs added |
| 3 |18.09.2026 - 23.09.2026 |Ulan| Filtering, normalization, enrichment, correlation added |

## Defense Notes (7–8 min per group)

1. What Meduza Stealer is and why it's disguised as game cheats (30s)
2. Week 1 — CTI glossary, CTI types & sources (1.5 min)
3. Week 2 — OSINT tools used + what we found (2.5 min, show VirusTotal/MISP screenshots)
4. Week 3 — Filtering/normalization/enrichment/correlation (2.5 min, show before/after)
5. Results + next steps (Cyber Kill Chain mapping, Week 4) (30s)


## AI Usage Disclosure

Generative AI tools (ChatGPT / Claude) were used throughout the project 
as a brainstorming and idea-generation aid. All final text, diagrams, 
and analysis were written and produced by the team.
