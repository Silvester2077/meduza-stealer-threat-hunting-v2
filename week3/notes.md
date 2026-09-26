# Week 3 — Data Processing and Exploitation

## 3.1 Data Processing Overview

During Week 3, we processed the indicators collected during Week 2.

The main goal of this stage was to make the collected data easier to analyze and identify possible relationships between different indicators.

The processing workflow included four main steps:

1. Data filtering
2. Data normalization
3. Data enrichment
4. IOC correlation

![Data processing workflow](data-processing-workflow.png)

*Figure 12. Data processing workflow used in the project.*

---

## 3.2 Data Filtering

The first step was filtering the collected indicators.

The initial dataset may contain duplicate values, incomplete information, or indicators that are not directly related to the research topic.

We removed duplicate entries and checked the collected values before continuing with the analysis.

For example, if the same hash appeared more than once, it was kept only once in the processed dataset.

<img width="1093" height="276" alt="image" src="https://github.com/user-attachments/assets/788cf40a-c07d-4503-9afd-29395accc278" />


*Figure 13. Initial IOC dataset before filtering.*

<img width="879" height="169" alt="image" src="https://github.com/user-attachments/assets/c6fccabf-c6ea-4b64-bada-42836fe2c45b" />


*Figure 14. IOC dataset after filtering.*

---

## 3.3 Data Normalization

After filtering, we normalized the indicators so that they had a consistent format.

Normalization helps avoid problems caused by different formatting of the same type of data.

For example:

| Indicator type | Example format |
|---|---|
| SHA-256 | 64 hexadecimal characters |
| IP address | IPv4 address format |
| Domain | Lowercase domain name |
| IP:Port | IP address followed by port |

We also removed unnecessary spaces and made the formatting consistent across the dataset.

<img width="1151" height="171" alt="image" src="https://github.com/user-attachments/assets/626df211-210e-4b55-8c48-a7feb8941e30" />


*Figure 15. Normalized IOC dataset.*

---

## 3.4 Data Enrichment

The next step was data enrichment.

Data enrichment means adding additional information to the indicators collected during the previous stage.

For example, a file hash can be checked against a malware analysis or threat intelligence service to obtain additional information.

An IP address can also be investigated to identify related infrastructure or other available information.

For our Meduza Stealer project, enrichment can provide information such as:

- malware detection results;
- file information;
- related domains;
- related IP addresses;
- URLs;
- reputation information;
- relationships with other indicators.

![IOC enrichment](ioc-enrichment.png)

*Figure 16. Additional information obtained during IOC enrichment.*

---

## 3.5 IOC Correlation

After filtering, normalization, and enrichment, we correlated the collected indicators.

Correlation means looking for relationships between different indicators.

For example, one malware sample may be connected to a specific hash, domain, IP address, or URL.

The following structure shows the basic relationship we investigated:

```text
Meduza Stealer
      |
      ↓
Malware Sample
      |
      ↓
File Hash
      |
      ↓
Related Infrastructure
      |
   ┌──┴───┐
   ↓      ↓
Domain   IP Address
   |
   ↓
  URL

This approach helps us understand how different indicators can be connected within the same threat intelligence investigation.

Figure 17. Correlation between different IOC types.

3.6 Processed IOC Dataset

After processing the collected information, we organized the indicators into a structured dataset.

IOC	Type	Source	Filtered	Normalized	Enriched
8844D41002892739EE42DB2B481E67D6EDBAAA0A9B9DF5E314C2C083F2900BEE	SHA-256	Any.Run	Yes	Yes	Yes
62.60.244.198:15666	IP:Port	ThreatFox	Yes	Yes	Yes
[ADD DOMAIN]	Domain	[SOURCE]	Yes	Yes	Yes
[ADD URL]	URL	[SOURCE]	Yes	Yes	Yes

The processed dataset provides a cleaner structure for further threat hunting analysis.

Figure 18. Final processed IOC dataset.

3.7 Results

The Week 3 processing stage allowed us to transform the initial IOC collection into a more structured dataset.

The main results were:

duplicate and irrelevant values were filtered;
indicators were normalized into consistent formats;
additional information was added through enrichment;
relationships between different IOC types were investigated.

The resulting workflow can be summarized as:

Initial IOC Collection
        ↓
Data Filtering
        ↓
Data Normalization
        ↓
Data Enrichment
        ↓
IOC Correlation
        ↓
Processed Threat Intelligence

Figure 19. Summary of the Week 3 processing results.

3.8 Conclusion

During Week 3, we applied data processing techniques to the indicators collected during Week 2.

Filtering helped us remove unnecessary or duplicate information. Normalization made the indicators consistent, while enrichment added additional context to the collected data.

Finally, IOC correlation helped us investigate possible relationships between hashes, domains, IP addresses, and URLs.

These steps prepared the collected threat intelligence for further threat hunting analysis.
