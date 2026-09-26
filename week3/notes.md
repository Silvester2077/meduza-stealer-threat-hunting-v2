# Week 3 — Data Processing and Exploitation

## 3.1 Data Filtering

After collecting the initial data, we performed filtering.

The purpose of filtering is to remove:

- duplicate indicators
- incomplete values
- irrelevant information
- incorrectly formatted entries

This makes the dataset easier to analyze.

![Dataset before filtering](before-filtering.png)

*Figure 12. Initial dataset before filtering.*

![Dataset after filtering](after-filtering.png)

*Figure 13. Dataset after filtering.*

## 3.2 Data Normalization

The collected information may have different formats. Therefore, normalization is
required before further analysis.

For example, domain names, IP addresses, hashes, and URLs should be stored in a
consistent format.

| Before | After |
|---|---|
| Example.COM | example.com |
| 192.168.1.1 | 192.168.1.1 |
| Duplicate hash | Single hash entry |

![Normalized dataset](normalized-dataset.png)

*Figure 14. Normalized IOC dataset.*

## 3.3 Data Enrichment

Data enrichment means adding additional information to the indicators that were
collected previously.

For example, an IP address can be enriched with additional information such as:

- country
- ASN
- organization
- reputation
- related domains

A file hash can be enriched with:

- detection information
- file type
- file name
- related URLs
- malware classification

![IOC enrichment](ioc-enrichment.png)

*Figure 15. Enrichment information for a collected IOC.*

## 3.4 IOC Correlation

After filtering, normalization, and enrichment, we can compare the indicators to
identify possible relationships.

```
Malware Sample
      |
      | SHA-256
      ↓
   File Hash
      |
      ↓
 VirusTotal
      |
 ┌────┴─────┐
 ↓          ↓
Domain      IP
 ↓          ↓
URL       Infrastructure
```

The purpose of correlation is to understand how different indicators may be connected.

![IOC correlation](ioc-correlation.png)

*Figure 16. Relationship between collected indicators.*

## 3.5 Processed IOC Dataset

After processing, the dataset can be represented in the following structure:

| IOC | Type | Source | Normalized | Enriched | Related IOC |
|---|---|---|---|---|---|
| 8844D41...F2900BEE | Hash | any.run | Yes | Yes | [ADD] |
| 62.60.244.198:15666 | IP:Port | ThreatFox | Yes | Yes | [ADD] |
| [ADD VALUE] | Domain | OSINT | Yes | Yes | [ADD] |
| [ADD VALUE] | URL | [SOURCE] | Yes | Yes | [ADD] |

![Final processed dataset](final-dataset.png)

*Figure 17. Final processed IOC dataset.*
