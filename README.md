 Cynera

> Threat intelligence research and analysis platform.

Cynera is a cybersecurity research project focused on collecting, processing, validating, and classifying threat intelligence from multiple security sources.

 Features

* RSS-based threat intelligence collection
* IOC extraction

  * IP addresses
  * URLs
  * Domains
  * MD5
  * SHA-1
  * SHA-256
  * CVEs
* IOC validation
* Initial contextual classification
* Structured intelligence models
* JSON-based processed intelligence

 Pipeline

```text
Threat Sources
      ↓
RSS Collection
      ↓
IOC Extraction
      ↓
IOC Validation
      ↓
Context Classification
      ↓
Processed Intelligence
```

 Current Sources

* Cisco Talos
* Dark Reading
* ESET WeLiveSecurity
* Google Security Blog

Tech Stack

* Python 3.13
* Requests
* Feedparser
* BeautifulSoup
* Pydantic
* FastAPI
* Uvicorn

 Project Structure

```text
cynera/
├── app/
│   ├── collectors/
│   ├── processors/
│   ├── intelligence/
│   ├── database/
│   └── api/
├── data/
│   ├── raw/
│   └── processed/
├── research/
│   ├── reports/
│   ├── threat-actors/
│   ├── campaigns/
│   └── vulnerabilities/
├── tests/
└── docs/
```

 Current Status

Cynera currently processes collected security articles through an end-to-end pipeline of **collection, IOC extraction, validation, and contextual classification**.

The classification system is currently heuristic and is being refined to improve contextual accuracy and reduce false positives.

 Roadmap

* [ ] Improve contextual classification
* [ ] Improve confidence scoring
* [ ] IOC enrichment
* [ ] Threat actor identification
* [ ] Malware intelligence
* [ ] Campaign correlation
* [ ] Vulnerability intelligence
* [ ] Database integration
* [ ] FastAPI backend
* [ ] Intelligence search API
* [ ] Web dashboard
* [ ] Automated threat reports

 Status

**Active Development**
