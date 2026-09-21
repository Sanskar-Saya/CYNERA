Cynera

Threat intelligence research and analysis platform for collecting, processing, validating, and analyzing cybersecurity intelligence from multiple sources.

Cynera is an ongoing cybersecurity research project focused on building a practical Threat Intelligence platform from the ground up.

The project currently focuses on automated collection of cybersecurity articles, extraction of Indicators of Compromise (IOCs), validation of extracted indicators, and contextual classification of threat intelligence.

Current Pipeline
        ┌──────────────────────┐
        │   Threat Intelligence │
        │       Sources         │
        └──────────┬───────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │    RSS Collection    │
        └──────────┬───────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │    IOC Extraction    │
        │                      │
        │ IPs / URLs / Domains │
        │ Hashes / CVEs        │
        └──────────┬───────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │    IOC Validation    │
        └──────────┬───────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │ Context Classification│
        └──────────┬───────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │ Processed Intelligence│
        └──────────────────────┘
Features Implemented
1. Threat Intelligence Collection

Cynera currently collects cybersecurity articles through RSS feeds from multiple security-focused sources.

Current sources include:

Cisco Talos
Dark Reading
ESET WeLiveSecurity
Google Security Blog

Collected information includes:

Article title
Source
URL
Publication date
Summary
2. IOC Extraction

Cynera automatically extracts potential indicators from collected intelligence.

Currently supported:

Indicator	Status
IPv4 addresses	Implemented
URLs	Implemented
Domains	Implemented
MD5	Implemented
SHA-1	Implemented
SHA-256	Implemented
CVE identifiers	Implemented

The extractor also attempts to reduce common false positives, such as interpreting filenames and documentation references as domains.

3. IOC Validation

Extracted indicators pass through a validation layer before being stored as intelligence.

The validator currently:

Validates IPv4 addresses
Separates public and private/reserved IP addresses
Validates URLs
Validates domain structure
Validates MD5, SHA-1 and SHA-256 formats
Validates CVE identifiers
Filters obvious non-domain strings

This creates a separation between:

Raw Extraction
      ↓
Validation
      ↓
Usable Intelligence
4. Contextual Classification

Cynera currently performs an initial classification of validated indicators.

Indicators can currently be classified into contexts such as:

vulnerability
reference_infrastructure
reference_url
suspicious_url_candidate
potential_threat_infrastructure
unclassified_hash
unknown

Each classified indicator can also contain a confidence level and contextual signals.

The classification system is currently heuristic and is being refined to reduce false positives and improve contextual accuracy.

Current Processing Results

The current pipeline was tested against 190 collected articles.

Articles processed: 190

Extracted:
    IPs       : 5
    URLs      : 360
    Domains   : 213
    MD5       : 0
    SHA-1     : 3
    SHA-256   : 0
    CVEs      : 8

Validated:
    IPs       : 2
    URLs      : 360
    Domains   : 213
    MD5       : 0
    SHA-1     : 3
    SHA-256   : 0
    CVEs      : 8

Current classification output:

Potential threat infrastructure : 2
Reference infrastructure        : 100
Reference URLs                  : 186
Suspicious URL candidates       : 25
Unclassified hashes             : 3
Unknown                         : 113
Unknown URLs                   : 149
Vulnerabilities                 : 8

These results are intended as an initial research baseline rather than definitive threat determinations.

Project Structure
cynera/
│
├── app/
│   ├── __init__.py
│   │
│   ├── collectors/
│   │   └── rss.py
│   │
│   ├── processors/
│   │   ├── extractor.py
│   │   ├── validator.py
│   │   ├── classifier.py
│   │   └── process_articles.py
│   │
│   ├── intelligence/
│   │   ├── __init__.py
│   │   └── models.py
│   │
│   ├── database/
│   │   └── __init__.py
│   │
│   └── api/
│       └── __init__.py
│
├── data/
│   ├── raw/
│   └── processed/
│
├── research/
│   ├── reports/
│   ├── threat-actors/
│   ├── campaigns/
│   └── vulnerabilities/
│
├── tests/
├── docs/
├── requirements.txt
└── .gitignore
Technology Stack
Python 3.13
Requests
Feedparser
BeautifulSoup
Pydantic
FastAPI
Uvicorn
Git / GitHub

The project currently uses a modular Python architecture so collectors, processors, intelligence logic, database components, and APIs can be developed independently.

Development Roadmap
Completed
 Project architecture
 Python environment
 Dependency setup
 RSS intelligence collection
 IOC extraction
 IOC validation
 Intelligence data model
 Initial contextual classification
 End-to-end processing pipeline
Next
 Improve contextual classification
 Detect Git commit hashes vs malware hashes
 Improve proximity-based threat detection
 Improve confidence scoring
 Reduce false positives
 Threat intelligence enrichment
 Threat actor identification
 Malware identification
 Campaign correlation
 Vulnerability intelligence
 Database layer
 FastAPI backend
 Intelligence search API
 Web dashboard
 Automated threat reports
Research Direction

Cynera is being developed as a practical research project around Threat Intelligence Research, with emphasis on:

IOC analysis
Threat detection
Threat actor research
Malware intelligence
Vulnerability intelligence
Campaign tracking
Intelligence correlation
Automated security research

The long-term goal is to move from simply collecting security information toward generating structured and contextualized threat intelligence.

Status

Current stage: Active Development

Cynera is currently in the collection → extraction → validation → classification phase.

The next major milestone is improving contextual classification before introducing external enrichment and correlation. Because apparently extracting a string from an article and deciding what it actually means are two completely different problems.
