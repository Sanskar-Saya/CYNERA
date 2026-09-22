import re
from urllib.parse import urlparse


REFERENCE_DOMAINS = {
    # Google
    "google.com",
    "googleblog.com",
    "googleusercontent.com",
    "googlesource.com",
    "deepmind.google",
    "cabforum.org",
    "android-developers.googleblog.com",
    "developer.android.com",
    "blog.google",
    "storage.googleapis.com",
    "g.co",
    "chrome.security",
    "chromium.org",
    "blog.chromium.org",
    "v8.dev",

    # Open source / development
    "github.com",
    "github.io",
    "gitlab.com",
    "gitlab.io",
    "googlesource.com",
    "cs.opensource.google",
    "pigweed.dev",
    "llvm.org",
    "rust-lang.org",
    "crates.io",

    # Security / research
    "nvd.nist.gov",
    "nist.gov",
    "googleprojectzero.blogspot.com",
    "citizenlab.ca",
    "dl.acm.org",
    "www.jedec.org",
    "browserbench.org",
    "webassembly.org",

    # Standards / organizations
    "c2pa.org",
    "contentcredentials.org",
    "artificialintelligenceact.eu",

    # Other known research infrastructure
    "akamai.com",
    "www.akamai.com",
}


SUSPICIOUS_URL_TERMS = {
    "payload",
    "loader",
    "dropper",
    "command-and-control",
}


THREAT_CONTEXT_TERMS = {
    "malware",
    "malicious",
    "attacker",
    "attackers",
    "threat actor",
    "command and control",
    "command-and-control",
    "c2",
    "payload",
    "botnet",
    "ransomware",
    "trojan",
    "backdoor",
    "exploit",
    "phishing",
    "stealer",
    "loader",
    "dropper",
}


def get_hostname(value: str) -> str:
    try:
        parsed = urlparse(value)

        if parsed.hostname:
            return parsed.hostname.lower()

    except Exception:
        pass

    return ""


def is_reference_domain(domain: str) -> bool:
    domain = domain.lower().strip()

    for reference_domain in REFERENCE_DOMAINS:
        if (
            domain == reference_domain
            or domain.endswith("." + reference_domain)
        ):
            return True

    return False


def find_threat_signals(context: str) -> list[str]:
    """
    Find threat terms using word/phrase boundaries.

    Important:
    'c2' must NOT match things like:
        C2PA
        c2pa.org
    """

    context_lower = context.lower()
    signals = []

    for term in THREAT_CONTEXT_TERMS:

        if term in {
            "c2",
            "malware",
            "botnet",
            "trojan",
            "backdoor",
            "payload",
            "dropper",
            "loader",
            "phishing",
            "ransomware",
            "stealer",
            "exploit",
            "attacker",
            "attackers",
            "malicious",
        }:

            pattern = rf"\b{re.escape(term)}\b"

            if re.search(pattern, context_lower):
                signals.append(term)

        else:

            if term in context_lower:
                signals.append(term)

    return sorted(set(signals))


def get_nearby_context(
    indicator: str,
    article_text: str,
    window: int = 180,
) -> str:

    if not article_text:
        return ""

    position = article_text.lower().find(
        indicator.lower()
    )

    if position == -1:
        return ""

    start = max(
        0,
        position - window,
    )

    end = min(
        len(article_text),
        position + len(indicator) + window,
    )

    return article_text[start:end]


def classify_cve(cve: str) -> dict:
    return {
        "indicator": cve,
        "type": "cve",
        "context": "vulnerability",
        "confidence": "high",
        "signals": ["CVE identifier"],
    }


def classify_hash(
    hash_value: str,
    hash_type: str,
    article_text: str = "",
) -> dict:

    context = get_nearby_context(
        hash_value,
        article_text,
    )

    signals = find_threat_signals(context)

    if signals:
        return {
            "indicator": hash_value,
            "type": hash_type,
            "context": "potential_malware_hash",
            "confidence": "low",
            "signals": signals,
            "evidence": context.strip(),
        }

    return {
        "indicator": hash_value,
        "type": hash_type,
        "context": "unclassified_hash",
        "confidence": "unknown",
        "signals": [],
    }


def classify_domain(
    domain: str,
    article_text: str = "",
) -> dict:

    domain = domain.lower().strip()

    # Known legitimate/reference infrastructure
    if is_reference_domain(domain):
        return {
            "indicator": domain,
            "type": "domain",
            "context": "reference_infrastructure",
            "confidence": "high",
            "signals": ["known reference domain"],
        }

    context = get_nearby_context(
        domain,
        article_text,
    )

    signals = find_threat_signals(context)

    # Do NOT immediately classify a domain as threat infrastructure
    # merely because generic security language surrounds it.
    if signals:
        return {
            "indicator": domain,
            "type": "domain",
            "context": "potential_threat_infrastructure",
            "confidence": "low",
            "signals": signals,
            "evidence": context.strip(),
        }

    return {
        "indicator": domain,
        "type": "domain",
        "context": "unknown",
        "confidence": "unknown",
        "signals": [],
    }


def normalize_url(url: str) -> str:
    """
    Normalize a URL before classification.

    Fragments such as:
        #section
        #:~:text=...
    do not identify separate infrastructure.
    """

    try:
        parsed = urlparse(url)

        return parsed._replace(
            fragment=""
        ).geturl()

    except Exception:
        return url


def classify_url(
    url: str,
    article_text: str = "",
) -> dict:

    normalized_url = normalize_url(url)
    hostname = get_hostname(normalized_url)

    # --------------------------------------------------
    # 1. Known/reference infrastructure
    # --------------------------------------------------

    if (
        hostname
        and is_reference_domain(hostname)
    ):
        return {
            "indicator": url,
            "type": "url",
            "context": "reference_url",
            "confidence": "high",
            "signals": [
                "known reference domain"
            ],
        }

    # --------------------------------------------------
    # 2. Strong URL-level suspicious patterns
    # --------------------------------------------------

    path = ""

    try:
        parsed = urlparse(normalized_url)
        path = parsed.path.lower()

    except Exception:
        pass

    strong_url_terms = {
        "payload",
        "dropper",
        "loader",
        "malware-download",
        "malware_payload",
        "phishing-kit",
        "credential-stealer",
    }

    suspicious_terms = [
        term
        for term in strong_url_terms
        if re.search(
            rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])",
            path,
        )
    ]

    if suspicious_terms:
        return {
            "indicator": url,
            "type": "url",
            "context": "suspicious_url_candidate",
            "confidence": "low",
            "signals": suspicious_terms,
        }

    # --------------------------------------------------
    # 3. Explicit threat-specific context
    # --------------------------------------------------

    context = get_nearby_context(
        normalized_url,
        article_text,
    )

    strong_threat_patterns = [
        r"\bc2 server\b",
        r"\bcommand[- ]and[- ]control server\b",
        r"\battacker[- ]controlled domain\b",
        r"\battacker[- ]controlled server\b",
        r"\bmalware connects to\b",
        r"\bconnects to .*domain\b",
        r"\bdownloads .*payload from\b",
        r"\bused by .*malware\b",
        r"\bused by .*threat actor\b",
        r"\bresolves to .*malicious\b",
    ]

    strong_signals = []

    context_lower = context.lower()

    for pattern in strong_threat_patterns:

        if re.search(
            pattern,
            context_lower,
        ):
            strong_signals.append(pattern)

    if strong_signals:
        return {
            "indicator": url,
            "type": "url",
            "context": "potential_threat_url",
            "confidence": "low",
            "signals": strong_signals,
            "evidence": context.strip(),
        }

    # --------------------------------------------------
    # 4. Insufficient evidence
    # --------------------------------------------------

    return {
        "indicator": url,
        "type": "url",
        "context": "unknown_url",
        "confidence": "unknown",
        "signals": [],
    }


def classify_ip(
    ip: str,
    article_text: str = "",
) -> dict:

    context = get_nearby_context(
        ip,
        article_text,
    )

    signals = find_threat_signals(context)

    if signals:
        return {
            "indicator": ip,
            "type": "ip",
            "context": "potential_threat_infrastructure",
            "confidence": "low",
            "signals": signals,
            "evidence": context.strip(),
        }

    return {
        "indicator": ip,
        "type": "ip",
        "context": "unknown_ip",
        "confidence": "unknown",
        "signals": [],
    }


def classify_indicators(
    iocs: dict,
    article_text: str = "",
) -> list:

    results = []

    for ip in iocs.get("ips", []):
        results.append(
            classify_ip(
                ip,
                article_text,
            )
        )

    for url in iocs.get("urls", []):
        results.append(
            classify_url(
                url,
                article_text,
            )
        )

    for domain in iocs.get("domains", []):
        results.append(
            classify_domain(
                domain,
                article_text,
            )
        )

    for value in iocs.get("md5", []):
        results.append(
            classify_hash(
                value,
                "md5",
                article_text,
            )
        )

    for value in iocs.get("sha1", []):
        results.append(
            classify_hash(
                value,
                "sha1",
                article_text,
            )
        )

    for value in iocs.get("sha256", []):
        results.append(
            classify_hash(
                value,
                "sha256",
                article_text,
            )
        )

    for cve in iocs.get("cves", []):
        results.append(
            classify_cve(cve)
        )

    return results