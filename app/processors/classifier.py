import re
from urllib.parse import urlparse


# Common legitimate development / documentation platforms.
# These are NOT malicious. They are classified as reference infrastructure.
REFERENCE_DOMAINS = {
    "github.com",
    "gitlab.com",
    "googlesource.com",
    "google.com",
    "googleblog.com",
    "googleusercontent.com",
    "github.io",
    "gitlab.io",
    "crates.io",
    "rust-lang.org",
    "android.com",
    "android.googlesource.com",
    "nvd.nist.gov",
    "nist.gov",
}


# Common URL/path indicators that deserve contextual attention.
SUSPICIOUS_URL_TERMS = {
    "payload",
    "malware",
    "loader",
    "download",
    "dropper",
    "c2",
    "command-and-control",
    "exploit",
    "phishing",
    "credential",
    "stealer",
}


def get_hostname(value: str) -> str:
    """
    Extract hostname from a URL or return an empty string.
    """

    try:
        parsed = urlparse(value)

        if parsed.hostname:
            return parsed.hostname.lower()

    except Exception:
        pass

    return ""


def is_reference_domain(domain: str) -> bool:
    """
    Determine whether a domain belongs to a commonly
    used legitimate development/documentation platform.
    """

    domain = domain.lower()

    for reference_domain in REFERENCE_DOMAINS:

        if (
            domain == reference_domain
            or domain.endswith("." + reference_domain)
        ):
            return True

    return False


def classify_cve(cve: str) -> dict:
    """
    Classify a CVE identifier.
    """

    return {
        "indicator": cve,
        "type": "cve",
        "context": "vulnerability",
        "confidence": "high",
    }


def classify_hash(hash_value: str, hash_type: str) -> dict:
    """
    Classify a hash based only on its format.

    A hash being syntactically valid does NOT mean
    it represents malware.
    """

    return {
        "indicator": hash_value,
        "type": hash_type,
        "context": "unclassified_hash",
        "confidence": "unknown",
    }


def classify_domain(domain: str) -> dict:
    """
    Classify a domain based on basic contextual information.
    """

    if is_reference_domain(domain):

        return {
            "indicator": domain,
            "type": "domain",
            "context": "reference_infrastructure",
            "confidence": "high",
        }

    return {
        "indicator": domain,
        "type": "domain",
        "context": "unknown",
        "confidence": "unknown",
    }


def classify_url(url: str) -> dict:
    """
    Classify a URL using lightweight contextual heuristics.
    """

    hostname = get_hostname(url)

    url_lower = url.lower()

    suspicious_terms = [
        term
        for term in SUSPICIOUS_URL_TERMS
        if term in url_lower
    ]

    if suspicious_terms:

        return {
            "indicator": url,
            "type": "url",
            "context": "suspicious_url_candidate",
            "confidence": "low",
            "signals": suspicious_terms,
        }

    if hostname and is_reference_domain(hostname):

        return {
            "indicator": url,
            "type": "url",
            "context": "reference_url",
            "confidence": "high",
        }

    return {
        "indicator": url,
        "type": "url",
        "context": "unknown_url",
        "confidence": "unknown",
    }


def classify_ip(ip: str, article_text: str = "") -> dict:
    """
    Classify an IP address using contextual keywords.

    This does NOT perform reputation checking.
    """

    text = article_text.lower()

    suspicious_terms = [
        term
        for term in [
            "command and control",
            "command-and-control",
            "c2",
            "malware",
            "attacker",
            "attackers",
            "payload",
            "botnet",
            "ransomware",
        ]
        if term in text
    ]

    if suspicious_terms:

        return {
            "indicator": ip,
            "type": "ip",
            "context": "potential_threat_infrastructure",
            "confidence": "low",
            "signals": suspicious_terms,
        }

    return {
        "indicator": ip,
        "type": "ip",
        "context": "unknown_ip",
        "confidence": "unknown",
    }


def classify_indicators(iocs: dict, article_text: str = "") -> list:
    """
    Convert extracted IOC categories into a unified
    list of classified indicators.
    """

    results = []

    # -------------------------
    # IPs
    # -------------------------

    for ip in iocs.get("ips", []):

        results.append(
            classify_ip(
                ip,
                article_text
            )
        )

    # -------------------------
    # URLs
    # -------------------------

    for url in iocs.get("urls", []):

        results.append(
            classify_url(url)
        )

    # -------------------------
    # Domains
    # -------------------------

    for domain in iocs.get("domains", []):

        results.append(
            classify_domain(domain)
        )

    # -------------------------
    # Hashes
    # -------------------------

    for value in iocs.get("md5", []):

        results.append(
            classify_hash(
                value,
                "md5"
            )
        )

    for value in iocs.get("sha1", []):

        results.append(
            classify_hash(
                value,
                "sha1"
            )
        )

    for value in iocs.get("sha256", []):

        results.append(
            classify_hash(
                value,
                "sha256"
            )
        )

    # -------------------------
    # CVEs
    # -------------------------

    for cve in iocs.get("cves", []):

        results.append(
            classify_cve(cve)
        )

    return results


if __name__ == "__main__":

    test_iocs = {
        "ips": [
            "8.8.8.8",
        ],
        "urls": [
            "https://malicious-example.com/payload",
            "https://github.com/example/project",
        ],
        "domains": [
            "github.com",
            "example-threat.com",
        ],
        "md5": [],
        "sha1": [
            "87f7abc323e345dd2729d5039a7ee0ee49c2fd56",
        ],
        "sha256": [],
        "cves": [
            "CVE-2026-76460",
        ],
    }

    article_text = """
    Attackers used a malicious payload and command and
    control infrastructure during the campaign.
    """

    print("[CYNERA] Testing contextual classifier...\n")

    results = classify_indicators(
        test_iocs,
        article_text
    )

    for result in results:
        print(result)

    print("\n[CYNERA] Classification test complete.")