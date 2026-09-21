import ipaddress
import re
from urllib.parse import urlparse


# Common file extensions that should never be treated as domains
FILE_EXTENSIONS = {
    "png",
    "jpg",
    "jpeg",
    "gif",
    "svg",
    "webp",
    "ico",
    "pdf",
    "html",
    "htm",
    "css",
    "js",
    "json",
    "xml",
    "txt",
    "csv",
    "zip",
    "tar",
    "gz",
    "exe",
    "dll",
    "bin",
    "rlib",
}


# Common programming/documentation patterns
NON_DOMAIN_PATTERNS = {
    "layout.align",
    "response.answers",
    "filename.bytes",
    "trait.globalalloc",
}


def is_public_ip(value: str) -> bool:
    """
    Return True if the value is a valid publicly routable IP address.
    """

    try:
        ip = ipaddress.ip_address(value)

        return (
            not ip.is_private
            and not ip.is_loopback
            and not ip.is_link_local
            and not ip.is_reserved
            and not ip.is_multicast
        )

    except ValueError:
        return False


def is_valid_ip(value: str) -> bool:
    """
    Validate whether a string is a valid IPv4 or IPv6 address.
    """

    try:
        ipaddress.ip_address(value)
        return True

    except ValueError:
        return False


def is_valid_domain(domain: str) -> bool:
    """
    Validate whether a string resembles a real domain name.
    """

    domain = domain.lower().strip()

    if not domain:
        return False

    # Reject known false-positive patterns
    if domain in NON_DOMAIN_PATTERNS:
        return False

    # Reject file names / extensions
    parts = domain.split(".")

    if len(parts) < 2:
        return False

    if parts[-1] in FILE_EXTENSIONS:
        return False

    # Domain labels
    domain_pattern = re.compile(
        r"^(?=.{1,253}$)"
        r"(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,63}$"
    )

    return bool(domain_pattern.match(domain))


def is_valid_url(url: str) -> bool:
    """
    Validate HTTP/HTTPS URLs.
    """

    try:
        parsed = urlparse(url)

        if parsed.scheme not in {"http", "https"}:
            return False

        if not parsed.netloc:
            return False

        return True

    except Exception:
        return False


def classify_ip(value: str) -> str:
    """
    Classify an IP address.
    """

    if not is_valid_ip(value):
        return "invalid"

    if is_public_ip(value):
        return "public"

    return "private_or_reserved"


def validate_iocs(iocs: dict) -> dict:
    """
    Validate and classify extracted indicators.

    The result separates potentially useful indicators
    from invalid or private indicators.
    """

    validated = {
        "ips": [],
        "urls": [],
        "domains": [],
        "md5": [],
        "sha1": [],
        "sha256": [],
        "cves": [],
    }

    ip_classification = {
        "public": [],
        "private_or_reserved": [],
        "invalid": [],
    }

    # -------------------------
    # IP addresses
    # -------------------------

    for ip in iocs.get("ips", []):

        classification = classify_ip(ip)

        ip_classification[classification].append(ip)

        if classification == "public":
            validated["ips"].append(ip)

    # -------------------------
    # URLs
    # -------------------------

    for url in iocs.get("urls", []):

        if is_valid_url(url):
            validated["urls"].append(url)

    # -------------------------
    # Domains
    # -------------------------

    for domain in iocs.get("domains", []):

        if is_valid_domain(domain):
            validated["domains"].append(domain)

    # -------------------------
    # Hashes
    # -------------------------

    for hash_value in iocs.get("md5", []):

        if re.fullmatch(r"[a-fA-F0-9]{32}", hash_value):
            validated["md5"].append(hash_value)

    for hash_value in iocs.get("sha1", []):

        if re.fullmatch(r"[a-fA-F0-9]{40}", hash_value):
            validated["sha1"].append(hash_value)

    for hash_value in iocs.get("sha256", []):

        if re.fullmatch(r"[a-fA-F0-9]{64}", hash_value):
            validated["sha256"].append(hash_value)

    # -------------------------
    # CVEs
    # -------------------------

    for cve in iocs.get("cves", []):

        if re.fullmatch(
            r"CVE-\d{4}-\d{4,7}",
            cve,
            re.IGNORECASE
        ):
            validated["cves"].append(cve.upper())

    return {
        "validated": validated,
        "ip_classification": ip_classification,
    }


if __name__ == "__main__":

    test_iocs = {
        "ips": [
            "192.168.0.1",
            "10.0.0.1",
            "8.8.8.8",
        ],
        "urls": [
            "https://malicious-example.com/payload",
            "not-a-url",
        ],
        "domains": [
            "malicious-example.com",
            "AFAM.png",
            "layout.align",
            "google.com",
        ],
        "md5": [
            "5d41402abc4b2a76b9719d911017c592",
        ],
        "sha1": [
            "87f7abc323e345dd2729d5039a7ee0ee49c2fd56",
        ],
        "sha256": [],
        "cves": [
            "CVE-2026-76460",
        ],
    }

    print("[CYNERA] Testing IOC validator...\n")

    result = validate_iocs(test_iocs)

    print("VALIDATED IOCS:")
    print(result["validated"])

    print("\nIP CLASSIFICATION:")
    print(result["ip_classification"])

    print("\n[CYNERA] IOC validation test complete.")