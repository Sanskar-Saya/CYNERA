import re
from urllib.parse import urlparse


# IPv4 address
IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)


# URLs
URL_PATTERN = re.compile(
    r"https?://[^\s\"'<>]+",
    re.IGNORECASE
)


# Standalone domain names
#
# Important:
# This intentionally requires a normal-looking TLD and
# avoids treating filenames such as "AFAM.png" as domains.
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|org|net|edu|gov|mil|int|io|co|ai|dev|app|"
    r"info|biz|xyz|online|site|tech|me|tv|ly|in|uk|de|fr|"
    r"jp|cn|ru|ca|au|us|cloud|google|github|dev)\b",
    re.IGNORECASE
)


# MD5
MD5_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{32}\b"
)


# SHA-1
SHA1_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{40}\b"
)


# SHA-256
SHA256_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{64}\b"
)


# CVE identifiers
CVE_PATTERN = re.compile(
    r"\bCVE-\d{4}-\d{4,7}\b",
    re.IGNORECASE
)


def clean_indicator(indicator: str) -> str:
    """
    Remove punctuation accidentally captured
    from surrounding text.
    """

    return indicator.rstrip(
        ".,;:!?)]}\"'>"
    )


def extract_url_domains(urls: set[str]) -> set[str]:
    """
    Extract actual hostnames from URLs.

    This prevents URL paths such as:

        /2026/04/example.html

    from being incorrectly interpreted as domains.
    """

    domains = set()

    for url in urls:

        try:
            parsed = urlparse(url)

            hostname = parsed.hostname

            if hostname:
                domains.add(hostname.lower())

        except Exception:
            continue

    return domains


def extract_iocs(text: str) -> dict:
    """
    Extract indicators of compromise and CVE identifiers
    from a block of text.
    """

    # -------------------------
    # URLs
    # -------------------------

    urls = {
        clean_indicator(url)
        for url in URL_PATTERN.findall(text)
    }

    # -------------------------
    # Domains
    # -------------------------
    #
    # Domains found inside URLs are extracted from the
    # hostname rather than from the URL path.
    #

    url_domains = extract_url_domains(urls)

    standalone_domains = {
        clean_indicator(domain).lower()
        for domain in DOMAIN_PATTERN.findall(text)
    }

    domains = url_domains | standalone_domains

    # -------------------------
    # IP addresses
    # -------------------------

    ips = {
        clean_indicator(ip)
        for ip in IP_PATTERN.findall(text)
    }

    # -------------------------
    # Hashes
    # -------------------------

    md5 = {
        clean_indicator(hash_value)
        for hash_value in MD5_PATTERN.findall(text)
    }

    sha1 = {
        clean_indicator(hash_value)
        for hash_value in SHA1_PATTERN.findall(text)
    }

    sha256 = {
        clean_indicator(hash_value)
        for hash_value in SHA256_PATTERN.findall(text)
    }

    # -------------------------
    # CVEs
    # -------------------------

    cves = {
        cve.upper()
        for cve in CVE_PATTERN.findall(text)
    }

    return {
        "ips": sorted(ips),
        "urls": sorted(urls),
        "domains": sorted(domains),
        "md5": sorted(md5),
        "sha1": sorted(sha1),
        "sha256": sorted(sha256),
        "cves": sorted(cves),
    }


if __name__ == "__main__":

    test_text = """
    Suspicious activity was observed from 192.168.1.25.

    The attacker used
    https://malicious-example.com/payload.

    Related infrastructure included evil-example.net.

    This documentation references:

    https://security.googleblog.com/2026/04/
    google-workspaces-continuous-approach.html

    It also contains an image:

    AFAM.png

    A Git commit:

    87f7abc323e345dd2729d5039a7ee0ee49c2fd56

    And a vulnerability:

    CVE-2026-76460.
    """

    print("[CYNERA] Testing IOC extraction...\n")

    results = extract_iocs(test_text)

    for category, indicators in results.items():

        print(
            f"{category.upper()}: "
            f"{indicators}"
        )

    print(
        "\n[CYNERA] IOC extraction test complete."
    )