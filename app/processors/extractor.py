import re
from urllib.parse import urlparse


IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

URL_PATTERN = re.compile(
    r"https?://[^\s\"'<>]+",
    re.IGNORECASE
)

DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|org|net|edu|gov|mil|int|io|co|ai|dev|app|"
    r"info|biz|xyz|online|site|tech|me|tv|ly|in|uk|de|fr|"
    r"jp|cn|ru|ca|au|us|cloud|google|github|dev)\b",
    re.IGNORECASE
)

MD5_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{32}\b"
)

SHA1_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{40}\b"
)

SHA256_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{64}\b"
)

CVE_PATTERN = re.compile(
    r"\bCVE-\d{4}-\d{4,7}\b",
    re.IGNORECASE
)


def clean_indicator(indicator: str) -> str:
    return indicator.rstrip(
        ".,;:!?)]}\"'>"
    )


def is_plausible_ip(ip: str) -> bool:
    parts = ip.split(".")

    if len(parts) != 4:
        return False

    try:
        octets = [int(part) for part in parts]
    except ValueError:
        return False

    if any(
        octet < 0 or octet > 255
        for octet in octets
    ):
        return False

    # Reject common technical section/version references
    # where the first three componets are very small
    #
    # Example:
    #   3.2.2.4  -> reject
    #   3.2.2.5  -> reject
    #
    # But:
    #   8.8.8.8  -> keep
    #   1.1.1.1  -> keep
    #   8.8.4.4  -> keep
    if (
        octets[0] <= 3
        and octets[1] <= 3
        and octets[2] <= 3
    ):
        return False

    return True


def extract_url_domains(urls: set[str]) -> set[str]:
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
    if not text:
        return {
            "ips": [],
            "urls": [],
            "domains": [],
            "md5": [],
            "sha1": [],
            "sha256": [],
            "cves": [],
        }

    urls = {
        clean_indicator(url)
        for url in URL_PATTERN.findall(text)
    }

    url_domains = extract_url_domains(urls)

    standalone_domains = {
        clean_indicator(domain).lower()
        for domain in DOMAIN_PATTERN.findall(text)
    }

    domains = url_domains | standalone_domains

    ips = {
        clean_indicator(ip)
        for ip in IP_PATTERN.findall(text)
        if is_plausible_ip(
            clean_indicator(ip)
        )
    }

    md5 = {
        clean_indicator(value)
        for value in MD5_PATTERN.findall(text)
    }

    sha1 = {
        clean_indicator(value)
        for value in SHA1_PATTERN.findall(text)
    }

    sha256 = {
        clean_indicator(value)
        for value in SHA256_PATTERN.findall(text)
    }

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
    Attackers used 8.8.8.8 as infrastructure.
    Technical reference 3.2.2.4 should not be treated as an IP.
    Technical reference 3.2.2.5 should not be treated as an IP.
    Visit https://malicious-example.com/payload.
    CVE-2026-76460 was disclosed.
    """

    print("[CYNERA] Extractor test")
    print("-----------------------")

    result = extract_iocs(test_text)

    for category, values in result.items():
        print(
            f"{category.upper():8}: {values}"
        )