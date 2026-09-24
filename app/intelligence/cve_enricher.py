import requests
from typing import Optional


NVD_API_URL = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0"
)

HEADERS = {
    "User-Agent": (
        "Cynera-Threat-Intelligence-Research/0.1"
    )
}

# Prevent repeated API requests for the same CVE
CVE_CACHE: dict[str, Optional[dict]] = {}


def enrich_cve(
    cve_id: str,
) -> Optional[dict]:

    # --------------------------------------------------
    # CACHE
    # --------------------------------------------------

    if cve_id in CVE_CACHE:
        print(
            f"[CYNERA] Using cached CVE: {cve_id}"
        )

        return CVE_CACHE[cve_id]

    # --------------------------------------------------
    # NVD REQUEST
    # --------------------------------------------------

    params = {
        "cveId": cve_id,
    }

    try:

        response = requests.get(
            NVD_API_URL,
            params=params,
            headers=HEADERS,
            timeout=15,
        )

        response.raise_for_status()

        data = response.json()

    except requests.RequestException as error:

        print(
            f"[CYNERA] CVE enrichment failed "
            f"for {cve_id}: {error}"
        )

        CVE_CACHE[cve_id] = None

        return None

    # --------------------------------------------------
    # EXTRACT CVE
    # --------------------------------------------------

    vulnerabilities = data.get(
        "vulnerabilities",
        [],
    )

    if not vulnerabilities:

        print(
            f"[CYNERA] No NVD record found "
            f"for {cve_id}"
        )

        CVE_CACHE[cve_id] = None

        return None

    cve = vulnerabilities[0].get(
        "cve",
        {},
    )

    # --------------------------------------------------
    # DESCRIPTION
    # --------------------------------------------------

    descriptions = cve.get(
        "descriptions",
        [],
    )

    description = ""

    for item in descriptions:

        if item.get("lang") == "en":

            description = item.get(
                "value",
                "",
            )

            break

    # --------------------------------------------------
    # CVSS
    # --------------------------------------------------

    metrics = cve.get(
        "metrics",
        {}
    )

    cvss_score = None
    severity = None

    # CVSS v4.0
    if "cvssMetricV40" in metrics:

        metric = metrics["cvssMetricV40"][0]

        cvss_data = metric.get(
            "cvssData",
            {},
        )

        cvss_score = cvss_data.get(
            "baseScore"
        )

        severity = cvss_data.get(
            "baseSeverity"
        )

    # CVSS v3.1
    elif "cvssMetricV31" in metrics:

        metric = metrics["cvssMetricV31"][0]

        cvss_data = metric.get(
            "cvssData",
            {},
        )

        cvss_score = cvss_data.get(
            "baseScore"
        )

        severity = cvss_data.get(
            "baseSeverity"
        )

    # CVSS v3.0
    elif "cvssMetricV30" in metrics:

        metric = metrics["cvssMetricV30"][0]

        cvss_data = metric.get(
            "cvssData",
            {},
        )

        cvss_score = cvss_data.get(
            "baseScore"
        )

        severity = cvss_data.get(
            "baseSeverity"
        )

    # --------------------------------------------------
    # DATES
    # --------------------------------------------------

    published = cve.get(
        "published"
    )

    last_modified = cve.get(
        "lastModified"
    )

    # --------------------------------------------------
    # REFERENCES
    # --------------------------------------------------

    references = []

    for reference in cve.get(
        "references",
        []
    ):

        url = reference.get(
            "url"
        )

        if url:
            references.append(url)

    # --------------------------------------------------
    # RESULT
    # --------------------------------------------------

    result = {
        "cve": cve_id,
        "description": description,
        "cvss_score": cvss_score,
        "severity": severity,
        "published": published,
        "last_modified": last_modified,
        "references": references,
    }

    # Store in cache
    CVE_CACHE[cve_id] = result

    print(
        f"[CYNERA] CVE enriched: "
        f"{cve_id} | "
        f"{severity} | "
        f"CVSS {cvss_score}"
    )

    return result


# ------------------------------------------------------
# TEST
# ------------------------------------------------------

if __name__ == "__main__":

    test_cve = "CVE-2026-76460"

    print(
        f"[CYNERA] Enriching {test_cve}"
    )

    result = enrich_cve(
        test_cve
    )

    if result:

        print("\n[CYNERA] Enrichment result")
        print("-------------------------")

        print(
            f"CVE: {result['cve']}"
        )

        print(
            f"CVSS: {result['cvss_score']}"
        )

        print(
            f"Severity: {result['severity']}"
        )

        print(
            f"Published: {result['published']}"
        )

        print(
            f"Modified: {result['last_modified']}"
        )

        print(
            f"References: "
            f"{len(result['references'])}"
        )

    else:

        print(
            "[CYNERA] Enrichment failed."
        )