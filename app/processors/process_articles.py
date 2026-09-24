import json
from pathlib import Path

from app.processors.extractor import extract_iocs
from app.processors.validator import validate_iocs
from app.processors.classifier import classify_indicators
from app.intelligence.cve_enricher import enrich_cve


INPUT_FILE = Path("data/raw/articles.json")
OUTPUT_FILE = Path("data/processed/intelligence.json")


def process_articles():
    print("[CYNERA] Starting intelligence processing...\n")

    if not INPUT_FILE.exists():
        print(f"[CYNERA] ERROR: {INPUT_FILE} not found.")
        print("[CYNERA] Run the RSS collector first.")
        return

    with open(INPUT_FILE, "r", encoding="utf-8") as file:
        articles = json.load(file)

    print(f"[CYNERA] Articles loaded: {len(articles)}")

    processed_articles = []

    total_extracted = {
        "ips": 0,
        "urls": 0,
        "domains": 0,
        "md5": 0,
        "sha1": 0,
        "sha256": 0,
        "cves": 0,
    }

    total_validated = {
        "ips": 0,
        "urls": 0,
        "domains": 0,
        "md5": 0,
        "sha1": 0,
        "sha256": 0,
        "cves": 0,
    }

    classification_counts = {}

    # Track enrichment statistics
    enriched_cves = 0
    enrichment_failures = 0

    for article in articles:

        title = article.get("title", "")
        summary = article.get("summary", "")

        text = f"{title} {summary}"

        # -------------------------
        # IOC extraction
        # -------------------------

        extracted_iocs = extract_iocs(text)

        for category, indicators in extracted_iocs.items():
            total_extracted[category] += len(indicators)

        # -------------------------
        # IOC validation
        # -------------------------

        validation_result = validate_iocs(
            extracted_iocs
        )

        validated_iocs = validation_result["validated"]

        for category, indicators in validated_iocs.items():
            total_validated[category] += len(indicators)

        # -------------------------
        # Context classification
        # -------------------------

        classified_indicators = classify_indicators(
            validated_iocs,
            text
        )

        for indicator in classified_indicators:

            context = indicator.get(
                "context",
                "unknown"
            )

            classification_counts[context] = (
                classification_counts.get(
                    context,
                    0
                ) + 1
            )

        # -------------------------
        # CVE enrichment
        # -------------------------

        cve_enrichment = []

        for cve in validated_iocs.get(
            "cves",
            []
        ):

            enrichment = enrich_cve(cve)

            if enrichment:

                cve_enrichment.append(
                    enrichment
                )

                enriched_cves += 1

            else:

                enrichment_failures += 1

        # -------------------------
        # Build processed article
        # -------------------------

        processed_article = {
            "title": title,

            "source": article.get(
                "source",
                "Unknown"
            ),

            "url": article.get(
                "url",
                ""
            ),

            "published": article.get(
                "published",
                ""
            ),

            "summary": summary,

            "iocs": validated_iocs,

            "ip_classification": validation_result[
                "ip_classification"
            ],

            "classified_indicators": (
                classified_indicators
            ),

            "cve_enrichment": cve_enrichment,
        }

        processed_articles.append(
            processed_article
        )

    # -------------------------
    # Save output
    # -------------------------

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            processed_articles,
            file,
            indent=4,
            ensure_ascii=False
        )

    # -------------------------
    # Statistics
    # -------------------------

    print("\n[CYNERA] Processing statistics")
    print("--------------------------------")

    print("\nExtracted indicators:")

    for category, count in total_extracted.items():
        print(
            f"  {category.upper():8} : {count}"
        )

    print("\nValidated indicators:")

    for category, count in total_validated.items():
        print(
            f"  {category.upper():8} : {count}"
        )

    print("\nClassified contexts:")

    for context, count in sorted(
        classification_counts.items()
    ):
        print(
            f"  {context:32} : {count}"
        )

    print("\nCVE enrichment:")
    print(
        f"  Enriched CVEs : {enriched_cves}"
    )
    print(
        f"  Failed CVEs   : {enrichment_failures}"
    )

    print("\n--------------------------------")

    print(
        f"[CYNERA] Processed: "
        f"{len(processed_articles)} articles"
    )

    print(
        f"[CYNERA] Saved to: "
        f"{OUTPUT_FILE}"
    )

    print(
        "\n[CYNERA] Intelligence processing complete."
    )


if __name__ == "__main__":
    process_articles()