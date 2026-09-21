import json
from pathlib import Path

import feedparser
import requests


OUTPUT_FILE = Path("data/raw/articles.json")

FEEDS = {
    "Cisco Talos": "https://blog.talosintelligence.com/rss/",
    "Dark Reading": "https://www.darkreading.com/rss.xml",
    "ESET WeLiveSecurity": "https://www.welivesecurity.com/en/rss/feed/",
    "Google Security Blog": "https://security.googleblog.com/feeds/posts/default",
}


def collect_feed(source: str, feed_url: str) -> list[dict]:
    """
    Collect articles from an RSS or Atom feed.
    """

    print(f"[CYNERA] Reading {source}...")

    try:
        response = requests.get(
            feed_url,
            headers={
                "User-Agent": "Cynera-Threat-Intelligence-Research/0.1"
            },
            timeout=15
        )

        print(f"[CYNERA] HTTP status: {response.status_code}")

        if response.status_code != 200:
            print(
                f"[CYNERA] {source} returned "
                f"HTTP {response.status_code}"
            )
            return []

        feed = feedparser.parse(response.content)

        print(
            f"[CYNERA] Entries found: "
            f"{len(feed.entries)}"
        )

        articles = []

        for entry in feed.entries:
            articles.append({
                "title": entry.get("title", ""),
                "url": entry.get("link", ""),
                "published": entry.get(
                    "published",
                    entry.get("updated", "")
                ),
                "summary": entry.get("summary", ""),
                "source": source
            })

        return articles

    except requests.RequestException as error:
        print(f"[CYNERA] Request failed: {error}")
        return []


def main():
    print("[CYNERA] Starting RSS collection...\n")

    all_articles = []

    for source, feed_url in FEEDS.items():

        articles = collect_feed(
            source,
            feed_url
        )

        all_articles.extend(articles)

        print(
            f"[CYNERA] {source}: "
            f"{len(articles)} articles\n"
        )

    if not all_articles:
        print("[CYNERA] No articles collected.")
        return

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
            all_articles,
            file,
            indent=4,
            ensure_ascii=False
        )

    print("--------------------------------")
    print(
        f"[CYNERA] Total articles: "
        f"{len(all_articles)}"
    )
    print(
        f"[CYNERA] Saved to: "
        f"{OUTPUT_FILE}"
    )
    print("[CYNERA] Collection complete.")
    print("--------------------------------")


if __name__ == "__main__":
    main()