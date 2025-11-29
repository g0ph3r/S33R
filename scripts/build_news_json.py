#!/usr/bin/env python3
"""
Build a consolidated JSON file with recent security news.

- Reads an OPML file containing RSS feeds (sec_feeds.xml)
- Walks the OPML tree respecting the actual group structure
- Assigns categories based on OPML group titles (Crypto, DFIR, Threat Intel, etc.)
- Fetches all feeds using feedparser
- Keeps only last N days (default: 30)
- Deduplicates by link
- Cleans HTML from summaries (no raw <p>, <img>, <!-- SC_OFF -->, etc.)
- Writes data/news_recent.json

This script is meant to be run from the repo root (S33R).
"""

import json
import time
import re
import html
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Iterable, Tuple
import xml.etree.ElementTree as ET

import feedparser  # type: ignore

ROOT = Path(__file__).resolve().parent.parent
OPML_PATH = ROOT / "sec_feeds.xml"
OUTPUT_PATH = ROOT / "data" / "news_recent.json"
DAYS_BACK = 30
MAX_SUMMARY_LEN = 500  # caracteres (depois de limpar HTML)

# Mapeia os grupos reais do sec_feeds.xml para as categorias usadas no front-end
GROUP_CATEGORY_MAP: Dict[str, str] = {
    "Crypto & Blockchain Security": "crypto",
    "Cybercrime, Darknet & Leaks": "cybercrime",
    "DFIR & Forensics": "dfir",
    "General Security & Blogs": "general",
    "Government, CERT & Advisories": "gov_cert",
    "Leaks & Breaches": "leaks",
    "Malware & Threat Research": "malware",  # base (subgrupos refinam)
    "OSINT, Communities & Subreddits": "osint",
    "Podcasts & YouTube": "podcasts",
    "Vendors & Product Blogs": "vendors",
    "Vulnerabilities, CVEs & Exploits": "vulns",  # base (subgrupos refinam)

    # Subgrupos internos
    "Threat Intel & APT Campaigns": "threat_intel",
    "Malware Analysis & Research": "malware_analysis",
    "Exploits & PoCs": "exploits",
    "Vulnerability Advisories & Research": "vuln_advisories",
}

# Regex simples para limpar HTML
TAG_RE = re.compile(r"<[^>]+>")
COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)


def clean_html(text: str) -> str:
    """Remove tags e comentários HTML, normaliza espaços e limita tamanho."""
    if not text:
        return ""

    # Remove comentários HTML (ex: <!-- SC_OFF --> ... <!-- SC_ON -->)
    text = COMMENT_RE.sub(" ", text)

    # Remove tags <p>, <img>, <div>, etc.
    text = TAG_RE.sub(" ", text)

    # Decodifica entidades (&nbsp;, &#32;, etc.)
    text = html.unescape(text)

    # Normaliza espaços
    text = re.sub(r"\s+", " ", text).strip()

    # Limita tamanho para não explodir o card (especialmente Reddit)
    if len(text) > MAX_SUMMARY_LEN:
        text = text[:MAX_SUMMARY_LEN].rstrip() + "…"

    return text


def guess_category_from_title(title: str) -> str:
    """
    Fallback leve caso o grupo não esteja mapeado explicitamente.
    Usa só como último recurso.
    """
    t = title.lower()
    if "crypto" in t or "blockchain" in t:
        return "crypto"
    if "darknet" in t or "cybercrime" in t:
        return "cybercrime"
    if "dfir" in t or "forensic" in t:
        return "dfir"
    if "osint" in t:
        return "osint"
    if "podcast" in t or "youtube" in t:
        return "podcasts"
    if "vendor" in t or "product" in t:
        return "vendors"
    if "exploit" in t or "0day" in t:
        return "exploits"
    if "advisories" in t or "advisory" in t:
        return "vuln_advisories"
    if "vuln" in t or "cve" in t:
        return "vulns"
    if "malware analysis" in t or "reverse" in t:
        return "malware_analysis"
    if "malware" in t or "ransomware" in t:
        return "malware"
    if "cert" in t or "government" in t or "gov" in t:
        return "gov_cert"
    if "leak" in t or "breach" in t:
        return "leaks"
    if "threat" in t or "apt" in t or "intel" in t:
        return "threat_intel"
    return "general"


def _iter_feeds_from_node(
    node: ET.Element,
    ancestors_titles: List[str],
    current_cat: Optional[str],
) -> Iterable[Tuple[str, str, str]]:
    """
    Caminha recursivamente na árvore de <outline>, respeitando a estrutura.

    - Atualiza a categoria com base em GROUP_CATEGORY_MAP quando encontra
      um título conhecido (ex: "Threat Intel & APT Campaigns").
    - Quando encontra um outline com xmlUrl (RSS), emite (feed_title, xmlUrl, category).
    """
    title = node.attrib.get("title") or node.attrib.get("text") or ""
    if title:
        ancestors_titles = ancestors_titles + [title]
    else:
        ancestors_titles = list(ancestors_titles)

    new_cat = current_cat

    # Se o grupo estiver mapeado explicitamente, sobrescreve categoria
    if title in GROUP_CATEGORY_MAP:
        new_cat = GROUP_CATEGORY_MAP[title]
    elif new_cat is None:
        # Se ainda não há categoria definida, tenta deduzir dos títulos
        joined = " / ".join(ancestors_titles)
        new_cat = guess_category_from_title(joined)

    xml_url = node.attrib.get("xmlUrl")
    if xml_url:
        feed_title = title or xml_url
        yield (feed_title, xml_url, new_cat or "general")

    # Recurse nos filhos
    for child in node.findall("outline"):
        yield from _iter_feeds_from_node(child, ancestors_titles, new_cat)


def parse_opml(path: Path) -> List[Tuple[str, str, str]]:
    """
    Lê o sec_feeds.xml e retorna uma lista de
    (feed_title, xmlUrl, category_code),
    com categoria baseada na estrutura real do arquivo.
    """
    tree = ET.parse(path)
    root = tree.getroot()
    body = root.find("body")
    if body is None:
        return []

    feeds: List[Tuple[str, str, str]] = []
    seen_urls: set[str] = set()

    for top in body.findall("outline"):
        for title, xml_url, cat in _iter_feeds_from_node(top, [], None):
            if xml_url in seen_urls:
                continue
            seen_urls.add(xml_url)
            feeds.append((title, xml_url, cat or "general"))

    return feeds


def parse_entry(entry, source_title: str, category: str) -> Optional[Dict[str, Any]]:
    title = getattr(entry, "title", None) or entry.get("title")
    link = getattr(entry, "link", None) or entry.get("link")
    if not title or not link:
        return None

    summary_raw = (
        getattr(entry, "summary", None)
        or entry.get("summary")
        or entry.get("description")
        or ""
    )
    summary = clean_html(summary_raw)

    published = None
    if getattr(entry, "published_parsed", None):
        published = datetime.fromtimestamp(
            time.mktime(entry.published_parsed), tz=timezone.utc
        )
    elif getattr(entry, "updated_parsed", None):
        published = datetime.fromtimestamp(
            time.mktime(entry.updated_parsed), tz=timezone.utc
        )
    else:
        raw_date = entry.get("published") or entry.get("updated")
        if raw_date:
            try:
                published = datetime.fromisoformat(raw_date)
                if published.tzinfo is None:
                    published = published.replace(tzinfo=timezone.utc)
            except Exception:
                published = None

    return {
        "title": title,
        "link": link,
        "summary": summary,
        "source": source_title,
        "category": category,
        "published": published.isoformat() if published else None,
    }


def main() -> None:
    if not OPML_PATH.exists():
        raise SystemExit(f"OPML file not found: {OPML_PATH}")

    print(f"[INFO] Using OPML: {OPML_PATH}")
    feeds = parse_opml(OPML_PATH)
    print(f"[INFO] Found {len(feeds)} feeds")

    cutoff = datetime.now(timezone.utc) - timedelta(days=DAYS_BACK)
    all_items: Dict[str, Dict[str, Any]] = {}

    for idx, (feed_title, xml_url, category) in enumerate(feeds, start=1):
        print(f"[{idx}/{len(feeds)}] Fetching {feed_title} :: {xml_url} (cat={category})")

        # Protege contra RemoteDisconnected, timeouts, etc.
        try:
            parsed = feedparser.parse(xml_url)
        except Exception as e:
            print(f"  [ERROR] Failed fetching feed: {xml_url} ({e})")
            continue

        if getattr(parsed, "bozo", False):
            print(
                f"  [WARN] Problem parsing feed: {xml_url} "
                f"({getattr(parsed, 'bozo_exception', 'bozo')})"
            )

        for entry in parsed.entries:
            item = parse_entry(entry, source_title=feed_title, category=category)
            if not item:
                continue

            pub_str = item.get("published")
            if pub_str:
                try:
                    pub_dt = datetime.fromisoformat(pub_str)
                    if pub_dt.tzinfo is None:
                        pub_dt = pub_dt.replace(tzinfo=timezone.utc)
                except Exception:
                    pub_dt = None
            else:
                pub_dt = None

            # Aplica cutoff de data se tivermos published
            if pub_dt and pub_dt < cutoff:
                continue

            # Dedup pela URL "normalizada"
            link = item["link"].rstrip("/")
            existing = all_items.get(link)
            if existing:
                existing_dt = None
                if existing.get("published"):
                    try:
                        existing_dt = datetime.fromisoformat(existing["published"])
                    except Exception:
                        existing_dt = None
                if existing_dt and pub_dt and pub_dt <= existing_dt:
                    continue

            all_items[link] = item

    items_list: List[Dict[str, Any]] = list(all_items.values())

    def sort_key(x: Dict[str, Any]):
        p = x.get("published")
        if not p:
            return 0.0
        try:
            return datetime.fromisoformat(p).timestamp()
        except Exception:
            return 0.0

    items_list.sort(key=sort_key, reverse=True)

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    out_data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "days_back": DAYS_BACK,
        "total_items": len(items_list),
        "items": items_list,
    }
    OUTPUT_PATH.write_text(json.dumps(out_data, indent=2), encoding="utf-8")
    print(f"[INFO] Wrote {len(items_list)} items to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
