#!/usr/bin/env python3
"""
Build a consolidated JSON file with recent security news.

- Reads an OPML file containing RSS feeds (sec_feeds.xml)
- Walks the OPML tree respecting the actual group structure
- Assigns categories based on OPML group titles (Crypto, DFIR, Threat Intel, etc.)
- Fetches all feeds using feedparser
- Keeps only last N days (default: 30)
- Deduplicates by link
- Cleans HTML from summaries
- Enriches items with keyword-based "smart_groups"
- Writes data/news_recent.json

This script is meant to be run from the repo root (S33R).
"""

import os
import json
import html
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
import xml.etree.ElementTree as ET
from typing import Iterable, List, Optional, Tuple

from email.utils import parsedate_to_datetime  # <-- NOVO

import feedparser


try:
    from bs4 import BeautifulSoup  # Optional, nicer HTML cleanup
except ImportError:  # pragma: no cover
    BeautifulSoup = None

# -------------------------------
# Configuration
# -------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
OPML_PATH = BASE_DIR / "sec_feeds.xml"
OUTPUT_PATH = BASE_DIR / "data" / "news_recent.json"

DAYS_BACK = int(os.environ.get("DAYS_BACK", "30"))

# Map OPML group titles to internal type slugs
CATEGORY_SLUGS = {
    "Crypto & Blockchain Security": "crypto",
    "Cybercrime, Darknet & Leaks": "cybercrime",
    "DFIR & Forensics": "dfir",
    "General Security & Blogs": "general",
    "General Security": "general",
    "Government, CERT & Advisories": "government",
    "Government, CERT": "government",
    "Leaks & Breaches": "leaks",
    "Malware": "malware",
    "Threat Intel": "threat_intel",
    "Malware Analysis": "malware_analysis",
    "OSINT, Communities & Subreddits": "osint",
    "OSINT & Communities": "osint",
    "Podcasts & YouTube": "podcasts",
    "Podcasts": "podcasts",
    "Vendors & Product Blogs": "vendors",
    "Vendors": "vendors",
    "Vulnerabilities & CVEs": "vulns",
    "Exploits": "exploits",
    "Vulnerability Advisories": "vuln_advisories",
}

# -------------------------------
# Keyword-based smart grouping
# -------------------------------
SMART_GROUP_RULES: List[Tuple[str, List[str]]] = [

    # === Ransomware ===
    ("Ransomware", [

    # General terms
    "ransomware", "ransom note", "double extortion",
    "locker", "crypto-locker", "ransom demand", "ransom gang",
    "extortion", "data exfiltration extortion",

    # MITRE groups known for ransomware operations
    "wizard spider",         # Ryuk
    "royal",                 # Royal Ransomware (ex-Wizard Spider splinter)
    "fin12",                 # Known ransomware affiliate
    "muddled libra",         # Ransomware extortion/social engineering
    "scattered spider",      # Also involved in ransomware breaches
    "black basta",           # Known ransomware gang
    "hellokitty",            # HelloKitty/FiveHands

    # Well-known ransomware gangs (not always MITRE groups but widely referenced)
    "lockbit", "lockbit 3.0", "lockbit 2.0",
    "alphv", "blackcat", "alphv/blackcat",
    "clop", "cl0p", "clop ransomware",
    "conti", "conti leaks",
    "emotet", # precursor/access vector for ransomware ops
    "ryuk",
    "maze", "maze cartel",
    "egregor",
    "revil", "sodinokibi",
    "darkside", "dark side",
    "blackmatter",
    "doppelpaymer",
    "vice society",
    "babuk",
    "netwalker",
    "hive ransomware", "hive",
    "royal ransomware",
    "play ransomware", "playcrypt",
    "phobos ransomware",
    "vice society",
    "bianlian",
    "redkite",
    "snatch ransomware",

    # Ransomware affiliates & IABs linked to MITRE groups
    "fin7",           # sometimes tied in supply-chain / IAB
    "fin13",
    "lazarus",        # has used faux-ransomware in ops
    "apt41",          # double-extortion impersonation cases

    # Common indicators / operational language
    "leak site", "ransom negotiation", "ransom portal",
    "ransomware-as-a-service", "raas",
    "affiliate program", "affiliate ransomware",
]),

    # === Vulnerabilities / CVEs ===
    ("Vulnerabilities / CVEs", [
        "cve-", "vulnerability", "vulnerabilities",
        "remote code execution", "rce",
        "privilege escalation", "buffer overflow",
        "out-of-bounds write", "sql injection",
        "authentication bypass", "zero-day", "0day",
    ]),

    # === Exploit / PoC ===
    ("Exploit / PoC", [
        "exploit", "poc released", "proof-of-concept",
        "exploit code", "weaponized", "exploit available",
        "exploit toolkit", "exploit released",
    ]),

    # === Microsoft Ecosystem ===
    ("Windows / Microsoft", [
        "windows", "exchange server", "office 365",
        "azure ad", "active directory",
        "powershell", "ms defender", "intune",
    ]),

    # === Linux Ecosystem ===
    ("Linux / Unix", [
        "linux", "ubuntu", "debian", "centos",
        "red hat", "rhel", "suse", "unix",
        "systemd", "kernel module",
    ]),

    # === Cloud / SaaS ===
    ("Cloud / SaaS", [
        "aws", "azure", "gcp", "google cloud",
        "cloudflare", "okta", "auth0", "saas",
        "s3 bucket", "cloud misconfiguration",
        "iam role", "cloudtrail", "kubernetes", "k8s",
    ]),

    # === Threat Actors / APT ===
    ("Threat Actors / APT", [
        " apt ", " apt-", "apt group",
        "lazarus", "sandworm", "fin7", "apt29",
        "apt28", "charming kitten", "oilrig",
        "turla", "cozy bear", "fancy bear",
        "wizard spider", "black basta", "lockbit",
        "muddled libra",
    ]),

    # === Malware / Payloads ===
    ("Malware / Payloads", [
        "malware", "trojan", "backdoor",
        "rootkit", "botnet", "loader",
        "infostealer", "info-stealer", "keylogger",
        "rat (remote access trojan)", "remote access trojan",
        "wiper", "locker", "locker malware",
    ]),

    # === Web App / API Security ===
    ("Web / API Security", [
        "xss", "cross-site scripting",
        "csrf", "cross-site request forgery",
        "sql injection", "sqli",
        "lfi", "rfi", "directory traversal",
        "api security", "graphql", "web application firewall",
    ]),

    # === Identity / Access ===
    ("Identity / Access", [
        "mfa", "2fa", "passwordless",
        "sso", "single sign-on",
        "oauth", "saml", "openid connect",
        "identity provider", "idp",
    ]),

    # === Network / OT / ICS ===
    ("Network / OT / ICS", [
        "ics", "scada", "plc",
        "industrial control systems",
        "critical infrastructure",
        "ot security", "operational technology",
    ]),

    # === Data Breaches / Leaks ===
    ("Data Breaches / Leaks", [
        "data breach", "data leak", "leaked data",
        "database leaked", "records exposed",
        "credentials leaked", "credential dump",
        "publicly exposed", "open database",
    ]),

    # === Phishing / Social Engineering ===
    ("Phishing / Social Engineering", [
        "phishing", "spear-phishing", "spear phishing",
        "social engineering", "credential harvesting",
        "smishing", "vishing",
        "business email compromise", "bec attack",
    ]),

    # === Crypto / Web3 ===
    ("Crypto / Web3", [
        "crypto exchange", "cryptocurrency",
        "defi", "dex", "web3",
        "smart contract", "solidity",
        "rug pull", "bridge exploit",
    ]),

    # === Supply-chain / Software ===
    ("Supply Chain / Software", [
        "software supply chain",
        "ci/cd pipeline",
        "dependency confusion",
        "typosquatting package",
        "malicious npm package", "malicious pypi package",
        "malicious nuget package",
    ]),
]

# -------------------------------
# Promotional / commercial content filtering
# -------------------------------
PROMO_PATTERNS: List[str] = [
    # Seasonal sales / generic deals
    "black friday",
    "cyber monday",
    "prime day",
    "boxing day sale",
    "back to school deals",
    "holiday deals",
    "christmas deals",
    "year-end sale",
    "new year sale",

    # Explicit deal / discount language
    "best deals",
    "best deal",
    "deal alert",
    "deal of the day",
    "doorbuster",
    "flash sale",
    "mega sale",
    "hot sale",
    "limited-time offer",
    "limited time offer",
    "time-limited offer",
    "price drop",
    "price drops",
    "on sale",
    "lowest price",
    "lowest-ever price",
    "cheapest price",
    "now only",
    "starting at",
    "starting from",
    "save up to",
    "save $",
    "save €",
    "% off",
    "off all",
    "discount code",
    "discounts on",
    "coupon code",
    "voucher code",

    # Buying guides / product roundups
    "best tvs",
    "best tv ",
    "best laptops",
    "best laptop",
    "best monitors",
    "best monitor",
    "best phones",
    "best phone",
    "best tablets",
    "best tablet",
    "best headphones",
    "best earbuds",
    "best soundbar",
    "best soundbars",
    "best gaming pc",
    "best gaming laptop",
    "best gaming monitor",
    "best routers",
    "best router",
    "best mesh wifi",
    "buying guide",
    "gift guide",
    "what to buy",
    "which one should you buy",
    "which should you buy",
    "top picks",
    "top deals",

    # Live deal tracking
    "live-tracking the best",
    "live tracking the best",
    "i'm live-tracking",
    "im live-tracking",

    # Highly likely promo phrasing
    "tv deals",
    "laptop deals",
    "monitor deals",
    "ipad deals",
    "iphone deals",
    "macbook deals",
    "ps5 deals",
    "xbox deals",
    "nintendo switch deals",
    "gaming pc deals",
    "gaming laptop deals",
]

BAD_CATEGORY_TERMS: List[str] = [
    "deal",
    "deals",
    "shopping",
    "buying guide",
    "reviews",
    "review",
    "best of",
    "top picks",
    "gift guide",
    "hardware deals",
    "software deals",
    "discounts",
    "sales",
]

def _collect_entry_tags(entry) -> list[str]:
    """Extract lowercase tag/category labels from a feedparser entry.

    We support both the attribute-style (entry.tags) and dict-style access,
    and handle objects with a ``term`` attribute or dicts with ``term``/``label`` keys.
    """
    tags: list[str] = []
    tags_attr = getattr(entry, "tags", None)
    if not tags_attr:
        return tags

    for t in tags_attr:
        term = getattr(t, "term", None)
        if term is None and isinstance(t, dict):
            term = t.get("term") or t.get("label")
        if term:
            tags.append(str(term).lower())
    return tags


def is_promotional_entry(entry, title: str, summary_raw: str) -> bool:
    """Return True if the entry looks like a commercial/deal article.

    This is deliberately conservative: we avoid blocking vendor names directly
    (amazon, walmart, target, etc.) and instead focus on:
      - explicit deal / discount / sale language in the title+summary
      - categories/tags that clearly mark the item as a deal/review/shopping
    """
    text = f"{title or ''} {summary_raw or ''}".lower()

    # 1) Check explicit promo/deal phrases in title+summary
    for pat in PROMO_PATTERNS:
        if pat in text:
            return True

    # 2) Check categories/tags
    tags = _collect_entry_tags(entry)
    for tag in tags:
        for bad in BAD_CATEGORY_TERMS:
            if bad in tag:
                return True

    return False


# -------------------------------
# Helpers
# -------------------------------
def slugify(label: str) -> str:
    text = label.lower()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    text = text.strip("-")
    return text or "unknown"


def normalize_category(group_title: str) -> Tuple[str, str]:
    label = (group_title or "General").strip()
    slug = CATEGORY_SLUGS.get(label)
    if not slug:
        slug = slugify(label)
    return slug, label


def clean_html_summary(raw: str) -> str:
    if not raw:
        return ""
    raw = html.unescape(raw)

    if BeautifulSoup is not None:
        soup = BeautifulSoup(raw, "html.parser")
        text = soup.get_text(separator=" ", strip=True)
    else:
        text = re.sub(r"<[^>]+>", " ", raw)
        text = re.sub(r"\s+", " ", text).strip()

    return text


def parse_published(entry) -> Optional[datetime]:
    """Return a timezone-aware datetime for a feed entry.
    Tries feedparser's *_parsed fields first, then falls back to date strings.
    If no timezone is present, assumes UTC.
    """
    # 1) Tenta primeiro os campos estruturados do feedparser
    dt_struct = getattr(entry, "published_parsed", None) or getattr(
        entry, "updated_parsed", None
    )

    if dt_struct is not None:
        # parsedate_to_datetime sabe lidar com struct_time?
        # Se não, usamos datetime diretamente.
        try:
            dt = datetime.fromtimestamp(
                datetime(*dt_struct[:6], tzinfo=timezone.utc).timestamp(),
                tz=timezone.utc,
            )
        except Exception:
            dt = None

        if dt is not None:
            return dt

    # 2) Fallback para campos de data em string
    candidate_fields = [
        "published",
        "updated",
        "pubDate",
        "dc:date",
        "dc_date",
        "date",
    ]

    for field in candidate_fields:
        # feedparser entries se comportam como dict + atributos
        value = getattr(entry, field, None)
        if not value and isinstance(entry, dict):
            value = entry.get(field)
        if not value:
            continue

        try:
            dt = parsedate_to_datetime(str(value))
        except (TypeError, ValueError):
            continue

        if dt is None:
            continue

        # Se não tiver timezone, assume UTC (como você pediu)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return dt

    # 3) Se nada funcionar, retorna None
    return None


def compute_smart_groups(title: str, summary: str) -> list[str]:
    text = f"{title or ''} {summary or ''}".lower()
    groups: list[str] = []

    for label, keywords in SMART_GROUP_RULES:
        for kw in keywords:
            if kw.lower() in text:
                groups.append(label)
                break

    # Dedup preservando ordem
    seen = set()
    deduped: list[str] = []
    for g in groups:
        if g not in seen:
            seen.add(g)
            deduped.append(g)
    return deduped


def iter_opml_feeds(opml_path: Path) -> Iterable[Tuple[str, str, str]]:
    tree = ET.parse(opml_path)
    root = tree.getroot()
    body = root.find("body")
    if body is None:
        return []

    for group in body.findall("outline"):
        group_title = group.attrib.get("title") or group.attrib.get("text") or "General"
        for feed in group.findall("outline"):
            xml_url = feed.attrib.get("xmlUrl")
            if not xml_url:
                continue
            feed_title = feed.attrib.get("title") or feed.attrib.get("text") or xml_url
            yield group_title, feed_title, xml_url


def main() -> None:
    if not OPML_PATH.exists():
        raise SystemExit(f"OPML file not found: {OPML_PATH}")

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=DAYS_BACK)

    items_by_link: dict[str, dict] = {}

    # -------------------------------
    # Incremental mode:
    #   - Carrega o JSON existente (se houver)
    #   - Reaproveita itens ainda dentro da janela DAYS_BACK
    #   - Evita duplicatas por link
    # -------------------------------
    if OUTPUT_PATH.exists():
        try:
            existing_data = json.loads(OUTPUT_PATH.read_text(encoding="utf-8"))
            existing_items = existing_data.get("items", [])
            kept_existing = 0

            for item in existing_items:
                link = item.get("link")
                if not link:
                    continue

                pub_ts = item.get("published_ts")
                # Se tiver timestamp, aplica o mesmo cutoff de DAYS_BACK
                if pub_ts is not None:
                    try:
                        existing_dt = datetime.fromtimestamp(pub_ts, tz=timezone.utc)
                        if existing_dt < cutoff:
                            # Muito antigo, deixa expirar naturalmente
                            continue
                    except Exception:
                        # Se der algum problema bizarro no timestamp, não derruba o script
                        pass

                items_by_link[link] = item
                kept_existing += 1

            if kept_existing:
                print(f"[INFO] Pre-loaded {kept_existing} existing items from {OUTPUT_PATH}")
        except Exception as e:
            print(f"[WARN] Could not load existing JSON from {OUTPUT_PATH}: {e!r}")

    print(f"[INFO] Using OPML: {OPML_PATH}")
    print(f"[INFO] Collecting items from the last {DAYS_BACK} days (>= {cutoff.isoformat()})")

    for group_title, feed_title, xml_url in iter_opml_feeds(OPML_PATH):
        type_slug, type_label = normalize_category(group_title)
        print(f"[INFO] Fetching feed: {feed_title} ({xml_url}) [{type_label}]")

        # --- robust fetch: don't let one broken feed kill the whole job
        try:
            parsed = feedparser.parse(xml_url)
        except Exception as e:  # network / TLS errors, RemoteDisconnected, etc.
            print(f"[WARN] Failed to fetch feed {feed_title} ({xml_url}): {e!r}")
            continue

        if getattr(parsed, "bozo", False) and getattr(parsed, "bozo_exception", None):
            print(
                f"[WARN] Bozo parsing feed {feed_title} ({xml_url}): "
                f"{parsed.bozo_exception!r}"
            )

        for entry in parsed.entries:
            link = getattr(entry, "link", None)
            title = getattr(entry, "title", "").strip()
            summary_raw = getattr(entry, "summary", "") or getattr(entry, "description", "")

            # Skip obvious promotional / commercial "deal" content
            if is_promotional_entry(entry, title, summary_raw):
                # Uncomment for debugging:
                # print(f"[DEBUG] Skipping promotional item: {title!r}")
                continue

            if not link or not title:
                continue

            pub_dt = parse_published(entry)
            if not pub_dt:
                pub_iso = None
                pub_ts = None
            else:
                # Respeita a janela de DAYS_BACK
                if pub_dt < cutoff:
                    continue
                pub_iso = pub_dt.isoformat()
                pub_ts = int(pub_dt.timestamp())

            summary = clean_html_summary(summary_raw)
            smart_groups = compute_smart_groups(title, summary)

            item = {
                "title": title,
                "summary": summary,
                "link": link,
                "source": feed_title,
                "type": type_slug,
                "type_label": type_label,
                "published": pub_iso,
                "published_ts": pub_ts,
                "smart_groups": smart_groups,
            }

            existing = items_by_link.get(link)
            if existing is None:
                # Novo link
                items_by_link[link] = item
            else:
                # Mesmo link: fica com a versão mais recente
                if (item["published_ts"] or 0) > (existing.get("published_ts") or 0):
                    items_by_link[link] = item

    # Converte para lista e ordena por published_ts desc
    items_list = list(items_by_link.values())
    items_list.sort(
        key=lambda x: x["published_ts"] if x["published_ts"] is not None else 0,
        reverse=True,
    )

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
