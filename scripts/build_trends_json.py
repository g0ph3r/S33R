#!/usr/bin/env python3
"""
Gera data/trends.json com métricas de tendências para o trend.html:

- Volume diário de notícias
- Breakdown por categoria (smart_groups / tags)
- Top keywords por janela (24h, 7d, 30d, 90d)
- Contagem por vendor por janela
- Tendências de termos de ataque (ransomware, supply chain, 0-day, etc.)
- Top CVEs por janela (para o ranking de CVEs)
- Linha do tempo de menções a threat actors (por dia)

Fonte de dados:
- data/news_recent.json
"""

import json
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List

BASE_DIR = Path(__file__).resolve().parent.parent
NEWS_RECENT_PATH = BASE_DIR / "data" / "news_recent.json"
OUTPUT_PATH = BASE_DIR / "data" / "trends.json"

# Janelas usadas pelo front
WINDOWS = {
    "24h": 1,
    "7d": 7,
    "30d": 30,
    "90d": 90,
}

STOPWORDS = {
    "the", "and", "for", "with", "from", "this", "that", "have", "has",
    "into", "over", "under", "about", "your", "you", "are", "was", "were",
    "will", "their", "they", "them", "its", "our", "out", "but", "not",
    "can", "could", "would", "should", "may", "might", "than", "then",
    "after", "before", "more", "less", "also", "just", "into", "via",
    "security", "cyber", "attack", "attacks", "threat", "threats",
    "vulnerability", "vulnerabilities", "report", "reports", "new",
    "zero", "day", "days", "research", "team", "blog", "post",
}

# Vendors simples (ajuste conforme necessário)
VENDOR_KEYWORDS = {
    "Microsoft": ["microsoft", "windows", "exchange", "azure"],
    "Cisco": ["cisco", "ios xe"],
    "Palo Alto": ["palo alto", "pan-os"],
    "Fortinet": ["fortinet", "fortigate"],
    "Cloudflare": ["cloudflare"],
    "Google": ["google", "chrome", "android", "gmail"],
    "Apple": ["apple", "macos", "ios", "ipados"],
    "VMware": ["vmware", "esxi"],
    "Citrix": ["citrix"],
    "Progress": ["progress", "moveit"],
    "Atlassian": ["atlassian", "jira", "confluence"],
}

# Termos de "attack trends" que aparecerão no gráfico Emerging attack trends
TRENDING_TERMS = {
    "ransomware": "Ransomware",
    "double extortion": "Double extortion",
    "supply chain": "Supply chain",
    "0-day": "0-day",
    "zero-day": "Zero-day",
    "data breach": "Data breach",
    "initial access": "Initial access",
    "phishing": "Phishing",
    "credential stuffing": "Credential stuffing",
}

# Threat actors (pode expandir depois)
THREAT_ACTOR_PATTERNS = [
    r"\bAPT ?\d+\b",
    r"\bTA\d+\b",
    r"\bUNC\d+\b",
    r"\bStorm-\d+\b",
    r"\bFIN\d+\b",
    r"\bLazarus\b",
    r"\bScattered Spider\b",
    r"\bOcto Tempest\b",
    r"\bSandworm\b",
    r"\bAPT28\b",
    r"\bAPT29\b",
]

CVE_REGEX = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def parse_iso(date_str: str) -> datetime:
    """
    Faz parse de uma string de data (ISO-ish) e retorna datetime com timezone UTC.
    """
    if not date_str:
        raise ValueError("empty date")
    s = date_str
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt


def load_news() -> List[Dict[str, Any]]:
    print(f"[INFO] Loading {NEWS_RECENT_PATH}...")
    data = json.loads(NEWS_RECENT_PATH.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise RuntimeError("news_recent.json não é uma lista de entradas.")
    return data


def normalize_text(entry: Dict[str, Any]) -> str:
    parts = [
        entry.get("title", "") or "",
        entry.get("summary", "") or "",
        entry.get("source", "") or "",
    ]
    return " ".join(parts).lower()


def tokenize(text: str) -> Iterable[str]:
    """
    Divide o texto em tokens simples, removendo stopwords e tokens muito curtos.
    """
    for token in re.findall(r"[a-zA-Z0-9\-]+", text.lower()):
        if len(token) < 3:
            continue
        if token in STOPWORDS:
            continue
        yield token


def get_categories(entry: Dict[str, Any]) -> List[str]:
    """
    Tenta obter categorias / smart_groups da entrada.
    """
    cats = []

    sg = entry.get("smart_groups") or entry.get("categories") or entry.get("tags")
    if isinstance(sg, list):
        cats.extend([str(c) for c in sg])
    elif isinstance(sg, str):
        cats.append(sg)

    cat = entry.get("category")
    if isinstance(cat, str):
        cats.append(cat)

    cleaned = []
    for c in cats:
        c = c.strip()
        if c:
            cleaned.append(c)
    return cleaned


def within_window(entry_dt: datetime, now: datetime, days: int) -> bool:
    return entry_dt >= (now - timedelta(days=days))


def main() -> None:
    news = load_news()
    now = datetime.now(timezone.utc)

    # Contadores agregados
    daily_counter = Counter()  # date_str -> total de notícias
    per_window_categories: Dict[str, Counter] = {w: Counter() for w in WINDOWS}
    per_window_keywords: Dict[str, Counter] = {w: Counter() for w in WINDOWS}
    per_window_vendors: Dict[str, Counter] = {w: Counter() for w in WINDOWS}
    per_window_trends: Dict[str, Counter] = {w: Counter() for w in WINDOWS}
    per_window_cves: Dict[str, Counter] = {w: Counter() for w in WINDOWS}
    threat_actor_daily_counter = Counter()  # date_str -> notícias que citam actor

    threat_actor_compiled = [re.compile(pat, re.IGNORECASE) for pat in THREAT_ACTOR_PATTERNS]

    processed = 0
    skipped_no_date = 0

    for entry in news:
        date_str = entry.get("published") or entry.get("date")
        if not date_str:
            skipped_no_date += 1
            continue

        try:
            dt = parse_iso(date_str)
        except Exception:
            skipped_no_date += 1
            continue

        date_only = dt.date().isoformat()
        text = normalize_text(entry)

        # Volume diário
        daily_counter[date_only] += 1

        # Threat actors (para timeline diária)
        has_actor = any(p.search(text) for p in threat_actor_compiled)
        if has_actor:
            threat_actor_daily_counter[date_only] += 1

        # Categorias
        cats = get_categories(entry)

        # Keywords
        tokens = list(tokenize(text))

        # Vendors
        vendor_hits = set()
        for vendor, patterns in VENDOR_KEYWORDS.items():
            for pat in patterns:
                if pat.lower() in text:
                    vendor_hits.add(vendor)
                    break

        # Trending terms
        trend_hits = set()
        for key, label in TRENDING_TERMS.items():
            if key.lower() in text:
                trend_hits.add(key)

        # CVEs
        cve_hits = set(m.upper() for m in CVE_REGEX.findall(text))

        # Aplicar em cada janela
        for win, days in WINDOWS.items():
            if not within_window(dt, now, days):
                continue

            for c in cats:
                per_window_categories[win][c] += 1

            for t in tokens:
                per_window_keywords[win][t] += 1

            for v in vendor_hits:
                per_window_vendors[win][v] += 1

            for key in trend_hits:
                per_window_trends[win][key] += 1

            for cve in cve_hits:
                per_window_cves[win][cve] += 1

        processed += 1

    print(f"[INFO] Processed entries: {processed}, skipped (no date): {skipped_no_date}")

    # daily_volume ordenado
    daily_volume = [
        {"date": d, "count": int(daily_counter[d])}
        for d in sorted(daily_counter.keys())
    ]

    def counter_to_sorted_list(cnt: Counter) -> List[List[Any]]:
        return [[k, int(v)] for k, v in cnt.most_common()]

    categories_out = {
        win: {k: int(v) for k, v in per_window_categories[win].most_common()}
        for win in WINDOWS
    }

    top_keywords_out = {
        win: counter_to_sorted_list(per_window_keywords[win])
        for win in WINDOWS
    }

    vendors_out = {
        win: counter_to_sorted_list(per_window_vendors[win])
        for win in WINDOWS
    }

    trending_terms_out: Dict[str, Dict[str, Any]] = {}
    for key, label in TRENDING_TERMS.items():
        counts_per_win = {}
        for win in WINDOWS:
            counts_per_win[win] = int(per_window_trends[win][key])
        trending_terms_out[key] = {
            "label": label,
            "counts": counts_per_win,
        }

    top_cves_out = {
        win: counter_to_sorted_list(per_window_cves[win])
        for win in WINDOWS
    }

    threat_actor_daily = [
        {"date": d, "count": int(threat_actor_daily_counter[d])}
        for d in sorted(threat_actor_daily_counter.keys())
    ]

    output = {
        "generated_at": now.isoformat(),
        "windows": list(WINDOWS.keys()),
        "daily_volume": daily_volume,
        "categories": categories_out,
        "top_keywords": top_keywords_out,
        "vendors": vendors_out,
        "trending_terms": trending_terms_out,
        "top_cves": top_cves_out,
        "threat_actor_daily": threat_actor_daily,
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[OK] Trends written to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
