#!/usr/bin/env python3
"""
build_news_archive.py

Lê data/news_recent.json (janela móvel de ~30 dias) e
alimenta arquivos de arquivo histórico mensais em:

  data/archive/YYYY/MM.json

Evita duplicadas com base em uma chave derivada do item.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Diretórios base
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
RECENT_PATH = DATA_DIR / "news_recent.json"
ARCHIVE_BASE = DATA_DIR / "archive"


def load_json_list(path: Path) -> List[Dict[str, Any]]:
    """Carrega um arquivo JSON que contém uma lista de objetos."""
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        return []
    data = json.loads(text)
    if isinstance(data, list):
        return data
    raise ValueError(f"Esperado lista em {path}, mas encontrei {type(data)}")


def save_json_list(path: Path, items: List[Dict[str, Any]]) -> None:
    """Salva uma lista de objetos em JSON, com indentação."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(items, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def parse_published(item: Dict[str, Any]) -> Optional[datetime]:
    """
    Parser ajustado para o formato real do seu news_recent.json:

        "Thu, 12 Dec 2024 22:31:00 +0000"

    Esse é o formato clássico de RSS (RFC 822 / 1123).
    """
    value = (
        item.get("published")
        or item.get("date")
        or item.get("pubDate")
    )
    if not value or not isinstance(value, str):
        return None

    v = value.strip()

    # Formato exato do feed: "Thu, 12 Dec 2024 22:31:00 +0000"
    try:
        return datetime.strptime(v, "%a, %d %b %Y %H:%M:%S %z")
    except Exception:
        pass

    # Fallback: formatos alternativos que podem aparecer
    fallback_formats = [
        "%d %b %Y %H:%M:%S %z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S%z",
    ]

    for fmt in fallback_formats:
        try:
            return datetime.strptime(v, fmt)
        except Exception:
            continue

    print("[WARN] Falha ao parsear data:", repr(v))
    return None


def item_key(item: Dict[str, Any]) -> Optional[str]:
    """
    Gera uma chave única para o item, para evitar duplicatas.

    Preferência:
      - id
      - link
      - url
      - guid
      - fallback: title+source/feed
    """
    for field in ("id", "link", "url", "guid"):
        val = item.get(field)
        if val:
            return f"{field}:{val}"

    title = item.get("title")
    source = item.get("source") or item.get("feed") or ""
    if title:
        return f"title:{title}|source:{source}"

    return None


def process_item(item: Dict[str, Any]) -> None:
    """Envia um item para o arquivo mensal correspondente, se possível."""
    dt = parse_published(item)
    if dt is None:
        # Sem data não sabemos em qual mês arquivar
        print("[WARN] Item sem data de publicação, ignorando:", item.get("title", "sem título"))
        return

    key = item_key(item)
    if key is None:
        print("[WARN] Item sem chave única identificável, ignorando:", item.get("title", "sem título"))
        return

    year = f"{dt.year:04d}"
    month = f"{dt.month:02d}"

    month_path = ARCHIVE_BASE / year / f"{month}.json"

    month_items = load_json_list(month_path)

    # Constrói conjunto de chaves existentes para evitar duplicatas
    existing_keys = set()
    for existing in month_items:
        k = item_key(existing)
        if k:
            existing_keys.add(k)

    if key in existing_keys:
        # Já temos esse item arquivado
        return

    month_items.append(item)
    save_json_list(month_path, month_items)
    print(f"[INFO] Adicionado item ao arquivo {month_path} ({key})")


def main() -> None:
    if not RECENT_PATH.exists():
        print(f"[ERROR] Arquivo {RECENT_PATH} não encontrado. "
              "Certifique-se de rodar antes o build_news_json.py.")
        return

    recent_items = load_json_list(RECENT_PATH)
    print(f"[INFO] Carregados {len(recent_items)} itens de {RECENT_PATH}")

    for item in recent_items:
        process_item(item)


if __name__ == "__main__":
    main()
