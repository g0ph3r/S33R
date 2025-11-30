#!/usr/bin/env python3
"""
build_news_archive.py

Lê data/news_recent.json (estrutura:
{
  "generated_at": "...",
  "days_back": 30,
  "total_items": ...,
  "items": [ ... ]
}
)
e atualiza arquivos de arquivo mensal e anual em:

- data/archive/monthly/<ano>/<ano>-<mes>.json
- data/archive/yearly/<ano>.json

Cada arquivo é uma LISTA de itens (mesma estrutura de item do news_recent.json).
O script é idempotente: pode ser executado várias vezes, pois faz merge + dedup.

Além disso, processa arquivos de debug `promo_filtered_*.json` gerados pelo
build_news_json.py, agregando-os em arquivos mensais de promo:

- data/archive/promo/monthly/<ano>/promo_<ano>-<mes>.json

Após o processamento, os arquivos `data/archive/promo_filtered_*.json` são apagados.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Caminhos base
BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
RECENT_PATH = DATA_DIR / "news_recent.json"

ARCHIVE_DIR = DATA_DIR / "archive"
MONTHLY_DIR = ARCHIVE_DIR / "monthly"
YEARLY_DIR = ARCHIVE_DIR / "yearly"

PROMO_DIR = ARCHIVE_DIR / "promo"
PROMO_MONTHLY_DIR = PROMO_DIR / "monthly"


# ---------- Utilidades de I/O ----------

def load_json_any(path: Path) -> Any:
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_json_list(path: Path, root_key: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Carrega um JSON e retorna uma lista de itens.

    - Se for uma lista na raiz, retorna direto.
    - Se for um dict com a chave `root_key` (ou 'items' por padrão), retorna essa lista.
    """
    if not path.exists():
        return []

    data = load_json_any(path)

    # Caso mais simples: já é lista
    if isinstance(data, list):
        return data

    # Caso dict (como news_recent.json)
    if isinstance(data, dict):
        # se root_key foi informado, tentar ela primeiro
        if root_key and isinstance(data.get(root_key), list):
            return data[root_key]

        # fallback padrão para "items"
        if isinstance(data.get("items"), list):
            return data["items"]

        raise ValueError(
            f"Esperado lista ou dict com chave 'items' em {path}, "
            f"mas encontrei dict com chaves: {list(data.keys())}"
        )

    raise ValueError(f"Esperado lista ou dict em {path}, mas encontrei {type(data)}")


def save_json_list(path: Path, items: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(items, f, ensure_ascii=False, indent=2)


# ---------- Helpers para datas ----------

def parse_datetime(value: Any) -> Optional[datetime]:
    """
    Tenta converter um campo de data (string ISO ou timestamp numérico) em datetime.
    """
    if value is None:
        return None

    if isinstance(value, (int, float)):
        # assume timestamp em segundos
        return datetime.fromtimestamp(float(value), tz=timezone.utc)

    if isinstance(value, str):
        # tenta ISO 8601
        try:
            # datetime.fromisoformat pode não entender 'Z', então tratamos
            if value.endswith("Z"):
                value = value[:-1] + "+00:00"
            return datetime.fromisoformat(value)
        except Exception:
            return None

    return None


def ensure_timestamp(item: Dict[str, Any]) -> float:
    """
    Garante que cada item tenha um campo numérico 'published_ts' (epoch em segundos)
    derivado de 'published' (string ISO) ou 'published_ts' já existente.
    """
    ts = item.get("published_ts")
    if isinstance(ts, (int, float)):
        return float(ts)

    dt = parse_datetime(item.get("published")) or parse_datetime(item.get("updated"))
    if dt is None:
        # fallback: agora
        dt = datetime.now(timezone.utc)

    item["published_ts"] = dt.timestamp()
    return item["published_ts"]


# ---------- Bucketização por mês/ano ----------

def bucket_items_by_month(items: List[Dict[str, Any]]) -> Dict[Tuple[int, int], List[Dict[str, Any]]]:
    """
    Agrupa itens por (ano, mês) com base em published_ts / published.
    """
    buckets: Dict[Tuple[int, int], List[Dict[str, Any]]] = {}

    for it in items:
        ts = ensure_timestamp(it)
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        key = (dt.year, dt.month)
        buckets.setdefault(key, []).append(it)

    return buckets


def bucket_items_by_year(items: List[Dict[str, Any]]) -> Dict[int, List[Dict[str, Any]]]:
    """
    Agrupa itens por ano.
    """
    buckets: Dict[int, List[Dict[str, Any]]] = {}

    for it in items:
        ts = ensure_timestamp(it)
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        key = dt.year
        buckets.setdefault(key, []).append(it)

    return buckets


# ---------- Merge + dedup por link ----------

def merge_and_dedup(existing: List[Dict[str, Any]], new: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Junta listas existente + nova, deduplicando principalmente por `link`.
    Se não tiver link, tenta (title, source) como fallback.
    """
    merged: Dict[Any, Dict[str, Any]] = {}

    def key_for(item: Dict[str, Any]) -> Any:
        link = item.get("link")
        if link:
            return ("link", link)
        return ("title_source", item.get("title"), item.get("source"))

    for item in existing + new:
        k = key_for(item)
        merged[k] = item

    # Converte de volta para lista e ordena por published_ts desc
    result = list(merged.values())

    def sort_key(it: Dict[str, Any]) -> float:
        dt = parse_datetime(it.get("published")) or parse_datetime(it.get("updated"))
        if dt is not None:
            return dt.timestamp()
        ts = it.get("published_ts")
        if isinstance(ts, (int, float)):
            return float(ts)
        return 0.0

    result.sort(key=sort_key, reverse=True)
    return result


# ---------- Processamento de promo_filtered_* (feeds com conteúdo promocional) ----------

def _normalize_promo_item(item: Dict[str, Any], seen_at: datetime) -> Dict[str, Any]:
    """
    Normaliza um item de promo para o formato usado nos arquivos mensais.

    Campos de saída:
      - feed_title
      - xml_url
      - type_label
      - first_seen / last_seen (ISO8601)
      - total_hits
      - examples (lista de strings, no máximo 10)
    """
    def _to_int(val: Any) -> int:
        try:
            return int(val)
        except (TypeError, ValueError):
            return 0

    promo_count = _to_int(item.get("promo_count", item.get("count", 0)))

    examples = item.get("examples") or []
    if not isinstance(examples, list):
        examples = [examples]
    examples = [str(e) for e in examples][:10]

    return {
        "feed_title": item.get("feed_title"),
        "xml_url": item.get("xml_url"),
        "type_label": item.get("type_label"),
        "first_seen": seen_at.isoformat(),
        "last_seen": seen_at.isoformat(),
        "total_hits": promo_count,
        "examples": examples,
    }


def _merge_promo_month_entries(
    existing: List[Dict[str, Any]],
    new_entries: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Junta entradas de promo para um mesmo mês, agregando por feed (chave xml_url ou feed_title).
    Soma total_hits, mescla exemplos e ajusta first_seen/last_seen.
    """
    merged: Dict[str, Dict[str, Any]] = {}

    def key_for(it: Dict[str, Any]) -> Optional[str]:
        return it.get("xml_url") or it.get("feed_title")

    def to_int(val: Any) -> int:
        try:
            return int(val)
        except (TypeError, ValueError):
            return 0

    def merge_one(target: Dict[str, Any], src: Dict[str, Any]) -> None:
        # Soma total_hits
        target["total_hits"] = to_int(target.get("total_hits")) + to_int(
            src.get("total_hits", src.get("promo_count", 0))
        )

        # Mescla exemplos (limitando em 10)
        existing_examples = [str(e) for e in (target.get("examples") or [])]
        seen = set(existing_examples)
        src_examples = src.get("examples") or []
        for ex in src_examples:
            ex_str = str(ex)
            if ex_str not in seen:
                existing_examples.append(ex_str)
                seen.add(ex_str)
            if len(existing_examples) >= 10:
                break
        target["examples"] = existing_examples

        # Ajusta first_seen / last_seen se presentes e em formato ISO
        src_first = src.get("first_seen")
        src_last = src.get("last_seen")

        if src_first:
            if not target.get("first_seen") or str(src_first) < str(target["first_seen"]):
                target["first_seen"] = src_first
        if src_last:
            if not target.get("last_seen") or str(src_last) > str(target["last_seen"]):
                target["last_seen"] = src_last

        # Mantém feed_title/xml_url/type_label mais recentes se vierem preenchidos
        for field in ("feed_title", "xml_url", "type_label"):
            if src.get(field):
                target[field] = src[field]

    # Primeiro, copiar existentes
    for it in existing:
        k = key_for(it)
        if not k:
            continue
        merged[k] = dict(it)

    # Depois, agregar novos
    for it in new_entries:
        k = key_for(it)
        if not k:
            continue
        if k in merged:
            merge_one(merged[k], it)
        else:
            # garantir campos padrão
            base = dict(it)
            base.setdefault("total_hits", to_int(it.get("total_hits", it.get("promo_count", 0))))
            base.setdefault("examples", it.get("examples") or [])
            merged[k] = base

    return list(merged.values())


def process_promo_filtered_files() -> None:
    """
    Procura por arquivos data/archive/promo_filtered_*.json, bucketiza por mês
    (com base no mtime do arquivo) e grava/atualiza:

        data/archive/promo/monthly/<ano>/promo_<ano>-<mes>.json

    Após o processamento bem-sucedido, os arquivos promo_filtered_* são apagados.
    """
    promo_files = sorted(ARCHIVE_DIR.glob("promo_filtered_*.json"))

    if not promo_files:
        print("[INFO] Nenhum arquivo promo_filtered_* para processar.")
        return

    monthly_new: Dict[Tuple[int, int], List[Dict[str, Any]]] = {}

    for path in promo_files:
        try:
            raw = load_json_any(path)
        except Exception as e:
            print(f"[WARN] Falha ao ler {path}: {e}")
            continue

        if raw is None:
            continue

        # Determina os itens dentro do arquivo
        if isinstance(raw, list):
            items = raw
        elif isinstance(raw, dict):
            # tentar algumas chaves comuns
            if isinstance(raw.get("items"), list):
                items = raw["items"]
            elif isinstance(raw.get("feeds"), list):
                items = raw["feeds"]
            else:
                # Último recurso: tentar interpretar valores de dict como lista de itens
                values = list(raw.values())
                if values and isinstance(values[0], list):
                    items = values[0]
                else:
                    print(f"[WARN] Formato inesperado em {path}, ignorando.")
                    continue
        else:
            print(f"[WARN] Formato inesperado em {path}, ignorando.")
            continue

        # Usa o mtime do arquivo para determinar ano/mês
        mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        year, month = mtime.year, mtime.month

        bucket_key = (year, month)
        bucket = monthly_new.setdefault(bucket_key, [])

        for it in items:
            if not isinstance(it, dict):
                continue
            norm = _normalize_promo_item(it, mtime)
            bucket.append(norm)

    # Atualiza arquivos mensais de promo
    for (year, month), new_entries in sorted(monthly_new.items()):
        year_str = f"{year}"
        month_str = f"{month:02d}"

        month_dir = PROMO_MONTHLY_DIR / year_str
        month_dir.mkdir(parents=True, exist_ok=True)
        promo_month_path = month_dir / f"promo_{year_str}-{month_str}.json"

        existing = load_json_list(promo_month_path)
        merged = _merge_promo_month_entries(existing, new_entries)
        save_json_list(promo_month_path, merged)

        print(
            f"[INFO] Arquivo mensal de promo atualizado: {promo_month_path} "
            f"(+{len(new_entries)} registros, total {len(merged)})"
        )

    # Limpa arquivos de entrada após o processamento
    for path in promo_files:
        try:
            path.unlink()
            print(f"[INFO] Arquivo processado e removido: {path}")
        except OSError as e:
            print(f"[WARN] Não foi possível apagar {path}: {e}")


# ---------- Função principal ----------

def main() -> None:
    if not RECENT_PATH.exists():
        raise FileNotFoundError(f"Arquivo recente não encontrado: {RECENT_PATH}")

    # news_recent.json é um dict com "items"
    recent_items = load_json_list(RECENT_PATH, root_key="items")
    print(f"[INFO] Carregados {len(recent_items)} itens recentes de {RECENT_PATH}")

    if not recent_items:
        print("[INFO] Nenhum item recente para arquivar. Encerrando.")
        return

    # Buckets por mês e ano
    monthly_buckets = bucket_items_by_month(recent_items)
    yearly_buckets = bucket_items_by_year(recent_items)

    # --------- Atualiza arquivos mensais ---------
    for (year, month), items in sorted(monthly_buckets.items()):
        year_str = f"{year}"
        month_str = f"{month:02d}"

        month_dir = MONTHLY_DIR / year_str
        month_path = month_dir / f"{year_str}-{month_str}.json"

        existing = load_json_list(month_path)
        merged = merge_and_dedup(existing, items)
        save_json_list(month_path, merged)

        print(
            f"[INFO] Arquivo mensal atualizado: {month_path} "
            f"(+{len(items)} itens, total {len(merged)})"
        )

    # --------- Atualiza arquivos anuais ---------
    for year, items in sorted(yearly_buckets.items()):
        year_str = f"{year}"
        year_path = YEARLY_DIR / f"{year_str}.json"

        existing = load_json_list(year_path)
        merged = merge_and_dedup(existing, items)
        save_json_list(year_path, merged)

        print(
            f"[INFO] Arquivo anual atualizado: {year_path} "
            f"(+{len(items)} itens, total {len(merged)})"
        )

    # --------- Processa arquivos promo_filtered_* ---------
    process_promo_filtered_files()

    print("[INFO] build_news_archive.py concluído com sucesso.")


if __name__ == "__main__":
    main()
