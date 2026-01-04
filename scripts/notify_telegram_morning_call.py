#!/usr/bin/env python3
"""
Send S33R Morning Call (data/morning_call_latest.json) to Telegram.

Required env vars:
  TELEGRAM_BOT_TOKEN
  TELEGRAM_CHAT_ID

Optional env vars:
  S33R_MORNING_CALL_PATH   (default: data/morning_call_latest.json)
  TELEGRAM_STATE_PATH      (default: data/telegram_state.json)
  TELEGRAM_DISABLE_PREVIEW (default: true)
  TELEGRAM_SILENT          (default: false)
  TELEGRAM_PREFIX          (default: "☕ S33R Morning Call")
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import List, Optional


MAX_TELEGRAM_TEXT = 4096  # Telegram message limit (UTF-8, post-entities parsing)


def _env_bool(name: str, default: bool) -> bool:
    val = (os.getenv(name) or "").strip().lower()
    if not val:
        return default
    return val in ("1", "true", "yes", "y", "on")


def chunk_text(text: str, limit: int = MAX_TELEGRAM_TEXT) -> List[str]:
    """
    Split text into chunks <= limit, preferring line boundaries.
    """
    text = (text or "").strip()
    if len(text) <= limit:
        return [text] if text else []

    lines = text.splitlines(keepends=True)
    chunks: List[str] = []
    cur = ""

    for line in lines:
        if len(cur) + len(line) <= limit:
            cur += line
            continue

        if cur.strip():
            chunks.append(cur.rstrip())
            cur = ""

        # If a single line is too big, hard-split it
        while len(line) > limit:
            chunks.append(line[:limit].rstrip())
            line = line[limit:]
        cur = line

    if cur.strip():
        chunks.append(cur.rstrip())

    return chunks


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_state(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def telegram_send_message(
    token: str,
    chat_id: str,
    text: str,
    disable_preview: bool = True,
    silent: bool = False,
    timeout_sec: int = 20,
) -> None:
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "disable_web_page_preview": "true" if disable_preview else "false",
        "disable_notification": "true" if silent else "false",
    }

    data = urllib.parse.urlencode(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
        body = resp.read().decode("utf-8", errors="replace")
        # Telegram always returns JSON with ok/result or ok=false/description (per docs)
        try:
            j = json.loads(body)
        except Exception:
            raise RuntimeError(f"Telegram API non-JSON response: {body[:300]}")
        if not j.get("ok"):
            raise RuntimeError(f"Telegram API error: {j.get('description')} (raw={body[:300]})")


def main() -> int:
    token = (os.getenv("TELEGRAM_BOT_TOKEN") or "").strip()
    chat_id = (os.getenv("TELEGRAM_CHAT_ID") or "").strip()
    if not token or not chat_id:
        print("Missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID", file=sys.stderr)
        return 2

    src = Path(os.getenv("S33R_MORNING_CALL_PATH", "data/morning_call_latest.json"))
    state_path = Path(os.getenv("TELEGRAM_STATE_PATH", "data/telegram_state.json"))

    disable_preview = _env_bool("TELEGRAM_DISABLE_PREVIEW", True)
    silent = _env_bool("TELEGRAM_SILENT", False)
    prefix = (os.getenv("TELEGRAM_PREFIX") or "☕ S33R Morning Call").strip()

    if not src.exists():
        print(f"Missing {src}", file=sys.stderr)
        return 3

    data = load_json(src)
    generated_at = (data.get("generated_at") or "").strip()
    window = (data.get("window") or "").strip()

    # content key: you mentioned "resumo pronto" — usually this is in morning_call_markdown
    md = (data.get("morning_call_markdown") or data.get("markdown") or "").strip()
    if not md:
        print("Missing morning_call_markdown (or markdown) in morning_call_latest.json", file=sys.stderr)
        return 4

    # Anti-spam: don't resend same generated_at
    state = load_state(state_path)
    last_sent = (state.get("last_sent_generated_at") or "").strip()
    if generated_at and last_sent == generated_at:
        print("No changes (generated_at already sent).")
        return 0

    header = prefix
    if window:
        header += f"\nWindow: {window}"
    if generated_at:
        header += f"\nGenerated: {generated_at}"
    header += "\n" + ("-" * 28) + "\n"

    # Plain-text; Telegram will auto-link URLs.
    message = header + md

    chunks = chunk_text(message, MAX_TELEGRAM_TEXT)
    if not chunks:
        print("Nothing to send.")
        return 0

    for i, chunk in enumerate(chunks, start=1):
        if len(chunks) > 1:
            chunk = f"[{i}/{len(chunks)}]\n" + chunk
        telegram_send_message(
            token=token,
            chat_id=chat_id,
            text=chunk,
            disable_preview=disable_preview,
            silent=silent,
        )
        # Being polite with rate limits
        time.sleep(1.1)

    # Persist state
    if generated_at:
        state["last_sent_generated_at"] = generated_at
        state["last_sent_at_epoch"] = int(time.time())
        save_state(state_path, state)

    print(f"Sent {len(chunks)} Telegram message(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
