#!/usr/bin/env python3
"""
Send S33R Morning Call (data/morning_call_latest.json) to Telegram, with formatting.

Required env vars:
  TELEGRAM_BOT_TOKEN
  TELEGRAM_CHAT_ID         # for public channels, use: @channel_username

Optional env vars:
  S33R_MORNING_CALL_PATH   (default: data/morning_call_latest.json)
  TELEGRAM_STATE_PATH      (default: data/telegram_state.json)
  TELEGRAM_DISABLE_PREVIEW (default: true)
  TELEGRAM_SILENT          (default: false)
  TELEGRAM_PREFIX          (default: "☕ S33R Morning Call")
  TELEGRAM_PARSE_MODE      (default: "HTML")  # HTML recommended
"""

from __future__ import annotations

import html
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import List


MAX_TELEGRAM_TEXT = 4096  # Telegram message limit


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


def _looks_like_bullet_line(s: str) -> bool:
    return s.lstrip().startswith(("• ", "- ", "* "))


def markdown_to_telegram_html(md: str) -> str:
    """
    Convert a subset of Markdown (common in morning_call_markdown) to Telegram-safe HTML.

    Strategy:
    - Escape everything first (prevents HTML injection)
    - Transform headers, bold, bullets, separators
    - Do a conservative italic conversion (avoids breaking on asterisks in random contexts)
    """
    if not md:
        return ""

    # Normalize line endings
    md = md.replace("\r\n", "\n").replace("\r", "\n").strip()

    # Escape early (Telegram HTML requires valid HTML)
    s = html.escape(md)

    # Convert horizontal rule-like separators
    # supports: "---" or "—" sequences in markdown
    s = re.sub(r'^\s*---+\s*$', '————————————', s, flags=re.MULTILINE)

    # Headers: ### Title / ## Title
    # Telegram doesn't have header tags; use bold.
    s = re.sub(r'^\s*###\s+(.*)$', r'<b>\1</b>', s, flags=re.MULTILINE)
    s = re.sub(r'^\s*##\s+(.*)$', r'<b>\1</b>', s, flags=re.MULTILINE)

    # Bold: **text** -> <b>text</b>
    # Because we've escaped HTML already, this is safe.
    s = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', s)

    # Bullets: "- " -> "• "
    s = re.sub(r'^\s*-\s+', '• ', s, flags=re.MULTILINE)

    # Convert "What:", "Why it matters:", etc. (already in your format)
    # Make the labels italic + bold-ish
    s = re.sub(r'^\s*•\s*(What:)\s*', r'• <i>\1</i> ', s, flags=re.MULTILINE)
    s = re.sub(r'^\s*•\s*(Why it matters:)\s*', r'• <i>\1</i> ', s, flags=re.MULTILINE)
    s = re.sub(r'^\s*•\s*(Recommended immediate actions:)\s*', r'• <i>\1</i> ', s, flags=re.MULTILINE)
    s = re.sub(r'^\s*•\s*(Logs sources:)\s*', r'• <i>\1</i> ', s, flags=re.MULTILINE)
    s = re.sub(r'^\s*•\s*(Focus:)\s*', r'• <i>\1</i> ', s, flags=re.MULTILINE)

    # Conservative italic: *text* -> <i>text</i>
    # Only apply when it looks like standalone emphasis (not bullet markers, not within words).
    # Avoid converting if there are angle-brackets already (we use them ourselves).
    def italics_repl(match: re.Match) -> str:
        inner = match.group(1)
        # Avoid italicizing very long spans that can get weird
        if len(inner) > 120:
            return match.group(0)
        return f"<i>{inner}</i>"

    # Pattern: *something* where something does not contain '*' or newlines
    # Also ensure it's not preceded/followed by word chars (to avoid mid-word)
    s = re.sub(r'(?<!\w)\*(?!\s)([^\n*]{1,120}?)(?<!\s)\*(?!\w)', italics_repl, s)

    # Improve spacing: add blank line after bold headers if not already
    # (Telegram renders better with whitespace)
    s = re.sub(r'(</b>)\n(?!\n)', r'\1\n\n', s)

    return s


def telegram_send_message(
    token: str,
    chat_id: str,
    text: str,
    parse_mode: str = "HTML",
    disable_preview: bool = True,
    silent: bool = False,
    timeout_sec: int = 20,
) -> None:
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": parse_mode,
        "disable_web_page_preview": "true" if disable_preview else "false",
        "disable_notification": "true" if silent else "false",
    }

    data = urllib.parse.urlencode(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
        body = resp.read().decode("utf-8", errors="replace")
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
    parse_mode = (os.getenv("TELEGRAM_PARSE_MODE") or "HTML").strip() or "HTML"

    if not src.exists():
        print(f"Missing {src}", file=sys.stderr)
        return 3

    data = load_json(src)
    generated_at = (data.get("generated_at") or "").strip()
    window = (data.get("window") or "").strip()

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

    header_lines = [f"<b>{html.escape(prefix)}</b>"]
    if window:
        header_lines.append(f"<i>Window:</i> {html.escape(window)}")
    if generated_at:
        header_lines.append(f"<i>Generated:</i> {html.escape(generated_at)}")
    header_lines.append("————————————")
    header = "\n".join(header_lines) + "\n\n"

    body = markdown_to_telegram_html(md)

    message = header + body

    chunks = chunk_text(message, MAX_TELEGRAM_TEXT)
    if not chunks:
        print("Nothing to send.")
        return 0

    for i, chunk in enumerate(chunks, start=1):
        if len(chunks) > 1:
            chunk = f"<i>[{i}/{len(chunks)}]</i>\n" + chunk
        telegram_send_message(
            token=token,
            chat_id=chat_id,
            text=chunk,
            parse_mode=parse_mode,
            disable_preview=disable_preview,
            silent=silent,
        )
        # gentle pacing
        time.sleep(1.1)

    if generated_at:
        state["last_sent_generated_at"] = generated_at
        state["last_sent_at_epoch"] = int(time.time())
        save_state(state_path, state)

    print(f"Sent {len(chunks)} Telegram message(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
