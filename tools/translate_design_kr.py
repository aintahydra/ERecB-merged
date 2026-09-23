#!/usr/bin/env python3
"""Create a resumable Korean mirror of the Markdown design corpus via local Ollama."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from urllib.request import Request, urlopen


PROMPT = """You are translating a cybersecurity engineering design document from English to Korean.
Return only the complete translated Markdown document, with no preface, explanation, or Markdown
fence around the whole response. Translate all natural-language prose, headings, table labels,
and prose list items into clear professional Korean. Preserve the exact Markdown structure,
filenames, relative links and URLs, identifiers, commands, code blocks, YAML/JSON/Python/shell
syntax, hashes, paths, option names, and literal configuration values. Do not omit, summarize,
invent, or reorder content. Keep security terminology technically accurate.

Document follows:

"""


def translate(source: Path, target: Path, model: str) -> None:
    original = source.read_text(encoding="utf-8")
    host = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
    payload = json.dumps({"model": model, "prompt": PROMPT + original, "stream": False}).encode("utf-8")
    request = Request(host + "/api/generate", data=payload, headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=900) as response:
        body = json.load(response)
    translated = str(body.get("response", "")).strip() + "\n"
    if len(translated) < max(120, len(original) // 12):
        raise RuntimeError(f"translation output for {source} is unexpectedly short")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(translated, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=Path("design"))
    parser.add_argument("--target", type=Path, default=Path("design_kr"))
    parser.add_argument("--model", default="gpt-oss:20b")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--only", help="source-relative Markdown path to translate")
    args = parser.parse_args()
    files = sorted(args.source.rglob("*.md"))
    if args.only:
        requested = (args.source / args.only).resolve()
        files = [path for path in files if path.resolve() == requested]
        if not files:
            raise ValueError(f"no design Markdown file matches {args.only}")
    for number, source in enumerate(files, 1):
        target = args.target / source.relative_to(args.source)
        if target.exists() and not args.force:
            print(f"[{number}/{len(files)}] retained {target}", flush=True)
            continue
        print(f"[{number}/{len(files)}] translating {source}", flush=True)
        translate(source, target, args.model)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"translation failed: {error}", file=sys.stderr)
        raise SystemExit(1)
