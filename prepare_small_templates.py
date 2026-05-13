"""Prepare a small template subset for ASMO testing (10-20 templates).

This script implements PHẦN 1 and Acceptance Test step (1).

Default behavior:
- If nuclei-templates repo is missing at `D:\\Nuclei\\nuclei-templates`, try to git clone it.
- Create `D:\\KLTN\\nuclei-small`
- Copy up to 20 templates from preferred directories:
  - http/technologies
  - http/exposures
  - http/cves/wordpress
  - http/misconfiguration

It skips templates whose info.tags contain intrusive/destructive when possible.

Usage:
    python prepare_small_templates.py
    python prepare_small_templates.py --max 20
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path
from typing import List

import yaml


DEFAULT_REPO_DIR = Path(r"D:\Nuclei\nuclei-templates")
DEFAULT_PROJECT_DIR = Path(r"D:\KLTN")
DEFAULT_SMALL_DIR = DEFAULT_PROJECT_DIR / "nuclei-small"

PREFERRED_DIRS = [
    Path("http") / "technologies",
    Path("http") / "exposures",
    Path("http") / "cves" / "wordpress",
    Path("http") / "misconfiguration",
]


def _try_clone(repo_dir: Path) -> bool:
    if repo_dir.exists():
        return True

    repo_dir.parent.mkdir(parents=True, exist_ok=True)

    try:
        subprocess.run(
            [
                "git",
                "clone",
                "https://github.com/projectdiscovery/nuclei-templates.git",
                str(repo_dir),
            ],
            check=True,
        )
        return True
    except Exception as exc:
        print(f"[WARN] Failed to clone nuclei-templates: {exc}")
        return False


def _read_tags(path: Path) -> List[str]:
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8", errors="ignore"))
        if not isinstance(doc, dict):
            return []
        info = doc.get("info") or {}
        if not isinstance(info, dict):
            return []
        tags = info.get("tags")
        if tags is None:
            return []
        if isinstance(tags, str):
            return [t.strip() for t in tags.split(",") if t.strip()]
        if isinstance(tags, list):
            return [str(t).strip() for t in tags if str(t).strip()]
        return [str(tags)]
    except Exception:
        return []


def _is_safe_template(path: Path) -> bool:
    tags = {t.lower() for t in _read_tags(path)}
    if "intrusive" in tags:
        return False
    if "destructive" in tags:
        return False
    return True


def _gather_candidates(repo_dir: Path) -> List[Path]:
    candidates: List[Path] = []

    for rel in PREFERRED_DIRS:
        base = repo_dir / rel
        if not base.exists():
            continue
        candidates.extend(sorted(list(base.rglob("*.yaml")) + list(base.rglob("*.yml"))))

    # Dedup preserve order
    seen = set()
    out: List[Path] = []
    for p in candidates:
        if p in seen:
            continue
        seen.add(p)
        out.append(p)
    return out


KEYWORDS = [
    "wordpress",
    "wp",
    "php",
    "nginx",
    "apache",
    "joomla",
    "drupal",
    "version",
    "detect",
]


def _priority_score(path: Path) -> int:
    name = path.name.lower()
    score = 0
    for i, k in enumerate(KEYWORDS):
        if k in name:
            score += 10 - min(i, 9)
    return score


def main() -> int:
    ap = argparse.ArgumentParser(description="Prepare a small subset of Nuclei templates for ASMO")
    ap.add_argument("--repo-dir", default=str(DEFAULT_REPO_DIR), help="Path to nuclei-templates repository")
    ap.add_argument("--out-dir", default=str(DEFAULT_SMALL_DIR), help="Output directory (nuclei-small)")
    ap.add_argument("--max", type=int, default=20, help="Max templates to copy")
    args = ap.parse_args()

    repo_dir = Path(args.repo_dir)
    out_dir = Path(args.out_dir)
    max_templates = int(args.max)

    if not _try_clone(repo_dir):
        print("[ERROR] nuclei-templates repo not available. Please clone it manually.")
        return 1

    candidates = _gather_candidates(repo_dir)
    if not candidates:
        print("[ERROR] No candidate templates found in preferred directories.")
        return 1

    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    copied = 0
    skipped = 0

    candidates = sorted(candidates, key=lambda p: (-_priority_score(p), p.as_posix()))

    copied_files: List[Path] = []
    for src in candidates:
        if copied >= max_templates:
            break

        if not _is_safe_template(src):
            skipped += 1
            continue

        rel = src.relative_to(repo_dir)
        dst = out_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        copied += 1
        copied_files.append(dst)

    print(f"Copied {copied} templates into: {out_dir}")
    if skipped:
        print(f"Skipped {skipped} intrusive/destructive templates")

    if copied == 0:
        print("[ERROR] Copied 0 templates. Please adjust selection.")
        return 1

    print("Copied files:")
    for p in copied_files:
        print(f"- {p}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
