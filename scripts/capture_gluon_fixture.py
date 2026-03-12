#!/usr/bin/env python3
"""Capture a sanitized Proton profile fixture with Gluon file families."""

from __future__ import annotations

import argparse
import json
import re
from datetime import date
from pathlib import Path
from typing import Dict, List

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+")
HEX_TOKEN_RE = re.compile(r"\b[a-fA-F0-9]{16,}\b")
SECRET_KV_RE = re.compile(
    r"(?im)\b(password|passphrase|token|secret|authorization)\b\s*[:=]\s*[^\s\"']+"
)

FAMILY_PATTERNS: Dict[str, List[str]] = {
    "gluon_message_store_files": ["backend/store/*/*"],
    "gluon_sqlite_primary_db": ["backend/db/*.db"],
    "gluon_sqlite_wal_sidecars": ["backend/db/*.db-wal", "backend/db/*.db-shm"],
    "gluon_deferred_delete_pool": ["backend/db/deferred_delete/**/*"],
    "imap_sync_state_files": ["sync-*", "sync-*.tmp"],
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Capture and sanitize Proton profile fixtures aligned to BE-016 file families."
    )
    parser.add_argument("--source-profile", type=Path, required=True, help="Path to source Proton profile root")
    parser.add_argument("--output-dir", type=Path, required=True, help="Directory where sanitized fixture files are written")
    parser.add_argument(
        "--manifest-out",
        type=Path,
        default=None,
        help="Output path for capture manifest JSON (default: <output-dir>/gluon_fixture_manifest.json)",
    )
    parser.add_argument(
        "--fixture-name",
        type=str,
        default="proton_profile_gluon_sanitized",
        help="Fixture name recorded in the generated manifest",
    )
    parser.add_argument("--dry-run", action="store_true", help="Discover files and print manifest without writing files")
    return parser.parse_args()


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def load_be016_families(root: Path) -> List[str]:
    target = root / "tests" / "fixtures" / "gluon_compatibility_target.json"
    data = json.loads(target.read_text(encoding="utf-8"))
    return [entry["family_id"] for entry in data["required_file_families"]]


def sanitize_segment(segment: str) -> str:
    replaced = EMAIL_RE.sub("email-redacted", segment)
    replaced = HEX_TOKEN_RE.sub("id-redacted", replaced)
    return replaced


def sanitize_text(payload: str) -> str:
    redacted = EMAIL_RE.sub("redacted@example.invalid", payload)
    redacted = SECRET_KV_RE.sub(r"\1=<redacted>", redacted)
    return redacted


def sanitize_copy(src: Path, dst: Path) -> None:
    raw = src.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        dst.write_bytes(raw)
        return

    sanitized = sanitize_text(text)
    dst.write_text(sanitized, encoding="utf-8")


def gather_family_paths(source_profile: Path) -> Dict[str, List[Path]]:
    captured: Dict[str, List[Path]] = {}
    for family_id, patterns in FAMILY_PATTERNS.items():
        matches: List[Path] = []
        for pattern in patterns:
            for candidate in sorted(source_profile.glob(pattern)):
                if candidate.is_file():
                    matches.append(candidate.relative_to(source_profile))
        captured[family_id] = sorted(set(matches))
    return captured


def main() -> int:
    args = parse_args()
    source_profile = args.source_profile.resolve()
    output_dir = args.output_dir.resolve()
    manifest_out = args.manifest_out.resolve() if args.manifest_out else output_dir / "gluon_fixture_manifest.json"

    if not source_profile.exists() or not source_profile.is_dir():
        raise SystemExit(f"--source-profile must be an existing directory: {source_profile}")

    root = repo_root()
    be016_families = load_be016_families(root)
    captured = gather_family_paths(source_profile)

    for family_id in be016_families:
        if family_id not in captured:
            captured[family_id] = []

    captured_families = []
    for family_id in be016_families:
        family_paths: List[str] = []
        for rel_path in captured[family_id]:
            sanitized_rel = Path(*[sanitize_segment(part) for part in rel_path.parts])
            destination = output_dir / sanitized_rel
            family_paths.append(str(sanitized_rel))

            if not args.dry_run:
                destination.parent.mkdir(parents=True, exist_ok=True)
                sanitize_copy(source_profile / rel_path, destination)

        captured_families.append({"family_id": family_id, "paths": family_paths})

    manifest = {
        "ticket": "BE-017",
        "captured_on": date.today().isoformat(),
        "fixture_name": args.fixture_name,
        "source_profile": str(source_profile),
        "compatibility_target_fixture": "tests/fixtures/gluon_compatibility_target.json",
        "output_dir": str(output_dir),
        "unsupported_cases": [
            "Sanitized sqlite and deferred-delete artifacts may be placeholder bytes for file-family coverage and are not guaranteed to be cache-openable by CompatibleStore."
        ],
        "sanitization": {
            "redacted_patterns": [
                "email addresses",
                "secret key/value fields",
                "hex-like long identifiers in filenames",
            ]
        },
        "captured_families": captured_families,
    }

    if not args.dry_run:
        manifest_out.parent.mkdir(parents=True, exist_ok=True)
        manifest_out.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
