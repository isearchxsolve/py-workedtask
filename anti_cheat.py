"""Javelin Python anti-cheat integrity guard."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import sys
from pathlib import Path
from typing import Mapping, Optional

INTEGRITY_FAILURE_EXIT_CODE = 3
_EXPECTED_SHA256_ENV = "JAVELIN_EXPECTED_SHA256"
_SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)

    return digest.hexdigest()


def verify_integrity(
    script_path: Optional[Path] = None,
    environ: Optional[Mapping[str, str]] = None,
) -> bool:
    """Return True when integrity checks are disabled or the script matches."""
    environment = os.environ if environ is None else environ
    expected = environment.get(_EXPECTED_SHA256_ENV)

    # Optional guard: absent configuration leaves integrity verification disabled.
    if expected is None or expected == "":
        return True

    if not _SHA256_PATTERN.fullmatch(expected):
        return False

    target = Path(__file__ if script_path is None else script_path).resolve()

    try:
        actual = sha256_file(target)
    except (OSError, PermissionError):
        return False

    return hmac.compare_digest(actual, expected.lower())


def guarded_integrity_check() -> None:
    if not verify_integrity():
        print("[Javelin AntiCheat] Integrity check failed. Exiting.", file=sys.stderr)
        raise SystemExit(INTEGRITY_FAILURE_EXIT_CODE)


def main() -> int:
    guarded_integrity_check()
    print("[Javelin AntiCheat] Integrity check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
