#!/usr/bin/env python3
"""Make the staged copy archivable for tool/native_payload.py; never publish.

The repository keeps `publish_to: none` on both packages until the owner
decides to release. `dart pub publish --to-archive` refuses such packages, so
this drops the line from the gate's disposable staged copy only.
"""
import argparse
from pathlib import Path
import re
import subprocess

PACKAGES = ["packages/pgp_dart", "packages/pgp_flutter"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staged-root", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()
    root = args.staged_root.resolve()
    # The gate's snapshot is a fresh `git init` with no commits; refuse to
    # edit a real checkout.
    has_history = subprocess.run(["git", "rev-parse", "--verify", "-q", "HEAD"], cwd=root,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    if has_history:
        raise SystemExit(f"Refusing to edit a checkout with history: {root}")
    for package in PACKAGES:
        manifest = root / package / "pubspec.yaml"
        text = manifest.read_text()
        updated = re.sub(r"^publish_to: none\b[^\n]*\n", "", text, flags=re.M)
        if updated == text:
            raise SystemExit(f"Expected publish_to: none in {manifest}")
        manifest.write_text(updated)
        print(f"{package}: dropped publish_to for the staged archive of {args.revision}")


if __name__ == "__main__":
    main()
