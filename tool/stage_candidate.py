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
import tempfile

PACKAGES = ["packages/pgp_dart", "packages/pgp_flutter"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staged-root", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()
    root = args.staged_root.resolve()
    # The gate stages a fresh `git init` with no refs under the temp dir;
    # refuse anything else rather than edit a real checkout.
    if not root.is_relative_to(Path(tempfile.gettempdir()).resolve()):
        raise SystemExit(f"Refusing to edit outside the temp dir: {root}")
    refs = subprocess.run(["git", "for-each-ref", "--count=1"], cwd=root,
                          capture_output=True, text=True)
    if refs.returncode or refs.stdout.strip():
        raise SystemExit(f"Refusing to edit a checkout with refs: {root}")
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
