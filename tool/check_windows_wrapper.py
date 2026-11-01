#!/usr/bin/env python3
"""Check packages/pgp_flutter/windows/rust against the crate it compiles.

The Windows wrapper builds ../../rust/src/lib.rs with the CNG backend, so its
[dependencies] must match the crate's apart from the backend selection, and
its library name and release profile must match too.
"""
import argparse
from pathlib import Path
import sys
import tomllib

BACKEND_ONLY = {"openssl-sys"}


def strip_backend(dependencies):
    result = {}
    for name, spec in dependencies.items():
        if name in BACKEND_ONLY:
            continue
        if isinstance(spec, dict):
            spec = {k: v for k, v in spec.items() if k not in ("features", "optional")}
            if set(spec) == {"version"}:
                spec = spec["version"]
        result[name] = spec
    return result


def check(repo):
    crate = tomllib.loads((repo / "packages/pgp_flutter/rust/Cargo.toml").read_text())
    wrapper = tomllib.loads((repo / "packages/pgp_flutter/windows/rust/Cargo.toml").read_text())
    problems = []
    if strip_backend(crate["dependencies"]) != strip_backend(wrapper["dependencies"]):
        problems.append(f"dependencies differ: {strip_backend(crate['dependencies'])} != {strip_backend(wrapper['dependencies'])}")
    sequoia = wrapper["dependencies"].get("sequoia-openpgp", {})
    if not isinstance(sequoia, dict) or sequoia.get("features") != ["crypto-cng"] or sequoia.get("default-features") is not False:
        problems.append("wrapper must use sequoia-openpgp with default-features = false and only crypto-cng")
    if wrapper["lib"].get("name") != crate["lib"].get("name"):
        problems.append("library names differ")
    if wrapper["lib"].get("path") != "../../rust/src/lib.rs":
        problems.append("wrapper must compile ../../rust/src/lib.rs")
    if wrapper.get("profile", {}).get("release") != crate.get("profile", {}).get("release"):
        problems.append("release profiles differ")
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parent.parent)
    problems = check(parser.parse_args().repo)
    for problem in problems:
        print(f"windows/rust: {problem}", file=sys.stderr)
    if problems:
        sys.exit(1)
    print("windows/rust matches packages/pgp_flutter/rust")


if __name__ == "__main__":
    main()
