"""Inspect the experimental Q4OS profile and replay authenticated historical frames."""

from __future__ import annotations

import argparse
import sys
from dataclasses import asdict
from pathlib import Path

from . import q4os
from .evidence import Refusal, canonical, parse, read, unseal
from .schema import load_map


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("inspect", "replay", "verify-report", "verify-iso"):
        p = sub.add_parser(name)
        p.add_argument("--map", type=Path, default=q4os.MAP)
        if name in ("replay", "verify-report"):
            p.add_argument("--manifest", type=Path, default=q4os.MANIFEST)
            p.add_argument("--originals", type=Path, default=q4os.ORIGINALS)
        if name == "verify-report":
            p.add_argument("report", type=Path)
        if name == "verify-iso":
            p.add_argument("iso", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command in ("replay", "verify-report"):
            result = q4os.replay_q4os(args.map, args.manifest, args.originals)
            if args.command == "verify-report":
                saved = unseal(parse(read(args.report)))
                if canonical(saved) != canonical(result["manifest"]):
                    raise Refusal("Saved report differs from independent replay")
                result = {"verified": True, "sha256": result["sha256"]}
        else:
            mapping = load_map(args.map, q4os.PROFILE)
            result = {
                "distribution": asdict(mapping.identity),
                "installer": asdict(mapping.installer),
                "states": len(mapping.states),
                "transitions": len(mapping.transitions),
                "terminal": mapping.terminal,
                "locators": {m: q4os.SURFACE.status(m) for m in q4os.Method},
            }
            if args.command == "verify-iso":
                mapping.identity.verify_iso(args.iso)
                result["local_iso_verified"] = True
        print(canonical(result).decode())
        return 0
    except (ValueError, OSError) as exc:
        print(
            canonical(
                {"status": "refused", "command": args.command, "errors": [str(exc)]}
            ).decode(),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
