"""GhostRE command line.

    python -m ghostre inspect <path>

Prints ONE JSON object to stdout. Exit codes: 0 = inspected,
2 = the path is missing or unreadable (stdout carries
``{"error": "..."}``).
"""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .inspect import InspectError, inspect_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ghostre",
        description="Ghost-native reverse-engineering inspector "
                    "(stdlib only, offline).")
    parser.add_argument("--version", action="version",
                        version=f"ghostre {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    p_inspect = sub.add_parser(
        "inspect", help="inspect one file or JavaScript app directory")
    p_inspect.add_argument("path", help="file or directory to inspect")
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "inspect":
        try:
            result = inspect_path(args.path)
        except InspectError as e:
            print(json.dumps({"error": str(e)}))
            return 2
        print(json.dumps(result))
        return 0
    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
