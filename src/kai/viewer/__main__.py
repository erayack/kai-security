"""CLI entry point: ``python -m kai.viewer <run_dir> [-o OUT] [--open]``.

Renders a run directory into a single self-contained HTML file. This is the
implementation the ``kai view`` subcommand wraps; it also works standalone.
"""

from __future__ import annotations

import argparse
import sys
import webbrowser
from pathlib import Path

from kai.viewer.html import write_html


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m kai.viewer",
        description="Render a kai run (findings + agent trace) to a single HTML file.",
    )
    parser.add_argument(
        "run_dir",
        help="run directory (a state/<run_id>/ dir with exploits.json and/or rollouts/)",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="output HTML path (default: <run_dir>/trace.html)",
    )
    parser.add_argument(
        "--open",
        action="store_true",
        help="open the rendered file in a browser",
    )
    args = parser.parse_args(argv)

    run_dir = Path(args.run_dir)
    if not run_dir.is_dir():
        print(f"error: {run_dir} is not a directory", file=sys.stderr)
        return 2

    out = Path(args.output) if args.output else None
    target = write_html(run_dir, out)
    print(target)
    if args.open:
        webbrowser.open(target.resolve().as_uri())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
