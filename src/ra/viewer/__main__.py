"""CLI entry point: ``python -m ra.viewer <run_dir> [-o OUT] [--open]``.

Renders any ``ra`` run's agent trace into a single self-contained HTML file.
Domain tools (e.g. ``kai view``) wrap a richer page on top of this.
"""

from __future__ import annotations

import argparse
import sys
import webbrowser
from pathlib import Path

from ra.viewer.html import write_trace_html


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m ra.viewer",
        description="Render an ra run's agent trace to a single HTML file.",
    )
    parser.add_argument(
        "run_dir",
        help="run directory (a dir with *.jsonl rollouts, or state/<id>/rollouts/)",
    )
    parser.add_argument(
        "-o", "--output", help="output HTML path (default: <run_dir>/trace.html)"
    )
    parser.add_argument(
        "--open", action="store_true", help="open the rendered file in a browser"
    )
    args = parser.parse_args(argv)

    run_dir = Path(args.run_dir)
    if not run_dir.is_dir():
        print(f"error: {run_dir} is not a directory", file=sys.stderr)
        return 2

    target = write_trace_html(run_dir, Path(args.output) if args.output else None)
    print(target)
    if args.open:
        webbrowser.open(target.resolve().as_uri())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
