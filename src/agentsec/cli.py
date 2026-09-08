"""Command-line entry point."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from pydantic import ValidationError

from .constants import SCENARIO_ID
from .runner import ScenarioRunner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentsec",
        description="Run the deterministic AgentSec Lab MVP scenario.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    run_parser = subparsers.add_parser("run", help="run a packaged scenario")
    run_parser.add_argument("scenario", choices=(SCENARIO_ID,))
    run_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("artifacts"),
        help="trusted directory where a new run subdirectory is created",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        arguments = parser.parse_args(argv)
        if arguments.command != "run":
            parser.error("a command is required")
        result = ScenarioRunner().run(arguments.scenario, arguments.output_dir)
    except (ValidationError, ValueError) as error:
        print(f"error: invalid input ({type(error).__name__})", file=sys.stderr)
        return 2
    except Exception as error:
        print(f"error: scenario failed ({type(error).__name__})", file=sys.stderr)
        return 1
    print(f"run_id={result.run_id}")
    print(f"detected={str(result.detection.detected).lower()}")
    print(f"artifacts={result.run_directory}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
