"""Command-line entry point."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from pydantic import ValidationError

from .constants import SCENARIO_ID
from .models import ApprovalSimulation, PolicyProfile
from .runner import ScenarioRunner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentsec",
        description="Run and compare deterministic AgentSec Lab security profiles.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    run_parser = subparsers.add_parser("run", help="run a packaged scenario")
    run_parser.add_argument("scenario", choices=(SCENARIO_ID,))
    run_parser.add_argument(
        "--profile",
        choices=tuple(profile.value for profile in PolicyProfile),
        default=PolicyProfile.VULNERABLE.value,
        help="runtime policy profile (default: vulnerable)",
    )
    run_parser.add_argument(
        "--approval-simulation",
        choices=tuple(mode.value for mode in ApprovalSimulation),
        default=None,
        help="strict-profile response for eligible approval requests (default: deny)",
    )
    _add_output_directory(run_parser)

    compare_parser = subparsers.add_parser(
        "compare", help="run vulnerable and strict profiles and compare their evidence"
    )
    compare_parser.add_argument("scenario", choices=(SCENARIO_ID,))
    _add_output_directory(compare_parser)
    return parser


def _add_output_directory(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("artifacts"),
        help="trusted directory where new artifact directories are created",
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        arguments = parser.parse_args(argv)
        runner = ScenarioRunner()
        if arguments.command == "run":
            profile = PolicyProfile(arguments.profile)
            if (
                profile is PolicyProfile.VULNERABLE
                and arguments.approval_simulation is not None
            ):
                raise ValueError("approval simulation applies only to the strict profile")
            approval = ApprovalSimulation(
                arguments.approval_simulation or ApprovalSimulation.DENY.value
            )
            result = runner.run(
                arguments.scenario,
                arguments.output_dir,
                profile=profile,
                approval_simulation=approval,
            )
            print(f"run_id={result.run_id}")
            print(f"profile={result.report.policy_profile.value}")
            print(f"outcome={result.report.outcome}")
            print(f"detected={str(result.detection.detected).lower()}")
            print(f"prevented={str(result.report.prevention.blocked).lower()}")
            print(f"artifacts={result.run_directory}")
            return 0
        if arguments.command == "compare":
            result = runner.compare(arguments.scenario, arguments.output_dir)
            print(f"comparison_id={result.comparison_id}")
            print(f"vulnerable_outcome={result.vulnerable.report.outcome}")
            print(f"strict_outcome={result.strict.report.outcome}")
            print(f"artifacts={result.comparison_directory}")
            return 0
        parser.error("a command is required")
    except (ValidationError, ValueError) as error:
        print(f"error: invalid input ({type(error).__name__})", file=sys.stderr)
        return 2
    except Exception as error:
        print(f"error: scenario failed ({type(error).__name__})", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
