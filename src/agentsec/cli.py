"""Command-line entry point."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from pydantic import ValidationError

from .constants import SCENARIO_ID
from .evaluation import EvaluationService
from .incidents import InvestigationService
from .models import ApprovalSimulation, PolicyProfile
from .replay import ReplayService
from .rule_engine import load_rules
from .rule_testing import execute_rule_tests
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

    rules_parser = subparsers.add_parser("rules", help="validate or test detection rules")
    rules_subparsers = rules_parser.add_subparsers(dest="rules_command", required=True)
    validate_parser = rules_subparsers.add_parser(
        "validate", help="validate bounded JSON rule files"
    )
    validate_parser.add_argument("--rules", type=Path, required=True)
    test_parser = rules_subparsers.add_parser("test", help="run deterministic rule fixtures")
    test_parser.add_argument("--rules", type=Path, required=True)
    test_parser.add_argument("--fixtures", type=Path, required=True)
    _add_output_directory(test_parser)

    replay_parser = subparsers.add_parser(
        "replay", help="evaluate rules over one existing SQLite run"
    )
    replay_parser.add_argument("--events", type=Path, required=True)
    replay_parser.add_argument("--run-id", required=True)
    replay_parser.add_argument("--rules", type=Path, required=True)
    _add_output_directory(replay_parser)

    investigate_parser = subparsers.add_parser(
        "investigate", help="derive alerts and incidents from one existing SQLite run"
    )
    investigate_parser.add_argument("--events", type=Path, required=True)
    investigate_parser.add_argument("--run-id", required=True)
    investigate_parser.add_argument("--rules", type=Path, required=True)
    _add_output_directory(investigate_parser)

    evaluate_parser = subparsers.add_parser(
        "evaluate", help="run the closed packaged incident-evaluation suite"
    )
    evaluate_parser.add_argument("--suite", choices=("core-lab-v1",), required=True)
    evaluate_parser.add_argument("--repetitions", type=int, default=1)
    _add_output_directory(evaluate_parser)

    dashboard_parser = subparsers.add_parser(
        "dashboard", help="serve selected lab artifacts in a read-only local dashboard"
    )
    dashboard_parser.add_argument("--manifest", type=Path, required=True)
    dashboard_parser.add_argument("--port", type=int, default=8765)
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
        if arguments.command == "run":
            runner = ScenarioRunner()
            profile = PolicyProfile(arguments.profile)
            if profile is PolicyProfile.VULNERABLE and arguments.approval_simulation is not None:
                raise ValueError("approval simulation applies only to the strict profile")
            approval = ApprovalSimulation(
                arguments.approval_simulation or ApprovalSimulation.DENY.value
            )
            run_result = runner.run(
                arguments.scenario,
                arguments.output_dir,
                profile=profile,
                approval_simulation=approval,
            )
            print(f"run_id={run_result.run_id}")
            print(f"profile={run_result.report.policy_profile.value}")
            print(f"outcome={run_result.report.outcome}")
            print(f"detected={str(run_result.detection.detected).lower()}")
            print(f"prevented={str(run_result.report.prevention.blocked).lower()}")
            print(f"artifacts={run_result.run_directory}")
            return 0
        if arguments.command == "compare":
            runner = ScenarioRunner()
            comparison_result = runner.compare(arguments.scenario, arguments.output_dir)
            print(f"comparison_id={comparison_result.comparison_id}")
            print(f"vulnerable_outcome={comparison_result.vulnerable.report.outcome}")
            print(f"strict_outcome={comparison_result.strict.report.outcome}")
            print(f"artifacts={comparison_result.comparison_directory}")
            return 0
        if arguments.command == "rules" and arguments.rules_command == "validate":
            rules = load_rules(arguments.rules)
            print(f"validated_rules={len(rules)}")
            return 0
        if arguments.command == "rules" and arguments.rules_command == "test":
            test_result = execute_rule_tests(
                arguments.rules, arguments.fixtures, arguments.output_dir
            )
            print(f"status={test_result.report.status}")
            print(
                f"rule_coverage={test_result.report.covered_rules}/{test_result.report.total_rules}"
            )
            print(f"artifacts={test_result.output_directory}")
            return 0 if test_result.report.status == "passed" else 2
        if arguments.command == "replay":
            replay_result = ReplayService().replay(
                arguments.events,
                arguments.run_id,
                arguments.rules,
                arguments.output_dir,
            )
            print(f"replay_id={replay_result.report.replay_id}")
            print(f"source_status={replay_result.report.source_status}")
            print(f"matches={replay_result.report.total_matches}")
            print(f"artifacts={replay_result.replay_directory}")
            return 0
        if arguments.command == "investigate":
            investigation = InvestigationService().investigate(
                arguments.events,
                arguments.run_id,
                arguments.rules,
                arguments.output_dir,
            )
            print(f"investigation_id={investigation.report.investigation_id}")
            print(f"source_status={investigation.report.source_status}")
            print(f"derived_alerts={len(investigation.report.derived_alerts)}")
            print(f"incidents={len(investigation.report.incidents)}")
            print(f"artifacts={investigation.investigation_directory}")
            return 0
        if arguments.command == "evaluate":
            evaluation = EvaluationService().evaluate(
                arguments.suite,
                arguments.repetitions,
                arguments.output_dir,
            )
            print(f"evaluation_id={evaluation.report.evaluation_id}")
            print(f"status={evaluation.report.status}")
            print(
                "children="
                f"{evaluation.report.completed_children}/{evaluation.report.scheduled_children}"
            )
            print(f"artifacts={evaluation.evaluation_directory}")
            if evaluation.report.status == "partial":
                return 1
            return 0 if evaluation.report.status == "passed" else 2
        if arguments.command == "dashboard":
            try:
                import uvicorn

                from .dashboard_api import create_dashboard_app
                from .dashboard_catalog import DashboardCatalog
            except ImportError:
                print(
                    "error: dashboard dependencies unavailable; install agentsec-lab[dashboard]",
                    file=sys.stderr,
                )
                return 2
            if not 1 <= arguments.port <= 65535:
                raise ValueError("dashboard port must be between 1 and 65535")
            catalog = DashboardCatalog.load(arguments.manifest)
            app = create_dashboard_app(catalog, port=arguments.port)
            uvicorn.run(
                app,
                host="127.0.0.1",
                port=arguments.port,
                reload=False,
                workers=1,
                access_log=False,
            )
            return 0
        parser.error("a command is required")
    except (ValidationError, ValueError) as error:
        print(f"error: invalid input ({type(error).__name__})", file=sys.stderr)
        return 2
    except Exception as error:
        print(f"error: operation failed ({type(error).__name__})", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
