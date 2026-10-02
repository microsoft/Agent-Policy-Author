# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import argparse
import json
from pathlib import Path

from incident_agent.orchestrator import IncidentResponseAgent


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a synthetic agentic incident-response pipeline."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    demo = subparsers.add_parser("demo", help="run an end-to-end synthetic incident")
    demo.add_argument(
        "--scenario",
        choices=["checkout-latency", "credential-abuse"],
        default="checkout-latency",
    )
    demo.add_argument("--output", type=Path, required=True)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.command == "demo":
        output = args.output.resolve()
        if output.exists() and any(output.iterdir()):
            raise SystemExit(f"output directory must be empty: {output}")
        output.mkdir(parents=True, exist_ok=True)
        summary = IncidentResponseAgent(output, args.scenario).run()
        print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
