#!/usr/bin/env python3
"""Validate runtime logs against frozen parity milestone patterns."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class Milestone:
    name: str
    any_of: tuple[str, ...]


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    required_milestones: tuple[Milestone, ...]


def load_fixture(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"fixture file not found: {path}")
    except json.JSONDecodeError as exc:
        raise SystemExit(f"failed to parse fixture JSON {path}: {exc}")


def parse_scenarios(raw: dict) -> dict[str, Scenario]:
    scenarios_raw = raw.get("scenarios")
    if not isinstance(scenarios_raw, list) or not scenarios_raw:
        raise SystemExit("fixture must define non-empty scenarios[]")

    parsed: dict[str, Scenario] = {}
    for idx, scenario_raw in enumerate(scenarios_raw):
        if not isinstance(scenario_raw, dict):
            raise SystemExit(f"scenarios[{idx}] must be an object")
        scenario_id = scenario_raw.get("id")
        if not isinstance(scenario_id, str) or not scenario_id.strip():
            raise SystemExit(f"scenarios[{idx}].id must be a non-empty string")
        if scenario_id in parsed:
            raise SystemExit(f"duplicate scenario id in fixture: {scenario_id}")
        milestones_raw = scenario_raw.get("required_milestones")
        if not isinstance(milestones_raw, list) or not milestones_raw:
            raise SystemExit(f"scenarios[{idx}].required_milestones must be non-empty")

        milestones: list[Milestone] = []
        for midx, milestone_raw in enumerate(milestones_raw):
            if not isinstance(milestone_raw, dict):
                raise SystemExit(
                    f"scenarios[{idx}].required_milestones[{midx}] must be an object"
                )
            name = milestone_raw.get("name")
            if not isinstance(name, str) or not name.strip():
                raise SystemExit(
                    f"scenarios[{idx}].required_milestones[{midx}].name must be non-empty"
                )
            any_of_raw = milestone_raw.get("any_of")
            if not isinstance(any_of_raw, list) or not any_of_raw:
                raise SystemExit(
                    f"scenarios[{idx}].required_milestones[{midx}].any_of must be non-empty"
                )
            patterns: list[str] = []
            for pidx, pattern in enumerate(any_of_raw):
                if not isinstance(pattern, str) or not pattern:
                    raise SystemExit(
                        f"scenarios[{idx}].required_milestones[{midx}].any_of"
                        f"[{pidx}] must be a non-empty string"
                    )
                try:
                    re.compile(pattern)
                except re.error as exc:
                    raise SystemExit(
                        f"invalid regex for {scenario_id}.{name}: {pattern!r}: {exc}"
                    )
                patterns.append(pattern)
            milestones.append(Milestone(name=name, any_of=tuple(patterns)))

        parsed[scenario_id] = Scenario(
            scenario_id=scenario_id,
            required_milestones=tuple(milestones),
        )

    return parsed


def first_match_after(patterns: Iterable[str], text: str, start_index: int) -> tuple[int, int] | None:
    best: tuple[int, int] | None = None
    for pattern in patterns:
        match = re.search(pattern, text[start_index:], flags=re.MULTILINE)
        if match is None:
            continue
        absolute_start = start_index + match.start()
        absolute_end = start_index + match.end()
        candidate = (absolute_start, absolute_end)
        if best is None or candidate < best:
            best = candidate
    return best


def has_match_anywhere(patterns: Iterable[str], text: str) -> bool:
    for pattern in patterns:
        if re.search(pattern, text, flags=re.MULTILINE) is not None:
            return True
    return False


def evaluate_scenario(
    log_text: str, scenario: Scenario
) -> tuple[bool, list[str], list[str], list[str]]:
    cursor = 0
    matched: list[str] = []
    missing: list[str] = []
    out_of_order: list[str] = []

    for milestone in scenario.required_milestones:
        matched_span = first_match_after(milestone.any_of, log_text, cursor)
        if matched_span is None:
            if has_match_anywhere(milestone.any_of, log_text):
                out_of_order.append(milestone.name)
            else:
                missing.append(milestone.name)
            continue
        _, end_idx = matched_span
        cursor = end_idx
        matched.append(milestone.name)

    return not missing and not out_of_order, matched, missing, out_of_order


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate OpenProton runtime logs against parity golden milestones."
    )
    parser.add_argument(
        "--fixture",
        default="tests/fixtures/parity_golden_logs.json",
        help="Path to parity golden log fixture JSON (default: %(default)s)",
    )
    parser.add_argument("--scenario", required=True, help="Scenario id from fixture")
    parser.add_argument("--log", required=True, help="Path to runtime log file to validate")
    parser.add_argument(
        "--report-json",
        help="Optional output path for machine-readable result report",
    )
    args = parser.parse_args()

    fixture_path = Path(args.fixture)
    log_path = Path(args.log)

    fixture = load_fixture(fixture_path)
    scenarios = parse_scenarios(fixture)
    scenario = scenarios.get(args.scenario)
    if scenario is None:
        available = ", ".join(sorted(scenarios.keys()))
        raise SystemExit(
            f"unknown scenario {args.scenario!r}; available scenarios: {available}"
        )

    try:
        log_text = log_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise SystemExit(f"log file not found: {log_path}")

    passed, matched, missing, out_of_order = evaluate_scenario(log_text, scenario)
    report = {
        "scenario": scenario.scenario_id,
        "passed": passed,
        "matched_milestones": matched,
        "missing_milestones": missing,
        "out_of_order_milestones": out_of_order,
        "fixture": str(fixture_path),
        "log": str(log_path),
    }

    if args.report_json:
        report_path = Path(args.report_json)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if passed:
        print(
            f"PASS: scenario={scenario.scenario_id} "
            f"matched={len(matched)}/{len(scenario.required_milestones)}"
        )
        return 0

    failure_parts: list[str] = []
    if missing:
        failure_parts.append(f"missing={', '.join(missing)}")
    if out_of_order:
        failure_parts.append(f"out_of_order={', '.join(out_of_order)}")
    detail = "; ".join(failure_parts) if failure_parts else "unknown mismatch"
    print(f"FAIL: scenario={scenario.scenario_id} {detail}", file=sys.stderr)
    if matched:
        print(
            f"matched milestones before failure: {', '.join(matched)}",
            file=sys.stderr,
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
