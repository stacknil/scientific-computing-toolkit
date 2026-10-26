#!/usr/bin/env python3
"""Bounded offline qualification. All generated evidence goes outside the checkout.

Run from the tool directory with an installed dev environment. This script never
publishes, installs packages, dispatches workflows or contacts evidence services.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import asdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GUARD = """import json, os, socket, sys
from pathlib import Path
def deny(event, args):
    blocked = event in {"socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyaddr"}
    if event in {"socket.connect", "socket.sendto"}:
        blocked = bool(args) and getattr(args[0], "family", None) in {socket.AF_INET, socket.AF_INET6}
    if blocked:
        with Path(os.environ["SCT_QUALIFICATION_NETWORK_LOG"]).open("a", encoding="utf-8") as log:
            log.write(json.dumps({"event": event, "action": "blocked-before-transport"}) + "\\n")
        raise RuntimeError("Live network access is forbidden during offline qualification")
sys.addaudithook(deny)
os.environ["SCT_QUALIFICATION_OFFLINE_GUARD"] = "1"
"""


def write_json(path, value):
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def inventory():
    paths = sorted(
        [
            *ROOT.glob("src/**/*.py"),
            *ROOT.glob("tests/*.py"),
            ROOT / "scripts" / "qualify-decision-stability.py",
            ROOT / "docs" / "policy-schema.md",
        ]
    )
    return {
        path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in paths
    }


def imports():
    sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]
    from test_decision_stability import observe_case, render_bundle
    from test_canonical_release_enrichment import exercise_c03_transition
    from test_decision_stability_negatives import CONTROLS, exercise_control
    from test_decision_stability_oracle import CASES, require, validate_case
    from test_decision_stability_pairs import (
        REPRESENTATIONS,
        TRANSITIONS,
        exercise_manifest_overlap,
        exercise_representation,
        exercise_transition,
    )
    from test_decision_stability_providers import (
        PROVIDERS,
        exercise_c02_transition,
        exercise_provider,
    )
    from test_decision_stability_reports import (
        CLI_CASES,
        SARIF_EXPECTED,
        cdx_component,
        consumer_decision,
        run_cli,
        validate_bundle,
    )

    return {
        "exercise_c03_transition": exercise_c03_transition,
        "observe_case": observe_case,
        "render_bundle": render_bundle,
        "CONTROLS": CONTROLS,
        "exercise_control": exercise_control,
        "CASES": CASES,
        "require": require,
        "validate_case": validate_case,
        "REPRESENTATIONS": REPRESENTATIONS,
        "TRANSITIONS": TRANSITIONS,
        "exercise_manifest_overlap": exercise_manifest_overlap,
        "exercise_representation": exercise_representation,
        "exercise_transition": exercise_transition,
        "PROVIDERS": PROVIDERS,
        "exercise_c02_transition": exercise_c02_transition,
        "exercise_provider": exercise_provider,
        "CLI_CASES": CLI_CASES,
        "SARIF_EXPECTED": SARIF_EXPECTED,
        "cdx_component": cdx_component,
        "consumer_decision": consumer_decision,
        "run_cli": run_cli,
        "validate_bundle": validate_bundle,
    }


def worker(output, seed):
    if os.environ.get("SCT_QUALIFICATION_OFFLINE_GUARD") != "1":
        raise RuntimeError("The subprocess offline guard is required")
    api = imports()
    import sbom_diff_risk

    if (
        Path(sbom_diff_risk.__file__).resolve()
        != ROOT / "src" / "sbom_diff_risk" / "__init__.py"
    ):
        raise RuntimeError("Qualification imported a different source checkout")
    # Expectations are persisted before any production observation in this round.
    write_json(
        output / "preregistration.json",
        {
            "seed": seed,
            "cases": [asdict(case) for case in api["CASES"]],
            "transitions": [asdict(item) for item in api["TRANSITIONS"]],
            "representations": [*api["REPRESENTATIONS"], "R19"],
            "negative_controls": list(api["CONTROLS"]),
            "C03": {
                "classification": "STABLE",
                "decisions": ["PASS", "PASS"],
                "contract": "CONTRACT_CLARIFIED_CANONICAL_RELEASE_VERSION",
            },
            "providers": [asdict(case) for case in api["PROVIDERS"]],
            "expectation_sources": [
                "tests/test_decision_stability_oracle.py",
                "tests/test_decision_stability_pairs.py",
                "tests/test_decision_stability_providers.py",
            ],
        },
    )
    microcases = []
    for case in api["CASES"]:
        actual, report = api["observe_case"](case, output / case.id, seed)
        api["validate_case"](case, actual)
        if report is not None:
            bundle = api["render_bundle"](report)
            api["validate_bundle"](
                bundle,
                actual["exit_code"],
                sarif_expected=api["SARIF_EXPECTED"].get(case.id),
                expected_rows=case.rows,
            )
            api["require"]("repeat-render", api["render_bundle"](report), bundle)
        microcases.append({"id": case.id, "family": case.family, "observation": actual})
    transitions = [
        api["exercise_transition"](item, output / item.id, seed)
        for item in api["TRANSITIONS"]
    ]
    transitions.extend(
        api["exercise_representation"](item, output / item, seed)
        for item in api["REPRESENTATIONS"]
    )
    transitions.append(api["exercise_manifest_overlap"](output / "R19"))
    providers = [
        api["exercise_provider"](case, output / case.id) for case in api["PROVIDERS"]
    ]
    transitions.append(api["exercise_c02_transition"](output / "C02"))
    transitions.append(api["exercise_c03_transition"](output / "C03"))
    cli_results = []
    for label, policy, flags, decision, expected_exit in api["CLI_CASES"]:
        code, bundle = api["run_cli"](
            output / ("cli-" + label),
            {"bomFormat": "CycloneDX", "components": []},
            {"bomFormat": "CycloneDX", "components": [api["cdx_component"]()]},
            policy,
            flags,
        )
        api["require"]("cli-expected-exit", code, expected_exit)
        api["require"]("cli-consumer", api["consumer_decision"](bundle, code), decision)
        cli_results.append({"id": label, "decision": decision, "exit_code": code})
    negatives = [
        api["exercise_control"](item, output / item[0], seed)
        for item in api["CONTROLS"]
    ]
    write_json(
        output / "results.json",
        {
            "seed": seed,
            "microcases": microcases,
            "transitions": transitions,
            "providers": providers,
            "cli": cli_results,
            "negative_controls": negatives,
            "import_origin": "src/sbom_diff_risk/__init__.py",
            "counts": {
                "microcases": len(microcases),
                "transitions": len(transitions),
                "provider_cases": len(providers),
                "cli_cases": len(cli_results),
                "negative_controls": len(negatives),
                "classifications": dict(
                    Counter(item["observed_classification"] for item in transitions)
                ),
            },
        },
    )


def command(output, label, args, environment):
    start = time.monotonic()
    with (
        (output / (label + ".stdout")).open("w", encoding="utf-8") as stdout,
        (output / (label + ".stderr")).open("w", encoding="utf-8") as stderr,
    ):
        result = subprocess.run(
            args,
            cwd=ROOT,
            env=environment,
            stdout=stdout,
            stderr=stderr,
            timeout=300,
            check=False,
        )
    receipt = {
        "label": label,
        "exit_code": result.returncode,
        "seconds": round(time.monotonic() - start, 3),
    }
    write_json(output / (label + ".receipt.json"), receipt)
    if result.returncode:
        raise RuntimeError(
            f"Qualification stopped at {label}, exit {result.returncode}; inspect the external logs"
        )
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--seeds", type=int, nargs="+", default=[103, 117, 120])
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    output = args.output_root.resolve()
    if output == ROOT or ROOT in output.parents or ROOT.parents[1] in output.parents:
        parser.error("Output must be outside the entire source checkout")
    if args.worker:
        worker(output, args.seeds[0])
        return
    if not 1 <= len(args.seeds) <= 3 or len(set(args.seeds)) != len(args.seeds):
        parser.error(
            "Use one to three distinct seeds; repeated seeds do not add independent cases"
        )
    output.mkdir(parents=True, exist_ok=False)
    initial_inventory = inventory()
    write_json(output / "source-inventory.json", initial_inventory)
    guard_dir = output / "offline-guard"
    guard_dir.mkdir()
    (guard_dir / "sitecustomize.py").write_text(GUARD, encoding="utf-8")
    environment = {
        **os.environ,
        "PYTHONPATH": str(guard_dir),
        "PYTHONDONTWRITEBYTECODE": "1",
        "GIT_OPTIONAL_LOCKS": "0",
    }
    environment["SCT_QUALIFICATION_NETWORK_LOG"] = str(
        output / "network-attempts.jsonl"
    )
    temporary = output / "tmp"
    temporary.mkdir()
    environment.update(TMP=str(temporary), TEMP=str(temporary))
    rounds = []
    for seed in args.seeds:
        round_root = output / f"round-{seed}"
        round_root.mkdir()
        command(
            round_root,
            "qualification",
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--worker",
                "--seeds",
                str(seed),
                "--output-root",
                str(round_root),
            ],
            environment,
        )
        junit = round_root / "full-suite.xml"
        command(
            round_root,
            "full-suite",
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "-ra",
                f"--junitxml={junit}",
                f"--basetemp={round_root / 'pytest'}",
                "-o",
                f"cache_dir={round_root / 'cache'}",
            ],
            environment,
        )
        suite = ET.parse(junit).getroot()
        totals = {
            key: sum(int(item.get(key, 0)) for item in suite.iter("testsuite"))
            for key in ("tests", "failures", "errors", "skipped")
        }
        if totals["failures"] or totals["errors"] or totals["skipped"]:
            raise RuntimeError(f"Non-passing full-suite result: {totals}")
        result = json.loads((round_root / "results.json").read_text(encoding="utf-8"))
        rounds.append({"seed": seed, "counts": result["counts"], "full_suite": totals})
        print(json.dumps(rounds[-1], sort_keys=True), flush=True)
    command(
        output,
        "example-artifacts",
        [sys.executable, "scripts/regenerate-example-artifacts.py", "--check"],
        environment,
    )
    bash = shutil.which("bash")
    consumer = {"status": "NOT_RUN", "reason": "bash unavailable"}
    if bash:
        records = []
        for expected in (0, 1, 2):
            destination = output / f"consumer-{expected}"
            destination.mkdir()
            # The comparison command is replaced with an actual observed status;
            # capture and final exit use the existing consumer example's shell logic.
            script = f"""set +e
(exit {expected})
status=$?
set -e
echo "exit_code=$status" >> "$GITHUB_OUTPUT"
exit "$status"
"""
            result = subprocess.run(
                [bash, "-c", script],
                cwd=destination,
                env={**environment, "GITHUB_OUTPUT": "outputs.txt"},
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            captured = (destination / "outputs.txt").read_text(encoding="utf-8").strip()
            if result.returncode != expected or captured != f"exit_code={expected}":
                raise RuntimeError("Consumer status propagation mismatch")
            records.append(
                {
                    "comparison_exit": expected,
                    "final_exit": result.returncode,
                    "output": captured,
                }
            )
        consumer = {
            "status": "PASS",
            "kind": "local bash status propagation, no workflow execution",
            "records": records,
        }
    write_json(output / "consumer.json", consumer)
    if (output / "network-attempts.jsonl").exists():
        raise RuntimeError(
            "A network operation was attempted; the guard blocked it and qualification cannot pass"
        )
    if inventory() != initial_inventory:
        raise RuntimeError(
            "Source changed during qualification; results do not qualify the final candidate"
        )
    manifest = {
        "status": "EXECUTED",
        "seeds": args.seeds,
        "rounds": rounds,
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "os": platform.system(),
        "dependencies": {
            name: importlib.metadata.version(name)
            for name in ("pytest", "packaging", "packageurl-python", "PyYAML")
        },
        "source_inventory": initial_inventory,
        "actual_network_attempts": 0,
        "consumer_shell": consumer,
        "parallelism": 1,
        "per_command_timeout_seconds": 300,
        "independent_cases_are_not_multiplied_by_round_count": True,
        "remote_ci": "NOT_RUN",
        "live_evidence_enrichment": "FORBIDDEN",
        "publication": "NOT_PERFORMED",
    }
    write_json(output / "execution.json", manifest)
    print(
        "All requested local rounds executed; final audit and product-policy decisions are separate gates."
    )


if __name__ == "__main__":
    main()
