"""The public replay entry point must execute its real offline worker."""

import json
import os
import runpy
import subprocess
import sys
from pathlib import Path


def test_replay_worker_executes_registered_cases_with_network_guard(tmp_path):
    root = Path(__file__).resolve().parents[1]
    script = root / "scripts" / "qualify-decision-stability.py"
    namespace = runpy.run_path(str(script), run_name="qualification_definition")
    guard = tmp_path / "guard"
    guard.mkdir()
    (guard / "sitecustomize.py").write_text(namespace["GUARD"], encoding="utf-8")
    output = tmp_path / "round"
    output.mkdir()
    attempts = tmp_path / "network-attempts.jsonl"
    environment = {
        **os.environ,
        "PYTHONPATH": str(guard),
        "PYTHONDONTWRITEBYTECODE": "1",
        "SCT_QUALIFICATION_NETWORK_LOG": str(attempts),
        "TMP": str(tmp_path),
        "TEMP": str(tmp_path),
    }
    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "--worker",
            "--seeds",
            "103",
            "--output-root",
            str(output),
        ],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    data = json.loads((output / "results.json").read_text(encoding="utf-8"))
    assert data["counts"]["microcases"] == 72
    assert data["counts"]["negative_controls"] == 14
    assert data["import_origin"] == "src/sbom_diff_risk/__init__.py"
    assert all(
        item["red_detected"] and item["green_validated"]
        for item in data["negative_controls"]
    )
    assert not attempts.exists()
