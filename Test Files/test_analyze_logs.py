import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = (
    Path(__file__).resolve().parents[1]
    / "AI Threat Scoring Engine"
)


def run_analyzer():
    result = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "analyze_logs.py")],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=True
    )

    return result.stdout


def test_alerts_are_sorted_by_threat_score():
    output = run_analyzer()

    highest = output.index("Event ID: AUTH-20261013-007")
    second_highest = output.index("Event ID: AUTH-20261013-006")

    assert highest < second_highest


def test_threat_summary_counts_are_correct():
    output = run_analyzer()

    assert "Total Events: 8" in output
    assert "High Severity: 1" in output
    assert "Medium Severity: 4" in output
    assert "Low Severity: 3" in output


def test_highest_risk_event_is_reported():
    output = run_analyzer()

    assert "Event ID: AUTH-20261013-007" in output
    assert "Threat Score: 100" in output
    assert "Average Threat Score: 43.12" in output