import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = (Path(__file__).resolve().parents[1] / "AI Threat Scoring Engine")


def run_analyzer():
    return subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "analyze_logs.py")],
        cwd=PROJECT_ROOT, capture_output=True, text=True
    )


def create_csv(tmp_path, row):
    csv_path = tmp_path / "test_logs.csv"

    with open(csv_path, "w") as f:
        f.write(
            "event_id,unusual_country,unknown_ip,failed_attempts,"
            "unusual_time,success_after_failures\n"
        )
        f.write(row + "\n")

    return csv_path


def test_invalid_boolean_values(tmp_path):
    row = "AUTH-20261013-001,maybe,true,0,false,true"
    csv_path = create_csv(tmp_path, row)

    result = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "analyze_logs.py"), str(csv_path)],
        cwd=PROJECT_ROOT, capture_output=True, text=True
    )

    assert result.returncode != 0
    assert "Invalid value(s) in column 'unusual_country'" in result.stderr


def test_invalid_failed_attempts(tmp_path):
    row = "AUTH-20261013-002,true,false,-1,true,false"
    csv_path = create_csv(tmp_path, row)

    result = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "analyze_logs.py"), str(csv_path)],
        cwd=PROJECT_ROOT, capture_output=True, text=True
    )

    assert result.returncode != 0
    assert "Invalid value(s) in column 'failed_attempts'" in result.stderr


def test_non_numeric_failed_attempts(tmp_path):
    row = "AUTH-20261013-003,true,false,abc,true,false"
    csv_path = create_csv(tmp_path, row)

    result = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "analyze_logs.py"), str(csv_path)],
        cwd=PROJECT_ROOT, capture_output=True, text=True
    )

    assert result.returncode != 0
    
    assert "Invalid value(s) in column 'failed_attempts'" in result.stderr
