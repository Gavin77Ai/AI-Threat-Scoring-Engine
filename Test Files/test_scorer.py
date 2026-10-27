
import sys
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "AI Threat Scoring Engine")
)

from scorer import score_threat


events = [
    {
        "name": "Normal Login",
        "unusual_country": False,
        "unknown_ip": False,
        "failed_attempts": 0,
        "unusual_time": False,
        "success_after_failures": False
    },
    {
        "name": "Unknown IP",
        "unusual_country": False,
        "unknown_ip": True,
        "failed_attempts": 0,
        "unusual_time": False,
        "success_after_failures": False
    },
    {
        "name": "Repeated Failed Logins",
        "unusual_country": False,
        "unknown_ip": False,
        "failed_attempts": 6,
        "unusual_time": False,
        "success_after_failures": False
    },
    {
        "name": "Suspicious Login Time",
        "unusual_country": False,
        "unknown_ip": False,
        "failed_attempts": 0,
        "unusual_time": True,
        "success_after_failures": False
    },
    {
        "name": "Unusual Country and Unknown IP",
        "unusual_country": True,
        "unknown_ip": True,
        "failed_attempts": 0,
        "unusual_time": False,
        "success_after_failures": False
    },
    {
        "name": "Possible Account Attack",
        "unusual_country": True,
        "unknown_ip": True,
        "failed_attempts": 6,
        "unusual_time": True,
        "success_after_failures": True
    }
]


def test_scorer_results():
    expected_scores = [0, 20, 25, 10, 45, 100]
    expected_severities = [
        "Low",
        "Low",
        "Low",
        "Low",
        "Medium",
        "High"
    ]

    for event, expected_score, expected_severity in zip(
        events, expected_scores, expected_severities
    ):
        result = score_threat(event)

        assert result["score"] == expected_score, event["name"]
        assert result["severity"] == expected_severity, event["name"]


if __name__ == "__main__":
    for event in events:
        result = score_threat(event)

        print("Event:", event["name"])
        print("Score:", result["score"])
        print("Severity:", result["severity"])
        print("Reasons:", ", ".join(result["reasons"]))
        print()
