
import sys
from pathlib import Path

import pandas as pd

from scorer import score_threat
from predict_threat import predict_threat

BASE_DIR = Path(__file__).resolve().parent
csv_path = Path(sys.argv[1]) if len(sys.argv) > 1 else BASE_DIR / "sample_logs.csv"

if not csv_path.is_absolute():
    csv_path = Path.cwd() / csv_path

logs = pd.read_csv(csv_path)

required_columns = {
    "event_id",
    "unusual_country",
    "unknown_ip",
    "failed_attempts",
    "unusual_time",
    "success_after_failures"
}

missing_columns = required_columns - set(logs.columns)

if missing_columns:
    raise ValueError(
        "CSV is missing required columns: "
        + ", ".join(sorted(missing_columns))
    )

boolean_columns = [
    "unusual_country",
    "unknown_ip",
    "unusual_time",
    "success_after_failures"
]

for column in boolean_columns:
    values = logs[column].astype(str).str.strip().str.lower()
    invalid_values = values[~values.isin(["true", "false", "0", "1"])]

    if not invalid_values.empty:
        raise ValueError(
            f"Invalid value(s) in column '{column}': "
            + ", ".join(invalid_values.unique())
        )

    logs[column] = values.map({
        "true": True,
        "false": False,
        "1": True,
        "0": False
    })

failed_attempts = pd.to_numeric(
    logs["failed_attempts"],
    errors="coerce"
)

invalid_attempts = (
    failed_attempts.isna()
    | (failed_attempts < 0)
    | (failed_attempts % 1 != 0)
)

if invalid_attempts.any():
    bad_values = logs.loc[
        invalid_attempts, "failed_attempts"
    ].astype(str).unique()

    raise ValueError(
        "Invalid value(s) in column 'failed_attempts': "
        + ", ".join(bad_values)
    )

logs["failed_attempts"] = failed_attempts.astype(int)

alerts = []

for _, row in logs.iterrows():
    event = {
        "unusual_country": row["unusual_country"],
        "unknown_ip": row["unknown_ip"],
        "failed_attempts": int(row["failed_attempts"]),
        "unusual_time": row["unusual_time"],
        "success_after_failures": row["success_after_failures"]
    }

    rule_result = score_threat(event)
    ml_result = predict_threat(event)

    alerts.append({
        "event_id": row["event_id"],
        "score": rule_result["score"],
        "severity": rule_result["severity"],
        "reasons": ", ".join(rule_result["reasons"]),
        "ml_prediction": ml_result["prediction"],
        "ml_confidence": ml_result["confidence"],
        "anomaly_status": ml_result["anomaly_status"],
        "anomaly_score": ml_result["anomaly_score"],
        "explanations": ml_result["explanations"]
    })

alerts.sort(key=lambda alert: alert["score"], reverse=True)

print("AI THREAT SCORING ENGINE")
print("=" * 60)

for alert in alerts:
    print(f"Event ID: {alert['event_id']}")
    print(f"Rule-Based Threat Score: {alert['score']}")
    print(f"Severity: {alert['severity']}")
    print(f"Reasons: {alert['reasons']}")
    print(f"ML Prediction: {alert['ml_prediction']}")
    print(f"ML Confidence: {alert['ml_confidence']:.1%}")
    print(f"Anomaly Status: {alert['anomaly_status']}")
    print(f"Anomaly Score: {alert['anomaly_score']:.4f}")

    if alert["explanations"]:
        print("Top ML Explanation Features:")

        for item in alert["explanations"][:3]:
            print(
                f"  - {item['feature']}: "
                f"{item['impact']:+.4f} "
                f"({item['direction']})"
            )

print("THREAT SUMMARY")
print("=" * 60)

total_events = len(alerts)

high_severity = sum(
    1 for alert in alerts
    if str(alert["severity"]).lower() in ("high", "critical")
)

medium_severity = sum(
    1 for alert in alerts
    if str(alert["severity"]).lower() == "medium"
)

low_severity = sum(
    1 for alert in alerts
    if str(alert["severity"]).lower() == "low"
)

suspicious_predictions = sum(
    1 for alert in alerts
    if alert["ml_prediction"] == "Suspicious"
)

anomalies = sum(
    1 for alert in alerts
    if alert["anomaly_status"] == "Anomaly Detected"
)

average_score = (
    sum(alert["score"] for alert in alerts) / total_events
    if total_events else 0
)

print("Total Events:", total_events)
print("High Severity:", high_severity)
print("Medium Severity:", medium_severity)
print("Low Severity:", low_severity)
print("ML Suspicious Predictions:", suspicious_predictions)
print("Anomalies Detected:", anomalies)
print("Average Threat Score:", round(average_score, 2))

if alerts:
    highest_alert = alerts[0]

    print("HIGHEST-SCORING EVENT")
    print("Event ID:", highest_alert["event_id"])
    print("Threat Score:", highest_alert["score"])
    print("Severity:", highest_alert["severity"])
    print("ML Prediction:", highest_alert["ml_prediction"])
    print("Anomaly Status:", highest_alert["anomaly_status"])

print("Review anomalies as investigation leads, not automatic proof of attacks.")
