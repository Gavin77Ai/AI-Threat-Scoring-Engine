def score_threat(event):
    score = 0
    reasons = []

    if event["unusual_country"]:
        score += 25
        reasons.append("Login from an unusual country")

    if event["unknown_ip"]:
        score += 20
        reasons.append("Login has an unknown IP address")

    if event["unusual_time"]:
        score += 10
        reasons.append("Login at an unusual time")

    if event["failed_attempts"] >= 5:
        score += 25
        reasons.append("Multiple failed login attempts")
    elif event["failed_attempts"] >= 3:
        score += 15
        reasons.append("Several failed login attempts")

    if event["success_after_failures"]:
        score += 20
        reasons.append("Successful login after multiple failures")

    score = min(score, 100)

    if score >= 70:
        severity = "High"
    elif score >= 40:
        severity = "Medium"
    else:
        severity = "Low"

    if not reasons:
        reasons.append("No risk indicators detected")

    return {
        "score": score,
        "severity": severity,
        "reasons": reasons,
    }


