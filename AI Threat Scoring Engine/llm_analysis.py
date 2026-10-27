
"""Local LLM explanations for the AI Threat Scoring Engine."""

import json
import urllib.error
import urllib.request

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3.2:3b"
REQUEST_TIMEOUT = 90


def generate_analyst_summary(alert):
    """Generate a cybersecurity summary grounded in supplied alert evidence."""

    evidence = {
        "rule_based_score": alert.get("Score"),
        "severity": alert.get("Severity"),
        "ml_prediction": alert.get("ML Prediction"),
        "ml_confidence": alert.get("ML Confidence"),
        "detection_evidence": alert.get("Detection Evidence", []),
        "shap_explanations": alert.get("explanations", []),
        "anomaly_status": alert.get("anomaly_status", "Unavailable"),
        "anomaly_score": alert.get("anomaly_score"),
        "event_data": alert.get("Event Data", {}),
    }

    prompt = f"""
You are assisting a cybersecurity analyst investigating an
authentication event.

Use only the evidence supplied below.

Rules:
- Never invent facts, users, IP addresses, or timestamps.
- Distinguish observed evidence from possible explanations.
- A suspicious prediction or anomaly does not prove an attack.
- Rule-based scoring, ML classification, and anomaly detection
  are separate signals, not automatic independent confirmation.
- Do not claim investigation steps have already been completed.
- Recommend practical, defensive investigation steps.
- Do not recommend automatically blocking accounts or IP addresses.
- Identify important missing information.

Return these sections:
1. Analyst Summary
2. Evidence and Limitations
3. Recommended Investigation Steps (three numbered steps)
4. Assessment Caveat

Alert evidence:
{json.dumps(evidence, indent=2, default=str)}
"""

    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.2},
    }

    request = urllib.request.Request(
        OLLAMA_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(
            request, timeout=REQUEST_TIMEOUT
        ) as response:
            result = json.loads(response.read().decode("utf-8"))

        summary = result.get("response", "").strip()

        if not summary:
            return {
                "success": False,
                "summary": "",
                "error": "Ollama returned an empty response.",
            }

        return {
            "success": True,
            "summary": summary,
            "error": None,
        }

    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {
            "success": False,
            "summary": "",
            "error": (
                "Ollama is unavailable or the request failed. "
                f"Details: {exc}"
            ),
        }

    except (json.JSONDecodeError, ValueError) as exc:
        return {
            "success": False,
            "summary": "",
            "error": f"Could not parse the Ollama response: {exc}",
        }
