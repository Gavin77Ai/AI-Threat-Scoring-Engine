
import joblib
import pandas as pd
import numpy as np
from pathlib import Path

MODEL_FILE = Path(__file__).resolve().parent / "threat_model.pkl"

saved_data = joblib.load(MODEL_FILE)

model = saved_data["model"]
anomaly_detector = saved_data["anomaly_detector"]
feature_columns = saved_data["feature_columns"]
boolean_columns = saved_data["boolean_columns"]


def clean_event(event):
    missing_features = [
        column for column in feature_columns
        if column not in event
    ]

    if missing_features:
        raise ValueError(
            "Missing required features: " + ", ".join(missing_features)
        )

    cleaned = {}

    for column in boolean_columns:
        value = event[column]

        if isinstance(value, str):
            value = value.strip().lower()

            if value not in ("true", "false"):
                raise ValueError(
                    f"Invalid Boolean value for '{column}': {event[column]}"
                )

            cleaned[column] = int(value == "true")

        elif isinstance(value, (bool, np.bool_)):
            cleaned[column] = int(value)

        elif isinstance(value, (int, np.integer)) and value in (0, 1):
            cleaned[column] = int(value)

        else:
            raise ValueError(
                f"Invalid Boolean value for '{column}': {value!r}"
            )

    attempts = pd.to_numeric(
        pd.Series([event["failed_attempts"]]),
        errors="coerce"
    ).iloc[0]

    if (
        pd.isna(attempts)
        or not np.isfinite(attempts)
        or attempts < 0
        or attempts % 1 != 0
    ):
        raise ValueError(
            "failed_attempts must be a non-negative integer."
        )

    cleaned["failed_attempts"] = int(attempts)

    data = pd.DataFrame(
        [{column: cleaned[column] for column in feature_columns}],
        columns=feature_columns
    )

    return data


def get_global_feature_importance():
    importances = getattr(model, "feature_importances_", None)

    if importances is None:
        return []

    ranked = sorted(
        zip(feature_columns, importances),
        key=lambda item: item[1],
        reverse=True
    )

    return [
        {
            "feature": feature,
            "importance": round(float(importance), 4)
        }
        for feature, importance in ranked
    ]


def explain_prediction(data, class_index):
    try:
        import shap

        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(data)

        if isinstance(shap_values, list):
            values = np.asarray(shap_values[class_index])
        else:
            values = np.asarray(shap_values)

            if values.ndim == 3:
                values = values[0, :, class_index]
            elif values.ndim == 2:
                values = values[0]
            else:
                return [], "global_feature_importance_fallback"

        values = values.reshape(-1)

        if len(values) != len(feature_columns):
            return [], "global_feature_importance_fallback"

        explanations = []

        for feature, value in zip(feature_columns, values):
            impact = float(value)
            feature_value = data.iloc[0][feature]

            if hasattr(feature_value, "item"):
                feature_value = feature_value.item()

            explanations.append({
                "feature": feature,
                "value": feature_value,
                "impact": round(impact, 4),
                "direction": (
                    "supports_prediction" if impact > 0
                    else "opposes_prediction" if impact < 0
                    else "neutral"
                )
            })

        explanations.sort(
            key=lambda item: abs(item["impact"]),
            reverse=True
        )

        return explanations, "SHAP"

    except Exception:
        return [], "global_feature_importance_fallback"


def predict_threat(event):
    data = clean_event(event)

    prediction = model.predict(data)[0]
    probabilities = model.predict_proba(data)[0]
    class_index = list(model.classes_).index(prediction)

    anomaly_prediction = int(anomaly_detector.predict(data)[0])
    anomaly_score = float(anomaly_detector.decision_function(data)[0])

    explanations, explanation_method = explain_prediction(
        data,
        class_index
    )

    return {
        "prediction": prediction,
        "confidence": round(float(probabilities[class_index]), 4),
        "explanations": explanations,
        "explanation_method": explanation_method,
        "global_feature_importance": get_global_feature_importance(),
        "is_anomaly": anomaly_prediction == -1,
        "anomaly_score": round(anomaly_score, 4),
        "anomaly_status": (
            "Anomaly Detected"
            if anomaly_prediction == -1
            else "Within Baseline"
        )
    }
